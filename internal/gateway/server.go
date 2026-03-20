// Package gateway implements the Legit Flow reverse proxy server.
// It intercepts requests to LLM endpoints, applies the detection/transformation
// pipeline, and streams responses through the output guard.
package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/legitflow/legitflow/internal/audit"
	"github.com/legitflow/legitflow/internal/common"
	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/outputguard"
	"github.com/legitflow/legitflow/internal/policy"
	"github.com/legitflow/legitflow/internal/transformer"
)

// Server is the main gateway server that proxies and inspects LLM traffic.
type Server struct {
	cfg          *common.Config
	logger       *slog.Logger
	detectorReg  *detector.Registry
	policyEngine *policy.Engine
	auditLogger  *audit.Logger
	proxy        *httputil.ReverseProxy
	mux          *http.ServeMux
}

// NewServer creates and configures the gateway server.
func NewServer(
	cfg *common.Config,
	logger *slog.Logger,
	reg *detector.Registry,
	eng *policy.Engine,
	auditor *audit.Logger,
) (*Server, error) {
	target, err := url.Parse(cfg.LLMBackendURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend URL: %w", err)
	}

	s := &Server{
		cfg:          cfg,
		logger:       logger,
		detectorReg:  reg,
		policyEngine: eng,
		auditLogger:  auditor,
		mux:          http.NewServeMux(),
	}

	// Configure reverse proxy
	s.proxy = httputil.NewSingleHostReverseProxy(target)
	s.proxy.ModifyResponse = s.modifyResponse

	// Routes
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/api/v1/policy/reload", s.handlePolicyReload)
	s.mux.HandleFunc("/", s.handleProxy)

	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleProxy is the main proxy handler — the core data plane.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := uuid.New().String()
	ctx := context.WithValue(r.Context(), ctxKeyRequestID, requestID)
	r = r.WithContext(ctx)

	s.logger.Info("request.start",
		"request_id", requestID,
		"method", r.Method,
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
	)

	// ── Step 1: Intercept request body ──────────────────────────
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	inputText := string(bodyBytes)

	// ── Step 2: Detect PII/Secrets in input ─────────────────────
	detections, err := s.detectorReg.DetectAll(ctx, inputText)
	if err != nil {
		s.logger.Error("detection failed", "error", err, "request_id", requestID)
		http.Error(w, "Internal detection error", http.StatusInternalServerError)
		return
	}

	// ── Step 3: Transform based on policy ───────────────────────
	actionMap := s.policyEngine.GetActionMap()
	transformedText, applied := transformer.TransformText(inputText, detections, actionMap)

	// Inject tokens mapping for round-trip decryption
	tokens := make(tokenMap)
	for _, a := range applied {
		if a.Action == transformer.ActionTokenize || a.Action == transformer.ActionPseudonym {
			tokens[a.Replacement] = a.Original
		}
	}
	ctx = context.WithValue(ctx, ctxKeyTokens, tokens)
	r = r.WithContext(ctx)

	// ── Step 4: Record metrics ──────────────────────────────────
	for _, det := range detections {
		action := actionMap[det.Tier]
		common.DetectionsTotal.WithLabelValues(string(det.Type), string(action)).Inc()
	}

	// ── Step 5: Audit Tier 1 (metadata, always) ─────────────────
	outcome := "allowed"
	if len(applied) > 0 {
		outcome = "transformed"
	}
	// Check if any detection resulted in a block
	for _, a := range applied {
		if a.Action == transformer.ActionBlock {
			outcome = "blocked"
			break
		}
	}

	tier1 := audit.Tier1Event{
		RequestID:  requestID,
		UserID:     r.Header.Get("X-User-ID"),
		SourceIP:   r.RemoteAddr,
		Action:     mostRestrictiveAction(applied),
		PolicyName: s.policyEngine.GetPolicy().Name,
		Detections: summarizeDetections(detections),
		Outcome:    outcome,
		LatencyMs:  time.Since(start).Milliseconds(),
	}
	s.auditLogger.LogTier1(tier1)

	// ── Step 6: Audit Tier 2 (redacted content, if enabled) ─────
	if len(applied) > 0 {
		s.auditLogger.LogTier2(audit.Tier2Event{
			EventID:           tier1.EventID,
			RedactedInput:     transformedText,
			TransformsSummary: applied,
		})
	}

	// ── Step 7: If blocked, return error to client ──────────────
	if outcome == "blocked" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", requestID)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"error":"request blocked by policy","request_id":%q}`, requestID)
		return
	}

	// ── Step 8: Forward transformed request to LLM backend ──────
	r.Body = io.NopCloser(bytes.NewReader([]byte(transformedText)))
	r.ContentLength = int64(len(transformedText))
	r.Header.Set("Content-Length", strconv.Itoa(len(transformedText)))
	r.Header.Set("X-Request-ID", requestID)

	// Check if streaming is requested
	if isStreamingRequest(r) {
		s.handleStreamingProxy(w, r, requestID)
		return
	}

	s.proxy.ServeHTTP(w, r)
}

// handleStreamingProxy handles SSE/chunked streaming responses with output guard.
func (s *Server) handleStreamingProxy(w http.ResponseWriter, r *http.Request, requestID string) {
	guard := outputguard.NewStreamGuard(s.detectorReg, s.cfg.HoldbackWindowSize)
	ctx := r.Context()

	// Create a custom transport that intercepts the streaming response
	target, _ := url.Parse(s.cfg.LLMBackendURL)
	proxyReq, err := http.NewRequestWithContext(ctx, r.Method,
		target.String()+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	// Copy headers
	for k, v := range r.Header {
		proxyReq.Header[k] = v
	}

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set streaming headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(resp.StatusCode)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Read chunks from backend, pass through output guard
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			result, guardErr := guard.ProcessChunk(ctx, chunk)
			if guardErr != nil {
				s.logger.Error("output guard error", "error", guardErr, "request_id", requestID)
				break
			}

			if result.Violation {
				// Stream truncated — send safe message and stop
				_, _ = fmt.Fprintf(w, "data: %s\n\n", result.Message)
				flusher.Flush()
				s.logger.Warn("stream truncated by output guard",
					"request_id", requestID)
				return
			}

			if result.SafeText != "" {
				safeText := result.SafeText
				if tokens, ok := ctx.Value(ctxKeyTokens).(tokenMap); ok && len(tokens) > 0 {
					for rep, orig := range tokens {
						safeText = strings.ReplaceAll(safeText, rep, orig)
					}
				}
				_, _ = fmt.Fprintf(w, "data: %s\n\n", safeText)
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}

	// Flush remaining buffer
	result, err := guard.Flush(ctx)
	if err != nil {
		s.logger.Error("output guard flush error", "error", err, "request_id", requestID)
		return
	}
	if result.SafeText != "" {
		safeText := result.SafeText
		if tokens, ok := ctx.Value(ctxKeyTokens).(tokenMap); ok && len(tokens) > 0 {
			for rep, orig := range tokens {
				safeText = strings.ReplaceAll(safeText, rep, orig)
			}
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", safeText)
		flusher.Flush()
	}
	if result.Violation {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", result.Message)
		flusher.Flush()
	}
}

// modifyResponse scans non-streaming responses through the output guard.
func (s *Server) modifyResponse(resp *http.Response) error {
	// For streaming responses, handled separately
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Scan response for PII/secrets
	ctx := context.Background()
	detections, err := s.detectorReg.DetectAll(ctx, string(bodyBytes))
	if err != nil {
		return err
	}

	if len(detections) > 0 {
		actionMap := s.policyEngine.GetActionMap()
		transformed, _ := transformer.TransformText(string(bodyBytes), detections, actionMap)
		bodyBytes = []byte(transformed)
	}

	// Restore tokens (Decryption)
	reqCtx := resp.Request.Context()
	if tokens, ok := reqCtx.Value(ctxKeyTokens).(tokenMap); ok && len(tokens) > 0 {
		text := string(bodyBytes)
		for rep, orig := range tokens {
			text = strings.ReplaceAll(text, rep, orig)
		}
		bodyBytes = []byte(text)
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	return nil
}

// ── Health endpoints ────────────────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.policyEngine.Reload(); err != nil {
		s.logger.Error("policy reload failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(`{"status":"reloaded"}`))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

type contextKey string

const ctxKeyRequestID contextKey = "request_id"
const ctxKeyTokens contextKey = "tokens"

type tokenMap map[string]string

func isStreamingRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream") ||
		strings.Contains(r.URL.RawQuery, "stream=true")
}

func mostRestrictiveAction(applied []transformer.AppliedTransform) transformer.Action {
	if len(applied) == 0 {
		return transformer.ActionAllow
	}
	priority := map[transformer.Action]int{
		transformer.ActionAllow:     0,
		transformer.ActionMask:      1,
		transformer.ActionPseudonym: 2,
		transformer.ActionTokenize:  3,
		transformer.ActionRedact:    4,
		transformer.ActionBlock:     5,
	}
	highest := transformer.ActionAllow
	for _, a := range applied {
		if priority[a.Action] > priority[highest] {
			highest = a.Action
		}
	}
	return highest
}

func summarizeDetections(dets []detector.Detection) []audit.DetectionSummary {
	counts := make(map[string]*audit.DetectionSummary)
	for _, d := range dets {
		key := string(d.Type) + "|" + string(d.Tier)
		if s, ok := counts[key]; ok {
			s.Count++
		} else {
			counts[key] = &audit.DetectionSummary{
				Type:  d.Type,
				Tier:  d.Tier,
				Count: 1,
			}
		}
	}
	var result []audit.DetectionSummary
	for _, s := range counts {
		result = append(result, *s)
	}
	return result
}
