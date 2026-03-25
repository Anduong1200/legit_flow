// Demo App — Product-oriented demo console for the Legit Flow gateway.
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/policy"
	"github.com/legitflow/legitflow/internal/transformer"
)

//go:embed *.html
var staticFiles embed.FS

var fallbackActionMap = map[detector.RiskTier]transformer.Action{
	detector.TierRestricted:   transformer.ActionTokenize,
	detector.TierConfidential: transformer.ActionTokenize,
	detector.TierInternal:     transformer.ActionAllow,
	detector.TierPublic:       transformer.ActionAllow,
}

type demoApp struct {
	gatewayURL string
	model      string
	streamPath string
	auditDir   string
	client     *http.Client
	inspector  *demoInspector
}

type demoInspector struct {
	registry     *detector.Registry
	policyEngine *policy.Engine
}

type chatRequest struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

type chatResponse struct {
	Reply     string `json:"reply"`
	RequestID string `json:"request_id"`
	Blocked   bool   `json:"blocked"`
}

type statusResponse struct {
	GatewayURL        string `json:"gateway_url"`
	GatewayReady      bool   `json:"gateway_ready"`
	GatewayStatus     string `json:"gateway_status"`
	Model             string `json:"model"`
	PolicyName        string `json:"policy_name"`
	PolicyVersion     string `json:"policy_version"`
	PolicyDescription string `json:"policy_description"`
	AuditDir          string `json:"audit_dir"`
	StreamPath        string `json:"stream_path"`
	CheckedAt         string `json:"checked_at"`
}

type inspectResponse struct {
	PolicyName            string             `json:"policy_name"`
	PolicyVersion         string             `json:"policy_version"`
	PolicyDescription     string             `json:"policy_description"`
	OverallAction         string             `json:"overall_action"`
	Summary               string             `json:"summary"`
	AuditNote             string             `json:"audit_note"`
	SanitizedInput        string             `json:"sanitized_input"`
	StructuredPreviewOnly bool               `json:"structured_preview_only"`
	Detections            []detectionPreview `json:"detections"`
}

type detectionPreview struct {
	Type   string `json:"type"`
	Tier   string `json:"tier"`
	Action string `json:"action"`
	Count  int    `json:"count"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

type auditLogEntry struct {
	EventID    string `json:"event_id"`
	Timestamp  string `json:"timestamp"`
	RequestID  string `json:"request_id"`
	UserID     string `json:"user_id"`
	SourceIP   string `json:"source_ip"`
	Action     string `json:"action"`
	PolicyName string `json:"policy_name"`
	Detections []struct {
		Type  string `json:"type"`
		Tier  string `json:"tier"`
		Count int    `json:"count"`
	} `json:"detections"`
	Outcome   string `json:"outcome"`
	LatencyMs int    `json:"latency_ms"`
}

type tier2LogEntry struct {
	EventID       string `json:"event_id"`
	RedactedInput string `json:"redacted_input"`
	Transforms    []struct {
		Type        string `json:"type"`
		Action      string `json:"action"`
		Replacement string `json:"replacement"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
	} `json:"transforms"`
}

type combinedLogsResponse struct {
	Tier1 []auditLogEntry `json:"tier1"`
	Tier2 []tier2LogEntry  `json:"tier2"`
}

func main() {
	app := newDemoApp()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("index.html")
		if err != nil {
			http.Error(w, "demo UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile("logs.html")
		if err != nil {
			http.Error(w, "logs UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/status", app.handleStatus)
	mux.HandleFunc("/api/inspect", app.handleInspect)
	mux.HandleFunc("/api/chat", app.handleChat)
	mux.HandleFunc("/api/chat/stream", app.handleChatStream)
	mux.HandleFunc("/api/notification", app.handleNotification)
	mux.HandleFunc("/api/logs", app.handleApiLogs)

	addr := envOr("LISTEN_ADDR", ":3000")
	log.Printf("Demo console running at http://localhost%s", addr)
	log.Printf("Gateway: %s", app.gatewayURL)
	log.Printf("Preview policy: %s", app.inspector.policyName())
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newDemoApp() *demoApp {
	policyDir := resolveFirstExistingDir(
		os.Getenv("DEMO_POLICY_DIR"),
		os.Getenv("LEGIT_POLICY_DIR"),
		"./policies",
		"../../policies",
	)
	auditDir := resolveFirstExistingDir(
		os.Getenv("DEMO_AUDIT_DIR"),
		os.Getenv("LEGIT_AUDIT_DIR"),
		"./audit-logs",
		"../../audit-logs",
	)

	if auditDir == "" {
		auditDir = "./audit-logs"
	}

	return &demoApp{
		gatewayURL: strings.TrimRight(envOr("GATEWAY_URL", "http://localhost:8080"), "/"),
		model:      envOr("DEMO_MODEL", "gpt-4o-mini"),
		streamPath: normalizePath(envOr("DEMO_STREAM_PATH", "/v1/chat/completions/stream")),
		auditDir:   filepath.Clean(auditDir),
		client:     &http.Client{Timeout: 30 * time.Second},
		inspector:  newDemoInspector(policyDir),
	}
}

func newDemoInspector(policyDir string) *demoInspector {
	reg := detector.NewRegistry()
	reg.Register(detector.NewL1RegexDetector())

	if apiKey := os.Getenv("GEMINI_API_KEY"); apiKey != "" {
		if l2 := detector.NewL2LLMDetector(apiKey); l2 != nil {
			reg.Register(l2)
		}
	}

	inspector := &demoInspector{registry: reg}
	if policyDir == "" {
		return inspector
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(policyDir, logger)
	if err != nil {
		log.Printf("policy preview disabled, falling back to default-hardened rules: %v", err)
		return inspector
	}
	inspector.policyEngine = eng
	return inspector
}

func (a *demoApp) handleStatus(w http.ResponseWriter, r *http.Request) {
	name, version, description, _ := a.inspector.policyContext()
	ready, gatewayStatus := a.checkGateway(r.Context())

	writeJSON(w, http.StatusOK, statusResponse{
		GatewayURL:        a.gatewayURL,
		GatewayReady:      ready,
		GatewayStatus:     gatewayStatus,
		Model:             a.model,
		PolicyName:        name,
		PolicyVersion:     version,
		PolicyDescription: description,
		AuditDir:          a.auditDir,
		StreamPath:        a.streamPath,
		CheckedAt:         time.Now().Format(time.RFC3339),
	})
}

func (a *demoApp) handleInspect(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeChatRequest(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, a.inspector.Inspect(r.Context(), req.Message))
}

func (a *demoApp) handleChat(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeChatRequest(w, r)
	if !ok {
		return
	}

	a.logUserAudit(req.Message, "/api/chat", req.UserID)

	proxyReq, err := a.buildGatewayRequest(r.Context(), "/v1/chat/completions", req.Message, false, req.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, chatResponse{
			Reply: "Không thể tạo request đến gateway.",
		})
		return
	}

	resp, err := a.client.Do(proxyReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, chatResponse{
			Reply: "Gateway unavailable: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	requestID := resp.Header.Get("X-Request-ID")

	if resp.StatusCode == http.StatusForbidden {
		var blocked struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(body, &blocked)
		if blocked.RequestID != "" {
			requestID = blocked.RequestID
		}
		writeJSON(w, http.StatusOK, chatResponse{
			Reply:     "Request bị chặn bởi Legit Flow policy trước khi rời hệ thống.",
			RequestID: requestID,
			Blocked:   true,
		})
		return
	}

	if resp.StatusCode >= http.StatusBadRequest {
		writeJSON(w, resp.StatusCode, chatResponse{
			Reply:     "Gateway returned an error while processing the request.",
			RequestID: requestID,
		})
		return
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	replyText := string(body)
	if err := json.Unmarshal(body, &openAIResp); err == nil && len(openAIResp.Choices) > 0 {
		replyText = openAIResp.Choices[0].Message.Content
	}

	writeJSON(w, http.StatusOK, chatResponse{
		Reply:     replyText,
		RequestID: requestID,
	})
}

func (a *demoApp) handleChatStream(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeChatRequest(w, r)
	if !ok {
		return
	}

	a.logUserAudit(req.Message, "/api/chat/stream", req.UserID)

	proxyReq, err := a.buildGatewayRequest(r.Context(), a.streamPath, req.Message, true, req.UserID)
	if err != nil {
		http.Error(w, "could not create streaming request", http.StatusInternalServerError)
		return
	}

	streamClient := &http.Client{}
	resp, err := streamClient.Do(proxyReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "Gateway unavailable: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest || !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		body, _ := io.ReadAll(resp.Body)
		if len(body) == 0 {
			body = []byte(`{"error":"gateway returned an unexpected response"}`)
		}
		contentType := resp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		if requestID := resp.Header.Get("X-Request-ID"); requestID != "" {
			w.Header().Set("X-Request-ID", requestID)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if requestID := resp.Header.Get("X-Request-ID"); requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	w.WriteHeader(http.StatusOK)

	reader := bufio.NewReader(resp.Body)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = w.Write(line)
			flusher.Flush()
		}
		if readErr != nil {
			if readErr == io.EOF {
				return
			}
			return
		}
	}
}

func (a *demoApp) buildGatewayRequest(ctx context.Context, path string, message string, stream bool, userID string) (*http.Request, error) {
	payload := map[string]interface{}{
		"model": a.model,
		"messages": []map[string]string{
			{"role": "user", "content": message},
		},
	}
	if stream {
		payload["stream"] = true
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.gatewayURL+normalizePath(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if userID == "" {
		userID = "demo-user"
	}
	req.Header.Set("X-User-ID", userID)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	if apiKey := os.Getenv("DEMO_API_KEY"); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	return req, nil
}

func (a *demoApp) checkGateway(ctx context.Context) (bool, string) {
	healthCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, a.gatewayURL+"/readyz", nil)
	if err != nil {
		return false, "Gateway URL is invalid"
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false, "Gateway unavailable"
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, "Gateway ready"
	}
	return false, resp.Status
}

func (a *demoApp) logUserAudit(message, endpoint, userID string) {
	if a.auditDir == "" {
		return
	}
	if userID == "" {
		userID = "demo-user"
	}
	f, err := os.OpenFile(filepath.Join(a.auditDir, "user_audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		timestamp := time.Now().Format(time.RFC3339)
		f.WriteString(fmt.Sprintf("[%s] [User: %s] [%s] User prompt: %s\n", timestamp, userID, endpoint, message))
	}
}

func (a *demoApp) handleNotification(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("thong_bao.txt")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Vui lòng nhập cẩn thận."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": string(content)})
}

func (a *demoApp) handleApiLogs(w http.ResponseWriter, r *http.Request) {
	if a.auditDir == "" {
		writeJSON(w, http.StatusOK, combinedLogsResponse{})
		return
	}

	files, err := os.ReadDir(a.auditDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Cannot read audit directory"})
		return
	}

	var tier1Logs []auditLogEntry
	var tier2Logs []tier2LogEntry

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}

		content, err := os.ReadFile(filepath.Join(a.auditDir, name))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			if strings.HasPrefix(name, "tier1_") {
				var entry auditLogEntry
				if err := json.Unmarshal([]byte(line), &entry); err == nil {
					tier1Logs = append(tier1Logs, entry)
				}
			} else if strings.HasPrefix(name, "tier2_") {
				var entry tier2LogEntry
				if err := json.Unmarshal([]byte(line), &entry); err == nil {
					tier2Logs = append(tier2Logs, entry)
				}
			}
		}
	}

	sort.Slice(tier1Logs, func(i, j int) bool {
		return tier1Logs[i].Timestamp > tier1Logs[j].Timestamp
	})

	writeJSON(w, http.StatusOK, combinedLogsResponse{Tier1: tier1Logs, Tier2: tier2Logs})
}

func (i *demoInspector) Inspect(ctx context.Context, text string) inspectResponse {
	name, version, description, actionMap := i.policyContext()

	detections, err := i.registry.DetectAll(ctx, text)
	if err != nil {
		return inspectResponse{
			PolicyName:            name,
			PolicyVersion:         version,
			PolicyDescription:     description,
			OverallAction:         string(transformer.ActionAllow),
			Summary:               "Không thể tạo structured preview trong lúc này.",
			AuditNote:             "Tier 1 metadata vẫn là nguồn kiểm chứng chính thức của gateway.",
			SanitizedInput:        text,
			StructuredPreviewOnly: true,
		}
	}

	sanitizedInput, applied := transformer.TransformText(text, detections, actionMap)
	overallAction := mostRestrictiveAction(applied)
	if overallAction == "" {
		overallAction = transformer.ActionAllow
	}

	return inspectResponse{
		PolicyName:            name,
		PolicyVersion:         version,
		PolicyDescription:     description,
		OverallAction:         string(overallAction),
		Summary:               previewSummary(overallAction, len(detections) > 0),
		AuditNote:             auditNote(overallAction),
		SanitizedInput:        sanitizedInput,
		StructuredPreviewOnly: true,
		Detections:            summarizeDetections(detections, actionMap),
	}
}

func (i *demoInspector) policyName() string {
	name, _, _, _ := i.policyContext()
	return name
}

func (i *demoInspector) policyContext() (string, string, string, map[detector.RiskTier]transformer.Action) {
	if i.policyEngine != nil {
		p := i.policyEngine.GetPolicy()
		return p.Name, p.Version, p.Description, i.policyEngine.GetActionMap()
	}

	return "default-hardened",
		"1.0.0",
		"Default policy — block restricted, mask confidential, allow internal/public",
		fallbackActionMap
}

func summarizeDetections(detections []detector.Detection, actionMap map[detector.RiskTier]transformer.Action) []detectionPreview {
	counts := make(map[string]*detectionPreview)
	for _, det := range detections {
		key := string(det.Type) + "|" + string(det.Tier)
		if existing, ok := counts[key]; ok {
			existing.Count++
			continue
		}

		counts[key] = &detectionPreview{
			Type:   string(det.Type),
			Tier:   string(det.Tier),
			Action: string(actionMap[det.Tier]),
			Count:  1,
			Label:  detectionLabel(det.Type),
			Detail: detectionDetail(det.Type),
		}
	}

	result := make([]detectionPreview, 0, len(counts))
	for _, item := range counts {
		result = append(result, *item)
	}

	sort.Slice(result, func(left, right int) bool {
		leftPriority := actionPriority(transformer.Action(result[left].Action))
		rightPriority := actionPriority(transformer.Action(result[right].Action))
		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}
		return result[left].Label < result[right].Label
	})

	return result
}

func previewSummary(action transformer.Action, hasDetections bool) string {
	switch action {
	case transformer.ActionBlock:
		return "Structured dữ liệu Restricted sẽ bị chặn trước khi rời ứng dụng để giữ đúng mục tiêu zero structured exfiltration."
	case transformer.ActionMask:
		return "Structured dữ liệu Confidential sẽ được mask rồi mới forward tới model để giữ utility và vẫn an toàn."
	case transformer.ActionTokenize:
		return "Dữ liệu nhạy cảm (Restricted/Confidential) sẽ được Tokenize thành mã hóa an toàn (VD: TOK_xxx) rồi gửi tới LLM. Khi nhận về, hệ thống tự động giải mã token để hiển thị dữ liệu gốc, đảm bảo LLM không bao giờ thấy PII thực sự!"
	default:
		if hasDetections {
			return "Prompt có tín hiệu nhưng vẫn được cho phép theo policy hiện tại."
		}
		return "Không phát hiện structured PII hoặc secrets trong bộ rule demo hiện tại."
	}
}

func auditNote(action transformer.Action) string {
	switch action {
	case transformer.ActionBlock:
		return "Tier 1 metadata luôn được ghi. Với case Restricted, UI sẽ chỉ thấy block message thay vì dữ liệu gốc."
	case transformer.ActionMask, transformer.ActionTokenize:
		return "Tier 1 metadata luôn bật và Tier 2 chỉ lưu bản đã redacted/masked/tokenized để phục vụ điều tra khi cần."
	default:
		return "Tier 1 metadata luôn bật để giữ auditability ngay cả khi request được cho phép."
	}
}

func detectionLabel(detType detector.DetectionType) string {
	switch detType {
	case detector.TypeCCCD:
		return "CCCD"
	case detector.TypePhoneVN:
		return "SĐT VN"
	case detector.TypeEmail:
		return "Email"
	case detector.TypeBankAccount:
		return "Tài khoản ngân hàng"
	case detector.TypeJWT:
		return "JWT Token"
	case detector.TypeAPIKey:
		return "API Key"
	case detector.TypeContextual:
		return "Contextual Signal"
	default:
		return string(detType)
	}
}

func detectionDetail(detType detector.DetectionType) string {
	switch detType {
	case detector.TypeCCCD:
		return "Định danh công dân Việt Nam"
	case detector.TypePhoneVN:
		return "Số điện thoại di động Việt Nam"
	case detector.TypeEmail:
		return "Địa chỉ email cá nhân hoặc công việc"
	case detector.TypeBankAccount:
		return "Số tài khoản ngân hàng"
	case detector.TypeJWT:
		return "Bearer/JWT token"
	case detector.TypeAPIKey:
		return "Credential hoặc secret key"
	case detector.TypeContextual:
		return "Tín hiệu phân loại ngữ cảnh"
	default:
		return "Structured detection signal"
	}
}

func mostRestrictiveAction(applied []transformer.AppliedTransform) transformer.Action {
	if len(applied) == 0 {
		return transformer.ActionAllow
	}

	highest := transformer.ActionAllow
	for _, item := range applied {
		if actionPriority(item.Action) > actionPriority(highest) {
			highest = item.Action
		}
	}
	return highest
}

func actionPriority(action transformer.Action) int {
	switch action {
	case transformer.ActionBlock:
		return 5
	case transformer.ActionRedact:
		return 4
	case transformer.ActionTokenize:
		return 3
	case transformer.ActionPseudonym:
		return 2
	case transformer.ActionMask:
		return 1
	default:
		return 0
	}
}

func decodeChatRequest(w http.ResponseWriter, r *http.Request) (chatRequest, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return chatRequest{}, false
	}

	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return chatRequest{}, false
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		http.Error(w, "message is required", http.StatusBadRequest)
		return chatRequest{}, false
	}

	return req, true
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func normalizePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func resolveFirstExistingDir(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate
		}
	}

	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}

	return ""
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
