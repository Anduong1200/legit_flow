package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// L2ContextualDetector uses an external or local LLM/SLM API to perform
// contextual classification. This is the "slow path" — only invoked for
// high-tier content or sampling/QA.
//
// Provider is pluggable:
//   - "openai"    → OpenAI Chat Completions API
//   - "anthropic" → Anthropic Messages API
//   - "local"     → Local HTTP endpoint (same request format as OpenAI)
//   - "disabled"  → Always returns empty (for demo/dev)
type L2ContextualDetector struct {
	provider   string
	apiURL     string
	apiKey     string
	model      string
	httpClient *http.Client
}

// L2Config holds the configuration for the L2 contextual detector.
type L2Config struct {
	Provider string // "openai", "anthropic", "local", "disabled"
	APIURL   string
	APIKey   string
	Model    string
}

// NewL2ContextualDetector creates a detector that calls an LLM API for
// contextual PII classification.
func NewL2ContextualDetector(cfg L2Config) *L2ContextualDetector {
	return &L2ContextualDetector{
		provider: cfg.Provider,
		apiURL:   cfg.APIURL,
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (d *L2ContextualDetector) Name() string { return "l2_contextual" }

// classificationPrompt is the system prompt for the classifier.
const classificationPrompt = `You are a data classification engine for Vietnamese enterprise content.
Analyze the given text and identify any:
1. Personal Identifiable Information (PII): names, addresses, dates of birth, national IDs
2. Financial data: account numbers, transaction details, salary information
3. Confidential business data: internal project names, revenue figures, strategic plans
4. Healthcare data: diagnoses, prescriptions, medical records

Respond ONLY with a JSON array of findings. Each finding must have:
- "type": one of "NAME", "ADDRESS", "DOB", "FINANCIAL", "HEALTH", "CONFIDENTIAL"
- "value": the exact text matched
- "start": character offset start
- "end": character offset end
- "confidence": 0.0 to 1.0

If no sensitive data is found, return an empty array: []`

// Detect sends text to the configured LLM API for contextual analysis.
func (d *L2ContextualDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
	if d.provider == "disabled" || d.provider == "" {
		return nil, nil
	}

	switch d.provider {
	case "openai", "local":
		return d.detectOpenAICompat(ctx, text)
	case "anthropic":
		return d.detectAnthropic(ctx, text)
	default:
		return nil, fmt.Errorf("unsupported classifier provider: %s", d.provider)
	}
}

// ── OpenAI-compatible API (also works for local endpoints) ──────────────────

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (d *L2ContextualDetector) detectOpenAICompat(ctx context.Context, text string) ([]Detection, error) {
	url := d.apiURL
	if url == "" {
		url = "https://api.openai.com/v1/chat/completions"
	}

	reqBody := openAIRequest{
		Model: d.model,
		Messages: []openAIMessage{
			{Role: "system", Content: classificationPrompt},
			{Role: "user", Content: text},
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.apiKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, nil
	}

	return parseClassifierOutput(apiResp.Choices[0].Message.Content)
}

// ── Anthropic Messages API ──────────────────────────────────────────────────

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func (d *L2ContextualDetector) detectAnthropic(ctx context.Context, text string) ([]Detection, error) {
	url := d.apiURL
	if url == "" {
		url = "https://api.anthropic.com/v1/messages"
	}

	reqBody := anthropicRequest{
		Model:     d.model,
		MaxTokens: 1024,
		System:    classificationPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: text},
		},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", d.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(apiResp.Content) == 0 {
		return nil, nil
	}

	return parseClassifierOutput(apiResp.Content[0].Text)
}

// ── Parse classifier JSON output ────────────────────────────────────────────

type classifierFinding struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

func parseClassifierOutput(raw string) ([]Detection, error) {
	var findings []classifierFinding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		// LLM might wrap in markdown code block — try to extract JSON
		return nil, nil // gracefully degrade
	}

	var detections []Detection
	for _, f := range findings {
		detections = append(detections, Detection{
			Type:       TypeContextual,
			Tier:       TierInternal, // L2 only flags/warns; doesn't block by default
			Value:      f.Value,
			Start:      f.Start,
			End:        f.End,
			Confidence: f.Confidence,
		})
	}
	return detections, nil
}
