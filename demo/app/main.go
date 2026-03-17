// Demo App — Simple chat UI that sends requests through the Legit Flow gateway.
// This is the app that demonstrates the end-to-end flow.
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

//go:embed index.html
var staticFiles embed.FS

var gatewayURL = envOr("GATEWAY_URL", "http://localhost:8080")

func main() {
	mux := http.NewServeMux()

	// Serve the chat UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := staticFiles.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Proxy chat requests through the Legit Flow gateway
	mux.HandleFunc("/api/chat", handleChat)

	addr := envOr("LISTEN_ADDR", ":3000")
	log.Printf("🖥️  Demo app running at http://localhost%s\n", addr)
	log.Printf("   Gateway: %s\n", gatewayURL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type chatRequest struct {
	Message string `json:"message"`
}

type chatResponse struct {
	Reply     string `json:"reply"`
	RequestID string `json:"request_id"`
	Blocked   bool   `json:"blocked"`
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Forward to gateway → LLM backend
	// Use standard OpenAI Chat Completions payload format
	model := envOr("DEMO_MODEL", "gpt-4o-mini") // Default to a fast/cheap model if using external API
	payload := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": req.Message},
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	proxyReq, _ := http.NewRequest("POST", gatewayURL+"/v1/chat/completions", bytes.NewReader(payloadBytes))
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("X-User-ID", "demo-user")

	// Pass API key if configured (needed when testing with real OpenAI behind Gateway)
	if apiKey := os.Getenv("DEMO_API_KEY"); apiKey != "" {
		proxyReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		_ = json.NewEncoder(w).Encode(chatResponse{Reply: "Gateway unavailable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	requestID := resp.Header.Get("X-Request-ID")

	w.Header().Set("Content-Type", "application/json")
	if resp.StatusCode == http.StatusForbidden {
		_ = json.NewEncoder(w).Encode(chatResponse{
			Reply:     "⛔ Request blocked by Legit Flow policy",
			RequestID: requestID,
			Blocked:   true,
		})
		return
	}

	// Try to parse standard OpenAI response format for a cleaner UI output if possible.
	// If it fails or is from a simple mock, just return raw body.
	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	replyText := string(body)
	if err := json.Unmarshal(body, &openaiResp); err == nil && len(openaiResp.Choices) > 0 {
		replyText = openaiResp.Choices[0].Message.Content
	}

	_ = json.NewEncoder(w).Encode(chatResponse{
		Reply:     replyText,
		RequestID: requestID,
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {
	// Suppress unused import warning
	_ = fmt.Sprintf
}
