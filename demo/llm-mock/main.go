// Mock LLM — Simulates an LLM endpoint for demo/testing.
// Echoes prompts back with optional PII injection for testing output guard.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", handleChat)
	mux.HandleFunc("/v1/chat/completions/stream", handleStream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := envOr("LISTEN_ADDR", ":11434")
	log.Printf("🤖 Mock LLM running at http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

type chatReq struct {
	Prompt   string `json:"prompt"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// handleChat returns a mock LLM response, sometimes injecting PII
// to test the output guard.
func handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	prompt := req.Prompt
	if prompt == "" && len(req.Messages) > 0 {
		prompt = req.Messages[len(req.Messages)-1].Content
	}

	// Generate mock response
	response := generateResponse(prompt)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]string{
					"role":    "assistant",
					"content": response,
				},
			},
		},
		"model": "mock-llm-v1",
		"usage": map[string]int{
			"prompt_tokens":     len(strings.Fields(prompt)),
			"completion_tokens": len(strings.Fields(response)),
		},
	})
}

// handleStream simulates SSE streaming responses.
func handleStream(w http.ResponseWriter, r *http.Request) {
	var req chatReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	prompt := req.Prompt
	if prompt == "" && len(req.Messages) > 0 {
		prompt = req.Messages[len(req.Messages)-1].Content
	}

	response := generateResponse(prompt)
	words := strings.Fields(response)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	for i, word := range words {
		sep := " "
		if i == 0 {
			sep = ""
		}
		_, _ = fmt.Fprintf(w, "data: %s%s\n\n", sep, word)
		flusher.Flush()
		time.Sleep(50 * time.Millisecond)
	}
	_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func generateResponse(prompt string) string {
	// For streaming output guard test, inject PII to test truncation
	piiResponse := "Tài khoản ngân hàng: 1234567890123456, chi nhánh Hà Nội. Token xác thực: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	if shouldForceSensitiveResponse(prompt) {
		return piiResponse
	}

	// Echo back the sanitized prompt so the chat UI shows the actual masked tokens
	return "[Echo] " + prompt
}

func shouldForceSensitiveResponse(prompt string) bool {
	lower := strings.ToLower(prompt)
	return strings.Contains(lower, "kiểm thử streaming output guard") ||
		strings.Contains(lower, "kiem thu streaming output guard") ||
		strings.Contains(lower, "simulate sensitive streaming leak")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
