// Mock LLM — Simulates an LLM endpoint for demo/testing.
// Echoes prompts back with optional PII injection for testing output guard.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
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
	json.NewDecoder(r.Body).Decode(&req)

	prompt := req.Prompt
	if prompt == "" && len(req.Messages) > 0 {
		prompt = req.Messages[len(req.Messages)-1].Content
	}

	// Generate mock response
	response := generateResponse(prompt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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
	json.NewDecoder(r.Body).Decode(&req)

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
		fmt.Fprintf(w, "data: %s%s\n\n", sep, word)
		flusher.Flush()
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func generateResponse(prompt string) string {
	responses := []string{
		"Cảm ơn bạn đã hỏi. Theo thông tin tôi có, dự án đang tiến triển tốt và đúng tiến độ.",
		"Tôi hiểu câu hỏi của bạn. Hãy để tôi giải thích chi tiết hơn về vấn đề này.",
		"Kết quả phân tích cho thấy hiệu suất hệ thống đạt p95 dưới 200ms như mục tiêu đề ra.",
	}

	// Sometimes inject PII in response to test output guard
	piiResponses := []string{
		"Thông tin liên hệ: Trần Thị B, CCCD 098765432101, email: tran.b@internal.vn, SĐT 0987654321.",
		"Tài khoản ngân hàng: 1234567890123456, chi nhánh Hà Nội. Token xác thực: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"API key nội bộ: sk-testkey1234567890abcdefghijklmnop. Vui lòng bảo mật.",
	}

	// 30% chance of PII injection for testing
	if rand.Intn(10) < 3 {
		return piiResponses[rand.Intn(len(piiResponses))]
	}
	_ = prompt
	return responses[rand.Intn(len(responses))]
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
