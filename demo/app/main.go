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
	payload, _ := json.Marshal(map[string]string{"prompt": req.Message})
	proxyReq, _ := http.NewRequest("POST", gatewayURL+"/v1/chat/completions", bytes.NewReader(payload))
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("X-User-ID", "demo-user")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		json.NewEncoder(w).Encode(chatResponse{Reply: "Gateway unavailable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	requestID := resp.Header.Get("X-Request-ID")

	w.Header().Set("Content-Type", "application/json")
	if resp.StatusCode == http.StatusForbidden {
		json.NewEncoder(w).Encode(chatResponse{
			Reply:     "⛔ Request blocked by Legit Flow policy",
			RequestID: requestID,
			Blocked:   true,
		})
		return
	}

	json.NewEncoder(w).Encode(chatResponse{
		Reply:     string(body),
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
