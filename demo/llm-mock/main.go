// Mock LLM — Simulates an LLM endpoint for demo/testing.
// Responds intelligently to show that it only sees sanitized/tokenized content.
// For streaming, can inject PII to test output guard truncation.
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

// handleChat returns a mock LLM response.
func handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatReq
	_ = json.NewDecoder(r.Body).Decode(&req)

	prompt := req.Prompt
	if prompt == "" && len(req.Messages) > 0 {
		prompt = req.Messages[len(req.Messages)-1].Content
	}

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
	lower := strings.ToLower(prompt)

	// ── Streaming output guard test: inject real PII in response ──
	if shouldForceSensitiveResponse(prompt) {
		return "Đây là thông tin bạn yêu cầu:\n" +
			"- Tài khoản ngân hàng: 9876543210987654\n" +
			"- SĐT liên hệ: 0912345678\n" +
			"- Token xác thực: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	}

	// ── Detect all protection types applied by gateway ──
	tokCount := countTokens(prompt)
	maskCount := strings.Count(prompt, "***")
	hasBlocked := strings.Contains(prompt, "[BLOCKED]")
	hasRedacted := strings.Contains(prompt, "[REDACTED]")
	blockedCount := strings.Count(prompt, "[BLOCKED]") + strings.Count(prompt, "[REDACTED]")

	// Build multi-action response if any protection detected
	if tokCount > 0 || maskCount > 0 || hasBlocked || hasRedacted {
		var parts []string
		parts = append(parts, "📊 Báo cáo bảo mật Legit Flow Gateway:\n")

		if tokCount > 0 {
			parts = append(parts, fmt.Sprintf("  🔐 Tokenized: %d trường — dữ liệu được mã hóa reversible (TOK_xxx), tôi không thể đọc nội dung gốc.", tokCount))
		}
		if maskCount > 0 {
			parts = append(parts, fmt.Sprintf("  🎭 Masked: %d trường — dữ liệu được ẩn một phần (ví dụ: 079***67), tôi chỉ thấy phần đầu và cuối.", maskCount))
		}
		if hasBlocked || hasRedacted {
			parts = append(parts, fmt.Sprintf("  🚫 Blocked: %d trường — nội dung bị chặn hoàn toàn, tôi chỉ thấy [BLOCKED].", blockedCount))
		}

		total := tokCount + maskCount + blockedCount
		parts = append(parts, fmt.Sprintf("\n→ Tổng cộng %d trường dữ liệu nhạy cảm đã được bảo vệ trước khi gửi tới tôi.", total))
		parts = append(parts, "→ Dữ liệu gốc không bao giờ rời khỏi hệ thống của bạn.")

		return strings.Join(parts, "\n")
	}

	// ── Check if prompt contains [BLOCKED] or [REDACTED] markers ──
	if strings.Contains(prompt, "[BLOCKED]") || strings.Contains(prompt, "[REDACTED]") {
		return "Tin nhắn đã được gateway xử lý — một số nội dung bị chặn/ẩn trước khi tôi nhận được. " +
			"Tôi chỉ nhìn thấy phần nội dung đã được phê duyệt bởi policy."
	}

	// ── Contextual responses for different scenarios ──

	// Quantum / general knowledge
	if strings.Contains(lower, "quantum") {
		return "Quantum computing sử dụng qubit thay vì bit truyền thống. " +
			"Khác với bit chỉ có 0 hoặc 1, qubit có thể ở trạng thái chồng chất (superposition), " +
			"cho phép xử lý đồng thời nhiều phép tính. Hiện nay Google, IBM và các tổ chức nghiên cứu " +
			"đang phát triển quantum computer với hàng nghìn qubit."
	}

	// HR / employee records
	if strings.Contains(lower, "hồ sơ") || strings.Contains(lower, "nhân viên") || strings.Contains(lower, "danh sách") {
		return "Tôi đã nhận được yêu cầu xử lý hồ sơ. " +
			"Lưu ý: để bảo vệ thông tin cá nhân, các trường CCCD, SĐT, và email của nhân viên " +
			"nên được mã hóa trước khi gửi qua hệ thống AI. " +
			"Vui lòng xác nhận rằng dữ liệu nhạy cảm đã được xử lý bởi Legit Flow trước khi tôi phân tích."
	}

	// Financial / banking
	if strings.Contains(lower, "chuyển tiền") || strings.Contains(lower, "ngân hàng") || strings.Contains(lower, "tài khoản") {
		return "Tôi nhận được yêu cầu liên quan đến giao dịch tài chính. " +
			"Với các thông tin như số tài khoản, tôi chỉ xử lý dữ liệu đã được mã hóa bởi gateway. " +
			"Nếu bạn thấy token (TOK_xxx) trong câu hỏi, điều đó có nghĩa dữ liệu nhạy cảm đã được bảo vệ."
	}

	// Contract / legal
	if strings.Contains(lower, "hợp đồng") || strings.Contains(lower, "pháp lý") {
		return "Tôi có thể hỗ trợ soạn thảo và xem xét hợp đồng. " +
			"Lưu ý quan trọng: thông tin cá nhân các bên (CCCD, SĐT, địa chỉ) sẽ được Legit Flow " +
			"mã hóa/ẩn trước khi tôi xử lý, đảm bảo tuân thủ quy định bảo mật dữ liệu."
	}

	// Medical / health records
	if strings.Contains(lower, "bệnh án") || strings.Contains(lower, "y tế") || strings.Contains(lower, "bệnh nhân") {
		return "Yêu cầu liên quan đến hồ sơ y tế đã được nhận. " +
			"Theo quy định, tất cả thông tin nhận dạng bệnh nhân (tên, CCCD, SĐT) " +
			"phải được mã hóa trước khi gửi tới hệ thống AI. " +
			"Legit Flow đảm bảo dữ liệu y tế nhạy cảm không bị lộ ra ngoài."
	}

	// Tool / export requests
	if strings.Contains(lower, "export") || strings.Contains(lower, "xuất") || strings.Contains(lower, "csv") {
		return "Yêu cầu export dữ liệu cần được kiểm tra quyền truy cập qua Tool Guard. " +
			"Nếu bạn là admin, vui lòng sử dụng endpoint /api/v1/tool/check với header X-Tool-Name " +
			"để xác minh quyền trước khi thực hiện export."
	}

	// Email / communication
	if strings.Contains(lower, "email") || strings.Contains(lower, "gửi mail") || strings.Contains(lower, "liên hệ") {
		return "Tôi nhận được yêu cầu liên quan đến thông tin liên hệ. " +
			"Lưu ý: địa chỉ email ​​và SĐT đã được mã hóa bởi Legit Flow. " +
			"Tôi sẽ xử lý dựa trên token, không thấy thông tin gốc."
	}

	// Default: acknowledge what was received
	return fmt.Sprintf(
		"Tôi đã nhận được tin nhắn của bạn và xử lý thành công. "+
			"Nội dung nhận được: «%s». "+
			"Nếu có dữ liệu nhạy cảm, Legit Flow Gateway đã xử lý trước khi tới tôi.",
		truncate(prompt, 100),
	)
}

func shouldForceSensitiveResponse(prompt string) bool {
	lower := strings.ToLower(prompt)
	return strings.Contains(lower, "kiểm thử streaming output guard") ||
		strings.Contains(lower, "kiem thu streaming output guard") ||
		strings.Contains(lower, "simulate sensitive") ||
		strings.Contains(lower, "mô phỏng") && strings.Contains(lower, "nhạy cảm")
}

func containsTokens(text string) bool {
	return strings.Contains(text, "TOK_") || strings.Contains(text, "PSEUDO-")
}

func countTokens(text string) int {
	count := 0
	count += strings.Count(text, "TOK_")
	count += strings.Count(text, "PSEUDO-")
	return count
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
