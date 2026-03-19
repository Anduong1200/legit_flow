# Legit Flow - Demo MVP

Để xem cách hoạt động của sản phẩm AI Security Gateway (Legit Flow) dưới dạng MVP nội bộ, bạn có thể chạy bộ End-to-End Test (E2E Test) mà chúng tôi đã thiết lập.

E2E Test này giả lập toàn bộ hành trình của một tin nhắn (prompt) gửi vào Gateway, đi qua Registry Detector, Policy Engine và Output Guard trước khi được log lại.

## Cách chạy Demo Test

1. Mở Terminal/Command Prompt tại thư mục dự án `legit_flow`.
2. Chạy lệnh sau để kích hoạt kịch bản thử nghiệm:
   ```bash
   go test ./test/e2e/... -v
   ```

## Kịch bản được kiểm chứng (Scenarios Demonstrated)

Test case có 4 kịch bản được chạy liên tiếp để chứng minh Gateway hoạt động chính xác theo **Default Policy**:

1. **Safe Request**: Một câu hỏi thông thường về AI/Khoa học ("how quantum computing works").
   - **Kết quả**: Được cho phép đi qua (`Action: Allow`). Không bị chặn.
2. **Vietnam CCCD (Restricted)**: Người dùng nhập mã số Căn cước công dân.
   - **Kết quả**: Gateway phát hiện qua Regex (L1), Policy Tier: `restricted` → Bị chặn dứt điểm (`Action: Block`, `Violation: true`).
3. **JWT Secret Token (Restricted)**: Người dùng vô tình paste một token xác thực.
   - **Kết quả**: Gateway nhận diện cấu trúc JWT Token rò rỉ, Policy Tier: `restricted` → Bị chặn dứt điểm (`Action: Block`, `Violation: true`).
4. **Phone Number (Confidential)**: Khách hàng nhập số điện thoại Việt Nam.
   - **Kết quả**: Gateway nhận diện số điện thoại, Policy Tier: `confidential` → Đánh dấu là vi phạm để bôi đen/chặn.

## Luồng log sự kiện (Audit Log)
Tất cả các hành động PII được phát hiện sẽ được Audit Logger ghi lại thành các Event dưới dạng JSONL không chứa dữ liệu nhạy cảm thực tế ở trong thư mục `testdata/audit_demo`. Đây chính là luồng **Tier 1 Audit** chứng minh **Tầm nhìn máy quét (Observability)** của sản phẩm với doanh nghiệp.

---

## 🌍 Thử nghiệm với AI API thật (OpenAI / Anthropic / Local LLM)

Mặc định, Demo App chạy qua một Mock Server nội bộ (để test Offline). Tuy nhiên, kiến trúc của Legit Flow cho phép đóng luồng hoàn toàn vào các AI Provider thực tế.
Giao diện `demo/app` hiện tại đã gửi Request theo **chuẩn của OpenAI** (`model`, `messages`).

**Để demo sử dụng GPT-4o-mini thực tế thông qua Gateway:**

1. Tắt instance `gateway` và `demo-app` hiện tại (nếu đang bật).
2. Khởi chạy lại Gateway, trỏ thẳng backend về OpenAI:
   ```bash
   export LEGIT_LISTEN_ADDR=":8080"
   export LEGIT_LLM_BACKEND_URL="https://api.openai.com"
   go run ./cmd/gateway
   ```
3. Khởi chạy lại Demo App, cung cấp API Key của bạn qua biến môi trường (Gateway sẽ chuyển tiếp Header Authorization này đến OpenAI):
   ```bash
   export DEMO_MODEL="gpt-4o-mini"
   export DEMO_API_KEY="sk-your-openai-api-key"
   go run ./demo/app
   ```
4. Truy cập `http://localhost:3000` và chat thử. Lúc này:
   - Nếu prompt an toàn: Sẽ nhận được câu trả lời thật từ quá trình suy luận của ChatGPT.
   - Nếu chèn CCCD / JWT: Bị Legit Flow Proxy chặn lập tức ở biên giới nội bộ, **OpenAI hoàn toàn không nhận được dữ liệu này**.
