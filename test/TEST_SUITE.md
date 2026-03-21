# Data Privacy Test Suite (PII & Secrets)

Bộ tài liệu này liệt kê danh sách các kịch bản kiểm thử (Test Cases) dành cho hệ thống Legit Flow (L1 Regex & L2 LLM). Dữ liệu máy học tương ứng có thể được tìm thấy trong file `pii_samples.json` cùng thư mục để phục vụ Automation Test.

## 1. Nhóm True Positive (TP) - Dữ liệu hợp lệ, cần bắt chính xác
Đảm bảo hệ thống L1 Regex hoạt động chuẩn xác với các dữ liệu PII và Secret truyền thống.

| ID | Kịch bản (Scenario) | Input (Dữ liệu đầu vào) | Kết quả kỳ vọng (Expected) |
| :--- | :--- | :--- | :--- |
| **TP_01** | CCCD 12 số chuẩn | Số CCCD của tôi là 079090123456 | `[MASKED_ID]` |
| **TP_02** | SĐT Việt Nam chuẩn | Liên hệ SĐT 0912345678 để biết thêm | `[MASKED_PHONE]` |
| **TP_03** | SĐT có dấu gạch ngang | SĐT: 091-234-5678 | `[MASKED_PHONE]` |
| **TP_04** | Email công việc/cá nhân | Gửi tài liệu vào admin@company.com.vn | `[MASKED_EMAIL]` |
| **TP_05** | OpenAI API Key | Config: api_key=sk-abc123def456ghi789jkl012mno345pqr678 | `[BLOCKED_SECRET]` |
| **TP_06** | JWT Token chuẩn | Bearer eyJhbGciOiJIUzI1NiIs...SflKxwRJSMe | `[BLOCKED_JWT]` |
| **TP_07** | AWS Access Key | AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE | `[BLOCKED_CREDENTIAL]` |
| **TP_08** | Multiple PII (Hỗn hợp) | Khách hàng A, CCCD 001122334455, sđt 0987654321, key sk-12345 | Mask/Block 3 items |

## 2. Nhóm True Negative (TN) - Dữ liệu an toàn, cần giữ nguyên
Đảm bảo hệ thống không can thiệp vào các đoạn hội thoại hoặc code snippet thông thường.

| ID | Kịch bản (Scenario) | Input (Dữ liệu đầu vào) | Kết quả kỳ vọng (Expected) |
| :--- | :--- | :--- | :--- |
| **TN_01** | Văn bản hội thoại | Hôm nay thời tiết đẹp. Hãy cho tôi biết dự báo thời tiết Hà Nội. | `passthrough` |
| **TN_02** | Code snippet an toàn | def get_user(id): return db.query(id) | `passthrough` |
| **TN_03** | Thông tin công khai | Hotline tổng đài là 1900 1560. | `passthrough` |
| **TN_04** | Chuỗi có cấu trúc giống | eyJhbG is a prefix but not a full JWT token | `passthrough` |

## 3. Nhóm False Positive (FP) - Chống nhận diện nhầm
Kiểm thử độ vững (robustness) của AI và Regex khi đối mặt với các chuỗi số/mã có độ dài tương tự nhưng không phải PII.

| ID | Kịch bản (Scenario) | Input (Dữ liệu đầu vào) | Kết quả kỳ vọng (Expected) |
| :--- | :--- | :--- | :--- |
| **FP_01** | Dãy số ngẫu nhiên 9 số | Mã đơn hàng của bạn là 123456789. | `passthrough` |
| **FP_02** | Dãy số ngẫu nhiên 12 số | Tổng tài sản công ty: 999123456789 VND. | `passthrough` |
| **FP_03** | Chuỗi UUID | Request ID: fde2e69d-bf25-46c8-8b98-8af1e866d8a1 | `passthrough` |
| **FP_04** | Phiên bản / Serial | Sản phẩm v1.0.12345678 | `passthrough` |

## 4. Nhóm False Negative (FN) - L2 LLM Defense-in-depth
Kiểm thử chiến lược bóc tách Contextual PII thông qua Gemini 1.5 Flash nhằm bắt các ca khó mà Regex (L1) bỏ lọt.

| ID | Kịch bản (Scenario) | Input (Dữ liệu đầu vào) | Kết quả kỳ vọng (Expected) |
| :--- | :--- | :--- | :--- |
| **FN_01** | CCCD có khoảng trắng | CCCD của tôi là 0 7 9 0 9 0 1 2 3 4 5 6 | `mask via L2 LLM` |
| **FN_02** | PII dạng chữ (Text) | Căn cước của em là không bảy chín, không chín không... | `mask via L2 LLM` |
| **FN_03** | Dấu câu xen kẽ | SĐT: 0.9.1.2.3.4.5.6.7.8 | `mask via L2 LLM` |
| **FN_04** | Ẩn trong JSON/Cấu trúc | {"user_id": "079090123456", "auth": "sk-123456..."} | `mask` |
| **FN_05** | Tiếng lóng/Từ viết tắt | Xác minh cccd: 001090123456 gửi về mail sếp ceo@corp.vn | `mask` |
