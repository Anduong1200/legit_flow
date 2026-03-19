package detector

import (
	"context"
	"testing"
)

func TestL1RegexDetector(t *testing.T) {
	d := NewL1RegexDetector()

	tests := []struct {
		name     string
		input    string
		wantType DetectionType
		wantN    int // expected number of detections for this type
	}{
		// ── CCCD ───────────────────────────────────────────
		{
			name:     "CCCD valid 12 digits",
			input:    "Số CCCD: 001234567890 của anh Nguyễn Văn A",
			wantType: TypeCCCD,
			wantN:    1,
		},
		{
			name:     "CCCD too short",
			input:    "Mã 12345 không phải CCCD",
			wantType: TypeCCCD,
			wantN:    0,
		},

		// ── Phone VN ───────────────────────────────────────
		{
			name:     "Phone VN 10 digits 09x",
			input:    "Liên hệ SĐT 0912345678 để biết thêm",
			wantType: TypePhoneVN,
			wantN:    1,
		},
		{
			name:     "Phone VN with dashes",
			input:    "Gọi 091-234-5678 ngay",
			wantType: TypePhoneVN,
			wantN:    1,
		},
		{
			name:     "Phone VN 03x prefix",
			input:    "SĐT mới: 0351234567",
			wantType: TypePhoneVN,
			wantN:    1,
		},

		// ── Email ──────────────────────────────────────────
		{
			name:     "Email standard",
			input:    "Email: nguyen.van.a@company.com.vn xác nhận",
			wantType: TypeEmail,
			wantN:    1,
		},
		{
			name:     "Email with plus",
			input:    "user+tag@gmail.com",
			wantType: TypeEmail,
			wantN:    1,
		},

		// ── JWT ────────────────────────────────────────────
		{
			name:     "JWT token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantType: TypeJWT,
			wantN:    1,
		},

		// ── API Keys ───────────────────────────────────────
		{
			name:     "AWS access key",
			input:    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			wantType: TypeAPIKey,
			wantN:    1,
		},
		{
			name:     "OpenAI key",
			input:    "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr678",
			wantType: TypeAPIKey,
			wantN:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.Detect(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}

			// Count detections of the expected type
			count := 0
			for _, r := range results {
				if r.Type == tt.wantType {
					count++
				}
			}

			if count != tt.wantN {
				t.Errorf("Detect() got %d detections of type %s, want %d. All detections: %+v",
					count, tt.wantType, tt.wantN, results)
			}

			// Verify all detections have confidence 1.0 (L1 = deterministic)
			for _, r := range results {
				if r.Confidence != 1.0 {
					t.Errorf("L1 detection should have confidence 1.0, got %f", r.Confidence)
				}
			}
		})
	}
}

// TestL1NoFalsePositivesOnCleanText verifies clean text produces no detections.
func TestL1NoFalsePositivesOnCleanText(t *testing.T) {
	d := NewL1RegexDetector()
	clean := "Hôm nay thời tiết đẹp. Hãy đi dạo công viên và thưởng thức cà phê."

	results, err := d.Detect(context.Background(), clean)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if len(results) > 0 {
		t.Errorf("Expected no detections on clean text, got %d: %+v", len(results), results)
	}
}

func TestL1BankAccountDoesNotShadowSpecificVNIdentifiers(t *testing.T) {
	d := NewL1RegexDetector()

	tests := []struct {
		name     string
		input    string
		wantType DetectionType
	}{
		{
			name:     "phone remains phone only",
			input:    "Liên hệ 0912345678 để xác nhận lịch hẹn",
			wantType: TypePhoneVN,
		},
		{
			name:     "cccd remains cccd only",
			input:    "CCCD khách hàng là 001234567890",
			wantType: TypeCCCD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.Detect(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}

			var specificCount int
			for _, r := range results {
				if r.Type == TypeBankAccount {
					t.Fatalf("unexpected bank account detection for %q: %+v", tt.input, results)
				}
				if r.Type == tt.wantType {
					specificCount++
				}
			}

			if specificCount != 1 {
				t.Fatalf("expected one %s detection, got %d: %+v", tt.wantType, specificCount, results)
			}
		})
	}
}
