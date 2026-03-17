package transformer

import (
	"testing"

	"github.com/legitflow/legitflow/internal/detector"
)

func TestMask(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0912345678", "091*****78"},
		{"abc", "***"},
		{"abcde", "*****"},
		{"abcdef", "abc*ef"},
		{"001234567890", "001*******90"},
	}
	for _, tt := range tests {
		got := Mask(tt.input)
		if got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPseudonymize_Consistency(t *testing.T) {
	// Same input should always produce the same output
	val := "0912345678"
	p1 := Pseudonymize(val, detector.TypePhoneVN)
	p2 := Pseudonymize(val, detector.TypePhoneVN)
	if p1 != p2 {
		t.Errorf("Pseudonymize not consistent: %q vs %q", p1, p2)
	}
	// Different inputs should produce different outputs
	p3 := Pseudonymize("0987654321", detector.TypePhoneVN)
	if p1 == p3 {
		t.Errorf("Different inputs produced same pseudonym")
	}
}

func TestTransformText(t *testing.T) {
	text := "Call me at 0912345678 or email test@example.com"
	detections := []detector.Detection{
		{Type: detector.TypePhoneVN, Tier: detector.TierConfidential, Value: "0912345678", Start: 11, End: 21},
		{Type: detector.TypeEmail, Tier: detector.TierConfidential, Value: "test@example.com", Start: 31, End: 47},
	}
	actionMap := map[detector.RiskTier]Action{
		detector.TierConfidential: ActionMask,
	}

	result, applied := TransformText(text, detections, actionMap)

	if len(applied) != 2 {
		t.Fatalf("Expected 2 transforms, got %d", len(applied))
	}

	// Phone and email should be masked
	if result == text {
		t.Error("Text was not transformed")
	}

	// Original values should not appear in result
	if contains(result, "0912345678") || contains(result, "test@example.com") {
		t.Errorf("Original PII still present in result: %s", result)
	}
}

func TestTransformText_Block(t *testing.T) {
	text := "Secret: sk-abcdefghijklmnopqrstuvwxyz123456"
	detections := []detector.Detection{
		{Type: detector.TypeAPIKey, Tier: detector.TierRestricted, Value: "sk-abcdefghijklmnopqrstuvwxyz123456", Start: 8, End: 42},
	}
	actionMap := map[detector.RiskTier]Action{
		detector.TierRestricted: ActionBlock,
	}

	result, applied := TransformText(text, detections, actionMap)

	if len(applied) != 1 {
		t.Fatalf("Expected 1 transform, got %d", len(applied))
	}
	if applied[0].Action != ActionBlock {
		t.Errorf("Expected block action, got %s", applied[0].Action)
	}
	if contains(result, "sk-") {
		t.Errorf("Blocked secret still present: %s", result)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
