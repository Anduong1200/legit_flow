package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/legitflow/legitflow/internal/common"
	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/transformer"
)

func TestEngine_DefaultPolicy(t *testing.T) {
	// Empty dir → should use defaults
	dir := t.TempDir()
	logger := common.NewLogger("error")

	engine, err := NewEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	m := engine.GetActionMap()
	if m[detector.TierRestricted] != transformer.ActionBlock {
		t.Errorf("Restricted default should be Block, got %s", m[detector.TierRestricted])
	}
	if m[detector.TierConfidential] != transformer.ActionMask {
		t.Errorf("Confidential default should be Mask, got %s", m[detector.TierConfidential])
	}
}

func TestEngine_LoadYAML(t *testing.T) {
	dir := t.TempDir()

	policyYAML := `
version: "1.0.0-test"
name: test-policy
description: Test policy
defaults:
  restricted: block
  confidential: pseudonymize
  internal: allow
  public: allow
rules:
  - name: block-cccd
    detection_types: [CCCD]
    tier: restricted
    action: block
    enabled: true
`
	err := os.WriteFile(filepath.Join(dir, "test-policy.yaml"), []byte(policyYAML), 0644)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	logger := common.NewLogger("error")
	engine, err := NewEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	p := engine.GetPolicy()
	if p.Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got %q", p.Name)
	}
	if p.Version != "1.0.0-test" {
		t.Errorf("Expected version '1.0.0-test', got %q", p.Version)
	}
	if len(p.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(p.Rules))
	}

	m := engine.GetActionMap()
	if m[detector.TierConfidential] != transformer.ActionPseudonym {
		t.Errorf("Confidential should be pseudonymize, got %s", m[detector.TierConfidential])
	}
}

func TestEngine_Evaluate_RuleMatch(t *testing.T) {
	dir := t.TempDir()
	policyYAML := `
version: "1.0.0-test"
name: rule-test
defaults:
  restricted: block
  confidential: mask
  internal: allow
  public: allow
rules:
  - name: tokenize-cccd
    detection_types: [CCCD]
    tier: restricted
    action: tokenize
    enabled: true
  - name: redact-jwt
    detection_types: [JWT]
    tier: restricted
    action: redact
    enabled: true
`
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policyYAML), 0644)
	logger := common.NewLogger("error")
	engine, err := NewEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	// CCCD should match the tokenize-cccd rule, NOT the tier default (block)
	action := engine.Evaluate(detector.Detection{Type: detector.TypeCCCD, Tier: detector.TierRestricted})
	if action != transformer.ActionTokenize {
		t.Errorf("CCCD should be tokenize (from rule), got %s", action)
	}

	// JWT should match redact-jwt rule
	action = engine.Evaluate(detector.Detection{Type: detector.TypeJWT, Tier: detector.TierRestricted})
	if action != transformer.ActionRedact {
		t.Errorf("JWT should be redact (from rule), got %s", action)
	}

	// BANK_ACCOUNT has no specific rule, should fall back to tier default (block)
	action = engine.Evaluate(detector.Detection{Type: detector.TypeBankAccount, Tier: detector.TierRestricted})
	if action != transformer.ActionBlock {
		t.Errorf("BANK_ACCOUNT should fall back to tier default (block), got %s", action)
	}

	// EMAIL is confidential, no rule → should be mask (tier default)
	action = engine.Evaluate(detector.Detection{Type: detector.TypeEmail, Tier: detector.TierConfidential})
	if action != transformer.ActionMask {
		t.Errorf("EMAIL should fall back to confidential default (mask), got %s", action)
	}
}

func TestEngine_Evaluate_DisabledRule(t *testing.T) {
	dir := t.TempDir()
	policyYAML := `
version: "1.0.0-test"
name: disabled-test
defaults:
  restricted: block
  confidential: mask
  internal: allow
  public: allow
rules:
  - name: tokenize-cccd
    detection_types: [CCCD]
    tier: restricted
    action: tokenize
    enabled: false
`
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policyYAML), 0644)
	logger := common.NewLogger("error")
	engine, err := NewEngine(dir, logger)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	// CCCD rule is disabled → should fall back to tier default (block)
	action := engine.Evaluate(detector.Detection{Type: detector.TypeCCCD, Tier: detector.TierRestricted})
	if action != transformer.ActionBlock {
		t.Errorf("Disabled rule should fall back to tier default (block), got %s", action)
	}
}
