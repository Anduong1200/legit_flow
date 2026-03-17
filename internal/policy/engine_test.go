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
