// Package policy implements the policy engine with rule-level evaluation and hot reload.
package policy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/transformer"
	"gopkg.in/yaml.v3"
)

// Policy defines the complete policy configuration.
type Policy struct {
	Version     string         `yaml:"version"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Rules       []Rule         `yaml:"rules"`
	Defaults    DefaultActions `yaml:"defaults"`
}

// Rule defines a detection-to-action mapping.
type Rule struct {
	Name           string                   `yaml:"name"`
	Description    string                   `yaml:"description"`
	DetectionTypes []detector.DetectionType `yaml:"detection_types"` // which types this rule applies to
	Tier           detector.RiskTier        `yaml:"tier"`
	Action         transformer.Action       `yaml:"action"`
	Enabled        bool                     `yaml:"enabled"`
}

// DefaultActions defines the fallback actions per risk tier.
type DefaultActions struct {
	Restricted   transformer.Action `yaml:"restricted"`
	Confidential transformer.Action `yaml:"confidential"`
	Internal     transformer.Action `yaml:"internal"`
	Public       transformer.Action `yaml:"public"`
}

// Engine manages policy loading, versioning, and evaluation.
type Engine struct {
	mu        sync.RWMutex
	current   *Policy
	policyDir string
	logger    *slog.Logger
}

// NewEngine creates a policy engine and loads the initial policy.
func NewEngine(policyDir string, logger *slog.Logger) (*Engine, error) {
	e := &Engine{
		policyDir: policyDir,
		logger:    logger,
	}

	if err := e.Load(); err != nil {
		return nil, err
	}
	return e, nil
}

// Load reads the first policy YAML file from the policy directory.
func (e *Engine) Load() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(e.policyDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("glob policy files: %w", err)
	}

	if len(files) == 0 {
		// Use default policy
		e.current = defaultPolicy()
		e.logger.Warn("no policy files found, using defaults", "dir", e.policyDir)
		return nil
	}

	// Load the first policy file (single active policy)
	data, err := os.ReadFile(files[0])
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	e.current = &p
	e.logger.Info("policy loaded",
		"name", p.Name,
		"version", p.Version,
		"rules", len(p.Rules),
		"enabled_rules", countEnabledRules(p.Rules),
		"file", files[0],
	)
	return nil
}

// Reload re-reads policy files (hot reload).
func (e *Engine) Reload() error {
	e.logger.Info("hot reloading policy")
	return e.Load()
}

// Evaluate returns the action for a specific detection by matching rules first,
// then falling back to tier defaults. This is the primary enforcement method.
//
// Priority:
//  1. Enabled rule matching detection type → rule action
//  2. Tier default → default action for that tier
func (e *Engine) Evaluate(det detector.Detection) transformer.Action {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Step 1: Check enabled rules matching this detection type
	for _, rule := range e.current.Rules {
		if !rule.Enabled {
			continue
		}
		for _, dt := range rule.DetectionTypes {
			if dt == det.Type {
				return rule.Action
			}
		}
	}

	// Step 2: Fall back to tier default
	return e.tierDefault(det.Tier)
}

// EvaluateAll returns actions for all detections, using rule-level matching.
// Returns a map from detection index to action.
func (e *Engine) EvaluateAll(dets []detector.Detection) map[int]transformer.Action {
	result := make(map[int]transformer.Action, len(dets))
	for i, det := range dets {
		result[i] = e.Evaluate(det)
	}
	return result
}

// ActionResolver returns a function suitable for TransformText.
// This bridges the new rule-based engine with the transformer package.
func (e *Engine) ActionResolver() func(detector.Detection) transformer.Action {
	return func(det detector.Detection) transformer.Action {
		return e.Evaluate(det)
	}
}

// GetActionMap returns the tier-based action map (legacy compatibility).
// Deprecated: Use Evaluate() or ActionResolver() for rule-level enforcement.
func (e *Engine) GetActionMap() map[detector.RiskTier]transformer.Action {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[detector.RiskTier]transformer.Action{
		detector.TierRestricted:   e.current.Defaults.Restricted,
		detector.TierConfidential: e.current.Defaults.Confidential,
		detector.TierInternal:     e.current.Defaults.Internal,
		detector.TierPublic:       e.current.Defaults.Public,
	}
}

// GetPolicy returns a copy of the current policy.
func (e *Engine) GetPolicy() Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return *e.current
}

// tierDefault returns the default action for a given tier.
func (e *Engine) tierDefault(tier detector.RiskTier) transformer.Action {
	switch tier {
	case detector.TierRestricted:
		return e.current.Defaults.Restricted
	case detector.TierConfidential:
		return e.current.Defaults.Confidential
	case detector.TierInternal:
		return e.current.Defaults.Internal
	case detector.TierPublic:
		return e.current.Defaults.Public
	default:
		return transformer.ActionAllow
	}
}

func defaultPolicy() *Policy {
	return &Policy{
		Version:     "1.0.0-default",
		Name:        "default",
		Description: "Default policy — block restricted, mask confidential",
		Defaults: DefaultActions{
			Restricted:   transformer.ActionBlock,
			Confidential: transformer.ActionMask,
			Internal:     transformer.ActionAllow,
			Public:       transformer.ActionAllow,
		},
	}
}

func countEnabledRules(rules []Rule) int {
	n := 0
	for _, r := range rules {
		if r.Enabled {
			n++
		}
	}
	return n
}
