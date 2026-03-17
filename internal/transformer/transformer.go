// Package transformer provides utility-preserving data transformations.
package transformer

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/legitflow/legitflow/internal/detector"
)

// Action defines what to do with a detection.
type Action string

const (
	ActionAllow     Action = "allow"        // passthrough
	ActionMask      Action = "mask"         // partial masking: 079***1234
	ActionPseudonym Action = "pseudonymize" // consistent fake replacement
	ActionTokenize  Action = "tokenize"     // reversible token
	ActionBlock     Action = "block"        // replace with [BLOCKED]
	ActionRedact    Action = "redact"       // replace with [REDACTED]
)

// Transformer applies an action to detected entities in text.
type Transformer interface {
	// Transform applies the transformation to the value.
	Transform(value string, det detector.Detection) string
}

// TransformText applies transformations to all detections in the text.
// Returns the transformed text and a list of applied transforms.
func TransformText(text string, detections []detector.Detection, actionMap map[detector.RiskTier]Action) (string, []AppliedTransform) {
	if len(detections) == 0 {
		return text, nil
	}

	var applied []AppliedTransform
	// Process detections in reverse order to preserve offsets
	result := []byte(text)
	for i := len(detections) - 1; i >= 0; i-- {
		det := detections[i]
		action := actionMap[det.Tier]
		if action == ActionAllow || action == "" {
			continue
		}

		var replacement string
		switch action {
		case ActionMask:
			replacement = Mask(det.Value)
		case ActionPseudonym:
			replacement = Pseudonymize(det.Value, det.Type)
		case ActionTokenize:
			replacement = Tokenize(det.Value)
		case ActionBlock:
			replacement = "[BLOCKED]"
		case ActionRedact:
			replacement = "[REDACTED]"
		}

		applied = append(applied, AppliedTransform{
			Type:        det.Type,
			Action:      action,
			Original:    det.Value,
			Replacement: replacement,
			Start:       det.Start,
			End:         det.End,
		})

		result = append(result[:det.Start], append([]byte(replacement), result[det.End:]...)...)
	}

	return string(result), applied
}

// AppliedTransform records what was transformed and how.
type AppliedTransform struct {
	Type        detector.DetectionType `json:"type"`
	Action      Action                 `json:"action"`
	Original    string                 `json:"-"` // never log raw for Restricted
	Replacement string                 `json:"replacement"`
	Start       int                    `json:"start"`
	End         int                    `json:"end"`
}

// ── Mask ────────────────────────────────────────────────────────────────────

// Mask partially hides a value, preserving first 3 and last 2 characters.
func Mask(value string) string {
	runes := []rune(value)
	if len(runes) <= 5 {
		return strings.Repeat("*", len(runes))
	}
	prefix := string(runes[:3])
	suffix := string(runes[len(runes)-2:])
	masked := strings.Repeat("*", len(runes)-5)
	return prefix + masked + suffix
}

// ── Pseudonymize ────────────────────────────────────────────────────────────

// Pseudonymize creates a consistent, deterministic fake replacement.
// Same input + type always produces the same output within a session.
func Pseudonymize(value string, detType detector.DetectionType) string {
	h := sha256.Sum256([]byte(value))
	short := fmt.Sprintf("%x", h[:4])
	switch detType {
	case detector.TypeCCCD:
		return fmt.Sprintf("PSEUDO-CCCD-%s", short)
	case detector.TypePhoneVN:
		return fmt.Sprintf("PSEUDO-PHONE-%s", short)
	case detector.TypeEmail:
		return fmt.Sprintf("pseudo-%s@example.com", short)
	case detector.TypeBankAccount:
		return fmt.Sprintf("PSEUDO-ACCT-%s", short)
	default:
		return fmt.Sprintf("PSEUDO-%s-%s", detType, short)
	}
}

// ── Tokenize ────────────────────────────────────────────────────────────────

// Tokenize creates a reversible token. In production this would use a vault.
// For MVP, we use a deterministic hash-based token.
func Tokenize(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("TOK_%x", h[:8])
}
