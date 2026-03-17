package detector

import (
	"context"
	"regexp"
)

// L1RegexDetector performs fast, deterministic detection of structured PII and secrets
// using regular expressions. This is the "fast path" — always runs, zero ML dependency.
type L1RegexDetector struct{}

// NewL1RegexDetector creates a new L1 regex-based detector.
func NewL1RegexDetector() *L1RegexDetector {
	return &L1RegexDetector{}
}

func (d *L1RegexDetector) Name() string { return "l1_regex" }

// pattern defines a single regex pattern with its detection type and risk tier.
type pattern struct {
	name DetectionType
	tier RiskTier
	re   *regexp.Regexp
}

// Vietnamese & universal patterns
var patterns = []pattern{
	// ── Vietnamese PII ──────────────────────────────────────────
	{
		name: TypeCCCD,
		tier: TierRestricted,
		// CCCD: exactly 12 digits, word-bounded
		re: regexp.MustCompile(`\b0\d{11}\b`),
	},
	{
		name: TypePhoneVN,
		tier: TierConfidential,
		// Vietnamese mobile: 0[3|5|7|8|9]x xxx xxxx (with optional separators)
		re: regexp.MustCompile(`\b0[35789]\d[\s.-]?\d{3}[\s.-]?\d{4}\b`),
	},
	{
		name: TypeEmail,
		tier: TierConfidential,
		re:   regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
	},
	{
		name: TypeBankAccount,
		tier: TierRestricted,
		// Vietnamese bank accounts: 8-19 digits (common formats)
		re: regexp.MustCompile(`\b\d{8,19}\b`),
	},

	// ── Secrets ─────────────────────────────────────────────────
	{
		name: TypeJWT,
		tier: TierRestricted,
		// JWT: three base64url segments separated by dots
		re: regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b`),
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// AWS access key
		re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// OpenAI-style key
		re: regexp.MustCompile(`\bsk-[a-zA-Z0-9]{20,}\b`),
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// Generic long hex secret (32+ hex chars)
		re: regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`),
	},
}

// Detect scans text against all L1 regex patterns.
func (d *L1RegexDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
	var detections []Detection
	for _, p := range patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			detections = append(detections, Detection{
				Type:       p.name,
				Tier:       p.tier,
				Value:      text[m[0]:m[1]],
				Start:      m[0],
				End:        m[1],
				Confidence: 1.0, // regex = deterministic
			})
		}
	}
	return detections, nil
}
