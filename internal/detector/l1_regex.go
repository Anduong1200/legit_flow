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

var (
	cccdPattern        = regexp.MustCompile(`\b0\d{11}\b`)
	phoneVNPattern     = regexp.MustCompile(`\b0[35789]\d[\s.-]?\d{3}[\s.-]?\d{4}\b`)
	emailPattern       = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	bankAccountPattern = regexp.MustCompile(`\b\d{8,19}\b`)
	creditCardPattern  = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
	jwtPattern         = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b`)
	awsAPIKeyPattern   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	openAIKeyPattern   = regexp.MustCompile(`\bsk-[a-zA-Z0-9]{20,}\b`)
	hexSecretPattern   = regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`)
)

// Vietnamese & universal patterns
var patterns = []pattern{
	// ── Vietnamese PII ──────────────────────────────────────────
	{
		name: TypeCCCD,
		tier: TierRestricted,
		// CCCD: exactly 12 digits, word-bounded
		re: cccdPattern,
	},
	{
		name: TypePhoneVN,
		tier: TierConfidential,
		// Vietnamese mobile: 0[3|5|7|8|9]x xxx xxxx (with optional separators)
		re: phoneVNPattern,
	},
	{
		name: TypeEmail,
		tier: TierConfidential,
		re:   emailPattern,
	},
	{
		name: TypeBankAccount,
		tier: TierRestricted,
		// Vietnamese bank accounts: 8-19 digits (common formats)
		re: bankAccountPattern,
	},
	{
		name: "credit_card",
		tier: TierConfidential,
		// Common credit card sizes
		re: creditCardPattern,
	},

	// ── Secrets ─────────────────────────────────────────────────
	{
		name: TypeJWT,
		tier: TierRestricted,
		// JWT: three base64url segments separated by dots
		re: jwtPattern,
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// AWS access key
		re: awsAPIKeyPattern,
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// OpenAI-style key
		re: openAIKeyPattern,
	},
	{
		name: TypeAPIKey,
		tier: TierRestricted,
		// Generic long hex secret (32+ hex chars)
		re: hexSecretPattern,
	},
}

// Detect scans text against all L1 regex patterns.
func (d *L1RegexDetector) Detect(ctx context.Context, text string) ([]Detection, error) {
	var detections []Detection
	for _, p := range patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			value := text[m[0]:m[1]]
			if shouldSkipL1Match(p.name, value) {
				continue
			}
			detections = append(detections, Detection{
				Type:       p.name,
				Tier:       p.tier,
				Value:      value,
				Start:      m[0],
				End:        m[1],
				Confidence: 1.0, // regex = deterministic
			})
		}
	}
	return detections, nil
}

func shouldSkipL1Match(detType DetectionType, value string) bool {
	switch detType {
	case TypeBankAccount:
		// Skip if it matches a more specific pattern (CCCD or phone)
		if cccdPattern.MatchString(value) || phoneVNPattern.MatchString(value) {
			return true
		}
		// Skip short numbers (≤9 digits) — likely order IDs, timestamps, etc.
		if len(value) <= 9 {
			return true
		}
		// Skip numbers that are clearly timestamps (10-digit Unix epoch)
		if len(value) == 10 && (value[0] == '1' || value[0] == '2') {
			return true
		}
		// Skip round numbers (likely monetary amounts: 999123456789)
		if isRoundNumber(value) {
			return true
		}
		return false
	case "credit_card":
		// Skip if too short or fails Luhn checksum
		if len(value) < 13 || !luhnValid(value) {
			return true
		}
		return false
	case TypeAPIKey:
		// For hex secrets: require minimum 40 chars and reject pure-digit strings
		if hexSecretPattern.MatchString(value) && !awsAPIKeyPattern.MatchString(value) && !openAIKeyPattern.MatchString(value) {
			if len(value) < 40 {
				return true
			}
			// Must contain at least some hex letters (a-f) to be a secret
			hasHexLetter := false
			for _, c := range value {
				if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
					hasHexLetter = true
					break
				}
			}
			if !hasHexLetter {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// isRoundNumber checks if a number ends with 3+ zeros (likely money, not PII)
func isRoundNumber(s string) bool {
	if len(s) < 6 {
		return false
	}
	trailingZeros := 0
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '0' {
			trailingZeros++
		} else {
			break
		}
	}
	return trailingZeros >= 3
}

// luhnValid validates a number string using the Luhn algorithm (credit card checksum)
func luhnValid(number string) bool {
	// Strip spaces and dashes
	var digits []int
	for _, c := range number {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
