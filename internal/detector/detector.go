// Package detector provides PII and secret detection for the Legit Flow data plane.
package detector

import "context"

// DetectionType identifies the category of a detection.
type DetectionType string

const (
	TypeCCCD        DetectionType = "CCCD"     // Vietnamese Citizen ID (12 digits)
	TypePhoneVN     DetectionType = "PHONE_VN" // Vietnamese phone number
	TypeEmail       DetectionType = "EMAIL"
	TypeBankAccount DetectionType = "BANK_ACCOUNT"
	TypeJWT         DetectionType = "JWT"
	TypeAPIKey      DetectionType = "API_KEY"
	TypeGenericPII  DetectionType = "GENERIC_PII"
	TypeContextual  DetectionType = "CONTEXTUAL" // L2 classifier result
)

// RiskTier determines the severity and default action for a detection.
type RiskTier string

const (
	TierRestricted   RiskTier = "restricted"   // block or hard-mask; never log raw
	TierConfidential RiskTier = "confidential" // mask/pseudonymize; log redacted
	TierInternal     RiskTier = "internal"     // warn/flag; log metadata only
	TierPublic       RiskTier = "public"       // passthrough
)

// Detection represents a single detected entity in the text.
type Detection struct {
	Type       DetectionType `json:"type"`
	Tier       RiskTier      `json:"tier"`
	Value      string        `json:"value"`      // The raw matched value
	Start      int           `json:"start"`      // Start offset in text
	End        int           `json:"end"`        // End offset in text
	Confidence float64       `json:"confidence"` // 0.0–1.0 for ML detectors; 1.0 for regex
}

// Detector is the interface all detection modules must implement.
type Detector interface {
	// Name returns the detector identifier.
	Name() string
	// Detect scans text and returns all detections.
	Detect(ctx context.Context, text string) ([]Detection, error)
}

// Registry holds all registered detectors.
type Registry struct {
	detectors []Detector
}

// NewRegistry creates an empty detector registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a detector to the registry.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// DetectAll runs all registered detectors and merges results.
func (r *Registry) DetectAll(ctx context.Context, text string) ([]Detection, error) {
	var all []Detection
	for _, d := range r.detectors {
		results, err := d.Detect(ctx, text)
		if err != nil {
			return nil, err
		}
		all = append(all, results...)
	}
	// Sort by start position for consistent processing
	sortByStart(all)
	return all, nil
}

func sortByStart(dets []Detection) {
	for i := 1; i < len(dets); i++ {
		for j := i; j > 0 && dets[j].Start < dets[j-1].Start; j-- {
			dets[j], dets[j-1] = dets[j-1], dets[j]
		}
	}
}
