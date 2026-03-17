// Package audit implements the 2-tier audit logging system.
// Tier 1: metadata always-on (who/when/policy/action) — never contains raw PII.
// Tier 2: redacted/pseudonymized content — only for authorized review.
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/legitflow/legitflow/internal/common"
	"github.com/legitflow/legitflow/internal/detector"
	"github.com/legitflow/legitflow/internal/transformer"
)

// Tier1Event contains metadata only — safe to always log.
type Tier1Event struct {
	EventID    string                   `json:"event_id"`
	Timestamp  time.Time                `json:"timestamp"`
	RequestID  string                   `json:"request_id"`
	UserID     string                   `json:"user_id"`
	SourceIP   string                   `json:"source_ip"`
	Action     transformer.Action       `json:"action"`
	PolicyName string                   `json:"policy_name"`
	Detections []DetectionSummary       `json:"detections"` // type + tier only, no values
	Outcome    string                   `json:"outcome"`    // "allowed", "blocked", "transformed", "truncated"
	LatencyMs  int64                    `json:"latency_ms"`
}

// DetectionSummary is a value-free summary of a detection for Tier 1 logging.
type DetectionSummary struct {
	Type  detector.DetectionType `json:"type"`
	Tier  detector.RiskTier      `json:"tier"`
	Count int                    `json:"count"`
}

// Tier2Event contains the redacted/pseudonymized content for authorized review.
type Tier2Event struct {
	EventID           string `json:"event_id"` // links to Tier1Event
	RedactedInput     string `json:"redacted_input,omitempty"`
	RedactedOutput    string `json:"redacted_output,omitempty"`
	TransformsSummary []transformer.AppliedTransform `json:"transforms,omitempty"`
}

// Logger handles audit event writing.
type Logger struct {
	tier1Enabled bool
	tier2Enabled bool
	outputDir    string
	logger       *slog.Logger
	mu           sync.Mutex
}

// NewLogger creates an audit logger.
func NewLogger(cfg *common.Config, logger *slog.Logger) (*Logger, error) {
	if cfg.AuditOutputDir != "" {
		if err := os.MkdirAll(cfg.AuditOutputDir, 0750); err != nil {
			return nil, fmt.Errorf("create audit dir: %w", err)
		}
	}
	return &Logger{
		tier1Enabled: cfg.AuditTier1Enabled,
		tier2Enabled: cfg.AuditTier2Enabled,
		outputDir:    cfg.AuditOutputDir,
		logger:       logger,
	}, nil
}

// LogTier1 records a metadata-only audit event.
func (l *Logger) LogTier1(event Tier1Event) {
	if !l.tier1Enabled {
		return
	}
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	common.AuditEventsTotal.WithLabelValues("tier1").Inc()

	// Structured log
	l.logger.Info("audit.tier1",
		"event_id", event.EventID,
		"request_id", event.RequestID,
		"user_id", event.UserID,
		"action", event.Action,
		"policy", event.PolicyName,
		"outcome", event.Outcome,
		"latency_ms", event.LatencyMs,
		"detection_count", len(event.Detections),
	)

	// Also write to file for SIEM/WORM
	l.writeToFile("tier1", event)
}

// LogTier2 records redacted content — only if tier2 is enabled and content is not Restricted.
func (l *Logger) LogTier2(event Tier2Event) {
	if !l.tier2Enabled {
		return
	}

	common.AuditEventsTotal.WithLabelValues("tier2").Inc()

	l.logger.Info("audit.tier2",
		"event_id", event.EventID,
	)

	l.writeToFile("tier2", event)
}

func (l *Logger) writeToFile(tier string, event any) {
	if l.outputDir == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	date := time.Now().Format("2006-01-02")
	filename := filepath.Join(l.outputDir, fmt.Sprintf("%s_%s.jsonl", tier, date))

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		l.logger.Error("audit write failed", "error", err)
		return
	}
	defer f.Close()

	data, _ := json.Marshal(event)
	f.Write(data)
	f.Write([]byte("\n"))
}

// ── Break-glass ─────────────────────────────────────────────────────────────

// BreakGlassRequest represents a request to access raw audit content.
type BreakGlassRequest struct {
	RequestedBy string    `json:"requested_by"`
	ApprovedBy  string    `json:"approved_by"` // 2-person rule
	TicketLink  string    `json:"ticket_link"`
	Reason      string    `json:"reason"`
	EventIDs    []string  `json:"event_ids"`
	ExpiresAt   time.Time `json:"expires_at"` // time-bound access
}

// ValidateBreakGlass checks if a break-glass request meets requirements.
func ValidateBreakGlass(req BreakGlassRequest) error {
	if req.RequestedBy == "" {
		return fmt.Errorf("requested_by is required")
	}
	if req.ApprovedBy == "" {
		return fmt.Errorf("approved_by is required (2-person rule)")
	}
	if req.RequestedBy == req.ApprovedBy {
		return fmt.Errorf("requester and approver must be different persons")
	}
	if req.TicketLink == "" {
		return fmt.Errorf("ticket_link is required for traceability")
	}
	if req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("break-glass access has expired")
	}
	if len(req.EventIDs) == 0 {
		return fmt.Errorf("at least one event_id is required")
	}
	return nil
}
