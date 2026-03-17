package audit

import (
	"testing"
	"time"
)

func TestValidateBreakGlass_Valid(t *testing.T) {
	req := BreakGlassRequest{
		RequestedBy: "analyst@corp.vn",
		ApprovedBy:  "manager@corp.vn",
		TicketLink:  "https://jira.corp.vn/SEC-1234",
		Reason:      "Incident investigation #1234",
		EventIDs:    []string{"evt-001", "evt-002"},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := ValidateBreakGlass(req); err != nil {
		t.Errorf("Expected valid request, got error: %v", err)
	}
}

func TestValidateBreakGlass_SamePerson(t *testing.T) {
	req := BreakGlassRequest{
		RequestedBy: "admin@corp.vn",
		ApprovedBy:  "admin@corp.vn", // same person!
		TicketLink:  "https://jira.corp.vn/SEC-1234",
		EventIDs:    []string{"evt-001"},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := ValidateBreakGlass(req); err == nil {
		t.Error("Expected error for same requester/approver")
	}
}

func TestValidateBreakGlass_Expired(t *testing.T) {
	req := BreakGlassRequest{
		RequestedBy: "analyst@corp.vn",
		ApprovedBy:  "manager@corp.vn",
		TicketLink:  "https://jira.corp.vn/SEC-1234",
		EventIDs:    []string{"evt-001"},
		ExpiresAt:   time.Now().Add(-1 * time.Hour), // expired!
	}
	if err := ValidateBreakGlass(req); err == nil {
		t.Error("Expected error for expired access")
	}
}

func TestValidateBreakGlass_MissingTicket(t *testing.T) {
	req := BreakGlassRequest{
		RequestedBy: "analyst@corp.vn",
		ApprovedBy:  "manager@corp.vn",
		TicketLink:  "", // missing!
		EventIDs:    []string{"evt-001"},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := ValidateBreakGlass(req); err == nil {
		t.Error("Expected error for missing ticket link")
	}
}
