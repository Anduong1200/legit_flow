package toolguard

import "testing"

func TestGuard_AllowlistedTool(t *testing.T) {
	guard := NewGuard([]ToolEndpoint{
		{
			Name:         "search_docs",
			Endpoint:     "/api/tools/search",
			AllowedRoles: []string{"analyst", "admin"},
			Permission:   PermRead,
		},
	})

	result := guard.Check(AccessRequest{
		ToolName: "search_docs",
		UserRole: "analyst",
		Action:   PermRead,
	})

	if !result.Allowed {
		t.Errorf("Expected allowed, got denied: %s", result.Reason)
	}
}

func TestGuard_NotInAllowlist(t *testing.T) {
	guard := NewGuard([]ToolEndpoint{
		{Name: "search_docs", AllowedRoles: []string{"*"}, Permission: PermRead},
	})

	result := guard.Check(AccessRequest{
		ToolName: "delete_user",
		UserRole: "analyst",
		Action:   PermExecute,
	})

	if result.Allowed {
		t.Error("Expected denied for tool not in allowlist")
	}
}

func TestGuard_WrongRole(t *testing.T) {
	guard := NewGuard([]ToolEndpoint{
		{Name: "admin_panel", AllowedRoles: []string{"admin"}, Permission: PermAdmin},
	})

	result := guard.Check(AccessRequest{
		ToolName: "admin_panel",
		UserRole: "analyst",
		Action:   PermRead,
	})

	if result.Allowed {
		t.Error("Expected denied for wrong role")
	}
}

func TestGuard_NeedsApproval(t *testing.T) {
	guard := NewGuard([]ToolEndpoint{
		{
			Name:          "deploy_prod",
			AllowedRoles:  []string{"engineer"},
			Permission:    PermExecute,
			NeedsApproval: true,
		},
	})

	result := guard.Check(AccessRequest{
		ToolName: "deploy_prod",
		UserRole: "engineer",
		Action:   PermExecute,
	})

	if !result.Allowed {
		t.Errorf("Expected allowed (with approval), got denied: %s", result.Reason)
	}
	if !result.NeedsApproval {
		t.Error("Expected NeedsApproval to be true")
	}
}

func TestGuard_DefaultDeny(t *testing.T) {
	guard := DefaultReadOnlyGuard()

	result := guard.Check(AccessRequest{
		ToolName: "anything",
		UserRole: "admin",
		Action:   PermRead,
	})

	if result.Allowed {
		t.Error("Default guard should deny all")
	}
}

func TestGuard_InsufficientPermission(t *testing.T) {
	guard := NewGuard([]ToolEndpoint{
		{Name: "read_only_tool", AllowedRoles: []string{"*"}, Permission: PermRead},
	})

	result := guard.Check(AccessRequest{
		ToolName: "read_only_tool",
		UserRole: "analyst",
		Action:   PermWrite, // trying to write on read-only tool
	})

	if result.Allowed {
		t.Error("Expected denied for insufficient permission")
	}
}
