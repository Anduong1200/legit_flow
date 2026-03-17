// Package toolguard implements the Tool/Action Guard for AI agent safety.
// It enforces allowlists, role-based access, and approval workflows
// for tool/action invocations. Default mode: read-only.
package toolguard

import (
	"fmt"
	"strings"
	"sync"
)

// Permission defines what a role can do with a tool.
type Permission string

const (
	PermRead     Permission = "read"
	PermWrite    Permission = "write"
	PermExecute  Permission = "execute"
	PermAdmin    Permission = "admin"
)

// ToolEndpoint defines an allowed tool with its constraints.
type ToolEndpoint struct {
	Name        string       `yaml:"name"`
	Endpoint    string       `yaml:"endpoint"`
	AllowedRoles []string    `yaml:"allowed_roles"`
	Permission  Permission   `yaml:"permission"`
	NeedsApproval bool      `yaml:"needs_approval"` // requires human approval
	Description string       `yaml:"description"`
}

// Guard enforces tool/action access control.
type Guard struct {
	mu        sync.RWMutex
	allowlist map[string]ToolEndpoint // tool name → endpoint config
}

// NewGuard creates a new tool guard with the given allowlist.
func NewGuard(endpoints []ToolEndpoint) *Guard {
	m := make(map[string]ToolEndpoint)
	for _, ep := range endpoints {
		m[ep.Name] = ep
	}
	return &Guard{allowlist: m}
}

// CheckAccess verifies the request is allowed.
type AccessRequest struct {
	ToolName string
	UserRole string
	Action   Permission
}

// AccessResult contains the result of an access check.
type AccessResult struct {
	Allowed       bool
	NeedsApproval bool
	Reason        string
}

// Check evaluates whether the given access request is permitted.
func (g *Guard) Check(req AccessRequest) AccessResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Not in allowlist → blocked
	ep, ok := g.allowlist[req.ToolName]
	if !ok {
		return AccessResult{
			Allowed: false,
			Reason:  fmt.Sprintf("tool %q not in allowlist", req.ToolName),
		}
	}

	// Check role
	if !g.hasRole(ep.AllowedRoles, req.UserRole) {
		return AccessResult{
			Allowed: false,
			Reason:  fmt.Sprintf("role %q not allowed for tool %q", req.UserRole, req.ToolName),
		}
	}

	// Check permission level
	if !g.permissionSufficient(ep.Permission, req.Action) {
		return AccessResult{
			Allowed: false,
			Reason:  fmt.Sprintf("permission %q insufficient for action %q", ep.Permission, req.Action),
		}
	}

	// Check if approval is needed
	if ep.NeedsApproval && (req.Action == PermWrite || req.Action == PermExecute) {
		return AccessResult{
			Allowed:       true,
			NeedsApproval: true,
			Reason:        fmt.Sprintf("tool %q requires approval for %s actions", req.ToolName, req.Action),
		}
	}

	return AccessResult{
		Allowed: true,
		Reason:  "access granted",
	}
}

func (g *Guard) hasRole(allowed []string, role string) bool {
	for _, r := range allowed {
		if strings.EqualFold(r, role) || strings.EqualFold(r, "*") {
			return true
		}
	}
	return false
}

// permissionSufficient checks if the endpoint's permission level covers the requested action.
func (g *Guard) permissionSufficient(endpointPerm, requestedAction Permission) bool {
	levels := map[Permission]int{
		PermRead:    1,
		PermWrite:   2,
		PermExecute: 3,
		PermAdmin:   4,
	}
	return levels[endpointPerm] >= levels[requestedAction]
}

// DefaultReadOnlyGuard creates a guard with no tools allowed (default deny).
func DefaultReadOnlyGuard() *Guard {
	return &Guard{allowlist: make(map[string]ToolEndpoint)}
}
