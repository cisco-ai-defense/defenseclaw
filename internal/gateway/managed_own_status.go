// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// ownStatusCoworkEvents reads the per-account last Cowork events from the
// audit store; a seam for tests.
var ownStatusCoworkEvents = coworkaudit.LastEvents

// handleOwnStatus serves GET managed.OwnStatusPath on the hook socket: the
// protection state of the socket's kernel-verified caller, for the
// `defenseclaw status` of a standard user on a managed computer, who holds
// no gateway token and was refused every status view (cowork-1-0-8
// GAP-0053). Users see only their own state (owner rule): the answer is
// whether the organization's Claude Code policy covers this computer (it
// covers Claude Cowork too, whose plugin runs the same hooks) and the
// caller's own last Cowork event. It names no other account, and carries
// no profile, enrollment list, path or other administrator configuration.
func (a *APIServer) handleOwnStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok {
		writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified)
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if g := a.generation(); g != nil && g.Config != nil {
		cfg = g.Config
	}
	self := strconv.Itoa(peer.UID)
	account := map[string]any{"uid": self}
	if peer.Name != "" {
		account["name"] = peer.Name
	}
	claudeCode := false
	desktopRefused := false
	auditDB := ""
	if cfg != nil {
		claudeCode = slices.Contains(cfg.ActiveConnectors(), enterprisepolicy.ConnectorClaudeCode)
		desktopRefused = gatewayconnector.SurfaceRefused(enterprisepolicy.ConnectorClaudeCode, gatewayconnector.HostSurfaceDesktop,
			cfg.Enterprise.Enrollment.UnverifiedVersionsFor(enterprisepolicy.ConnectorClaudeCode))
		auditDB = strings.TrimSpace(cfg.AuditDB)
	}
	cowork := map[string]any{}
	if last, found := ownLastCoworkEvent(r.Context(), auditDB, self, peer.Name); found {
		cowork["last_event_at"] = last.UTC().Format(time.RFC3339)
	}
	switch {
	case !claudeCode:
		cowork["protected"] = false
		cowork["state"] = "not protected: your organization has not turned DefenseClaw on for Claude Code on this computer"
	case desktopRefused:
		cowork["protected"] = false
		cowork["state"] = "refused: your organization does not allow this Claude Desktop version, so DefenseClaw refuses its Cowork calls"
	default:
		cowork["protected"] = true
		cowork["state"] = "protected: Cowork runs the Claude Code hooks your organization manages"
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"own":         true,
		"managed":     true,
		"managed_by":  "your organization",
		"account":     account,
		"claude_code": map[string]any{"protected": claudeCode},
		"cowork":      cowork,
	})
}

// ownLastCoworkEvent is the caller's own last Cowork hook event in the audit
// store: the row's OS-derived user id is the caller's uid, or, for a row
// without one, its account name is the caller's. Other accounts' rows are
// read here, on the gateway, and never leave it.
func ownLastCoworkEvent(ctx context.Context, auditDB, uid, name string) (time.Time, bool) {
	if auditDB == "" {
		return time.Time{}, false
	}
	events, _, err := ownStatusCoworkEvents(ctx, auditDB)
	if err != nil {
		return time.Time{}, false
	}
	var last time.Time
	for _, event := range events {
		if !ownCoworkEvent(event, uid, name) || !event.At.After(last) {
			continue
		}
		last = event.At
	}
	return last, !last.IsZero()
}

func ownCoworkEvent(event enterprisestatus.CoworkAccountEvent, uid, name string) bool {
	if id := strings.TrimSpace(event.UserID); id != "" {
		return id == uid
	}
	return name != "" && useridentity.EqualFold(strings.TrimSpace(event.UserName), name)
}
