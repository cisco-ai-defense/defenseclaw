// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/coworkaudit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// ownStatusCoworkEvents reads the per-account last Cowork events from the
// audit store; a seam for tests.
var ownStatusCoworkEvents = coworkaudit.LastEvents

// ownStatusGuardianAuthorization reads the same fresh, trusted guardian
// record used by managed readiness and verification; a seam for tests.
var ownStatusGuardianAuthorization = readManagedGuardianAuthorization

// ownStatusWindowsAccountName names a verified Windows account SID for the
// own-status answer (LookupAccountSid, set on Windows); "" when the LSA does
// not name it.
var ownStatusWindowsAccountName = func(string) string { return "" }

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
	a.writeJSON(w, http.StatusOK, a.ownStatusAnswer(r.Context(), "uid", strconv.Itoa(peer.UID), peer.Name))
}

// ownStatusForWindowsAccount is the own-status answer, as JSON, for the
// account a managed Windows gateway named from its own-status pipe's client
// token (refusalpipe.ServeOwnStatus): a standard account of a managed
// Windows computer has no hook socket and holds no gateway credential
// (cowork-1-0-8 GAP-0060). The same rule holds: the answer is that account's
// own state and nothing else. A SID that is not a user account's gets none.
func (a *APIServer) ownStatusForWindowsAccount(ctx context.Context, sid string) []byte {
	if !refusalpipe.AccountSID(sid) {
		return nil
	}
	body, err := json.Marshal(a.ownStatusAnswer(ctx, "sid", sid, ownStatusWindowsAccountName(sid)))
	if err != nil || len(body) > refusalpipe.MaxOwnStatusBytes {
		return nil
	}
	return body
}

// ownStatusAnswer is the own-status answer for the verified caller whose OS
// identifier (a uid, or a SID on Windows) is self, under idKey, and whose
// account name is name.
func (a *APIServer) ownStatusAnswer(ctx context.Context, idKey, self, name string) map[string]any {
	cfg := a.runtimeConfigSnapshot()
	if g := a.generation(); g != nil && g.Config != nil {
		cfg = g.Config
	}
	account := map[string]any{idKey: self}
	if name != "" {
		account["name"] = name
	}
	claudeCode := false
	claudeConfigured := false
	desktopRefused := false
	auditDB := ""
	if cfg != nil {
		claudeConfigured = slices.Contains(enterprisepolicy.StandaloneConnectors(cfg), enterprisepolicy.ConnectorClaudeCode)
		claudeCode = claudeConfigured
		desktopRefused = gatewayconnector.SurfaceRefused(enterprisepolicy.ConnectorClaudeCode, gatewayconnector.HostSurfaceDesktop,
			cfg.Enterprise.Enrollment.UnverifiedVersionsFor(enterprisepolicy.ConnectorClaudeCode))
		auditDB = strings.TrimSpace(cfg.AuditDB)
	}
	// The launcher lists every configured connector. On Unix, the policy-view
	// watcher supplies the published vendor-source proof used to judge managed
	// hook calls. A missing or changed view never claims protection.
	var connectors map[string]any
	if idKey == "uid" && cfg != nil {
		connectors = a.ownConnectorStates(cfg, self, name)
	} else if idKey == "sid" && cfg != nil {
		connectors = a.ownWindowsConnectorStates(cfg, self, name)
	}
	if connectors != nil {
		// Claude Code and Cowork follow the Claude Code row: configured, and
		// not listed unprotected for this caller by the enumerator's scan.
		claudeCode = false
		if row, ok := connectors[enterprisepolicy.ConnectorClaudeCode].(map[string]any); ok {
			claudeCode, _ = row["protected"].(bool)
		}
	}
	cowork := ownCoworkRow(true, "protected", "cowork_hooks", "Cowork runs the Claude Code hooks your organization manages")
	switch {
	case !claudeCode && claudeConfigured:
		cowork = ownCoworkRow(false, "not confirmed", "claude_code_unverified", "Claude Code policy or enrollment is not verified for this account")
	case !claudeCode:
		cowork = ownCoworkRow(false, "not protected", "claude_code_off", "your organization has not turned DefenseClaw on for Claude Code on this computer")
	case desktopRefused:
		cowork = ownCoworkRow(false, "refused", "desktop_version_refused", "your organization does not allow this Claude Desktop version, so DefenseClaw refuses its Cowork calls")
	}
	if last, found := ownLastCoworkEvent(ctx, auditDB, self, name); found {
		cowork["last_event_at"] = last.UTC().Format(time.RFC3339)
	}
	answer := map[string]any{
		"own":         true,
		"managed":     true,
		"managed_by":  "your organization",
		"account":     account,
		"claude_code": map[string]any{"protected": claudeCode},
		"cowork":      cowork,
	}
	if connectors != nil {
		answer["connectors"] = connectors
	}
	return answer
}

// ownWindowsConnectorStates keeps the Windows status roster aligned with the
// managed configuration. The own-status pipe proves the caller's SID, but it
// does not carry per-connector hook proof, so the only protected row is
// Claude Code, configured and not listed unprotected for the caller by the
// enumerator's last completed scan (the record the administrator's status
// reads, copied where the service can read it). The other configured
// connectors, and every row while that scan is unknown, are unconfirmed.
func (a *APIServer) ownWindowsConnectorStates(cfg *config.Config, sid, name string) map[string]any {
	scan := a.ownUnprotectedAgents(cfg, ownStatusCaller{sid: sid, name: name})
	states := make(map[string]any)
	for _, connector := range enterprisepolicy.StandaloneConnectors(cfg) {
		state := ownNotConfirmed(ownCauseWindowsUnchecked)
		if decided, ok := scan.state(connector); ok {
			state = decided
		} else if connector == enterprisepolicy.ConnectorClaudeCode {
			state = ownProtected()
		}
		states[connector] = state
	}
	// A connector an administrator took off the roster is "not managed
	// (removed from roster)", never protected and never pending.
	for name, row := range ownRemovedConnectorStates(cfg, a.configDataDir(), sid) {
		if _, configured := states[name]; !configured {
			states[name] = row
		}
	}
	return states
}

// ownConnectorStates reports the caller's configured connector roster. The
// managed policy view is published before the Unix hook socket begins serving
// requests and updated when the vendor policy changes. The guardian record
// supplies each per-user connector's enrollment and strict machine-policy
// enrollment; a missing or stale record is never reported protected.
func (a *APIServer) ownConnectorStates(cfg *config.Config, uid, name string) map[string]any {
	view := a.managedPolicyView.Load()
	states := make(map[string]any)
	guardian, _ := ownStatusGuardianAuthorization(a.configDataDir())
	if guardian != nil {
		if ok, _ := managedGuardianAuthorizationCovers(*guardian, nil, true); !ok {
			guardian = nil
		}
	}
	strict := strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny)
	callerUID, err := strconv.Atoi(uid)
	if err != nil {
		return states
	}
	// Agents the enumerator cannot protect for this caller: the administrator's
	// status lists them, so the caller's own status never says protected for
	// them. An unreadable record, or an entry that may be the caller but
	// cannot be matched, confirms nothing.
	scan := a.ownUnprotectedAgents(cfg, ownStatusCaller{uid: &callerUID, name: name})
	peer := managedHookPeer{UID: callerUID, Name: name}
	strictExempt := strict && len(cfg.Enterprise.Enrollment.ExemptUsers) > 0 &&
		(&managedHookAuthorizer{enrollment: cfg.Enterprise.Enrollment}).hostRunExempt(peer)
	rootDenied := callerUID == 0 && strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.Root), config.EnterpriseRootDeny)
	enrolled := func(connector string) bool {
		if guardian == nil {
			return false
		}
		for _, target := range guardian.ProtectedTargets {
			if !target.OK || connector != "" && managedGuardianTargetConnector(target) != connector {
				continue
			}
			if target.UID != 0 && target.UID == callerUID || target.UID == 0 && name != "" && target.User == name {
				return true
			}
		}
		return false
	}
	for _, connector := range enterprisepolicy.StandaloneConnectors(cfg) {
		if decided, ok := scan.state(connector); ok {
			states[connector] = decided
			continue
		}
		if view != nil && (view.admitted == nil || view.admitted[connector]) {
			if proof, ok := view.connectors[connector]; ok {
				unproven := proof.shared || proof.allAccounts || proof.accounts[name]
				switch {
				case !rootDenied && !unproven && (!strict || callerUID == 0 || strictExempt || enrolled("")):
					states[connector] = ownProtected()
				case rootDenied:
					states[connector] = ownNotProtected(ownCauseRootDenied)
				case unproven:
					states[connector] = ownNotProtected(ownCauseUnprovenSource)
				case guardian != nil:
					states[connector] = ownNotProtected(ownCauseNotEnrolled)
				default:
					states[connector] = ownNotConfirmed(ownCauseNoGuardianRecord)
				}
				continue
			}
		}
		switch {
		case rootDenied:
			states[connector] = ownNotProtected(ownCauseRootDenied)
		case guardian == nil:
			states[connector] = ownNotConfirmed(ownCauseNoGuardianRecord)
		case enrolled(connector):
			states[connector] = ownProtected()
		default:
			states[connector] = ownNotProtected(ownCauseNoSetup)
		}
	}
	return states
}

// ownLastCoworkEvent is the caller's own last Cowork hook event in the audit
// store: the row's OS-derived user id is the caller's uid or SID (a SID
// compares without case), or, for a row without one, its account name is
// the caller's. Other accounts' rows are
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
		return strings.EqualFold(id, uid)
	}
	return name != "" && useridentity.EqualFold(strings.TrimSpace(event.UserName), name)
}
