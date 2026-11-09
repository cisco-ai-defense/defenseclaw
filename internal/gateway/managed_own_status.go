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

// ownStatusWindowsAccount names a verified Windows account SID for the
// own-status answer from one LookupAccountSid result: the bare account name
// and the domain it was found in (set on Windows). Both are "" when the LSA
// does not name the SID. The pipe passes the bare account name, so the
// DOMAIN\account spelling the enumerator matches exclude_users by is built from
// the domain of the same result; two lookups could disagree.
var ownStatusWindowsAccount = func(string) (name, domain string) { return "", "" }

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
	a.writeJSON(w, http.StatusOK, a.ownStatusAnswer(r.Context(), "uid", strconv.Itoa(peer.UID), peer.Name, ""))
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
	name, domain := ownStatusWindowsAccount(sid)
	body, err := json.Marshal(a.ownStatusAnswer(ctx, "sid", sid, name, domain))
	if err != nil || len(body) > refusalpipe.MaxOwnStatusBytes {
		return nil
	}
	return body
}

// ownStatusAnswer is the own-status answer for the verified caller whose OS
// identifier (a uid, or a SID on Windows) is self, under idKey, and whose
// account name is name and whose Windows domain is domain ("" on Unix, and
// where the LSA did not name it).
func (a *APIServer) ownStatusAnswer(ctx context.Context, idKey, self, name, domain string) map[string]any {
	cfg := a.runtimeConfigSnapshot()
	if g := a.generation(); g != nil && g.Config != nil {
		cfg = g.Config
	}
	account := map[string]any{idKey: self}
	if name != "" {
		account["name"] = name
	}
	// The profile folder is read once, so the exclusion and the can-it-be-judged
	// check below see the same lookup result.
	folder := ""
	if idKey == "sid" {
		folder = userScopedIdentityHome(self)
	}
	excluded := cfg != nil && ownAccountExcluded(cfg.Enterprise.Enrollment, idKey, self, name, domain, folder)
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
	if excluded {
		connectors = a.ownExcludedConnectorStates(cfg, idKey, self, name)
	} else if cfg != nil && ownExclusionUnjudgeable(cfg.Enterprise.Enrollment, idKey, self, name, domain, folder) {
		connectors = ownUnresolvedConnectorStates(cfg)
	} else if idKey == "uid" && cfg != nil {
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
	case excluded:
		// Cowork runs the Claude Code hooks, so it follows that connector.
		cause := ownExcludedCause(a.ownExcludedInspection(cfg, idKey, self, name, enterprisepolicy.ConnectorClaudeCode))
		cowork = ownCoworkRow(false, "excluded", cause.code, cause.reason)
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

// ownAccountExcluded reports whether enterprise.enrollment.exclude_users names
// the caller, as the enumerator matches it: on Linux and macOS the exact
// account name or decimal uid; on Windows (windowsProfileEnrollmentDecision)
// the SID, the profile folder name, the account name, or DOMAIN\account, in
// any case. folder is the caller's profile directory (Windows), "" when the
// lookup failed. A qualified entry selects one domain: it never matches the
// same short name in another. Root is never excluded by name: enrollment.root
// decides its calls.
func ownAccountExcluded(enrollment config.EnterpriseEnrollmentConfig, idKey, self, name, domain, folder string) bool {
	if idKey == "uid" && self == "0" {
		return false
	}
	var names []string
	if idKey == "sid" {
		names = []string{self, name}
		account := name
		if _, short, qualified := strings.Cut(name, `\`); qualified {
			names = append(names, short)
			account = short
		}
		if domain = strings.TrimSpace(domain); domain != "" && account != "" {
			names = append(names, domain+`\`+account)
		}
		if folder != "" {
			names = append(names, accountFolderName(folder))
		}
	}
	for _, entry := range enrollment.ExcludeUsers {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "":
		case idKey == "uid" && (entry == self || name != "" && entry == name):
			return true
		case idKey == "sid" && requireSandboxListMatches([]string{entry}, names):
			return true
		}
	}
	return false
}

// ownExclusionUnjudgeable reports whether an exclude_users entry may name the
// caller in a spelling the lookups did not give the means to judge. On Windows
// any entry needs the account name, a DOMAIN\account entry needs the domain
// too, and any other entry may be the profile folder name, so it needs the
// folder. That includes an entry spelled as a SID that is not the caller own
// SID: the enumerator also compares the folder name, and a folder can be named
// like a different account or Entra SID. On Unix an entry needs the account
// name (the uid is proven by the kernel). The enumerator matches those spellings and may already
// have removed the hook, so the status claims no protection. An entry the
// caller already matched was decided as excluded before this is asked.
func ownExclusionUnjudgeable(enrollment config.EnterpriseEnrollmentConfig, idKey, self, name, domain, folder string) bool {
	if idKey == "uid" && self == "0" {
		return false
	}
	nameKnown := strings.TrimSpace(name) != ""
	domainKnown := strings.TrimSpace(domain) != "" || strings.Contains(name, `\`)
	folderKnown := strings.TrimSpace(folder) != ""
	for _, entry := range enrollment.ExcludeUsers {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "":
		case !nameKnown:
			return true
		case idKey == "sid" && strings.Contains(entry, `\`) && !domainKnown,
			idKey == "sid" && !strings.Contains(entry, `\`) && !folderKnown:
			return true
		}
	}
	return false
}

// ownUnresolvedConnectorStates is the roster of a Windows caller whose
// exclude_users entries cannot be judged: every configured connector is not
// confirmed, for there is no coverage proof.
func ownUnresolvedConnectorStates(cfg *config.Config) map[string]any {
	states := make(map[string]any)
	for _, connector := range enterprisepolicy.StandaloneConnectors(cfg) {
		states[connector] = ownNotConfirmed(ownCauseAccountUnresolved)
	}
	return states
}

// ownExcludedConnectorStates is the roster of an excluded account: every
// connector the machine policy would otherwise cover is excluded, for the
// account never inherits the machine-wide state. Each row reason says what
// the gateway still does with the account calls for that connector.
func (a *APIServer) ownExcludedConnectorStates(cfg *config.Config, idKey, uid, name string) map[string]any {
	states := make(map[string]any)
	for _, connector := range enterprisepolicy.StandaloneConnectors(cfg) {
		states[connector] = ownExcluded(a.ownExcludedInspection(cfg, idKey, uid, name, connector))
	}
	return states
}

// ownExcludedInspection says what the hook authorizer does with the calls of
// an excluded account for connector, from the inputs it decides with: the
// connectors it admitted for machine policy (the published policy view),
// enrollment.unenrolled_users and enrollment.exempt_users. A machine policy
// runs the hook for every local account, so with unenrolled_users not deny the
// excluded account is still inspected (managedHookAuthorizer.decideFor); with
// deny it is refused unless exempt. Without a machine policy for the
// connector nothing is installed for the account. The Windows pipe has no
// policy view, so it claims nothing.
func (a *APIServer) ownExcludedInspection(cfg *config.Config, idKey, uid, name, connector string) ownInspection {
	if idKey != "uid" || cfg == nil {
		return ownInspectionUnknown
	}
	view := a.managedPolicyView.Load()
	if view == nil {
		return ownInspectionNone
	}
	if _, ok := view.connectors[connector]; !ok || view.admitted != nil && !view.admitted[connector] {
		return ownInspectionNone
	}
	callerUID, err := strconv.Atoi(uid)
	if err != nil {
		return ownInspectionUnknown
	}
	enrollment := cfg.Enterprise.Enrollment
	if !strings.EqualFold(strings.TrimSpace(enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) {
		return ownInspectionPolicy
	}
	if len(enrollment.ExemptUsers) > 0 && (&managedHookAuthorizer{enrollment: enrollment}).hostRunExempt(managedHookPeer{UID: callerUID, Name: name}) {
		return ownInspectionPolicy
	}
	return ownInspectionRefused
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
