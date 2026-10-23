// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The require-sandbox gate (plan §6.1, spec §2.11).
//
// On a standalone managed host, a connector the caller's sandbox floor F
// lists in required_for runs only in a sandbox. Its host hooks are refused
// at the first blockable event (SessionStart where the agent honours a
// block there, else the prompt and every pre-tool event) before anything
// is evaluated, with a paste-ready `defenseclaw sandbox run` command. Where
// a sandbox can't run for the caller (sandbox_availability.go), the run is
// refused with the "not available" text, or allowed and alerted under
// when_unavailable: alert. Exempt users (enterprise.enrollment.exempt_users)
// are never refused on the host.
//
// The gate decides from what the gateway verified, never from what the
// hook sent: a wrapper bypass (DEFENSECLAW_NO_SANDBOX=1) or a forged
// nested-run variable (DEFENSECLAW_SANDBOX_ID, DEFENSECLAW_SANDBOX_TOKEN)
// only turns a run into a host run, which the gate refuses, because host
// hooks never read those variables and a hook-socket request carries no
// bearer the gateway honours. The only hook it lets through is one whose
// context the managed gateway rebuilt from a live sandbox registration
// (relayedSandboxRequest). The surface a hook names (app, extension) only
// words the refusal.
//
// It is a policy control on the agents whose hooks the machine owns
// (Claude Code, Codex, Cursor, Copilot), not an exec deny: an agent whose
// hooks the user can switch off is outside it (SandboxAdvisories says so).
//
// The gate fails closed: a panic anywhere in it (reading the live
// configuration, the floor, the probe, rendering the refusal) refuses the
// host run of a connector some floor requires as policy_unloadable.

// Outcomes of the gate, recorded on the hook's audit row as
// require_sandbox=<outcome> by finalizeAgentHookAnswer.
const (
	// requireSandboxRefused: a sandbox can run; the host run is refused.
	requireSandboxRefused = "refused"
	// requireSandboxUnavailable: no sandbox can run; refused (Q1).
	requireSandboxUnavailable = "unavailable_refused"
	// requireSandboxAlert: no sandbox can run; allowed and alerted
	// (when_unavailable: alert).
	requireSandboxAlert = "unavailable_alert"
	// requireSandboxExempt: an exempt user's host run, allowed.
	requireSandboxExempt = "exempt"
	// requireSandboxUnloadable: the floor can't be computed for a
	// connector some floor requires, or the gate failed; refused, closed.
	requireSandboxUnloadable = "policy_unloadable"
)

// requireSandboxReasonRequired is the telemetry reason code of a refused
// host run: the caller's floor lists the connector in required_for.
const requireSandboxReasonRequired = "required_for"

// requireSandboxOutcome is the gate's decision for one hook. Outcome ""
// means the gate does not apply.
type requireSandboxOutcome struct {
	Outcome string
	// Message is the refusal text the agent shows (refusing outcomes).
	Message string
	// Why is the reason no sandbox can run (unavailable outcomes).
	Why string
	// Code is the registered reason code of Why, or required_for for a
	// refused host run, for the sandbox telemetry.
	Code string
	// Failed marks a gate that panicked (policy_unloadable).
	Failed bool
	// Profile is the caller's guardrail profile match the floor came from
	// (refused and unavailable outcomes), for the telemetry record.
	Profile profileDecision
}

// refuses reports whether the outcome refuses the host run.
func (o requireSandboxOutcome) refuses() bool {
	switch o.Outcome {
	case requireSandboxRefused, requireSandboxUnavailable, requireSandboxUnloadable:
		return true
	}
	return false
}

// auditExtra is the outcome's fields on the hook's audit row.
func (o requireSandboxOutcome) auditExtra() map[string]string {
	if o.Outcome == "" {
		return nil
	}
	extra := map[string]string{"require_sandbox": o.Outcome}
	if o.Why != "" {
		extra["require_sandbox_unavailable"] = o.Why
	}
	if o.Failed {
		extra["require_sandbox_error"] = "internal"
	}
	return extra
}

// requireSandboxFloor is F, the caller's sandbox floor for profile ("" =
// openshell.admin alone): config.SandboxFloor (tests replace it).
var requireSandboxFloor = func(cfg *config.Config, profile string) (config.OpenShellAdminConfig, string, error) {
	return cfg.SandboxFloor(profile)
}

// relayedSandboxRequest reports a request whose context the managed
// gateway rebuilt from a live sandbox registration (spec §2.4, the
// relay-verified marker): the one hook the gate never refuses.
// It is isRelayedSandboxRequest (sandbox_relay.go); tests replace it.
var relayedSandboxRequest = isRelayedSandboxRequest

// requireSandboxRecord is one gate decision for the managed sandbox
// telemetry (spec §2.10 and change log 3): log.sandbox.host_run_refused for
// a refused host run, log.sandbox.host_run_unavailable where no sandbox can
// run (Allowed under when_unavailable: alert). Its fields are those of
// audit.SandboxHostRunRefusedEvent and audit.SandboxHostRunUnavailableEvent:
// Connector is the sandbox identity's connector, Reason the registered
// code, Rule the required_for entry that matched, and the user the
// verified caller.
//
// Profile, ProfileDigest, ProfileMatch, MatchedGroup and Provisional are
// the caller's own guardrail profile match the floor came from.
type requireSandboxRecord struct {
	Unavailable, Allowed bool
	Connector            string
	Reason, Rule         string
	UserID, UserName     string
	Profile              string
	ProfileDigest        string
	ProfileMatch         string
	MatchedGroup         string
	Provisional          bool
}

// recordRequireSandbox emits one gate record (emitRequireSandboxRecord:
// log.sandbox.host_run_refused or log.sandbox.host_run_unavailable); tests
// replace it.
var recordRequireSandbox = emitRequireSandboxRecord

// requireSandboxEvent reports the events the gate judges: a session start,
// a prompt and every pre-tool event. Whether the agent honours a block on
// the event is the connector's (requireSandboxHostRun).
func requireSandboxEvent(event string) bool {
	return canonicalEvent(event) == "sessionstart" || isPromptLikeEvent(event) || isGenericToolInspectionEvent(event)
}

// requireSandboxSurface is the host surface a refusal names: an IDE
// extension for the Copilot VS Code Local dialect, else the surface the hook
// classified its caller as (hookexec.AgentSurfaceHeader), else the CLI.
// The hook can set it, so it only words the refusal.
func requireSandboxSurface(ctx context.Context, header http.Header) string {
	if copilotVSCodeLocalFromContext(ctx) {
		return connector.HostSurfaceExtension
	}
	if surface := connector.ValidHostSurface(header.Get(hookexec.AgentSurfaceHeader)); surface != "" {
		return surface
	}
	return connector.HostSurfaceCLI
}

// connectorListed reports whether list names connectorName.
func connectorListed(list []string, connectorName string) bool {
	for _, name := range list {
		if config.NormalizeConnectorName(name) == connectorName {
			return true
		}
	}
	return false
}

// requiredAnywhere reports whether openshell.admin or any profile's
// sandbox section requires connectorName.
func requiredAnywhere(cfg *config.Config, connectorName string) bool {
	if connectorListed(cfg.OpenShell.Admin.RequiredFor, connectorName) {
		return true
	}
	for _, p := range cfg.Guardrail.Profiles {
		if p.Sandbox != nil && connectorListed(p.Sandbox.RequiredFor, connectorName) {
			return true
		}
	}
	return false
}

// requireSandboxHostGate is the gate's rule for a host run: "" where the
// caller's floor does not require the connector (required: required_for
// lists it), requireSandboxExempt for an account exempt_users lists, else
// requireSandboxRefused, which requireSandboxDecision turns into an
// unavailable outcome where no sandbox can run. The hook decision and every
// policy view (enterprise policy show and verify, sandbox policy explain)
// take the host-run answer from it, so a view never says a host run is
// refused for an account whose host runs the hook allows (GAP-0555).
func requireSandboxHostGate(required, exempt bool) string {
	switch {
	case !required:
		return ""
	case exempt:
		return requireSandboxExempt
	}
	return requireSandboxRefused
}

// Host-run answers of RequireSandboxHostGate.
const (
	// RequireSandboxHostRunExempt: the floor requires it, but the account
	// is in enterprise.enrollment.exempt_users, so its host run is allowed.
	RequireSandboxHostRunExempt = requireSandboxExempt
	// RequireSandboxHostRunRefused: the host run is refused (or, where no
	// sandbox can run, handled by when_unavailable).
	RequireSandboxHostRunRefused = requireSandboxRefused
)

// RequireSandboxHostGate is requireSandboxHostGate for connectorName under a
// floor that requires requiredFor, for the administrator's policy views.
func RequireSandboxHostGate(requiredFor []string, connectorName string, exempt bool) string {
	return requireSandboxHostGate(connectorListed(requiredFor, config.NormalizeConnectorName(connectorName)), exempt)
}

// EnrollmentExemptFromSandbox reports whether enrollment exempts the Unix
// account uid/name from required_for as the hook socket does
// (managedHookAuthorizer.hostRunExempt): by its uid or account name, and in
// the gateway by its verified directory facts. A view that can't ask the
// gateway uses it.
func EnrollmentExemptFromSandbox(enrollment config.EnterpriseEnrollmentConfig, uid int, name string) bool {
	return (&managedHookAuthorizer{enrollment: enrollment}).hostRunExempt(managedHookPeer{UID: uid, Name: name})
}

// requireSandboxExemptUser reports an account enterprise.enrollment.exempt_users
// lists: the hook socket marks it (managedHookPeerAuth); a per-user
// credential (Windows) is matched here, as Windows enrollment matches it
// (requireSandboxAccountListed).
func requireSandboxExemptUser(ctx context.Context, cfg *config.Config) bool {
	if exempt, _ := ctx.Value(enterpriseExemptUserContextKey{}).(bool); exempt {
		return true
	}
	subject, ok := verifiedSubjectFromContext(ctx)
	if !ok || subject.Source != subjectSourceUserCredential {
		return false
	}
	return requireSandboxAccountListed(cfg.Enterprise.Enrollment.ExemptUsers, subject)
}

// requireSandboxAccountForID names the account of a SID and its domain
// (LookupAccountSid), as Windows enrollment looks them up; tests replace it.
var requireSandboxAccountForID = sandboxAccountForSID

// requireSandboxAccountListed reports whether list names the account of a
// per-user credential the way Windows enrollment does
// (enterprisehooks.windowsProfileEnrollmentDecision), so the gate and the
// enrollment never disagree on who is exempt: case-insensitively, by the
// SID, the profile folder's name, the account name or DOMAIN\account. The
// account and its domain are looked up from the SID only when an entry
// that is not a SID matched nothing else; where the lookup fails, the
// verified subject's account name and account domain stand in. An entry
// also names the account when it selects it as a guardrail users entry does
// (userEntryMatches): its SID, the sAMAccountName of a directory account,
// DOMAIN\name in its verified domain, its UPN or principal, whichever form
// its user signed in with (GAP-0533).
func requireSandboxAccountListed(list []string, subject VerifiedSubject) bool {
	names := []string{subject.UserID, subject.UserName}
	if home := userScopedIdentityHome(subject.UserID); home != "" {
		names = append(names, accountFolderName(home))
	}
	if requireSandboxListMatches(list, names) {
		return true
	}
	canonical := profileSubjectFromVerified(subject, false)
	if anyMatches(list, func(entry string) bool { return userEntryMatches(&canonical, entry) }) {
		return true
	}
	if !slices.ContainsFunc(list, func(entry string) bool {
		entry = strings.TrimSpace(entry)
		return entry != "" && !strings.HasPrefix(strings.ToUpper(entry), "S-1-")
	}) {
		return false
	}
	account, domain, ok := requireSandboxAccountForID(subject.UserID)
	if !ok {
		account, domain = subject.UserName, subject.Directory.AccountDomain
	}
	account, domain = strings.TrimSpace(account), strings.TrimSpace(domain)
	if account == "" {
		return false
	}
	names = append(names, account)
	if domain != "" {
		names = append(names, domain+`\`+account)
	}
	return requireSandboxListMatches(list, names)
}

// requireSandboxListMatches reports whether an entry of list names one of
// names, case-insensitively (windowsEnrollmentListMatches).
func requireSandboxListMatches(list, names []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		for _, name := range names {
			if name = strings.TrimSpace(name); name != "" && strings.EqualFold(entry, name) {
				return true
			}
		}
	}
	return false
}

// accountFolderName is the last element of a profile directory, with
// either separator (a Windows profile path read on any OS).
func accountFolderName(home string) string {
	home = strings.TrimRight(strings.TrimSpace(home), `\/`)
	if i := strings.LastIndexAny(home, `\/`); i >= 0 {
		return home[i+1:]
	}
	return home
}

// requestPeerUID is the kernel-verified uid of a hook-socket caller.
func requestPeerUID(ctx context.Context) (int, bool) {
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		return peer.UID, true
	}
	if subject, ok := verifiedSubjectFromContext(ctx); ok && subject.Source == subjectSourcePeerCredentials {
		if uid, err := strconv.Atoi(subject.UserID); err == nil {
			return uid, true
		}
	}
	return 0, false
}

// requireSandboxCaller is the verified account a gate record is about.
func requireSandboxCaller(ctx context.Context) (id, name string) {
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		return strconv.Itoa(peer.UID), peer.Name
	}
	if subject, ok := verifiedSubjectFromContext(ctx); ok {
		return subject.UserID, subject.UserName
	}
	return "", ""
}

// requireSandboxDecision is the gate's outcome for a hook of connectorName
// with event, working directory cwd and host surface, before the
// connector's ability to block the event is considered.
func (a *APIServer) requireSandboxDecision(ctx context.Context, connectorName, event, cwd, surface string) requireSandboxOutcome {
	cfg := a.liveBaseConfig(ctx)
	if cfg == nil || !cfg.StandaloneEnterprise() || !requireSandboxEvent(event) || relayedSandboxRequest(ctx) {
		return requireSandboxOutcome{}
	}
	connectorName = config.NormalizeConnectorName(connectorName)
	decision := a.resolveProfile(ctx)
	profile := decision.Name
	floor, _, err := requireSandboxFloor(cfg, profile)
	if err != nil {
		if requiredAnywhere(cfg, connectorName) {
			return requireSandboxOutcome{Outcome: requireSandboxUnloadable, Message: sandboxapi.PolicyUnloadable()}
		}
		return requireSandboxOutcome{}
	}
	// The exemption is looked up only for a required connector (on Windows
	// it can take an account lookup).
	required := connectorListed(floor.RequiredFor, connectorName)
	switch requireSandboxHostGate(required, required && requireSandboxExemptUser(ctx, cfg)) {
	case "":
		return requireSandboxOutcome{}
	case requireSandboxExempt:
		return requireSandboxOutcome{Outcome: requireSandboxExempt}
	}
	// A floor from the default profile only because the directory lookup
	// failed or was slow is provisional: the refusal says so and to retry,
	// as the person's own profile may not require a sandbox (GAP-0293).
	provisional := decision.Match == profileMatchDefaultLookupFailed
	word := func(message string) string {
		if provisional {
			return sandboxapi.ProvisionalRefusal(message)
		}
		return message
	}
	uid, known := requestPeerUID(ctx)
	if avail := defaultSandboxAvailability.check(cfg, uid, known, floor); !avail.Available {
		if strings.TrimSpace(floor.WhenUnavailable) == config.OpenShellWhenUnavailableAlert {
			return requireSandboxOutcome{Outcome: requireSandboxAlert, Why: avail.Why, Code: avail.Code, Profile: decision}
		}
		return requireSandboxOutcome{Outcome: requireSandboxUnavailable, Why: avail.Why, Code: avail.Code, Profile: decision,
			Message: word(sandboxapi.HostRunUnavailable(connectorName, avail.Why, avail.Code, floor.RequestAccess))}
	}
	return requireSandboxOutcome{Outcome: requireSandboxRefused, Code: requireSandboxReasonRequired, Profile: decision,
		Message: word(sandboxapi.HostRunRefusedOn(connectorName, surface, profile, cwd, floor.RequestAccess))}
}

// requireSandboxHostRun runs the gate for one host hook. When the outcome
// refuses and the connector honours a block on the event, it returns the
// refusal as the hook's response and true: the hook is then not evaluated.
// A refusing outcome on an event the agent can't block is dropped (the
// next blockable event refuses), so its audit row carries nothing. A
// panic anywhere in the gate is answered by requireSandboxGateFailed.
func (a *APIServer) requireSandboxHostRun(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	surface string,
) (outcome requireSandboxOutcome, resp agentHookResponse, gated bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			a.handleHookPanic(ctx, connectorName, req.HookEventName, fmt.Sprintf("require-sandbox gate panic: %v", recovered))
			outcome, resp, gated = a.requireSandboxGateFailed(ctx, profile, connectorName, req, rawBody, payload)
		}
	}()
	// The cd command names the folder the hook reported: the managed
	// gateway can't check a path under a home folder (req.CWD is then ""),
	// and the text is only pasted by the person in their own shell, quoted
	// by sandboxapi.HostRunRefused (GAP-0185, GAP-0187).
	cwd := req.ReportedCWD
	if cwd == "" {
		cwd = req.CWD
	}
	outcome = a.requireSandboxDecision(ctx, connectorName, req.HookEventName, cwd, surface)
	if !outcome.refuses() {
		a.requireSandboxEmit(ctx, connectorName, outcome)
		return outcome, agentHookResponse{}, false
	}
	action, wouldBlock := mapHookActionForProfile("block", "action", req.HookEventName, profile.Capabilities, profile, payload)
	if action != "block" {
		return requireSandboxOutcome{}, agentHookResponse{}, false
	}
	resp = agentHookResponse{
		Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action",
		WouldBlock: wouldBlock, Reason: outcome.Message,
	}
	resp = a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, outcome.Message)
	a.requireSandboxEmit(ctx, connectorName, outcome)
	return outcome, resp, true
}

// requireSandboxGateFailed answers a hook whose gate panicked. For a
// judged event of a connector some floor requires it refuses the host run
// (policy_unloadable): the outcome the gate could not compute might have
// refused it. Any other hook is evaluated as usual. The refusal is
// rendered for the agent where that works, else it stays a bare block.
func (a *APIServer) requireSandboxGateFailed(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) (outcome requireSandboxOutcome, resp agentHookResponse, gated bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			// outcome, resp and gated keep what was set before the panic:
			// once the refusal is decided, a block with the callback-free
			// native denial.
			if gated {
				resp.Reason = outcome.Message
				resp.HookOutput = blockFallbackOutput(profile, connectorName, req, outcome.Message)
			}
			a.handleHookPanic(ctx, connectorName, req.HookEventName, fmt.Sprintf("require-sandbox refusal render panic: %v", recovered))
		}
	}()
	cfg := a.requireSandboxFallbackConfig(ctx)
	if cfg == nil || !cfg.StandaloneEnterprise() || !requireSandboxEvent(req.HookEventName) || relayedSandboxRequest(ctx) ||
		!requiredAnywhere(cfg, config.NormalizeConnectorName(connectorName)) {
		return requireSandboxOutcome{}, agentHookResponse{}, false
	}
	outcome = requireSandboxOutcome{Outcome: requireSandboxUnloadable, Message: sandboxapi.PolicyUnloadable(), Failed: true}
	resp = agentHookResponse{
		Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action",
		WouldBlock: true, Reason: outcome.Message,
	}
	gated = true
	resp = a.renderSandboxVerdict(ctx, profile, req, rawBody, payload, resp, outcome.Message)
	return outcome, resp, gated
}

// requireSandboxFallbackConfig is the configuration a failed gate judges
// by: the live one, else (when reading it panics too) the start-time one.
func (a *APIServer) requireSandboxFallbackConfig(ctx context.Context) (cfg *config.Config) {
	if a == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			cfg = a.scannerCfg
		}
	}()
	return a.liveBaseConfig(ctx)
}

// requireSandboxEmit records a refused or unavailable outcome in the
// managed sandbox telemetry (requireSandboxRecord); other outcomes have no
// record of their own.
func (a *APIServer) requireSandboxEmit(ctx context.Context, connectorName string, o requireSandboxOutcome) {
	rec := requireSandboxRecord{Connector: config.NormalizeConnectorName(connectorName), Reason: o.Code}
	rec.Rule = rec.Connector
	switch o.Outcome {
	case requireSandboxRefused:
	case requireSandboxUnavailable:
		rec.Unavailable = true
	case requireSandboxAlert:
		rec.Unavailable, rec.Allowed = true, true
	default:
		return
	}
	rec.UserID, rec.UserName = requireSandboxCaller(ctx)
	p := o.Profile
	rec.Profile, rec.ProfileDigest, rec.ProfileMatch, rec.MatchedGroup = p.Name, p.Digest, p.Match, p.MatchedGroup
	rec.Provisional = p.Match == profileMatchDefaultLookupFailed
	recordRequireSandbox(ctx, a, rec)
}
