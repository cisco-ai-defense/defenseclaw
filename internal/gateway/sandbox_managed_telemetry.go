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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The managed sandbox records (spec 2.10): the managed gateway emits the
// policy records (resolved, re-matched), the require-sandbox gate's records
// (host run refused or unavailable) and, stamped with the identity it
// verified from the peer credential, the records the user's daemon reports
// through POST sandbox/events (foreign sandboxes, rules and containers,
// settings drift, refused access). Nothing a sandbox or daemon sends names
// the person: the subject is always the hook-socket peer.

// managedSandboxRecorders holds each API server's recorder of the managed
// sandbox records, created on first use (like APIServer.sandboxAuthority).
var managedSandboxRecorders sync.Map // *APIServer -> *audit.SandboxRecorder

// managedSandboxRecorder is a's recorder of the managed sandbox records.
func (a *APIServer) managedSandboxRecorder() *audit.SandboxRecorder {
	if a == nil {
		return nil
	}
	if r, ok := managedSandboxRecorders.Load(a); ok {
		return r.(*audit.SandboxRecorder)
	}
	fresh := audit.NewSandboxRecorder(a.logger)
	// One account tracks at most as many managed sandboxes as it may hold
	// registrations: a lifecycle record past that is dropped and logged.
	fresh.LimitManagedPhases(sandboxreg.MaxEntriesPerUID)
	r, _ := managedSandboxRecorders.LoadOrStore(a, fresh)
	return r.(*audit.SandboxRecorder)
}

// refreshManagedSandboxActive exports the managed recorder's active-sandbox
// gauge again when its last export is SandboxActiveExportInterval old
// (audit.SandboxRecorder.RecordActiveSandboxesIfDue); nothing before the
// recorder tracked anything.
func (a *APIServer) refreshManagedSandboxActive(ctx context.Context) {
	r, ok := managedSandboxRecorders.Load(a)
	if !ok {
		return
	}
	if err := r.(*audit.SandboxRecorder).RecordActiveSandboxesIfDue(context.WithoutCancel(ctx), audit.SandboxActiveExportInterval); err != nil {
		sandboxRecordFailed("sandbox active", err)
	}
}

// trackManagedSandboxActive has the managed recorder count reg's sandbox
// from the registration, running while its daemon reports it running,
// unless a lifecycle record tracks it (audit.SandboxRecorder.
// TrackManagedSandbox). After the gateway starts again its recorder tracks
// nothing, and a sandbox that runs on quietly sends no lifecycle record to
// count it by: its daemon's polls, once a minute, count it again (#1241).
func (a *APIServer) trackManagedSandboxActive(ctx context.Context, auth *sandboxAuthority, uid int, reg sandboxreg.Registration) {
	if reg.State != sandboxreg.StateLive && reg.State != sandboxreg.StateStopped || reg.SandboxName == "" {
		return
	}
	phase := audit.SandboxPhaseStopped
	if sandboxreg.EffectiveState(reg, auth.clock()) == sandboxreg.StateLive {
		phase = audit.SandboxPhaseReady
	}
	changed, err := a.managedSandboxRecorder().TrackManagedSandbox(context.WithoutCancel(ctx), reg.ID, reg.Connector,
		sandboxRecordSubject(reg).UserID, phase)
	sandboxRecordFailed("sandbox active", err)
	if changed {
		// Revoked or removed meanwhile: the store's OnGone may have run
		// before it was tracked.
		a.sandboxForgetIfGone(auth, uid, reg)
	}
}

// sandboxRegistrationGone stops tracking the phase of reg's sandbox. The
// registration store calls it (sandboxreg.FileStore.OnGone) whenever a
// registration is revoked, removed or evicted, by any path, so a sandbox
// whose deleted phase never arrives neither stays in the managed
// recorder's phase map nor counts in sandbox.active; the daemon's deleted
// record is not relied on.
func (a *APIServer) sandboxRegistrationGone(reg sandboxreg.Registration) {
	a.sandboxGuestSignalForget(reg)
	if r, ok := managedSandboxRecorders.Load(a); ok {
		r.(*audit.SandboxRecorder).ForgetManagedSandbox(context.Background(), reg.ID)
	}
}

// sandboxForgetIfGone stops tracking the phase of reg's sandbox when reg was
// revoked or removed while a batch of its lifecycle records was being
// recorded: the store's OnGone may have run before one of them tracked the
// phase again.
func (a *APIServer) sandboxForgetIfGone(auth *sandboxAuthority, uid int, reg sandboxreg.Registration) {
	cur, ok, err := auth.store.Get(uid, reg.ID)
	if err == nil && (!ok || cur.State == sandboxreg.StateRevoked) {
		a.sandboxRegistrationGone(reg)
	}
}

// sandboxRecordFailed logs a managed record the recorder refused; the
// operation it describes goes on.
func sandboxRecordFailed(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] %s record: %v\n", what, err)
	}
}

// sandboxManagedStamp is the managed stamp of reg: registration, guardrail
// profile, effective policy and the person's keyed pseudonym. A
// descriptive value the registry does not take is left out.
func sandboxManagedStamp(reg sandboxreg.Registration) audit.SandboxManaged {
	provisional := reg.Provisional
	stamp := audit.SandboxManaged{
		RegistrationID: reg.ID, GuardrailProfile: reg.Profile, ProfileDigest: reg.ProfileDigest,
		ProfileMatch: reg.ProfileMatch, MatchedGroup: reg.MatchedGroup, PolicyDigest: reg.EffectiveDigest,
		Provisional: &provisional, SubjectKey: reg.SubjectKey, OpenShellVersion: reg.OpenShell, InstallMode: reg.InstallMode,
	}
	if reg.Generation <= math.MaxInt64 {
		stamp.PolicyGeneration = int64(reg.Generation)
	}
	switch stamp.ProfileMatch {
	case audit.SandboxProfileMatchAgent, audit.SandboxProfileMatchUser, audit.SandboxProfileMatchGroup,
		audit.SandboxProfileMatchConnector, audit.SandboxProfileMatchDefault,
		audit.SandboxProfileMatchDefaultUnverified, audit.SandboxProfileMatchDefaultLookupFailed:
	default:
		stamp.ProfileMatch = ""
	}
	if stamp.InstallMode != audit.SandboxInstallPrerequisite && stamp.InstallMode != audit.SandboxInstallSetup {
		stamp.InstallMode = ""
	}
	if !sandboxOpenShellVersion.MatchString(stamp.OpenShellVersion) {
		// enterprise.openshell.version in prerequisite mode is a range
		// (">=0.1.1 <0.2.0"), not the version the user runs: the managed
		// families refuse a stamp the registry does not take, which cost
		// every resolved and re-matched record (GAP-0470).
		stamp.OpenShellVersion = ""
	}
	return stamp
}

// sandboxOpenShellVersion is the registry's shape of
// defenseclaw.openshell.version: one concrete version.
var sandboxOpenShellVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$`)

// sandboxRecordIdentity is the sandbox identity of reg's records.
func sandboxRecordIdentity(reg sandboxreg.Registration) audit.SandboxIdentity {
	identity := audit.SandboxIdentity{
		ID: reg.SandboxID, Name: reg.SandboxName, Connector: reg.Connector, Runtime: audit.SandboxRuntimeOpenShell,
		WorkdirMode: audit.SandboxWorkdirCopy, BindingID: reg.BindingID, Managed: sandboxManagedStamp(reg),
	}
	if reg.Driver == audit.SandboxDriverDocker || reg.Driver == audit.SandboxDriverVM {
		identity.Driver = reg.Driver
		if slices.Contains(audit.SandboxDriverReasons, reg.DriverReason) {
			identity.DriverReason = reg.DriverReason
		}
	}
	return identity
}

// sandboxRecordSubject is the person of reg's records: the account the
// registration was made by (its uid and the account name at peer auth).
func sandboxRecordSubject(reg sandboxreg.Registration) audit.SandboxManagedSubject {
	return audit.SandboxManagedSubject{UserID: strconv.Itoa(reg.UID), UserName: reg.UserName}
}

// emitSandboxPolicyResolved records a registration (log.sandbox.policy.resolved).
func emitSandboxPolicyResolved(a *APIServer, reg sandboxreg.Registration) {
	reason := ""
	if reg.Provisional {
		reason = "offline_floor"
	}
	sandboxRecordFailed("policy resolved", a.managedSandboxRecorder().RecordSandboxPolicyResolved(context.Background(),
		audit.SandboxPolicyResolvedEvent{Sandbox: sandboxRecordIdentity(reg), Subject: sandboxRecordSubject(reg), Reason: reason,
			Timestamp: time.Now().UTC()}))
}

// emitSandboxPolicyResolveRefused records a resolution the gateway refused
// (log.sandbox.policy.resolved, failed, with the refusal's reason code): an
// enforced outcome, so the record is mandatory. Should the recorder refuse
// the profile stamp, it is recorded with the subject key alone.
func emitSandboxPolicyResolveRefused(a *APIServer, attempt sandboxreg.Registration, reason string) {
	r := a.managedSandboxRecorder()
	if r == nil {
		return
	}
	ev := audit.SandboxPolicyResolvedEvent{Sandbox: sandboxRecordIdentity(attempt), Subject: sandboxRecordSubject(attempt),
		Failed: true, Reason: reason, Timestamp: time.Now().UTC()}
	if err := r.RecordSandboxPolicyResolved(context.Background(), ev); err != nil {
		sandboxRecordFailed("policy resolve refused (stamped)", err)
		ev.Sandbox.Managed = audit.SandboxManaged{SubjectKey: attempt.SubjectKey}
		sandboxRecordFailed("policy resolve refused", r.RecordSandboxPolicyResolved(context.Background(), ev))
	}
}

// emitSandboxPolicyRematched records a re-match (log.sandbox.policy.rematched)
// and why: a configuration generation change, a provisional match whose
// lookup resolved, or changed directory facts.
func emitSandboxPolicyRematched(a *APIServer, before, after sandboxreg.Registration) {
	reason := audit.SandboxRematchFacts
	switch {
	case before.Generation != after.Generation:
		reason = audit.SandboxRematchGeneration
	case before.Provisional && !after.Provisional:
		reason = audit.SandboxRematchLookupResolved
	}
	sandboxRecordFailed("policy rematched", a.managedSandboxRecorder().RecordSandboxPolicyRematched(context.Background(),
		audit.SandboxPolicyRematchedEvent{Sandbox: sandboxRecordIdentity(after), Subject: sandboxRecordSubject(after), Reason: reason,
			PreviousProfile: before.Profile, PreviousDigest: before.EffectiveDigest, Timestamp: time.Now().UTC()}))
}

// emitRequireSandboxRecord records one require-sandbox gate decision
// (log.sandbox.host_run_refused, log.sandbox.host_run_unavailable), stamped
// with the caller's own profile match and subject key
// (requireSandboxIdentity). The record is an enforced outcome: should the
// recorder refuse the stamp, it is recorded without it.
func emitRequireSandboxRecord(ctx context.Context, a *APIServer, rec requireSandboxRecord) {
	r := a.managedSandboxRecorder()
	if r == nil {
		return
	}
	subject := audit.SandboxManagedSubject{UserID: rec.UserID, UserName: rec.UserName}
	now := time.Now().UTC()
	record := func(identity audit.SandboxIdentity) error {
		if rec.Unavailable {
			return r.RecordSandboxHostRunUnavailable(ctx, audit.SandboxHostRunUnavailableEvent{
				Sandbox: identity, Subject: subject, Reason: rec.Reason, Allowed: rec.Allowed, Rule: rec.Rule, Timestamp: now})
		}
		return r.RecordSandboxHostRunRefused(ctx, audit.SandboxHostRunRefusedEvent{
			Sandbox: identity, Subject: subject, Reason: rec.Reason, Rule: rec.Rule, Timestamp: now})
	}
	what := "host run refused"
	if rec.Unavailable {
		what = "host run unavailable"
	}
	if err := record(a.requireSandboxIdentity(rec)); err != nil {
		sandboxRecordFailed(what+" (stamped)", err)
		sandboxRecordFailed(what, record(audit.SandboxIdentity{Connector: rec.Connector}))
	}
}

// requireSandboxIdentity is the sandbox identity of a gate record: the
// connector, the caller's own guardrail profile match (name, digest, match,
// matched group, provisional) and subject key, as a registration's records
// carry them, so a fleet groups host-run refusals by profile and person on
// every platform (GAP-0184, GAP-0229, GAP-0243, GAP-0410).
func (a *APIServer) requireSandboxIdentity(rec requireSandboxRecord) audit.SandboxIdentity {
	return audit.SandboxIdentity{Connector: rec.Connector, Managed: sandboxManagedStamp(sandboxreg.Registration{
		Profile: rec.Profile, ProfileDigest: rec.ProfileDigest, ProfileMatch: rec.ProfileMatch,
		MatchedGroup: rec.MatchedGroup, Provisional: rec.Provisional, SubjectKey: a.requireSandboxSubjectKey(rec),
	})}
}

// requireSandboxSubjectKey is the subject key of the gate record's caller,
// keyed like a registration's (sandboxSubjectKey): the uid and account name
// on Linux and macOS, the SID and account name on Windows, where there is
// no uid (-1). "" when the caller or the key is unknown.
func (a *APIServer) requireSandboxSubjectKey(rec requireSandboxRecord) string {
	id := strings.TrimSpace(rec.UserID)
	if id == "" {
		return ""
	}
	auth, err := a.sandboxAuth()
	if err != nil {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(id), "S-1-") {
		return sandboxSubjectKey(auth.key, -1, rec.UserName, id)
	}
	uid, err := strconv.Atoi(id)
	if err != nil {
		return ""
	}
	return sandboxSubjectKey(auth.key, uid, rec.UserName, "")
}

// sandboxForeignIdentity is the identity of a record about a foreign
// sandbox or container: the item itself, never the sandbox of the
// registration the batch was posted under; the connector of the harness the
// daemon found in it (none when the claim names no harness DefenseClaw runs:
// the batch registration's connector is another sandbox's, GAP-0434); and the
// caller's own guardrail profile match for that connector (name, digest,
// match, matched group, provisional) with the subject key, as the
// require-sandbox gate records carry them, so a fleet groups foreign items
// by profile whether or not the person has a registration (GAP-0444).
func (a *APIServer) sandboxForeignIdentity(ctx context.Context, reg sandboxreg.Registration, id, name, harnessName, runtime string) audit.SandboxIdentity {
	connectorName := ""
	if _, ok := harness.Get(harnessName); ok {
		connectorName = sandboxConnectorClaim(harnessName)
	}
	match := a.sandboxMatchPeer(ctx, managedHookPeer{UID: reg.UID, Name: reg.UserName}, connectorName, 0)
	d := match.decision
	if !profileTelemetryGroupFits(d.MatchedGroup) {
		d.MatchedGroup = ""
	}
	if len(d.Unproven) > 0 {
		// A candidate profile, possibly another account's, is not the
		// caller's proven policy, refused or observed
		// (guardrailProfileTelemetryFromDecision).
		d.Name, d.Digest, d.MatchedGroup = "", "", ""
	}
	return audit.SandboxIdentity{ID: id, Name: name, Connector: connectorName, Runtime: runtime,
		Managed: sandboxManagedStamp(sandboxreg.Registration{
			Profile: d.Name, ProfileDigest: d.Digest, ProfileMatch: d.Match, MatchedGroup: d.MatchedGroup,
			Provisional: match.provisional, SubjectKey: reg.SubjectKey,
		})}
}

// sandboxRelayProfileExtra adds to a relayed sandbox hook call's audit row
// the guardrail profile the call was decided under (name, digest, match and
// matched group, as its decision record carries them), so the row names the
// person's profile like the managed sandbox and require-sandbox records do
// (GAP-0482). Only a relay-verified call has a verified subject; a local
// sandbox ingress call adds nothing.
func sandboxRelayProfileExtra(ctx context.Context, extra map[string]string) {
	if !isRelayVerifiedSandboxRequest(ctx) {
		return
	}
	p := guardrailProfileTelemetryFor(ctx)
	for key, value := range map[string]func() (string, bool){
		"guardrail_profile": p.Name.Get, "guardrail_profile_digest": p.Digest.Get,
		"guardrail_profile_match": p.Match.Get, "guardrail_profile_matched_group": p.MatchedGroup.Get,
	} {
		if v, ok := value(); ok && v != "" {
			extra[key] = v
		}
	}
}

// sandboxEventPayload is the union of the daemon's event payloads
// (manager.managedEvent). Every field is a claim: it only describes the
// record, whose person and registration the gateway stamps.
type sandboxEventPayload struct {
	Sandbox     string   `json:"sandbox"`
	SandboxID   string   `json:"sandbox_id"`
	Action      string   `json:"action"`
	Rules       []string `json:"rules"`
	ContainerID string   `json:"container_id"`
	Name        string   `json:"name"`
	Field       string   `json:"field"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Rule        string   `json:"rule"`
	Reason      string   `json:"reason"`
	// Harness is the agent harness the daemon found running in a foreign
	// container, or the harness label of a foreign sandbox.
	Harness string `json:"harness"`
	// Image is the image reference of a foreign container (GAP-0677).
	Image string `json:"image"`
}

// sandboxAccountBusyCode is the registered reason (defenseclaw.sandbox.managed.reason)
// of a run refused because another account is using the sandboxes of the
// computer.
const sandboxAccountBusyCode = "account_busy"

// sandboxEventRulesMax bounds the foreign rules one event records.
const sandboxEventRulesMax = 16

// sandboxManagedAction maps the daemon's action words to the registered ones.
func sandboxManagedAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "stop", "stopped":
		return audit.SandboxManagedStop
	case "remove", "removed":
		return audit.SandboxManagedRemove
	default:
		return audit.SandboxManagedAlert
	}
}

// emitSandboxDaemonEvent records one daemon event of reg, with the person
// and registration the gateway verified.
func emitSandboxDaemonEvent(ctx context.Context, a *APIServer, reg sandboxreg.Registration, ev sandboxrelay.Event) {
	if sandboxrelay.EventTelemetry(ev.Kind) {
		emitSandboxTelemetryClaim(ctx, a, reg, ev)
		return
	}
	var p sandboxEventPayload
	if len(ev.Payload) > 0 && json.Unmarshal(ev.Payload, &p) != nil {
		sandboxRecordFailed(ev.Kind, fmt.Errorf("payload is not the event's JSON"))
		return
	}
	r := a.managedSandboxRecorder()
	subject := sandboxRecordSubject(reg)
	identity := sandboxRecordIdentity(reg)
	at := ev.Time
	// A foreign item's record is the person's alert: should the recorder
	// refuse the profile stamp, it is recorded with the subject key alone.
	recordForeign := func(kind string, foreign audit.SandboxIdentity, record func(audit.SandboxIdentity) error) {
		if err := record(foreign); err != nil {
			sandboxRecordFailed(kind+" (stamped)", err)
			foreign.Managed = audit.SandboxManaged{SubjectKey: reg.SubjectKey}
			sandboxRecordFailed(kind, record(foreign))
		}
	}
	switch ev.Kind {
	case sandboxrelay.EventForeignSandbox:
		// The foreign sandbox is not the registration's; only the person is.
		recordForeign(ev.Kind, a.sandboxForeignIdentity(ctx, reg, p.SandboxID, p.Sandbox, p.Harness, audit.SandboxRuntimeOpenShell),
			func(foreign audit.SandboxIdentity) error {
				return r.RecordSandboxForeignSandbox(ctx, audit.SandboxForeignSandboxEvent{
					Sandbox: foreign, Subject: subject, Action: sandboxManagedAction(p.Action), Timestamp: at})
			})
	case sandboxrelay.EventForeignRule:
		if p.Sandbox != "" && p.Sandbox != identity.Name {
			identity = audit.SandboxIdentity{Name: p.Sandbox, Connector: reg.Connector, Runtime: audit.SandboxRuntimeOpenShell,
				Managed: audit.SandboxManaged{SubjectKey: reg.SubjectKey}}
		}
		rules := p.Rules
		if len(rules) == 0 {
			rules = []string{p.Rule}
		}
		if len(rules) > sandboxEventRulesMax {
			rules = rules[:sandboxEventRulesMax]
		}
		for _, rule := range rules {
			sandboxRecordFailed(ev.Kind, r.RecordSandboxPolicyForeignRule(ctx, audit.SandboxPolicyForeignRuleEvent{
				Sandbox: identity, Subject: subject, Action: sandboxManagedAction(p.Action), Rule: rule, Timestamp: at}))
		}
	case sandboxrelay.EventForeignContainer:
		recordForeign(ev.Kind, a.sandboxForeignIdentity(ctx, reg, p.ContainerID, p.Name, p.Harness, ""),
			func(container audit.SandboxIdentity) error {
				return r.RecordSandboxForeignContainer(ctx, audit.SandboxForeignContainerEvent{
					Sandbox: container, Subject: subject, Image: p.Image, Timestamp: at})
			})
	case sandboxrelay.EventAccountBusy:
		// A run the caller's daemon refused because another account holds the
		// sandbox ports: an enforced refusal of the caller's own, recorded as
		// an unavailable sandbox with the reason account_busy, stamped with
		// the caller's own profile match and subject key and naming nobody
		// else (GAP-0598). Should the recorder refuse the profile stamp, it
		// is recorded with the subject key alone.
		recordForeign(ev.Kind, a.sandboxForeignIdentity(ctx, reg, "", "", p.Harness, ""),
			func(busy audit.SandboxIdentity) error {
				return r.RecordSandboxHostRunUnavailable(ctx, audit.SandboxHostRunUnavailableEvent{
					Sandbox: busy, Subject: subject, Reason: sandboxAccountBusyCode, Timestamp: at})
			})
	case sandboxrelay.EventSettingsDrift:
		sandboxRecordFailed(ev.Kind, r.RecordSandboxSettingsDrift(ctx, audit.SandboxSettingsDriftEvent{
			Sandbox: identity, Subject: subject, Field: p.Field, Timestamp: at}))
	case sandboxrelay.EventAccessRefused:
		sandboxRecordFailed(ev.Kind, r.RecordSandboxAccessRefused(ctx, audit.SandboxAccessRefusedEvent{
			Sandbox: identity, Subject: subject, Host: p.Host, Port: p.Port, Rule: p.Rule, Reason: p.Reason, Timestamp: at}))
	}
}

// emitSandboxTelemetryClaim records one of the daemon's sandbox telemetry
// records (daemonRelayTelemetry): a phase change (log.sandbox.lifecycle) or
// an egress decision or connection end (log.egress.*) of reg's sandbox. The
// sandbox name and id, its registration, guardrail profile and policy stamp
// and the person come from reg, which the gateway verified is the peer's own
// (handleSandboxEvents), as on every other managed sandbox record; the
// payload only adds what the daemon observed, and never the image digest,
// network profile or policy revision, which no registration vouches for. A
// registration not bound to a sandbox yet takes no record (the daemon posts
// only after the bind), and a record naming another sandbox than reg's is
// dropped, so a telemetry record cannot name a sandbox other than the one
// held by the registration (sandboxPhaseKey).
func emitSandboxTelemetryClaim(ctx context.Context, a *APIServer, reg sandboxreg.Registration, ev sandboxrelay.Event) {
	var c sandboxTelemetryClaim
	if len(ev.Payload) == 0 || json.Unmarshal(ev.Payload, &c) != nil {
		sandboxRecordFailed(ev.Kind, fmt.Errorf("payload is not the event's JSON"))
		return
	}
	switch {
	case reg.SandboxName == "":
		sandboxRecordFailed(ev.Kind, fmt.Errorf("registration %s is not bound to a sandbox", reg.ID))
		return
	case c.Sandbox != reg.SandboxName, c.SandboxID != "" && reg.SandboxID != "" && c.SandboxID != reg.SandboxID:
		sandboxRecordFailed(ev.Kind, fmt.Errorf("registration %s is not sandbox %q's", reg.ID, c.Sandbox))
		return
	}
	identity := sandboxRecordIdentity(reg)
	identity.Phase = audit.SandboxPhase(c.Phase)
	identity.Pack = c.Pack
	subject := sandboxRecordSubject(reg)
	r := a.managedSandboxRecorder()
	record := func(identity audit.SandboxIdentity) error {
		if ev.Kind == sandboxrelay.EventSandboxLifecycle {
			// The phase sets the severity (error HIGH, unknown MEDIUM).
			e := audit.SandboxLifecycleEvent{Sandbox: identity, PreviousPhase: audit.SandboxPhase(c.PreviousPhase),
				Trigger: audit.SandboxLifecycleTrigger(c.Trigger), ExitCode: c.ExitCode, Timestamp: ev.Time,
				UserID: subject.UserID, UserName: subject.UserName,
				// A revoked registration's sandbox is no longer tracked
				// (sandboxRegistrationGone): its last records never track
				// it again.
				TrackedOnly: reg.State == sandboxreg.StateRevoked}
			if c.Condition != nil {
				e.Condition = &audit.SandboxCondition{Type: c.Condition.Type, Status: c.Condition.Status,
					Reason: c.Condition.Reason, Message: c.Condition.Message}
			}
			return r.RecordSandboxLifecycle(ctx, e)
		}
		floor := observability.SeverityInfo
		if c.Blocked {
			floor = observability.SeverityMedium
		}
		return r.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: identity, Source: audit.SandboxEgressSource(c.Source),
			End: audit.SandboxEgressEnd(c.End), TimedOut: c.TimedOut, Terminated: c.Terminated, BytesUp: c.BytesUp, BytesDown: c.BytesDown,
			Duration: sandboxClaimDuration(c.DurationMS), PID: c.PID, Executable: c.Executable,
			ConversationID: c.ConversationID, Host: c.Host, Port: c.Port, Scheme: c.Scheme, Path: c.Path, ResolvedIP: c.ResolvedIP,
			Blocked: c.Blocked, DecisionCode: c.DecisionCode, Reason: c.Reason, PolicyOutcome: c.PolicyOutcome,
			Severity: sandboxClaimSeverity(c.Severity, floor), Timestamp: ev.Time, UserID: subject.UserID, UserName: subject.UserName})
	}
	if err := record(identity); err != nil {
		if errors.Is(err, audit.ErrSandboxPhaseLimit) {
			sandboxRecordFailed(ev.Kind, err)
			return
		}
		// Should the recorder refuse the profile stamp, the record keeps
		// the registration and the subject key alone.
		sandboxRecordFailed(ev.Kind+" (stamped)", err)
		identity.Managed = audit.SandboxManaged{RegistrationID: reg.ID, SubjectKey: reg.SubjectKey}
		if err := record(identity); err != nil {
			sandboxRecordFailed(ev.Kind, err)
			return
		}
	}
	// Only a record accepted for this bound sandbox after bind is a sighting.
	// The gateway stamps receipt time: queued creation records predate the bind.
	// Tombstone telemetry still records the sandbox's last phases, but cannot
	// establish a new sighting for a revoked registration.
	if reg.State != sandboxreg.StateRevoked {
		a.sandboxMarkGuestSeen(reg)
	}
}

// sandboxTelemetryAfterRevoke is how long after a registration was revoked
// (its daemon reported the sandbox deleted, or the gateway revoked it) its
// tombstone still takes the sandbox's last records (the stopping, stopped,
// error, deleting and deleted phases, the ends of its connections), which
// the daemon posts within seconds.
const sandboxTelemetryAfterRevoke = sandboxreg.RevokedTelemetryWindow

// sandboxClaimMaxDuration bounds a claimed connection duration.
const sandboxClaimMaxDuration = 30 * 24 * time.Hour

// sandboxTelemetryAdmit admits a batch carrying n sandbox telemetry records
// under reg, or answers the refusal:
//
//   - a registration not bound to a sandbox (pending, or no sandbox name)
//     names no sandbox to record for: 403 sandbox_not_allowed;
//   - a revoked registration takes them only within
//     sandboxTelemetryAfterRevoke of the revocation, whether its daemon
//     reported the sandbox deleted or the gateway revoked it (a changed
//     policy or subject: the daemon then stops and deletes the sandbox and
//     reports its going away), but never once its daemon reported the
//     sandbox foreign, which the registration never named: 410 otherwise.
//     What such a tombstone takes is the sandbox's going away alone
//     (sandboxTelemetryRecordAllowed);
//   - the account's records budget (sandboxRecordBudget): 429 with
//     Retry-After when it is spent.
func sandboxTelemetryAdmit(w http.ResponseWriter, auth *sandboxAuthority, peer managedHookPeer, reg sandboxreg.Registration, n int) bool {
	now := auth.clock()
	switch {
	case reg.State == sandboxreg.StatePending || strings.TrimSpace(reg.SandboxName) == "":
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, sandboxTextNotBound)
		return false
	case reg.State == sandboxreg.StateRevoked && (reg.RevokedReason == sandboxreg.ReasonForeign || reg.RevokedAt.IsZero() ||
		now.Sub(reg.RevokedAt) > sandboxTelemetryAfterRevoke):
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationRevoked, sandboxTextRegistrationGone)
		return false
	}
	return sandboxBudgetAdmit(w, &auth.records, peer, n, now)
}

// sandboxBudgetAdmit spends n records of peer's budget b, or answers 429
// with Retry-After when it is spent.
func sandboxBudgetAdmit(w http.ResponseWriter, b *sandboxRecordBudget, peer managedHookPeer, n int, now time.Time) bool {
	wait, ok := b.take(peer.UID, n, now)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
		writeSandboxRefusal(w, http.StatusTooManyRequests, managedHookReasonRateLimited,
			"DefenseClaw is limiting the sandbox records of this account; retry shortly")
		return false
	}
	return true
}

// sandboxEventRows is the number of managed records a daemon event of a
// kind other than telemetry makes: a foreign_rule event one per rule it
// names (at most sandboxEventRulesMax), every other kind one.
func sandboxEventRows(ev sandboxrelay.Event) int {
	if ev.Kind != sandboxrelay.EventForeignRule {
		return 1
	}
	var p struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(ev.Payload, &p) != nil {
		return 1
	}
	return min(max(len(p.Rules), 1), sandboxEventRulesMax)
}

// sandboxTelemetryRecordAllowed reports whether one telemetry record of an
// admitted batch (sandboxTelemetryAdmit) is recorded: never one dated before
// its registration was made, and under a tombstone only the records of its
// sandbox going away (the stopping, stopped, error, deleting and deleted
// phases and the ends of its connections), dated before the tombstone stops
// taking records. None of them tracks the sandbox's phase again
// (audit.SandboxLifecycleEvent.TrackedOnly).
func sandboxTelemetryRecordAllowed(reg sandboxreg.Registration, ev sandboxrelay.Event) bool {
	if !reg.CreatedAt.IsZero() && ev.Time.Before(reg.CreatedAt) {
		return false
	}
	if reg.State != sandboxreg.StateRevoked {
		return true
	}
	if ev.Time.After(reg.RevokedAt.Add(sandboxTelemetryAfterRevoke)) {
		return false
	}
	var c sandboxTelemetryClaim
	if json.Unmarshal(ev.Payload, &c) != nil {
		return false
	}
	if ev.Kind == sandboxrelay.EventSandboxEgress {
		return c.End != ""
	}
	switch audit.SandboxPhase(c.Phase) {
	case audit.SandboxPhaseStopping, audit.SandboxPhaseStopped, audit.SandboxPhaseError,
		audit.SandboxPhaseDeleting, audit.SandboxPhaseDeleted:
		return true
	}
	return false
}

// sandboxClaimSeverity is the severity of a claimed egress record: the
// claim, raised to floor (a block is at least MEDIUM) and capped at HIGH, so
// a daemon can neither make up a CRITICAL nor play a block down; floor for
// a claim that is no severity.
func sandboxClaimSeverity(claimed string, floor observability.Severity) string {
	normalized := observability.NormalizeSeverity(claimed)
	if !normalized.Valid || !normalized.Present {
		return string(floor)
	}
	rank, _ := observability.SeverityRank(normalized.Severity)
	floorRank, _ := observability.SeverityRank(floor)
	highRank, _ := observability.SeverityRank(observability.SeverityHigh)
	switch {
	case rank < floorRank:
		return string(floor)
	case rank > highRank:
		return string(observability.SeverityHigh)
	}
	return string(normalized.Severity)
}

// sandboxClaimDuration is a claimed connection duration in milliseconds,
// bounded to [0, sandboxClaimMaxDuration] without overflowing.
func sandboxClaimDuration(ms int64) time.Duration {
	if ms <= 0 {
		return 0
	}
	if ms > sandboxClaimMaxDuration.Milliseconds() {
		return sandboxClaimMaxDuration
	}
	return time.Duration(ms) * time.Millisecond
}

// errSandboxClaimKeyCollision is the error of a payload two of whose object
// keys are one key once cleaned ("rule" and "ru\u200ble"): which of them a
// record would take is the daemon's pick, so the batch is refused.
var errSandboxClaimKeyCollision = errors.New("two keys of the payload are the same key once cleaned")

// sandboxClaimPayload is a daemon event's payload with every string in it,
// object keys included, made safe for the managed audit (sandboxClaimText):
// the daemon runs as the user, so each value is the user's text. Every kind
// of daemon record is cleaned here, once, before it is decoded. A payload
// whose keys collide once cleaned is errSandboxClaimKeyCollision.
func sandboxClaimPayload(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing data after the payload")
	}
	clean, err := sandboxClaimValue(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(clean)
}

func sandboxClaimValue(v any) (any, error) {
	switch t := v.(type) {
	case string:
		return sandboxClaimText(t), nil
	case []any:
		for i := range t {
			clean, err := sandboxClaimValue(t[i])
			if err != nil {
				return nil, err
			}
			t[i] = clean
		}
		return t, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			key := sandboxClaimText(k)
			if _, taken := out[key]; taken {
				return nil, fmt.Errorf("%w: %q", errSandboxClaimKeyCollision, key)
			}
			clean, err := sandboxClaimValue(e)
			if err != nil {
				return nil, err
			}
			out[key] = clean
		}
		return out, nil
	}
	return v, nil
}

// sandboxClaimText is s without the characters that would rewrite or hide
// text in a terminal or a log viewer that shows the audit: the C0 and C1
// control characters (NUL, ESC and DEL among them), the bidirectional
// marks, overrides and isolates (U+061C, U+200E, U+200F, U+202A-U+202E,
// U+2066-U+2069), the zero-width and invisible characters (U+200B-U+200D,
// U+2060-U+2064, U+FEFF) and the tag characters (U+E0000-U+E007F). A tab,
// newline, carriage return, line separator (U+2028) or paragraph separator
// (U+2029) becomes a space.
func sandboxClaimText(s string) string {
	if !strings.ContainsFunc(s, sandboxClaimControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029:
			b.WriteByte(' ')
		case sandboxClaimControl(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sandboxClaimControl reports a character sandboxClaimText replaces or
// removes.
func sandboxClaimControl(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r >= 0x200b && r <= 0x200f, r == 0x2028, r == 0x2029, r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x2069, r == 0xfeff, r >= 0xe0000 && r <= 0xe007f:
		return true
	}
	return false
}
