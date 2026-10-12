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
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
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
// sandbox records, created on first use (like sandboxAuthorities).
var managedSandboxRecorders sync.Map // *APIServer -> *audit.SandboxRecorder

// managedSandboxRecorder is a's recorder of the managed sandbox records.
func (a *APIServer) managedSandboxRecorder() *audit.SandboxRecorder {
	if a == nil {
		return nil
	}
	if r, ok := managedSandboxRecorders.Load(a); ok {
		return r.(*audit.SandboxRecorder)
	}
	r, _ := managedSandboxRecorders.LoadOrStore(a, audit.NewSandboxRecorder(a.logger))
	return r.(*audit.SandboxRecorder)
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
