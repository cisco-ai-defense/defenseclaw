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

package audit

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// SandboxManagedTelemetry is the v8 telemetry surface of the managed
// (identity-based, enterprise) sandbox records. Like SandboxTelemetry, every
// method emits exactly one generated log family and none accepts a family
// name, a builder or free-form attributes. *SandboxRecorder implements both.
// The managed gateway and the user's daemon (through POST sandbox/events)
// are the callers; the gateway stamps the person from the peer, never from
// anything the sandbox sent.
type SandboxManagedTelemetry interface {
	RecordSandboxPolicyResolved(context.Context, SandboxPolicyResolvedEvent) error
	RecordSandboxPolicyRematched(context.Context, SandboxPolicyRematchedEvent) error
	RecordSandboxPolicyForeignRule(context.Context, SandboxPolicyForeignRuleEvent) error
	RecordSandboxAskDecided(context.Context, SandboxAskDecidedEvent) error
	RecordSandboxHostRunRefused(context.Context, SandboxHostRunRefusedEvent) error
	RecordSandboxHostRunUnavailable(context.Context, SandboxHostRunUnavailableEvent) error
	RecordSandboxAccessRefused(context.Context, SandboxAccessRefusedEvent) error
	RecordSandboxForeignSandbox(context.Context, SandboxForeignSandboxEvent) error
	RecordSandboxForeignContainer(context.Context, SandboxForeignContainerEvent) error
	RecordSandboxSettingsDrift(context.Context, SandboxSettingsDriftEvent) error
	RecordSandboxRegistrationWithoutGuest(context.Context, SandboxRegistrationWithoutGuestEvent) error
}

var _ SandboxManagedTelemetry = (*SandboxRecorder)(nil)

// Registered values of the managed sandbox attributes.
const (
	// defenseclaw.openshell.install_mode (enterprise.openshell.install).
	SandboxInstallPrerequisite = "prerequisite"
	SandboxInstallSetup        = "setup"

	// defenseclaw.guardrail.profile.match, as the registration stores it.
	SandboxProfileMatchAgent               = "agent"
	SandboxProfileMatchUser                = "user"
	SandboxProfileMatchGroup               = "group"
	SandboxProfileMatchConnector           = "connector"
	SandboxProfileMatchDefault             = "default"
	SandboxProfileMatchDefaultUnverified   = "default_unverified"
	SandboxProfileMatchDefaultLookupFailed = "default_lookup_failed"

	// defenseclaw.sandbox.policy.rematch.reason.
	SandboxRematchGeneration     = "generation"
	SandboxRematchFacts          = "facts"
	SandboxRematchLookupResolved = "lookup_resolved"

	// defenseclaw.sandbox.managed.action.
	SandboxManagedRefuse            = "refuse"
	SandboxManagedAllow             = "allow"
	SandboxManagedStop              = "stop"
	SandboxManagedAlert             = "alert"
	SandboxManagedRemove            = "remove"
	SandboxGuestRelayWithoutGuest   = "relay_without_guest"
	SandboxGuestRunningWithoutGuest = "running_without_guest"
	// SandboxGuestRunningAfterStop: a running report for a registration
	// whose daemon reported its sandbox stopped, refused (GAP-0673).
	SandboxGuestRunningAfterStop = "running_after_stop"
)

// Bounds of the managed attributes, as the registry declares them.
const (
	maxSandboxRegistrationID   = 128
	maxSandboxProfileName      = 128
	maxSandboxMatchedGroup     = 256
	maxSandboxManagedPrincipal = 512
)

var (
	sandboxSubjectKeyPattern  = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	sandboxOpenShellVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$`)
	sandboxProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sandboxManagedCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	sandboxPolicyRulePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sandboxSettingsFieldRe    = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
)

// SandboxManaged is what the managed gateway knows about the sandbox's
// governance and stamps on every sandbox record of a managed host: the
// registration, the matched guardrail profile, the effective sandbox policy
// and the OpenShell provision. The zero value is an unmanaged sandbox: every
// field is then omitted. SubjectKey is the keyed pseudonym of the account
// (hmac-sha256:<64 hex>); it, not the principal, names the person when
// ai_discovery.include_user_principal is off. Nothing here is a metric label.
type SandboxManaged struct {
	// RegistrationID is the managed gateway registration (reg-...).
	RegistrationID string
	// GuardrailProfile, ProfileDigest, ProfileMatch and MatchedGroup are the
	// matched guardrail profile (defenseclaw.guardrail.profile.*); the
	// profile is empty when the organization floor alone governs.
	GuardrailProfile string
	ProfileDigest    string
	ProfileMatch     string
	MatchedGroup     string
	// PolicyDigest is the digest of the effective sandbox policy
	// (sha256:<64 hex>) and PolicyGeneration the gateway's configuration
	// generation (0 = unknown).
	PolicyDigest     string
	PolicyGeneration int64
	// Provisional is non-nil on a managed sandbox: true while it runs on the
	// offline floor because the directory lookup has not resolved.
	Provisional *bool
	// SubjectKey is the keyed pseudonym of the account.
	SubjectKey string
	// OpenShellVersion and InstallMode (SandboxInstall*) describe the
	// user's OpenShell.
	OpenShellVersion string
	InstallMode      string
}

// validate is the strict check the managed-only record families apply: a
// stamp that does not fit the registry is a bug in the managed gateway, and
// it is refused before anything is emitted.
func (managed SandboxManaged) validate() error {
	if err := managed.validateIdentifying(); err != nil {
		return err
	}
	for _, check := range managed.metadataChecks() {
		if check.value != "" && !check.ok(check.value) {
			return fmt.Errorf("audit: sandbox %s is not registered or bounded", check.field)
		}
	}
	return nil
}

// validateIdentifying checks the stamps that name the registration, the
// profile, the policy and the person. The records of the existing sandbox
// families (egress, approval, policy mutation) carry the managed stamps too,
// and a malformed descriptive stamp must never cost them the record: they
// check these and drop the descriptive ones (see lenient).
func (managed SandboxManaged) validateIdentifying() error {
	for _, check := range []struct {
		field, value string
		ok           func(string) bool
	}{
		{"registration id", managed.RegistrationID, func(v string) bool { return sandboxIdentifier(v, maxSandboxRegistrationID) }},
		{"guardrail profile", managed.GuardrailProfile, sandboxProfileNamePattern.MatchString},
		{"guardrail profile digest", managed.ProfileDigest, sandboxDigestPattern.MatchString},
		{"policy digest", managed.PolicyDigest, sandboxDigestPattern.MatchString},
		{"subject key", managed.SubjectKey, sandboxSubjectKeyPattern.MatchString},
	} {
		if check.value != "" && !check.ok(check.value) {
			return fmt.Errorf("audit: sandbox %s is not registered or bounded", check.field)
		}
	}
	if managed.PolicyGeneration < 0 {
		return fmt.Errorf("audit: sandbox policy generation must not be negative")
	}
	return nil
}

type sandboxManagedCheck struct {
	field, value string
	ok           func(string) bool
	drop         func(*SandboxManaged)
}

// metadataChecks are the descriptive stamps: the profile match, the matched
// group and the user's OpenShell version and install mode. They explain a
// record; none of them decides whether it is recorded.
func (managed SandboxManaged) metadataChecks() []sandboxManagedCheck {
	return []sandboxManagedCheck{
		{"guardrail profile match", managed.ProfileMatch, sandboxProfileMatchValid,
			func(m *SandboxManaged) { m.ProfileMatch = "" }},
		{"matched group", managed.MatchedGroup, sandboxMatchedGroupValid,
			func(m *SandboxManaged) { m.MatchedGroup = "" }},
		{"OpenShell version", managed.OpenShellVersion, sandboxOpenShellVersionRe.MatchString,
			func(m *SandboxManaged) { m.OpenShellVersion = "" }},
		{"OpenShell install mode", managed.InstallMode, func(v string) bool {
			return v == SandboxInstallPrerequisite || v == SandboxInstallSetup
		}, func(m *SandboxManaged) { m.InstallMode = "" }},
	}
}

// lenient returns the stamps without any descriptive one that does not fit
// the registry. The existing sandbox families record through it, so the
// mandatory egress-denied, approval-resolved and policy-mutation records
// survive a malformed version string.
func (managed SandboxManaged) lenient() SandboxManaged {
	for _, check := range managed.metadataChecks() {
		if check.value != "" && !check.ok(check.value) {
			check.drop(&managed)
		}
	}
	return managed
}

// validateManaged is validate for the managed-only record families: the
// identity checks, then the strict stamp check.
func (identity SandboxIdentity) validateManaged(requireName bool) error {
	if err := identity.validate(requireName); err != nil {
		return err
	}
	return identity.Managed.validate()
}

func sandboxProfileMatchValid(value string) bool {
	switch value {
	case SandboxProfileMatchAgent, SandboxProfileMatchUser, SandboxProfileMatchGroup,
		SandboxProfileMatchConnector, SandboxProfileMatchDefault,
		SandboxProfileMatchDefaultUnverified, SandboxProfileMatchDefaultLookupFailed:
		return true
	}
	return false
}

func sandboxMatchedGroupValid(value string) bool {
	if len(value) > maxSandboxMatchedGroup || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// SandboxManagedSubject is the person a managed record is about. The
// gateway fills it from the peer credential and the verified identity,
// never from a sandbox-supplied header.
type SandboxManagedSubject struct {
	// UserID and UserName are the host account (POSIX uid or Windows SID,
	// and its name).
	UserID   string
	UserName string
	// UserPrincipal is the directory principal. The caller sets it only
	// when ai_discovery.include_user_principal is on; otherwise it is left
	// empty and SandboxManaged.SubjectKey names the person.
	UserPrincipal string
}

// sandboxManagedPerson is the user.* projection of one subject.
type sandboxManagedPerson struct {
	id, kind, name, principal observability.Optional[string]
}

func sandboxManagedPersonFor(subject SandboxManagedSubject) sandboxManagedPerson {
	principal := observability.Absent[string]()
	if value := strings.TrimSpace(subject.UserPrincipal); value != "" && len(value) <= maxSandboxManagedPrincipal &&
		utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		principal = observability.Present(value)
	}
	return sandboxManagedPerson{
		id:        optionalNetworkIdentifier(subject.UserID),
		kind:      optionalNetworkUserIDKind(useridentity.KindForID(subject.UserID)),
		name:      observability.UserName(subject.UserName, optionalNetworkIdentifier),
		principal: principal,
	}
}

// sandboxManagedCode validates a DefenseClaw-owned reason code.
func sandboxManagedCode(what, value string, required bool) (observability.Optional[string], error) {
	if value == "" {
		if required {
			return observability.Absent[string](), fmt.Errorf("audit: sandbox %s requires a reason code", what)
		}
		return observability.Absent[string](), nil
	}
	if !sandboxManagedCodePattern.MatchString(value) {
		return observability.Absent[string](), fmt.Errorf("audit: sandbox %s reason %q is not a registered code", what, value)
	}
	return observability.Present(value), nil
}

// optionalSandboxRule bounds an operator-chosen rule name. A name that does
// not fit is omitted: the refusal or removal it describes must still be
// recorded.
func optionalSandboxRule(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if !sandboxPolicyRulePattern.MatchString(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

// foreign drops a foreign sandbox or container name that is not a bounded
// identifier: the user chose it, and an alert must not be lost over it.
func (identity SandboxIdentity) foreign() SandboxIdentity {
	if identity.Name != "" && !sandboxIdentifier(identity.Name, maxSandboxNameBytes) {
		identity.Name = ""
	}
	if identity.ID != "" && !sandboxIdentifier(identity.ID, maxSandboxIDBytes) {
		identity.ID = ""
	}
	return identity
}

func firstSandboxToken(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "sandbox"
}

// SandboxPolicyResolvedEvent is one resolution of a registration's effective
// sandbox policy (log.sandbox.policy.resolved): the profile match and the
// floor the gateway held the sandbox to, including the offline floor of a
// provisional registration.
type SandboxPolicyResolvedEvent struct {
	Sandbox SandboxIdentity
	Subject SandboxManagedSubject
	// Failed is true when the policy could not be built; the registration
	// is then refused.
	Failed bool
	// Reason is an optional registered code such as offline_floor.
	Reason    string
	Timestamp time.Time
}

// RecordSandboxPolicyResolved emits one generated log family; see SandboxPolicyResolvedEvent.
func (recorder *SandboxRecorder) RecordSandboxPolicyResolved(ctx context.Context, input SandboxPolicyResolvedEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	reason, err := sandboxManagedCode("policy resolution", input.Reason, false)
	if err != nil {
		return err
	}
	outcome, severity := observability.OutcomeCompleted, "INFO"
	if input.Failed {
		outcome, severity = observability.OutcomeFailed, "MEDIUM"
	}
	target := firstSandboxToken(identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxPolicy, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxPolicy, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSandboxPolicyResolved, phase: "resolve",
		outcome: outcome,
		// A policy that could not be built ends in a refused registration:
		// that is an enforced outcome and keeps the floor.
		mandatory: input.Failed,
		facts:     observability.MandatoryFacts{EnforcedOutcome: input.Failed},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxPolicyResolved(observability.LogSandboxPolicyResolvedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedReason: reason,
				MandatoryEnforcedOutcome:        input.Failed,
			})
		},
	}
	var metrics []RuntimeV8GeneratedMetric
	if result := sandboxProvisionalResolution(identity.Managed, input.Failed); result != "" {
		metrics = newSandboxManagedProvisionalMetric(event, sandboxManagedLabelsFor(identity, fields), result)
	}
	return recorder.emit(ctx, log, metrics)
}

// SandboxPolicyRematchedEvent is one re-match of a live registration
// (log.sandbox.policy.rematched): a configuration generation change, an
// identity refresh that changed the facts, or a provisional registration
// whose directory lookup has resolved. Sandbox.Managed carries the profile
// and policy after the re-match; the previous ones are named here. It is a
// control-plane mutation and therefore mandatory.
type SandboxPolicyRematchedEvent struct {
	Sandbox SandboxIdentity
	Subject SandboxManagedSubject
	// Reason is SandboxRematchGeneration, SandboxRematchFacts or
	// SandboxRematchLookupResolved.
	Reason string
	// PreviousProfile and PreviousDigest are the guardrail profile name and
	// effective sandbox policy digest before the re-match.
	PreviousProfile string
	PreviousDigest  string
	// Failed is true when the new policy could not be applied.
	Failed    bool
	Timestamp time.Time
}

// RecordSandboxPolicyRematched emits one generated log family; see SandboxPolicyRematchedEvent.
func (recorder *SandboxRecorder) RecordSandboxPolicyRematched(ctx context.Context, input SandboxPolicyRematchedEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	switch input.Reason {
	case SandboxRematchGeneration, SandboxRematchFacts, SandboxRematchLookupResolved:
	default:
		return fmt.Errorf("audit: sandbox re-match reason %q is not registered", input.Reason)
	}
	if input.PreviousProfile != "" && !sandboxProfileNamePattern.MatchString(input.PreviousProfile) {
		return fmt.Errorf("audit: sandbox previous profile is not a bounded name")
	}
	if input.PreviousDigest != "" && !sandboxDigestPattern.MatchString(input.PreviousDigest) {
		return fmt.Errorf("audit: sandbox previous policy digest must be sha256:<64 lowercase hex>")
	}
	outcome, severity := observability.OutcomeApplied, "INFO"
	if input.Failed {
		outcome, severity = observability.OutcomeFailed, "MEDIUM"
	}
	target := firstSandboxToken(identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxPolicyRematched, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxPolicyRematched, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSandboxPolicyRematched, phase: "rematch",
		outcome:   outcome,
		mandatory: true,
		facts:     observability.MandatoryFacts{ControlPlaneMutation: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxPolicyRematched(observability.LogSandboxPolicyRematchedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:                person.principal,
				DefenseClawSandboxPolicyRematchReason:   input.Reason,
				DefenseClawSandboxPolicyPreviousProfile: optionalSandboxEnum(input.PreviousProfile),
				DefenseClawSandboxPolicyPreviousDigest:  optionalSandboxEnum(input.PreviousDigest),
				MandatoryControlPlaneMutation:           true,
			})
		},
	}
	var metrics []RuntimeV8GeneratedMetric
	if input.Reason == SandboxRematchLookupResolved {
		result := SandboxProvisionalResolved
		if input.Failed {
			result = SandboxProvisionalFailed
		}
		metrics = newSandboxManagedProvisionalMetric(event, sandboxManagedLabelsFor(identity, fields), result)
	}
	return recorder.emit(ctx, log, metrics)
}

// SandboxPolicyForeignRuleEvent is one network rule found in a managed
// sandbox that neither the rendered policy nor a stored decision accounts
// for (log.sandbox.policy.foreign_rule). Action is SandboxManagedRemove for
// a rule taken out, SandboxManagedStop for a repeat that stopped the
// sandbox, or SandboxManagedAlert when only an alert was configured.
type SandboxPolicyForeignRuleEvent struct {
	Sandbox SandboxIdentity
	Subject SandboxManagedSubject
	Action  string
	// Failed is true when the removal or stop did not succeed.
	Failed bool
	// Host and Port are the destination the rule opened (canonicalized; an
	// unusable value is omitted) and Rule its name in the sandbox policy.
	Host      string
	Port      int
	Rule      string
	Timestamp time.Time
}

// RecordSandboxPolicyForeignRule emits one generated log family; see SandboxPolicyForeignRuleEvent.
func (recorder *SandboxRecorder) RecordSandboxPolicyForeignRule(ctx context.Context, input SandboxPolicyForeignRuleEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(true); err != nil {
		return err
	}
	switch input.Action {
	case SandboxManagedRemove, SandboxManagedStop, SandboxManagedAlert:
	default:
		return fmt.Errorf("audit: sandbox foreign rule action %q is not registered", input.Action)
	}
	outcome, severity := observability.OutcomeApplied, "MEDIUM"
	switch {
	case input.Action == SandboxManagedAlert && !input.Failed:
		outcome = observability.OutcomeSkipped
	case input.Failed:
		outcome, severity = observability.OutcomeFailed, "HIGH"
	}
	enforced := outcome != observability.OutcomeSkipped
	destination := canonicalSandboxDestination(input.Host, input.Port)
	target := identity.Name
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxPolicyForeignRule, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxPolicyForeignRule, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxPolicyForeignRule, phase: "reconcile",
		outcome:   outcome,
		mandatory: enforced,
		facts:     observability.MandatoryFacts{EnforcedOutcome: enforced},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxPolicyForeignRule(observability.LogSandboxPolicyForeignRuleInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: identity.Name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedAction: input.Action,
				DefenseClawSandboxPolicyRule:    optionalSandboxRule(input.Rule),
				ServerAddress:                   destination.address(), ServerPort: destination.port,
				MandatoryEnforcedOutcome: enforced,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedForeignMetric(event, sandboxManagedLabelsFor(identity, fields),
		SandboxForeignKindRule, input.Action))
}

// SandboxAskDecidedEvent is the managed gateway's decision on a user's ask,
// unblock or block (log.sandbox.ask.decided), bounded by the administrator's
// floor. Reason is a registered code such as floor_denied when the floor,
// not the user, decided. It is an approval resolution and therefore
// mandatory.
type SandboxAskDecidedEvent struct {
	Sandbox    SandboxIdentity
	Subject    SandboxManagedSubject
	ApprovalID string
	Kind       SandboxApprovalKind
	// Result is approved, denied, expired or cancelled (SandboxApproval*),
	// and Scope applies to an approved decision only.
	Result string
	Scope  SandboxApprovalScope
	// Host and Port are the destination (canonicalized; an unusable value
	// is omitted).
	Host string
	Port int
	// Stored is non-nil when the gateway kept (true) or did not keep (false)
	// the decision.
	Stored    *bool
	Reason    string
	Timestamp time.Time
}

// ValidApprovalID reports whether id is an approval id the sandbox approval
// records accept: the decisions route refuses any other, so a decision it
// takes is never one its mandatory record would reject (GAP-0659).
func ValidApprovalID(id string) bool {
	return runtimeV8Identifier(id)
}

// RecordSandboxAskDecided emits one generated log family; see SandboxAskDecidedEvent.
func (recorder *SandboxRecorder) RecordSandboxAskDecided(ctx context.Context, input SandboxAskDecidedEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	approvalID := strings.TrimSpace(input.ApprovalID)
	if approvalID != "" && !runtimeV8Identifier(approvalID) {
		return fmt.Errorf("audit: sandbox ask decision requires a stable approval id")
	}
	switch input.Kind {
	case "", SandboxApprovalNetworkRule, SandboxApprovalHostPort:
	default:
		return fmt.Errorf("audit: sandbox ask kind %q is not registered", input.Kind)
	}
	outcome, ok := sandboxApprovalOutcome(input.Result)
	if !ok {
		return fmt.Errorf("audit: sandbox ask result %q is not registered", input.Result)
	}
	switch input.Scope {
	case "":
	case SandboxApprovalScopeSandbox, SandboxApprovalScopeAlways:
		if input.Result != SandboxApprovalApproved {
			return fmt.Errorf("audit: only an approved sandbox ask has a scope")
		}
	default:
		return fmt.Errorf("audit: sandbox ask scope %q is not registered", input.Scope)
	}
	reason, err := sandboxManagedCode("ask decision", input.Reason, false)
	if err != nil {
		return err
	}
	stored := observability.Absent[bool]()
	if input.Stored != nil {
		stored = observability.Present(*input.Stored)
	}
	destination := canonicalSandboxDestination(input.Host, input.Port)
	severity := "INFO"
	target := firstSandboxToken(approvalID, identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxApproval, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxApproval, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSandboxAskDecided, phase: "ask",
		outcome:   outcome,
		mandatory: true,
		facts:     observability.MandatoryFacts{ApprovalResolution: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxAskDecided(observability.LogSandboxAskDecidedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxApprovalKind:  optionalSandboxEnum(string(input.Kind)),
				DefenseClawSandboxApprovalScope: optionalSandboxEnum(string(input.Scope)),
				ServerAddress:                   destination.address(), ServerPort: destination.port,
				DefenseClawApprovalID: optionalSandboxEnum(approvalID), DefenseClawApprovalResult: input.Result,
				DefenseClawSandboxDecisionStored: stored, DefenseClawSandboxManagedReason: reason,
				MandatoryApprovalResolution: true,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedAskMetric(event, sandboxManagedLabelsFor(identity, fields), input.Result, reason))
}

// SandboxHostRunRefusedEvent is a hook of an agent running on the host
// that was refused because the matched profile requires a sandbox for it
// (log.sandbox.host_run_refused). Sandbox.Connector names the agent; Reason
// is a registered code such as required_for and Rule the required_for
// entry that matched (the caller's own match only). It is an enforced
// outcome and therefore mandatory.
type SandboxHostRunRefusedEvent struct {
	Sandbox   SandboxIdentity
	Subject   SandboxManagedSubject
	Reason    string
	Rule      string
	Timestamp time.Time
}

// RecordSandboxHostRunRefused emits one generated log family; see SandboxHostRunRefusedEvent.
func (recorder *SandboxRecorder) RecordSandboxHostRunRefused(ctx context.Context, input SandboxHostRunRefusedEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	_, err := sandboxManagedCode("host run refusal", input.Reason, true)
	if err != nil {
		return err
	}
	outcome, severity := observability.OutcomeBlocked, "MEDIUM"
	target := firstSandboxToken(identity.Connector, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxHostRunRefused, phase: "gate",
		outcome:   outcome,
		mandatory: true,
		facts:     observability.MandatoryFacts{EnforcedOutcome: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxHostRunRefused(observability.LogSandboxHostRunRefusedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedReason: input.Reason,
				DefenseClawSandboxPolicyRule:    optionalSandboxRule(input.Rule),
				MandatoryEnforcedOutcome:        true,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedRefusalMetric(event, sandboxManagedLabelsFor(identity, fields),
		observability.Present(input.Reason)))
}

// SandboxHostRunUnavailableEvent is a host agent run that needs a sandbox
// this computer cannot provide (log.sandbox.host_run_unavailable): Windows,
// no docker group, no /dev/kvm, a missing prerequisite. Allowed is true when
// the profile's when_unavailable is alert and the run went ahead; the
// record is then an alert, otherwise a refusal (an enforced outcome, and
// therefore mandatory).
type SandboxHostRunUnavailableEvent struct {
	Sandbox SandboxIdentity
	Subject SandboxManagedSubject
	// Reason is a registered code such as os_unsupported, no_docker_group,
	// no_kvm or prerequisite_missing.
	Reason    string
	Allowed   bool
	Rule      string
	Timestamp time.Time
}

// RecordSandboxHostRunUnavailable emits one generated log family; see SandboxHostRunUnavailableEvent.
func (recorder *SandboxRecorder) RecordSandboxHostRunUnavailable(ctx context.Context, input SandboxHostRunUnavailableEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	_, err := sandboxManagedCode("host run unavailability", input.Reason, true)
	if err != nil {
		return err
	}
	outcome, action, severity := observability.OutcomeBlocked, SandboxManagedRefuse, "MEDIUM"
	if input.Allowed {
		outcome, action = observability.OutcomeAllowed, SandboxManagedAllow
	}
	enforced := !input.Allowed
	target := firstSandboxToken(identity.Connector, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxHostRunUnavailable, phase: "gate",
		outcome:   outcome,
		mandatory: enforced,
		facts:     observability.MandatoryFacts{EnforcedOutcome: enforced},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxHostRunUnavailable(observability.LogSandboxHostRunUnavailableInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedReason: input.Reason, DefenseClawSandboxManagedAction: action,
				DefenseClawSandboxPolicyRule: optionalSandboxRule(input.Rule),
				MandatoryEnforcedOutcome:     enforced,
			})
		},
	}
	var metrics []RuntimeV8GeneratedMetric
	if enforced {
		metrics = newSandboxManagedRefusalMetric(event, sandboxManagedLabelsFor(identity, fields), observability.Present(input.Reason))
	}
	return recorder.emit(ctx, log, metrics)
}

// SandboxAccessRefusedEvent is a destination the managed policy refused to
// a sandbox, or an ask for one (log.sandbox.access_refused). Rule is the
// policy rule that refused it (the caller's own match only) and Host and
// Port the destination (canonicalized; an unusable value is omitted). It is
// an enforced outcome and therefore mandatory.
type SandboxAccessRefusedEvent struct {
	Sandbox   SandboxIdentity
	Subject   SandboxManagedSubject
	Host      string
	Port      int
	Rule      string
	Reason    string
	Timestamp time.Time
}

// RecordSandboxAccessRefused emits one generated log family; see SandboxAccessRefusedEvent.
func (recorder *SandboxRecorder) RecordSandboxAccessRefused(ctx context.Context, input SandboxAccessRefusedEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	reason, err := sandboxManagedCode("access refusal", input.Reason, false)
	if err != nil {
		return err
	}
	destination := canonicalSandboxDestination(input.Host, input.Port)
	outcome, severity := observability.OutcomeBlocked, "MEDIUM"
	target := firstSandboxToken(identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxAccessRefused, phase: "access",
		outcome:   outcome,
		mandatory: true,
		facts:     observability.MandatoryFacts{EnforcedOutcome: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxAccessRefused(observability.LogSandboxAccessRefusedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal: person.principal,
				ServerAddress:            destination.address(), ServerPort: destination.port,
				DefenseClawSandboxPolicyRule:    optionalSandboxRule(input.Rule),
				DefenseClawSandboxManagedReason: reason,
				MandatoryEnforcedOutcome:        true,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedRefusalMetric(event, sandboxManagedLabelsFor(identity, fields), reason))
}

// SandboxForeignSandboxEvent is a sandbox on a managed user's OpenShell
// gateway that DefenseClaw did not create (log.sandbox.foreign_sandbox).
// Sandbox.Name and ID are the foreign sandbox's (dropped when they are not
// bounded identifiers: the user chose them). Action is SandboxManagedStop
// or SandboxManagedAlert per foreign_sandboxes.
type SandboxForeignSandboxEvent struct {
	Sandbox SandboxIdentity
	Subject SandboxManagedSubject
	Action  string
	// Failed is true when the stop did not succeed.
	Failed    bool
	Timestamp time.Time
}

// RecordSandboxForeignSandbox emits one generated log family; see SandboxForeignSandboxEvent.
func (recorder *SandboxRecorder) RecordSandboxForeignSandbox(ctx context.Context, input SandboxForeignSandboxEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	identity = identity.foreign()
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	switch input.Action {
	case SandboxManagedStop, SandboxManagedAlert:
	default:
		return fmt.Errorf("audit: sandbox foreign sandbox action %q is not registered", input.Action)
	}
	outcome, severity := observability.OutcomeApplied, "MEDIUM"
	switch {
	case input.Action == SandboxManagedAlert && !input.Failed:
		outcome = observability.OutcomeSkipped
	case input.Failed:
		outcome, severity = observability.OutcomeFailed, "HIGH"
	}
	enforced := outcome != observability.OutcomeSkipped
	target := firstSandboxToken(identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxForeignSandbox, phase: "reconcile",
		outcome:   outcome,
		mandatory: enforced,
		facts:     observability.MandatoryFacts{EnforcedOutcome: enforced},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxForeignSandbox(observability.LogSandboxForeignSandboxInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedAction: input.Action,
				MandatoryEnforcedOutcome:        enforced,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedForeignMetric(event, sandboxManagedLabelsFor(identity, fields),
		SandboxForeignKindSandbox, input.Action))
}

// SandboxForeignContainerEvent is an agent container started outside
// DefenseClaw, for example with a plain docker run
// (log.sandbox.foreign_container). It is alert-only: the container is never
// stopped. Sandbox.Name is the container's name (dropped when it is not a
// bounded identifier). Image is the image reference the container engine
// reports for it, so an operator can tell which image runs the agent
// (GAP-0677); it is dropped when it is not a plain reference.
type SandboxForeignContainerEvent struct {
	Sandbox   SandboxIdentity
	Subject   SandboxManagedSubject
	Image     string
	Timestamp time.Time
}

// maxSandboxContainerImageBytes bounds defenseclaw.sandbox.container.image.
const maxSandboxContainerImageBytes = 256

// sandboxContainerImagePattern is a plain image reference: a repository
// with a tag or a digest, or an image ID.
var sandboxContainerImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)

// optionalSandboxContainerImage is the image reference, or absent when it
// is not a plain one: an engine's value never costs the record.
func optionalSandboxContainerImage(image string) observability.Optional[string] {
	if image == "" || len(image) > maxSandboxContainerImageBytes || !sandboxContainerImagePattern.MatchString(image) {
		return observability.Absent[string]()
	}
	return observability.Present(image)
}

// RecordSandboxForeignContainer emits one generated log family; see SandboxForeignContainerEvent.
func (recorder *SandboxRecorder) RecordSandboxForeignContainer(ctx context.Context, input SandboxForeignContainerEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	identity = identity.foreign()
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	severity := "MEDIUM"
	target := firstSandboxToken(identity.Name, identity.Managed.RegistrationID)
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSandboxForeignContainer, phase: "reconcile",
		mandatory: false,
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxForeignContainer(observability.LogSandboxForeignContainerInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:         person.principal,
				DefenseClawSandboxContainerImage: optionalSandboxContainerImage(input.Image),
				DefenseClawSandboxManagedAction:  SandboxManagedAlert,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedForeignMetric(event, sandboxManagedLabelsFor(identity, fields),
		SandboxForeignKindContainer, SandboxManagedAlert))
}

// SandboxSettingsDriftEvent is an OpenShell setting that no longer matches
// enterprise.openshell (log.sandbox.settings_drift): the user's sandboxes are
// paused. Field is the setting's key (never its value). It is an enforced
// outcome and therefore mandatory.
type SandboxSettingsDriftEvent struct {
	Sandbox   SandboxIdentity
	Subject   SandboxManagedSubject
	Field     string
	Timestamp time.Time
}

// RecordSandboxSettingsDrift emits one generated log family; see SandboxSettingsDriftEvent.
func (recorder *SandboxRecorder) RecordSandboxSettingsDrift(ctx context.Context, input SandboxSettingsDriftEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(false); err != nil {
		return err
	}
	if !sandboxSettingsFieldRe.MatchString(input.Field) {
		return fmt.Errorf("audit: sandbox settings drift field %q is not a setting key", input.Field)
	}
	outcome, severity := observability.OutcomeBlocked, "HIGH"
	target := input.Field
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, target, severity, input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketEnforcementAction,
		eventName: observability.TelemetryEventSandboxSettingsDrift, phase: "drift",
		outcome:   outcome,
		mandatory: true,
		facts:     observability.MandatoryFacts{EnforcedOutcome: true},
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxSettingsDrift(observability.LogSandboxSettingsDriftInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawGuardrailProfileName:         fields.guardrailProfile,
				DefenseClawGuardrailProfileDigest:       fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch:        fields.guardrailMatch,
				DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID:                    fields.id, DefenseClawSandboxName: fields.name,
				DefenseClawSandboxRuntime: fields.runtime, DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID:      fields.bindingID,
				DefenseClawSandboxRegistrationID: fields.registrationID, DefenseClawSandboxPolicyDigest: fields.policyDigest,
				DefenseClawSandboxPolicyGeneration: fields.policyGeneration, DefenseClawSandboxPolicyProvisional: fields.provisional,
				DefenseClawOpenshellVersion: fields.openshellVersion, DefenseClawOpenshellInstallMode: fields.installMode,
				DefenseClawSubjectKey:            fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:          person.principal,
				DefenseClawOpenshellSettingsField: input.Field,
				DefenseClawSandboxManagedAction:   observability.Present(SandboxManagedRefuse),
				MandatoryEnforcedOutcome:          true,
			})
		},
	}
	return recorder.emit(ctx, log, newSandboxManagedDriftMetric(event, sandboxManagedLabelsFor(identity, fields), input.Field))
}

// SandboxRegistrationWithoutGuestEvent is a watched registration used or
// reported running after grace without an accepted guest record since bind.
// It is an alert only.
type SandboxRegistrationWithoutGuestEvent struct {
	Sandbox   SandboxIdentity
	Subject   SandboxManagedSubject
	Reason    string
	Timestamp time.Time
}

// RecordSandboxRegistrationWithoutGuest emits one managed alert family.
func (recorder *SandboxRecorder) RecordSandboxRegistrationWithoutGuest(ctx context.Context, input SandboxRegistrationWithoutGuestEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	identity := input.Sandbox
	if err := identity.validateManaged(true); err != nil {
		return err
	}
	if identity.Managed.RegistrationID == "" {
		return fmt.Errorf("audit: sandbox registration without guest requires a registration id")
	}
	switch input.Reason {
	case SandboxGuestRelayWithoutGuest, SandboxGuestRunningWithoutGuest, SandboxGuestRunningAfterStop:
	default:
		return fmt.Errorf("audit: sandbox registration without guest reason %q is not registered", input.Reason)
	}
	if identity.Phase != SandboxPhaseReady && identity.Phase != SandboxPhaseStopped {
		return fmt.Errorf("audit: sandbox registration without guest requires a running state")
	}
	fields := sandboxV8FieldsFor(identity)
	person := sandboxManagedPersonFor(input.Subject)
	event := recorder.newEvent(ctx, ActionSandboxManaged, identity, identity.Name, "MEDIUM", input.Timestamp)
	policyDigest, policyGeneration := livePolicyStamp()
	log := sandboxV8Log{
		action: ActionSandboxManaged, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSandboxRegistrationWithoutGuest, phase: "watch",
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSandboxRegistrationWithoutGuest(observability.LogSandboxRegistrationWithoutGuestInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel,
				DefenseClawGuardrailProfileName: fields.guardrailProfile, DefenseClawGuardrailProfileDigest: fields.guardrailDigest,
				DefenseClawGuardrailProfileMatch: fields.guardrailMatch, DefenseClawGuardrailProfileMatchedGroup: fields.guardrailGroup,
				DefenseClawSandboxID: fields.id, DefenseClawSandboxName: fields.name, DefenseClawSandboxRuntime: fields.runtime,
				DefenseClawSandboxDriver: fields.driver, DefenseClawSandboxDriverReason: fields.driverReason,
				DefenseClawSandboxImageDigest: fields.imageDigest, DefenseClawSandboxPolicyVersion: fields.policyVersion,
				DefenseClawSandboxProfile: fields.profile, DefenseClawSandboxPack: fields.pack,
				DefenseClawSandboxPhase: fields.phase, DefenseClawSandboxWorkdirMode: fields.workdirMode,
				DefenseClawSandboxBindingID: fields.bindingID, DefenseClawSandboxRegistrationID: fields.registrationID,
				DefenseClawSandboxPolicyDigest: fields.policyDigest, DefenseClawSandboxPolicyGeneration: fields.policyGeneration,
				DefenseClawSandboxPolicyProvisional: fields.provisional, DefenseClawOpenshellVersion: fields.openshellVersion,
				DefenseClawOpenshellInstallMode: fields.installMode, DefenseClawSubjectKey: fields.subjectKey,
				DefenseClawPolicyEffectiveDigest: policyDigest, DefenseClawPolicyGeneration: policyGeneration,
				UserID: person.id, DefenseClawUserIDKind: person.kind, DefenseClawUserName: person.name,
				DefenseClawUserPrincipal:        person.principal,
				DefenseClawSandboxManagedReason: input.Reason, DefenseClawSandboxManagedAction: SandboxManagedAlert,
			})
		},
	}
	return recorder.emit(ctx, log, nil)
}
