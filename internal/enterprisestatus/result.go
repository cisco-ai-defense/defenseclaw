// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package enterprisestatus defines the one lifecycle result every
// standalone enterprise installer prints (Linux, macOS and Windows), so MDM
// detection scripts, status and verify parse a single contract.
package enterprisestatus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// SchemaVersion is the lifecycle result schema. Version 1 is the Secure
// Client Windows installer's status document, which this does not replace.
const SchemaVersion = 2

// Exit codes. Windows keeps MSI-compatible values so Intune and other
// MDMs classify results without custom return-code tables; unix uses
// sysexits-style values.
const (
	ExitOK = 0

	WindowsExitFailure     = 1603 // ERROR_INSTALL_FAILURE
	WindowsExitBusy        = 1618 // ERROR_INSTALL_ALREADY_RUNNING: MDMs retry
	WindowsExitInvalidArgs = 1639 // ERROR_INVALID_COMMAND_LINE
	WindowsExitReboot      = 3010 // reserved: success, reboot required
	// WindowsExitAccessDenied (ERROR_ACCESS_DENIED): a standard account ran
	// status or verify, which only an elevated prompt can check.
	WindowsExitAccessDenied = 5

	UnixExitFailure     = 1
	UnixExitInvalidArgs = 2
	UnixExitBusy        = 75 // EX_TEMPFAIL
)

// Service is one managed service or unit.
type Service struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // gateway, guardian, enumerator, sensor_helper, socket, timer, path, sandbox
	State     string `json:"state"`
	StartMode string `json:"start_mode,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Restarts  int    `json:"restarts,omitempty"`
	Required  bool   `json:"required"`
}

// Readiness splits "running" from "enforcing".
type Readiness struct {
	Gateway      bool `json:"gateway"`
	Guardian     bool `json:"guardian"`
	Enumerator   bool `json:"enumerator"`
	SensorHelper bool `json:"sensor_helper"`
}

// Inspection reports who decides verdicts.
type Inspection struct {
	Local     string `json:"local"`      // active, disabled
	AIDefense string `json:"ai_defense"` // disabled, ok, unknown, unavailable:<code>
}

// CodeAIDefenseUnavailable warns that enabled Cisco AI Defense inspection is
// failing, for example with a rejected key (unavailable:auth_failed).
const CodeAIDefenseUnavailable = "ai_defense_unavailable"

// AddAIDefenseWarning warns when Inspection.AIDefense is unavailable:<code>.
// Not an error: the local policy engine keeps deciding, but the cloud
// inspection the administrator enabled is not running.
func (r *Result) AddAIDefenseWarning() {
	if !strings.HasPrefix(r.Inspection.AIDefense, "unavailable") {
		return
	}
	fix := "Check the enterprise.inspection.ai_defense credential and network access"
	if r.Inspection.AIDefense == "unavailable:auth_failed" {
		fix = "Cisco AI Defense rejected the stored API key (HTTP 401 or 403): store a valid key under the " +
			"credential enterprise.inspection.ai_defense.credential names, with `enterprise secret set`"
	}
	r.AddWarning(CodeAIDefenseUnavailable, "Cisco AI Defense inspection is enabled but reports "+
		r.Inspection.AIDefense+"; the local policy engine keeps deciding. "+fix)
}

// MachinePolicyState is the per-connector machine policy report.
type MachinePolicyState struct {
	Ownership        string   `json:"ownership"`      // merge, verify_only, off
	Lock             string   `json:"lock,omitempty"` // configured: enforce, preserve
	EffectiveLock    string   `json:"effective_lock,omitempty"`
	OwnedEntries     int      `json:"owned_entries"`
	ForeignEntries   int      `json:"foreign_entries"`
	HigherPrecedence []string `json:"higher_precedence,omitempty"`
	Conflicts        []string `json:"conflicts,omitempty"`
	LiveVerifiedAt   string   `json:"live_verified_at,omitempty"`
}

// Enrollment summarizes guardian targets.
type Enrollment struct {
	Targets int `json:"targets"`
	Pending int `json:"pending"`
	Failed  int `json:"failed"`
	Exempt  int `json:"exempt"`
	// Accounts names each enrolled account and its connectors' states, where
	// the platform reports them (Windows standalone).
	Accounts []EnrollmentAccount `json:"accounts,omitempty"`
}

// EnrollmentAccount is one enrolled account and the state of each of its
// connectors in the guardian's last reconcile: enrolled, pending (waiting
// for the account's session) or failed.
type EnrollmentAccount struct {
	Account    string            `json:"account"`
	SID        string            `json:"sid,omitempty"`
	Connectors map[string]string `json:"connectors"`
	// Reason says why a connector is pending or failed, and what happens
	// next; empty when every connector is enrolled.
	Reason string `json:"reason,omitempty"`
}

// PortHolder is a process, other than the DefenseClaw gateway, listening
// where the gateway API must bind. Image and Account are empty when the
// reporting account cannot identify the process.
type PortHolder struct {
	Address string `json:"address"`
	PID     int    `json:"pid"`
	Image   string `json:"image,omitempty"`
	Account string `json:"account,omitempty"`
}

// Message is a stable machine code plus a human sentence.
type Message struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Destination is one observability destination the installed config.yaml
// compiles to, as status reports it (GAP-1105).
type Destination struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Enabled bool     `json:"enabled"`
	Preset  string   `json:"preset,omitempty"`
	Signals []string `json:"signals"`
	// RedactionProfiles are the distinct effective profiles of the
	// destination's send routes; empty for a destination that sends only
	// metrics.
	RedactionProfiles []string `json:"redaction_profiles"`
}

// Result is the lifecycle result document.
type Result struct {
	SchemaVersion      int                           `json:"schema_version"`
	OK                 bool                          `json:"ok"`
	Action             string                        `json:"action"`
	Noop               bool                          `json:"noop"`
	NoopReason         string                        `json:"noop_reason,omitempty"`
	Profile            string                        `json:"profile"`
	Platform           string                        `json:"platform"`
	ProductVersion     string                        `json:"product_version"`
	FloorSource        string                        `json:"floor_source,omitempty"`
	InstalledVersion   string                        `json:"installed_version,omitempty"`
	Installed          bool                          `json:"installed"`
	TransactionPending bool                          `json:"transaction_pending"`
	Services           []Service                     `json:"services"`
	Readiness          Readiness                     `json:"readiness"`
	Inspection         Inspection                    `json:"inspection"`
	MachinePolicy      map[string]MachinePolicyState `json:"machine_policy"`
	Enrollment         Enrollment                    `json:"enrollment"`
	CoverageComplete   bool                          `json:"coverage_complete"`
	SecurityComplete   bool                          `json:"security_complete"`
	Errors             []Message                     `json:"errors"`
	Warnings           []Message                     `json:"warnings,omitempty"`
	// Changes lists, in plain words, what a Linux or macOS repair or ensure
	// changed on a deployment that was already installed (files rewritten,
	// services started, per-account hooks rewritten), which key a
	// rotate-credentials committed and whom it moved, or, on every OS, which
	// config a run migrated to config_version 9. Empty means there was
	// nothing to repair.
	Changes        []string     `json:"changes,omitempty"`
	APIPortHolders []PortHolder `json:"api_port_holders,omitempty"`
	// Policy is the effective policy state; nil (omitted) under the Secure
	// Client integration and when the gateway did not report it.
	Policy *PolicyState `json:"policy,omitempty"`
	// Bundle is the signed policy bundle state of a standalone device in
	// bundle mode: the last receipt that reached staging and the bundle that
	// enforces; nil (omitted) when neither exists.
	Bundle      *BundleState   `json:"bundle,omitempty"`
	LastRefusal *BundleRefusal `json:"last_refusal,omitempty"`
	// Scanners is the standalone Windows scanner runtime (skill, MCP and
	// plugin scanners); nil (omitted) everywhere else.
	Scanners *ScannerRuntime `json:"scanners,omitempty"`
	// Destinations lists, for status, the observability destinations of the
	// installed config.yaml with their effective redaction profiles, from the
	// compiler `defenseclaw observability plan` uses (GAP-1105).
	Destinations []Destination `json:"destinations,omitempty"`
	// Connectors, OpenShell and Identity are the status v2 blocks of status
	// and verify on the standalone profile (connector_block.go,
	// openshell_block.go, identity_block.go); nil (omitted) elsewhere.
	Connectors map[string]ConnectorState `json:"connectors,omitempty"`
	OpenShell  *OpenShellCapability      `json:"openshell,omitempty"`
	Identity   *IdentityHealth           `json:"identity,omitempty"`
	LogPath    string                    `json:"log_path,omitempty"`
	ExitCode   int                       `json:"exit_code"`
	// ConfigRefused marks a run that refused the submitted config before it
	// changed anything: the policy, services and advisories it reports are
	// the running deployment's. Text output only (GAP-0564).
	ConfigRefused bool `json:"-"`
	// PreserveNotRootDeploymentState retains the pre-1.0 Secure Client JSON
	// shape for an unelevated macOS lifecycle command.
	PreserveNotRootDeploymentState bool `json:"-"`

	// securityBy and coverageBy are why security_complete and
	// coverage_complete are false (MarkSecurityIncomplete,
	// MarkCoverageIncomplete); Finish names them on Linux and macOS.
	securityBy, coverageBy []string
}

// CodeSecurityIncomplete is the warning that names why security_complete
// (and coverage_complete) is false. Windows Setup uses it when no other
// warning explains an incomplete result; Linux and macOS status, verify and
// the package result list the warning codes behind each field, so an upgrade
// that turns a field false says which check did (GAP-1861, GAP-1863).
const CodeSecurityIncomplete = "security_incomplete"

// MarkSecurityIncomplete sets security_complete false for reason: the code of
// the warning or error that says why, or a short phrase when no warning does.
func (r *Result) MarkSecurityIncomplete(reason string) {
	r.SecurityComplete = false
	r.securityBy = appendReason(r.securityBy, reason)
}

// MarkCoverageIncomplete sets coverage_complete and security_complete false
// for reason (see MarkSecurityIncomplete).
func (r *Result) MarkCoverageIncomplete(reason string) {
	r.CoverageComplete = false
	r.coverageBy = appendReason(r.coverageBy, reason)
	r.MarkSecurityIncomplete(reason)
}

// ResetCompleteness starts the completeness verdict again: both fields true,
// no reason. The Linux and macOS describe pass computes them from scratch.
func (r *Result) ResetCompleteness() {
	r.CoverageComplete, r.SecurityComplete = true, true
	r.securityBy, r.coverageBy = nil, nil
}

func appendReason(reasons []string, reason string) []string {
	reason = strings.TrimSpace(reason)
	if reason == "" || slices.Contains(reasons, reason) {
		return reasons
	}
	return append(reasons, reason)
}

// nameIncompleteFields replaces the security_incomplete warning with one that
// lists why each false field is false. A field that ended true drops its
// reasons (a later pass recomputed it); a result whose only reasons are its
// errors gets no warning, the errors say it.
func (r *Result) nameIncompleteFields() {
	if r.CoverageComplete {
		r.coverageBy = nil
	}
	if r.SecurityComplete {
		r.securityBy = nil
	}
	warnings := make([]Message, 0, len(r.Warnings)+1)
	for _, warning := range r.Warnings {
		if warning.Code != CodeSecurityIncomplete {
			warnings = append(warnings, warning)
		}
	}
	r.Warnings = warnings
	if r.SecurityComplete || len(r.securityBy) == 0 {
		return
	}
	message := "security_complete is false because of: " + strings.Join(r.securityBy, ", ")
	if len(r.Errors) > 0 {
		message += " and the errors above"
	}
	if r.CoverageComplete {
		message += "; coverage_complete is true"
	} else if len(r.coverageBy) > 0 {
		message += "; coverage_complete is false because of: " + strings.Join(r.coverageBy, ", ")
	}
	r.Warnings = append(r.Warnings, Message{Code: CodeSecurityIncomplete, Message: message + "; each warning above says what to do"})
}

// ScannerRuntime reports the scanners a standalone Windows deployment runs.
type ScannerRuntime struct {
	// State: ready, not_prepared (installed but not unpacked), untrusted
	// (not the executable the payload trust policy admitted, so not run),
	// missing.
	State string `json:"state"`
	// Versions of the pinned components (skill-scanner, mcp-scanner,
	// litellm, python, ...).
	Versions map[string]string `json:"versions,omitempty"`
	// Policy is scanners.skill_scanner.policy; JudgeModel the resolved
	// scanner LLM judge model ("" when no judge is configured).
	Policy     string `json:"policy,omitempty"`
	JudgeModel string `json:"judge_model,omitempty"`
	// Problem names the unpacked file that is missing or changed when a
	// prepared runtime is damaged (State not_prepared).
	Problem string `json:"problem,omitempty"`
}

// PolicyState reports the effective policy a lifecycle step left in place.
type PolicyState struct {
	// EffectiveDigest is effective_policy_digest computed from the
	// committed config and its assets ("sha256:<hex>").
	EffectiveDigest string `json:"effective_digest"`
	// ConfigGeneration is config_generation from config.generation.json.
	ConfigGeneration uint64 `json:"config_generation"`
	// Applied is true when the gateway reports the same digest.
	Applied bool `json:"applied"`
	// GatewayReportedDigest is the digest /health reported; empty when the
	// gateway was not reachable.
	GatewayReportedDigest string `json:"gateway_reported_digest,omitempty"`
	// LastReloadError is policy.last_reload_error from /health: why the
	// gateway rejected its last reload. While it is set the gateway enforces
	// an older policy than the installed config, so Applied is false.
	LastReloadError string `json:"last_reload_error,omitempty"`
	// ConfigUnrecorded is true when config.yaml was changed outside the
	// lifecycle: its generation is not the one config.generation.json
	// records, and the running gateway may already enforce it.
	ConfigUnrecorded bool `json:"config_unrecorded,omitempty"`
}

// Bundle receipt states (management plane spec P1 section 7). A receipt
// moves received, verified, staged, applied, confirmed; failed (with an
// error code) ends it from any state before confirmed.
const (
	BundleReceived  = "received"
	BundleVerified  = "verified"
	BundleStaged    = "staged"
	BundleApplied   = "applied"
	BundleConfirmed = "confirmed"
	BundleFailed    = "failed"
)

// BundleState is the result v2 "bundle" block: the last receipt (the
// newest bundle the device received and how far it got) and the confirmed
// bundle that enforces. ConfigGeneration is the persistent config
// generation of config.generation.json, not the gateway policy generation
// that restarts at 1 with the gateway.
type BundleState struct {
	// ReceiptID names the receipt this block reports: the file name of its
	// public receipt (<etc>/bundles/receipt-events/<receipt_id>.json) that a
	// management agent forwards. A repeated delivery of the current bundle
	// discards its own receipt, so the block names the confirmed one.
	ReceiptID string `json:"receipt_id,omitempty"`
	// DeliveryID is the --delivery-id of the delivery that receipt records
	// (absent without it); a repeat names the confirmed receipt, so it is
	// that delivery id, not the repeat one.
	DeliveryID       string   `json:"delivery_id,omitempty"`
	BundleID         string   `json:"bundle_id"`
	DisabledByBundle []string `json:"disabled_by_bundle,omitempty"`
	WarningCodes     []string `json:"warning_codes,omitempty"`
	Version          uint64   `json:"version"`
	State            string   `json:"state"`
	// SessionsRestartRequired is a live scan. A confirmed receipt proves the
	// gateway applied the policy; coverage_complete also requires its count
	// to be zero because already-running agents can retain earlier hooks.
	SessionsRestartRequired *SessionRestartStatus `json:"sessions_restart_required,omitempty"`
	// ErrorCode is the bundle error code of a failed receipt.
	ErrorCode string `json:"error_code,omitempty"`
	// EffectivePolicyDigest is the digest the receipt recorded: the staged
	// config computes to it, and a confirmed receipt is enforced with it.
	EffectivePolicyDigest string `json:"effective_policy_digest,omitempty"`
	ConfigGeneration      uint64 `json:"config_generation,omitempty"`
	// AppliedAt and ConfirmedAt are RFC 3339 UTC.
	AppliedAt       string `json:"applied_at,omitempty"`
	ConfirmedAt     string `json:"confirmed_at,omitempty"`
	Restart         bool   `json:"restart,omitempty"`
	RestartRequired bool   `json:"restart_required,omitempty"`
	// CurrentBundleID and CurrentVersion name the confirmed bundle that
	// enforces when this receipt is not its confirmed receipt: a newer
	// bundle pending or failed (the last good bundle keeps enforcing), or
	// the enforcing bundle delivered again.
	CurrentBundleID string `json:"current_bundle_id,omitempty"`
	CurrentVersion  uint64 `json:"current_version,omitempty"`
}

// ShortDigest is "sha256:" and the first 12 hex digits of a digest, or "none".
func ShortDigest(digest string) string {
	if digest == "" {
		return "none"
	}
	if len(digest) > len("sha256:")+12 {
		return digest[:len("sha256:")+12]
	}
	return digest
}

// Line is the one human-readable line status, verify and ensure print for the
// policy: the config generation, the effective digest and whether the gateway
// enforces it. The same facts are in --json under "policy".
func (p *PolicyState) Line() string {
	line := fmt.Sprintf("policy: config generation %d, effective digest %s", p.ConfigGeneration, ShortDigest(p.EffectiveDigest))
	switch {
	case p.LastReloadError != "":
		line += "; the gateway rejected its last reload (" + p.LastReloadError + ") and keeps enforcing the policy it last built"
	case p.Applied:
		line += "; applied by the gateway"
	case p.GatewayReportedDigest == "":
		line += "; the gateway did not report a policy, so it is not confirmed as applied"
	default:
		line += "; the gateway reports " + ShortDigest(p.GatewayReportedDigest) + " and applies this one on its next reload"
	}
	if p.ConfigUnrecorded {
		line += "; config.yaml was changed outside the lifecycle"
	}
	return line
}

// RunningDeploymentPrefix starts each warning of a run that refused the
// submitted config before it changed anything: the warning is the running
// deployment's, not the refused file's (GAP-0564, #1201).
const RunningDeploymentPrefix = "running deployment (the refused config changed nothing): "

// LabelRunningDeployment marks r as a run that refused the submitted config
// (ConfigRefused) and labels each warning from index from on as the running
// deployment's, except those whose code is in keep: they describe the
// refused request itself. A warning already labelled stays as it is.
func (r *Result) LabelRunningDeployment(from int, keep ...string) {
	if r == nil {
		return
	}
	r.ConfigRefused = true
	for i := max(from, 0); i < len(r.Warnings); i++ {
		if slices.Contains(keep, r.Warnings[i].Code) || strings.HasPrefix(r.Warnings[i].Message, RunningDeploymentPrefix) {
			continue
		}
		r.Warnings[i].Message = RunningDeploymentPrefix + r.Warnings[i].Message
	}
}

// PolicyLine is Policy.Line(), labelled as the running deployment's when the
// run refused the submitted config (ConfigRefused); "" without a policy.
func (r *Result) PolicyLine() string {
	if r == nil || r.Policy == nil {
		return ""
	}
	line := r.Policy.Line()
	if r.ConfigRefused {
		line = "running policy (the refused config changed nothing)" + strings.TrimPrefix(line, "policy")
	}
	return line
}

// PolicyStateFileName is the lifecycle state file holding the last applied
// policy state (PolicyStateRecord), next to deployment.json.
const PolicyStateFileName = "policy-state.json"

// PolicyStateRecord is policy-state.json.
type PolicyStateRecord struct {
	EffectiveDigest  string `json:"effective_digest"`
	ConfigGeneration uint64 `json:"config_generation"`
	// AppliedAt is RFC 3339 UTC.
	AppliedAt string `json:"applied_at"`
	// BundleID and BundleVersion name the signed policy bundle whose config
	// computes to EffectiveDigest; absent without bundles.
	BundleID      string `json:"bundle_id,omitempty"`
	BundleVersion uint64 `json:"bundle_version,omitempty"`
}

// New returns a result with the schema version and empty collections set,
// so JSON consumers never see null where they expect a list or map.
func New(action, profile, platform, productVersion string) *Result {
	return &Result{
		SchemaVersion:  SchemaVersion,
		Action:         action,
		Profile:        profile,
		Platform:       platform,
		ProductVersion: productVersion,
		Services:       []Service{},
		MachinePolicy:  map[string]MachinePolicyState{},
		Errors:         []Message{},
	}
}

// AddError records a failure; a result with errors is never OK.
func (r *Result) AddError(code, message string) {
	r.Errors = append(r.Errors, Message{Code: code, Message: message})
	r.OK = false
}

// AddWarning records a non-fatal condition.
func (r *Result) AddWarning(code, message string) {
	r.Warnings = append(r.Warnings, Message{Code: code, Message: message})
}

// Finish sets OK from the error list and the exit code for goos, then
// returns the code. failureCode overrides the generic failure code when a
// more specific one applies (busy, invalid arguments).
//
// A result with an error is never security_complete: Windows verify
// reported security_complete:true next to the error that the guardian could
// not verify an enrolled target's hooks, so a script that read the flag
// was told the host was protected (GAP-0664).
func (r *Result) Finish(goos string, failureCode int) int {
	if r.Bundle != nil && r.Bundle.SessionsRestartRequired != nil && r.Bundle.SessionsRestartRequired.Count > 0 {
		code, _ := SessionWarning(*r.Bundle.SessionsRestartRequired)
		r.MarkCoverageIncomplete(code)
	}
	r.OK = len(r.Errors) == 0
	if !r.OK {
		r.SecurityComplete = false
	}
	if goos != "windows" {
		r.nameIncompleteFields()
	}
	switch {
	case r.OK:
		r.ExitCode = ExitOK
	case failureCode != 0:
		r.ExitCode = failureCode
	case goos == "windows":
		r.ExitCode = WindowsExitFailure
	default:
		r.ExitCode = UnixExitFailure
	}
	return r.ExitCode
}

// BusyExitCode is the "another lifecycle run holds the lock" code for goos.
func BusyExitCode(goos string) int {
	if goos == "windows" {
		return WindowsExitBusy
	}
	return UnixExitBusy
}

// InvalidArgsExitCode is the invalid-arguments code for goos.
func InvalidArgsExitCode(goos string) int {
	if goos == "windows" {
		return WindowsExitInvalidArgs
	}
	return UnixExitInvalidArgs
}

// notRootCode is the refusal of a Linux or macOS action run without root.
const notRootCode = "not_root"

// deploymentStateFields report the deployment. A not_root result checked
// nothing (a standard user cannot read the root-only deployment record), so
// it leaves them out instead of reporting installed: false, no services and
// every readiness flag false, which a script that ignores the error code read
// as "not installed" (GAP-0279).
var deploymentStateFields = []string{
	"installed", "installed_version", "transaction_pending", "services", "readiness", "inspection", "machine_policy", "enrollment",
	"destinations", "connectors", "openshell", "identity",
}

func (r Result) refusedNotRoot() bool {
	for _, e := range r.Errors {
		if e.Code == notRootCode {
			return true
		}
	}
	return false
}

// MarshalJSON renders services in a stable order.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	sorted := plain(r)
	sorted.Services = append([]Service{}, r.Services...)
	sort.SliceStable(sorted.Services, func(i, j int) bool { return sorted.Services[i].Name < sorted.Services[j].Name })
	if sorted.Services == nil {
		sorted.Services = []Service{}
	}
	if sorted.MachinePolicy == nil {
		sorted.MachinePolicy = map[string]MachinePolicyState{}
	}
	if sorted.Errors == nil {
		sorted.Errors = []Message{}
	}
	// Encode without HTML escaping: messages carry PowerShell next steps
	// ("& 'C:\\...\\defenseclaw.exe' ...") and a Marshaler's bytes are kept
	// as-is by an outer encoder with SetEscapeHTML(false) (GAP-2504).
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(sorted); err != nil {
		return nil, err
	}
	if !r.refusedNotRoot() || r.PreserveNotRootDeploymentState {
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		return nil, err
	}
	for _, name := range deploymentStateFields {
		delete(fields, name)
	}
	buf.Reset()
	if err := encoder.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
