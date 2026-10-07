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
	"sort"
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
	Kind      string `json:"kind"` // gateway, guardian, enumerator, sensor_helper, socket, timer, path
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
	AIDefense string `json:"ai_defense"` // disabled, ok, unavailable:<code>
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
	// services started, per-account hooks rewritten), or which key a
	// rotate-credentials committed and whom it moved. Empty means there was
	// nothing to repair.
	Changes        []string     `json:"changes,omitempty"`
	APIPortHolders []PortHolder `json:"api_port_holders,omitempty"`
	// Policy is the effective policy state; nil (omitted) under the Secure
	// Client integration and when the gateway did not report it.
	Policy *PolicyState `json:"policy,omitempty"`
	// Scanners is the standalone Windows scanner runtime (skill, MCP and
	// plugin scanners); nil (omitted) everywhere else.
	Scanners *ScannerRuntime `json:"scanners,omitempty"`
	LogPath  string       `json:"log_path,omitempty"`
	ExitCode int          `json:"exit_code"`
}

// ScannerRuntime reports the scanners a standalone Windows deployment runs.
type ScannerRuntime struct {
	// State: ready, not_prepared (installed but not unpacked), missing.
	State string `json:"state"`
	// Versions of the pinned components (skill-scanner, mcp-scanner,
	// litellm, python, ...).
	Versions map[string]string `json:"versions,omitempty"`
	// Policy is scanners.skill_scanner.policy; JudgeModel the resolved
	// scanner LLM judge model ("" when no judge is configured).
	Policy     string `json:"policy,omitempty"`
	JudgeModel string `json:"judge_model,omitempty"`
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

// PolicyStateFileName is the lifecycle state file holding the last applied
// policy state (PolicyStateRecord), next to deployment.json.
const PolicyStateFileName = "policy-state.json"

// PolicyStateRecord is policy-state.json.
type PolicyStateRecord struct {
	EffectiveDigest  string `json:"effective_digest"`
	ConfigGeneration uint64 `json:"config_generation"`
	// AppliedAt is RFC 3339 UTC.
	AppliedAt string `json:"applied_at"`
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
func (r *Result) Finish(goos string, failureCode int) int {
	r.OK = len(r.Errors) == 0
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
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
