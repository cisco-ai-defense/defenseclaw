// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone profile wraps the installer's schema-1 document in the
// cross-platform enterprisestatus schema-2 result, registers the deployment
// for MDM detection, and records every run in the event log and a rotated
// lifecycle log. None of this runs for the Secure Client profile.

// windowsEnterpriseStandaloneRun is one installer run on PowerShell 7.
type windowsEnterpriseStandaloneRun struct {
	Output    []byte
	Truncated bool
	ExitCode  int
}

// windowsEnterpriseInstallerReport is the subset of the installer's schema-1
// status document the standalone result is built from.
type windowsEnterpriseInstallerReport struct {
	SchemaVersion                     int      `json:"schema_version"`
	OK                                bool     `json:"ok"`
	Action                            string   `json:"action"`
	Installed                         bool     `json:"installed"`
	TransactionPending                bool     `json:"transaction_pending"`
	InstallRoot                       string   `json:"install_root"`
	StateRoot                         string   `json:"state_root"`
	GatewayService                    string   `json:"gateway_service"`
	GuardianService                   string   `json:"guardian_service"`
	GatewayServiceState               string   `json:"gateway_service_state"`
	GuardianServiceState              string   `json:"guardian_service_state"`
	SensorHelperService               string   `json:"sensor_helper_service"`
	SensorHelperServiceState          string   `json:"sensor_helper_service_state"`
	EnumeratorService                 string   `json:"enumerator_service"`
	EnumeratorServiceState            string   `json:"enumerator_service_state"`
	GatewayReady                      bool     `json:"gateway_ready"`
	GuardianReady                     bool     `json:"guardian_ready"`
	CodexMachineRequirementsReady     bool     `json:"codex_machine_requirements_ready"`
	CodexMachineRequirementsDisposion string   `json:"codex_machine_requirements_disposition"`
	CodexTargetEnabled                bool     `json:"codex_target_enabled"`
	CursorTargetEnabled               bool     `json:"cursor_target_enabled"`
	ClaudeTargetEnabled               bool     `json:"claude_target_enabled"`
	ClaudeEffectivePolicyVerified     bool     `json:"claude_effective_policy_verified"`
	SecurityComplete                  bool     `json:"security_complete"`
	InstalledVersion                  string   `json:"installed_version"`
	TrustMode                         string   `json:"trust_mode"`
	Error                             string   `json:"error"`
	Errors                            []string `json:"errors"`
	// A committed standalone uninstall reports the DefenseClaw per-user
	// registrations it could not remove from users' agent configurations.
	// They are decoded leniently: a malformed value must not hide the
	// lifecycle's report.
	UserRegistrationsPending json.RawMessage `json:"user_registrations_pending"`
	UserRegistrationsFailed  json.RawMessage `json:"user_registrations_failed"`
	// UserStateRemaining names each enrolled account's per-user folder the
	// uninstall left ("user (SID): path"; with purge, each one it could
	// not remove, followed by ": reason").
	UserStateRemaining json.RawMessage `json:"user_state_remaining"`
	// UserStatePurged names each enrolled account whose per-user folder and
	// per-user binaries a purge removed ("user (SID): path").
	UserStatePurged json.RawMessage `json:"user_state_purged"`
	// MachineStateRemaining names what a standalone purge could not remove
	// outside StateRoot ("path: reason"), such as a stale protected
	// PowerShell temp folder (GAP-1734).
	MachineStateRemaining json.RawMessage `json:"machine_state_remaining"`
	// Pending-transaction recovery reports each managed-hook lifecycle step
	// it ran with the Setup's verified gateway, and why it kept the staged
	// one. Decoded leniently, like the registration lists.
	RecoveryGatewayRuns    json.RawMessage `json:"recovery_gateway_runs"`
	RecoveryGatewayRefusal json.RawMessage `json:"recovery_gateway_refusal"`
	// RollbackLeftovers names what the rollback of a failed first install
	// could not remove ("user (SID) [connectors]: item", or a machine item).
	// Decoded leniently, like the registration lists.
	RollbackLeftovers json.RawMessage `json:"rollback_leftovers"`
	// StaleLifecycleJournalRemoved is set when the lifecycle removed a
	// stale committed managed-hook lifecycle journal itself (GAP-1322); it
	// holds the retire failure that made the journal stale.
	StaleLifecycleJournalRemoved string `json:"stale_lifecycle_journal_removed"`
	// CursorAdapterRestored is set when the lifecycle wrote this release's
	// Cursor enterprise adapter back over a changed or deleted one (GAP-2480).
	CursorAdapterRestored bool `json:"cursor_adapter_restored"`

	// probeFailed marks a failure document that reports no deployment
	// state at all (no installed field and no pending transaction): the
	// installer refused before it could read the host.
	probeFailed bool
}

var (
	windowsEnterpriseStandaloneRunner = runWindowsEnterprisePowerShell7
	// windowsEnterpriseStandaloneObserver records a finished standalone
	// result (registration, event log, lifecycle log). Tests replace it.
	windowsEnterpriseStandaloneObserver = observeWindowsEnterpriseStandaloneResult
	// windowsEnterpriseStandaloneFootprint reports whether any standalone
	// deployment state or service exists; uninstall on a clean host is a
	// no-op.
	windowsEnterpriseStandaloneFootprint = windowsEnterpriseStandaloneFootprintPresent
	windowsEnterpriseEnsureDriftDetector = windowsEnterpriseEnsureDrift
	// windowsEnterpriseEnsureConfigLoader reads the standalone config ensure
	// enumerates the first guardian manifest from.
	windowsEnterpriseEnsureConfigLoader = config.LoadFromFile

	windowsEnterpriseMessageCodePattern = regexp.MustCompile(`^([a-z][a-z0-9_]{2,63}):\s`)
)

// windowsEnterpriseLifecycleBusyMarker is the installer's lock-contention
// diagnostic (Enter-DefenseClawLifecycleLock).
const windowsEnterpriseLifecycleBusyMarker = "holds the protected file lock"

func windowsEnterpriseStandaloneRequested(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && (windowsEnterpriseStandalone(opts) ||
		managed.IsStandaloneProfile(opts.profile))
}

// windowsEnterpriseUnknownProfileRequested reports a --profile that names
// neither profile. Secure Client Setup never passes one, so the refusal uses
// the standalone result and its invalid-arguments exit 1639 (GAP-1962).
func windowsEnterpriseUnknownProfileRequested(opts *windowsEnterpriseLifecycleOptions) bool {
	if opts == nil {
		return false
	}
	profile := managed.NormalizeEnterpriseProfile(opts.profile)
	return profile != "" && profile != managed.ProfileSecureClient && profile != managed.ProfileStandalone
}

// runWindowsEnterprisePowerShell7 runs the installer on the validated
// PowerShell 7 engine and captures its schema-1 JSON document.
func runWindowsEnterprisePowerShell7(
	ctx context.Context,
	cmd *cobra.Command,
	script string,
	args []string,
) (windowsEnterpriseStandaloneRun, error) {
	engine, err := windowsEnterprisePowerShell7Finder()
	if err != nil {
		return windowsEnterpriseStandaloneRun{}, err
	}
	environment := func(temp string) ([]string, error) {
		return trustedWindowsEnterprisePowerShell7Environment(temp, engine)
	}
	stderr := &windowsEnterpriseOutputCapture{}
	capture, runErr := runWindowsEnterprisePowerShellEngine(
		ctx, cmd, engine.Executable, environment, script, args,
		io.Discard, io.MultiWriter(cmd.ErrOrStderr(), stderr),
	)
	run := windowsEnterpriseStandaloneRun{}
	if capture != nil {
		run.Output = append([]byte(nil), capture.buffer.Bytes()...)
		run.Truncated = capture.truncated
	}
	if runErr != nil {
		// A nonzero installer exit that still produced its JSON document is
		// a reported failure, not a launch failure.
		if code, ok := windowsEnterpriseInstallerExitCode(runErr); ok && len(bytes.TrimSpace(run.Output)) != 0 {
			run.ExitCode = code
			return run, nil
		}
		// A refusal before the installer could emit JSON (engine, bitness,
		// language mode) names its stable code on stderr; keep it.
		if detail := windowsEnterpriseStderrCode(stderr.buffer.Bytes()); detail != "" {
			return run, fmt.Errorf("%s (%w)", detail, runErr)
		}
		return run, runErr
	}
	return run, nil
}

// windowsEnterpriseStderrCode returns the first stderr line that carries a
// stable refusal code.
func windowsEnterpriseStderrCode(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		for _, code := range windowsEnterpriseKnownCodes {
			if index := strings.Index(line, code+":"); index >= 0 {
				detail := line[index:]
				if len(detail) > windowsEnterpriseDiagnosticMax {
					detail = detail[:windowsEnterpriseDiagnosticMax]
				}
				return detail
			}
		}
	}
	return ""
}

var windowsEnterpriseInstallerExitPattern = regexp.MustCompile(`\(exit code (-?[0-9]+)\)|exited with code (-?[0-9]+)`)

func windowsEnterpriseInstallerExitCode(err error) (int, bool) {
	match := windowsEnterpriseInstallerExitPattern.FindStringSubmatch(err.Error())
	if match == nil {
		return 0, false
	}
	value := match[1]
	if value == "" {
		value = match[2]
	}
	code, parseErr := strconv.Atoi(value)
	return code, parseErr == nil
}

// runWindowsEnterpriseStandaloneAction runs one explicit lifecycle action
// and reports it as a schema-2 result.
func runWindowsEnterpriseStandaloneAction(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	args []string,
) error {
	if action == "uninstall" {
		present, err := windowsEnterpriseStandaloneFootprint()
		if err == nil && !present {
			result := newWindowsEnterpriseStandaloneResult(action, opts)
			result.Noop = true
			result.NoopReason = "not_installed"
			result.Inspection.Local = "disabled"
			return finishWindowsEnterpriseStandalone(cmd, opts, result, 0)
		}
	}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, args)
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	if action == "uninstall" && windowsEnterpriseRecoveredFailedInstall(report) {
		// Uninstall rolled back a failed first install. The host is at the
		// requested end state, so an MDM must see success, not a retryable
		// failure that would loop forever.
		if present, err := windowsEnterpriseStandaloneFootprint(); err == nil && !present {
			result.Noop = true
			result.NoopReason = "recovered_failed_install"
			result.AddWarning("recovered_failed_install", "uninstall rolled back a failed initial install; nothing remains installed")
			return finishWindowsEnterpriseStandalone(cmd, opts, result, 0)
		}
	}
	if (action == "status" || action == "verify") && !windowsEnterpriseIsElevated() && windowsEnterpriseInstallerRefusedModule(report) {
		// A standard account cannot run the installer's own integrity checks,
		// which only an administrator can; its refusal read as a broken
		// install with administrator-only advice (GAP-1720). Its --json
		// result still reports what any account can read: the recorded
		// deployment and the service states (GAP-2162).
		applyWindowsEnterpriseRecordedDeployment(result)
		result.AddError("elevation_required", windowsEnterpriseStandardUserInspectionAnswer(action))
		return finishWindowsEnterpriseStandalone(cmd, opts, result, enterprisestatus.WindowsExitAccessDenied)
	}
	if action != "status" {
		report = windowsEnterpriseFailureWithDeploymentState(ctx, cmd, opts, script, report)
	}
	applyWindowsEnterpriseInstallerReport(result, opts, report, run)
	if (action == "status" || action == "verify") && report.Installed {
		if report.CursorTargetEnabled {
			result.AddWarning("cursor_agent_prompt_hook_unavailable", "Cursor Agent CLI 2026.10.01 does not send beforeSubmitPrompt; prompt text is not inspected. Check hook_decision rows for actual coverage")
		}
		if report.GatewayReady {
			if body, err := windowsStandaloneGatewayHealth(); err == nil {
				appendStandaloneGatewayWarnings(result, body)
			}
		}
	}
	addWindowsEnterpriseNothingInstalledError(result, report, action)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// The standalone gateway's machine API uses the default loopback port. This
// advisory read is bounded; the installer has already established readiness.
func windowsStandaloneGatewayHealth() ([]byte, error) {
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", config.DefaultGatewayAPIPort))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway health returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// addWindowsEnterpriseNothingInstalledError fails an install or upgrade
// whose lifecycle reported success while the host has no deployment. An MDM
// or administrator reading ok with exit 0 would treat the device as
// protected while nothing is installed (GAP-1079).
func addWindowsEnterpriseNothingInstalledError(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport, action string) {
	if action != "install" && action != "upgrade" {
		return
	}
	if report == nil || !report.OK || report.Installed || report.TransactionPending || len(result.Errors) != 0 {
		return
	}
	result.AddError("not_installed", fmt.Sprintf(
		"%s reported success but left no DefenseClaw deployment on this host, so nothing protects it; run the same command again, and if it repeats keep the enterprise lifecycle log for support",
		action,
	))
}

// windowsEnterpriseFailureWithDeploymentState gives a lifecycle action that
// failed before it read the host (the installer's failure document carries
// no installed state) the deployment state a status probe reads, and keeps
// the action's own errors. Without it a refused repair reported installed
// false, no services and readiness all false for a deployment that was
// installed and running, and an MDM reading that result would treat the
// host as uninstalled; a failing verify did the same. A probe that cannot
// read the host leaves the report as it was.
func windowsEnterpriseFailureWithDeploymentState(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	failure *windowsEnterpriseInstallerReport,
) *windowsEnterpriseInstallerReport {
	if failure == nil || !failure.probeFailed {
		return failure
	}
	status, _, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script,
		windowsEnterprisePowerShellArgs("status", windowsEnterpriseEnsureProbeOptions(opts)))
	if err != nil || status.probeFailed {
		return failure
	}
	merged := *status
	merged.OK = false
	merged.Action = failure.Action
	merged.Error, merged.Errors = failure.Error, failure.Errors
	merged.UserRegistrationsPending, merged.UserRegistrationsFailed = failure.UserRegistrationsPending, failure.UserRegistrationsFailed
	merged.RecoveryGatewayRuns, merged.RecoveryGatewayRefusal = failure.RecoveryGatewayRuns, failure.RecoveryGatewayRefusal
	return &merged
}

// windowsEnterpriseRecoveredFailedInstall reports whether the lifecycle
// stopped only because it rolled back a failed initial install, which leaves
// the host without a deployment rather than broken.
func windowsEnterpriseRecoveredFailedInstall(report *windowsEnterpriseInstallerReport) bool {
	if report == nil || report.OK || report.Installed || report.TransactionPending {
		return false
	}
	messages := append([]string{}, report.Errors...)
	if strings.TrimSpace(report.Error) != "" {
		messages = append(messages, report.Error)
	}
	if len(messages) == 0 {
		return false
	}
	for _, message := range messages {
		if !strings.Contains(message, "recovered a failed initial install") {
			return false
		}
	}
	return true
}

func runWindowsEnterpriseStandaloneInstaller(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	args []string,
) (*windowsEnterpriseInstallerReport, windowsEnterpriseStandaloneRun, error) {
	if !containsString(args, "-Json") {
		args = append(append([]string{}, args...), "-Json")
	}
	run, err := windowsEnterpriseStandaloneRunner(ctx, cmd, script, args)
	if err != nil {
		return nil, run, err
	}
	if run.Truncated {
		return nil, run, errors.New("the installer's JSON report exceeded the capture limit")
	}
	report, parseErr := parseWindowsEnterpriseInstallerReport(run.Output)
	if parseErr != nil {
		return nil, run, fmt.Errorf("installer exited %d without a valid JSON report: %w", run.ExitCode, parseErr)
	}
	return report, run, nil
}

// parseWindowsEnterpriseInstallerReport takes the last JSON object line;
// PowerShell may emit warnings or host output before the document.
func parseWindowsEnterpriseInstallerReport(body []byte) (*windowsEnterpriseInstallerReport, error) {
	lines := bytes.Split(trimWindowsJSONBOM(bytes.TrimSpace(body)), []byte("\n"))
	for index := len(lines) - 1; index >= 0; index-- {
		line := bytes.TrimSpace(trimWindowsJSONBOM(lines[index]))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var report windowsEnterpriseInstallerReport
		if err := json.Unmarshal(line, &report); err != nil {
			continue
		}
		if report.SchemaVersion != 1 {
			return nil, fmt.Errorf("installer report schema_version %d is not 1", report.SchemaVersion)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(line, &fields); err == nil {
			// A standalone failure carries its recovery evidence, including
			// transaction_pending: false, without reading the host, so only
			// a pending transaction counts as deployment state here.
			_, installed := fields["installed"]
			report.probeFailed = !report.OK && !installed && !report.TransactionPending
		}
		return &report, nil
	}
	return nil, errors.New("no JSON object in installer output")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func newWindowsEnterpriseStandaloneResult(action string, opts *windowsEnterpriseLifecycleOptions) *enterprisestatus.Result {
	version := strings.TrimSpace(opts.productVersion)
	if version == "" {
		version = strings.TrimSpace(appVersion)
	}
	result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", version)
	result.Inspection = enterprisestatus.Inspection{Local: "active", AIDefense: "disabled"}
	for _, record := range opts.ignoredDeploymentRecords {
		result.AddWarning("untrusted_deployment_record", "ignored a deployment record an administrator did not write: "+record)
	}
	return result
}

func applyWindowsEnterpriseInstallerReport(
	result *enterprisestatus.Result,
	opts *windowsEnterpriseLifecycleOptions,
	report *windowsEnterpriseInstallerReport,
	run windowsEnterpriseStandaloneRun,
) {
	result.Installed = report.Installed
	result.TransactionPending = report.TransactionPending
	result.InstalledVersion = report.InstalledVersion
	if !report.Installed {
		// Nothing inspects verdicts once the deployment is gone (GAP-2257).
		result.Inspection.Local = "disabled"
	} else if !report.GatewayReady {
		// The gateway inspects verdicts; while it is not ready, report what
		// Linux and macOS report when it does not answer (GAP-2285).
		result.Inspection.Local = "unknown"
	}
	if opts != nil {
		opts.deploymentTrustMode = windowsEnterpriseRecordedTrustMode(report.TrustMode)
	}
	for _, service := range []struct {
		name, state, kind string
	}{
		{report.GatewayService, report.GatewayServiceState, "gateway"},
		{report.GuardianService, report.GuardianServiceState, "guardian"},
		{report.EnumeratorService, report.EnumeratorServiceState, "enumerator"},
		{report.SensorHelperService, report.SensorHelperServiceState, "sensor_helper"},
	} {
		if strings.TrimSpace(service.name) == "" {
			continue
		}
		result.Services = append(result.Services, enterprisestatus.Service{
			Name:     service.name,
			Kind:     service.kind,
			State:    service.state,
			Required: true,
		})
	}
	result.Readiness = enterprisestatus.Readiness{
		Gateway:      report.GatewayReady,
		Guardian:     report.GuardianReady,
		Enumerator:   report.EnumeratorServiceState == "running",
		SensorHelper: report.SensorHelperServiceState == "running",
	}
	if report.CodexTargetEnabled {
		result.MachinePolicy["codex"] = windowsEnterpriseMachinePolicy(report.CodexMachineRequirementsReady)
	}
	if report.ClaudeTargetEnabled {
		result.MachinePolicy["claudecode"] = windowsEnterpriseMachinePolicy(report.ClaudeEffectivePolicyVerified)
	}
	if report.CursorTargetEnabled {
		result.MachinePolicy["cursor"] = windowsEnterpriseMachinePolicy(report.GuardianReady)
	}
	result.CoverageComplete = report.Installed && report.GuardianReady && !report.TransactionPending
	result.SecurityComplete = report.SecurityComplete
	if report.Installed {
		enrollment, err := readWindowsEnterpriseStandaloneEnrollment()
		if err == nil {
			result.Enrollment = enrollment
		}
		aiDefense, err := readWindowsEnterpriseStandaloneAIDefense()
		if err == nil && aiDefense {
			result.Inspection.AIDefense = "unavailable:gateway_not_ready"
			if report.GatewayReady {
				result.Inspection.AIDefense = "ok"
			}
		}
		applyWindowsEnterpriseUnprotectedAgents(result)
		applyWindowsEnterpriseEnrolledConnectors(result)
		applyWindowsEnterpriseAmpMachineFolder(result)
		applyWindowsEnterpriseAccountFolders(result)
	}
	applyWindowsEnterpriseGatewayStartFailure(result, report)
	applyWindowsEnterpriseAPIPortHolders(result, report)
	messages := append([]string{}, report.Errors...)
	if len(messages) == 0 && strings.TrimSpace(report.Error) != "" {
		messages = append(messages, report.Error)
	}
	// A failed lifecycle tells the administrator what failed in plain terms
	// and what to run next; internal security-descriptor detail stays in a
	// lifecycle_diagnostic warning for support.
	lifecycle := windowsEnterpriseStandaloneLifecycleAction(result.Action)
	firstError := len(result.Errors)
	for _, message := range messages {
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		enumeratorCode := ""
		if text, specific, unwrapped := windowsEnterpriseEnumeratorFailureText(message); unwrapped {
			result.AddWarning("lifecycle_diagnostic", windowsEnterpriseBoundedDiagnostic(message))
			message, enumeratorCode = text, specific
		}
		message = windowsEnterpriseNameServiceRights(message, result.Action == "status" || result.Action == "verify")
		code := windowsEnterpriseMessageCode(message, "lifecycle_error")
		if enumeratorCode != "" {
			code = enumeratorCode
		}
		if lifecycle {
			original := message
			if text, ok := windowsEnterpriseInstallerBuildMismatchText(message, result.Action, opts != nil && opts.purge); ok {
				result.AddWarning("lifecycle_diagnostic", windowsEnterpriseBoundedDiagnostic(message))
				message, code = text, "installer_build_mismatch"
			}
			if text, internal := windowsEnterpriseStandaloneErrorText(message); internal {
				result.AddWarning("lifecycle_diagnostic", windowsEnterpriseBoundedDiagnostic(message))
				message = text
			}
			message += windowsEnterprisePerUserDataDirNextStep(original, message)
			message += windowsEnterpriseInvalidRuntimeBundleNextStep(original)
		}
		result.AddError(code, message)
	}
	if !report.OK && len(result.Errors) == 0 {
		code := "not_ready"
		if !report.Installed {
			code = "not_installed"
		}
		result.AddError(code, windowsEnterpriseNotHealthyMessage(result.Services, run.ExitCode))
	}
	if lifecycle && !report.OK && len(result.Errors) > firstError {
		configPath := ""
		purge := false
		if opts != nil {
			configPath = opts.configPath
			purge = opts.purge
		}
		if next := windowsEnterpriseStandaloneNextStep(
			result.Action,
			configPath,
			purge,
			report.TransactionPending,
			decodeWindowsEnterpriseRecoveryGatewayRuns(report.RecoveryGatewayRuns),
			decodeWindowsEnterpriseRecoveryGatewayRefusal(report.RecoveryGatewayRefusal),
		); next != "" {
			result.Errors[firstError].Message += " " + next
		}
	}
	if !lifecycle && !report.OK && !report.TransactionPending && len(result.Errors) > firstError {
		result.Errors[firstError].Message += windowsEnterpriseStoppedServiceNextStep(result.Services)
	}
	if !lifecycle && report.TransactionPending {
		configPath := ""
		if opts != nil {
			configPath = opts.configPath
		}
		step := windowsEnterprisePendingInspectionStep(configPath)
		named := false
		for i := firstError; i < len(result.Errors); i++ {
			if message := result.Errors[i].Message; strings.Contains(message, "lifecycle transaction is pending") {
				result.Errors[i].Message = strings.TrimSuffix(strings.TrimSuffix(message, "; run Repair"), ".") + ". " + step
				named = true
			}
		}
		if !named {
			result.AddWarning("transaction_pending", step)
		}
	}
	addWindowsEnterpriseUserRegistrationWarnings(result, report)
	if opts != nil && opts.purge {
		addWindowsEnterpriseUserStateWarning(result, report)
	}
	addWindowsEnterpriseMachineStateWarning(result, report)
	addWindowsEnterpriseRecoveryGatewayWarnings(result, report)
	// Only when nothing above explains it. A completed uninstall leaves
	// nothing to secure; only a deployment that is still installed (or a
	// lifecycle stuck mid-transaction) reports why its security is not
	// complete.
	if report.Installed || report.TransactionPending {
		addEnterpriseSecurityIncompleteReasons(result, report.TransactionPending)
	}
}

// addWindowsEnterpriseUserStateWarning names each enrolled account whose
// DefenseClaw per-user data a purge removed (in Changes), and each one it
// could not remove, with the reason. What stays holds per-user hook tokens
// that nothing accepts any more.
func addWindowsEnterpriseUserStateWarning(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	for _, entry := range windowsEnterpriseReportStrings(report.UserStatePurged) {
		result.Changes = append(result.Changes, windowsEnterprisePurgedUserStateChange(entry))
	}
	var notLocalSystem, remaining []string
	for _, entry := range windowsEnterpriseReportStrings(report.UserStateRemaining) {
		if account, found := strings.CutSuffix(entry, ": "+windowsManagedHooksNotLocalSystemReason); found {
			notLocalSystem = append(notLocalSystem, account)
			continue
		}
		remaining = append(remaining, entry)
	}
	if len(notLocalSystem) > 0 {
		// A purge that did not run as LocalSystem removed the machine
		// deployment but none of these accounts' data: it is not the
		// delete-everything result the caller asked for, so it fails
		// (GAP-1111).
		result.AddError("per_user_state_remaining", fmt.Sprintf(
			"--purge did not run as LocalSystem, so it removed the machine deployment but not the DefenseClaw per-user data, binaries and agent registrations of %d enrolled account(s). To remove them, %s. Accounts: %s",
			len(notLocalSystem),
			windowsEnterpriseLocalSystemRemedy("/uninstall PURGE=1"),
			windowsEnterpriseBoundedLabels(notLocalSystem),
		))
	}
	if len(remaining) > 0 {
		result.AddWarning("per_user_state_remaining", fmt.Sprintf(
			"--purge could not remove all DefenseClaw per-user data and binaries of %d enrolled account(s), which keep per-user hook tokens that nothing accepts any more; remove what stays as LocalSystem: %s",
			len(remaining),
			windowsEnterpriseBoundedLabels(remaining),
		))
	}
}

// addWindowsEnterpriseMachineStateWarning names the machine folders outside
// StateRoot that the uninstall could not remove. Every standalone uninstall
// removes them, not only --purge, so the MDM default uninstall reports them
// too (GAP-1734).
func addWindowsEnterpriseMachineStateWarning(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if kept := windowsEnterpriseReportStrings(report.MachineStateRemaining); len(kept) > 0 {
		result.AddWarning("machine_state_remaining", fmt.Sprintf(
			"the uninstall could not remove %d DefenseClaw machine folder(s); remove them from an elevated prompt: %s",
			len(kept),
			windowsEnterpriseBoundedLabels(kept),
		))
	}
}

// addWindowsEnterpriseRecoveryGatewayWarnings records which gateway a
// pending-transaction recovery ran and why, and what the rollback of a failed
// first install left. Ensure can apply the same installer report twice (once
// when a repair recovers, again as the final result), so an identical warning
// is recorded once.
func addWindowsEnterpriseRecoveryGatewayWarnings(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if result == nil || report == nil {
		return
	}
	warnings := windowsEnterpriseRecoveryGatewayWarnings(
		decodeWindowsEnterpriseRecoveryGatewayRuns(report.RecoveryGatewayRuns),
		decodeWindowsEnterpriseRecoveryGatewayRefusal(report.RecoveryGatewayRefusal),
	)
	warnings = append(warnings, windowsEnterpriseRollbackLeftoverWarnings(report.RollbackLeftovers)...)
	if removed := strings.TrimSpace(report.StaleLifecycleJournalRemoved); removed != "" {
		// The lifecycle deleted a protected journal on its own; say so in
		// the result and the lifecycle log (GAP-1680).
		warnings = append(warnings, enterprisestatus.Message{
			Code: "stale_lifecycle_journal_removed",
			Message: "Setup removed the stale committed managed-hook lifecycle journal " +
				"(managed-hooks-lifecycle-journal.json in the protected install state) because its retire could not complete: " +
				windowsEnterpriseBoundedDiagnostic(removed),
		})
	}
	if report.CursorAdapterRestored {
		// The lifecycle rewrote a protected file on its own; say so in the
		// result and the lifecycle log (GAP-2480).
		warnings = append(warnings, enterprisestatus.Message{
			Code: "cursor_adapter_restored",
			Message: `DefenseClaw restored the changed or missing Cursor enterprise adapter ` +
				`(C:\ProgramData\Cursor\defenseclaw-hook.ps1) from this release`,
		})
	}
	for _, warning := range warnings {
		duplicate := false
		for _, existing := range result.Warnings {
			if existing == warning {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result.AddWarning(warning.Code, warning.Message)
		}
	}
}

// windowsEnterpriseRollbackLeftoverWarnings names each item the rollback of
// a failed first install could not remove, with what removes it. A file the
// account changed after DefenseClaw wrote it is kept whole, so only a manual
// edit removes DefenseClaw's entries from it. Everything else is removed by a
// successful install followed by an uninstall, both as LocalSystem while the
// accounts are signed in (an uninstall acts only for signed-in accounts). An
// administrator at an elevated prompt gets LocalSystem from a one-time
// scheduled task, which the remedy names.
func windowsEnterpriseRollbackLeftoverWarnings(raw json.RawMessage) []enterprisestatus.Message {
	var warnings []enterprisestatus.Message
	for _, leftover := range windowsEnterpriseReportStrings(raw) {
		remedy := "to remove it, run DefenseClaw Setup /ensure and then /uninstall, both as LocalSystem " + windowsEnterpriseActiveSessionWhen + " " +
			"(an MDM system context, or from an elevated prompt a one-time scheduled task that runs as SYSTEM; " +
			"see \"Run Setup as LocalSystem\" in the Windows enterprise guide)"
		if strings.HasSuffix(leftover, ", which changed after DefenseClaw wrote it") {
			remedy = "remove DefenseClaw's entries from that file by hand"
		}
		warnings = append(warnings, enterprisestatus.Message{
			Code:    "rollback_leftover",
			Message: fmt.Sprintf("the rollback of the failed first install could not remove %s; %s", leftover, remedy),
		})
	}
	return warnings
}

func windowsEnterpriseBoundedDiagnostic(message string) string {
	if len(message) > windowsEnterpriseDiagnosticMax {
		return message[:windowsEnterpriseDiagnosticMax] + "..."
	}
	return message
}

// windowsEnterpriseUserRegistrationListMax bounds how many connector/SID
// labels one warning names.
const windowsEnterpriseUserRegistrationListMax = 20

// addWindowsEnterpriseUserRegistrationWarnings tells the administrator which
// DefenseClaw per-user registrations an uninstall left in place: those of
// users who were signed out, of every user when the uninstall did not run as
// LocalSystem, and removals that failed. They stay inert (enrollment
// revoked, hook runtime and binary removed).
func addWindowsEnterpriseUserRegistrationWarnings(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	failed := windowsEnterpriseReportStrings(report.UserRegistrationsFailed)
	if pending := windowsEnterpriseReportStrings(report.UserRegistrationsPending); len(pending) > 0 {
		reason := "those accounts " + windowsEnterpriseNoActiveSession
		// "not LocalSystem" means no removal was attempted: the pending
		// warning says so and names the remedy, so it is not also reported
		// as a failed removal (GAP-1568).
		var attempted []string
		for _, failure := range failed {
			if strings.HasPrefix(failure, windowsManagedHooksRegistrationsNotRemovedPrefix) {
				reason = "this uninstall did not run as LocalSystem"
				continue
			}
			attempted = append(attempted, failure)
		}
		failed = attempted
		result.AddWarning("user_registrations_pending", fmt.Sprintf(
			"uninstall could not act as %d user connector registration(s) because %s; DefenseClaw's inert registration stays in that account's agent configuration. To remove them, %s. Accounts: %s",
			len(pending),
			reason,
			windowsEnterpriseLocalSystemRemedy("/uninstall"),
			windowsEnterpriseBoundedLabels(windowsEnterpriseRegistrationsByAccount(pending)),
		))
	}
	if len(failed) > 0 {
		result.AddWarning("user_registrations_failed", fmt.Sprintf(
			"removing DefenseClaw per-user registrations failed: %s. The entries that stay are inert (the managed install is gone); remove the named DefenseClaw entries from those files as that user, or %s",
			windowsEnterpriseBoundedLabels(failed),
			windowsEnterpriseLocalSystemRemedy("/uninstall"),
		))
	}
}

// windowsEnterpriseRegistrationsByAccount groups "connector/SID" labels by
// account, named as "user (SID): connector, connector" where the SID
// resolves, so the administrator sees which accounts keep what.
func windowsEnterpriseRegistrationsByAccount(entries []string) []string {
	var order []string
	connectors := map[string][]string{}
	for _, entry := range entries {
		connector, sid, found := strings.Cut(entry, "/")
		if !found || strings.TrimSpace(sid) == "" {
			order = append(order, entry)
			continue
		}
		sid = strings.TrimSpace(sid)
		if _, seen := connectors[sid]; !seen {
			order = append(order, sid)
		}
		connectors[sid] = append(connectors[sid], strings.TrimSpace(connector))
	}
	labels := make([]string, 0, len(order))
	for _, key := range order {
		names, ok := connectors[key]
		if !ok {
			labels = append(labels, key)
			continue
		}
		labels = append(labels, enterpriseHookWindowsAccountLabel(enterpriseHookReconcileRow{SID: key})+": "+strings.Join(names, ", "))
	}
	return labels
}

// windowsEnterpriseReportStrings decodes a string list the lifecycle
// forwarded; a single string is one item and anything else is ignored.
func windowsEnterpriseReportStrings(raw json.RawMessage) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var single string
		if json.Unmarshal(raw, &single) != nil {
			return nil
		}
		list = []string{single}
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item = strings.Join(strings.Fields(item), " "); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func windowsEnterpriseBoundedLabels(items []string) string {
	if len(items) <= windowsEnterpriseUserRegistrationListMax {
		return strings.Join(items, "; ")
	}
	return fmt.Sprintf(
		"%s; and %d more",
		strings.Join(items[:windowsEnterpriseUserRegistrationListMax], "; "),
		len(items)-windowsEnterpriseUserRegistrationListMax,
	)
}

// windowsEnterpriseUnprotectedAgentsReader reads the enumerator's
// unprotected-agents record; tests replace it.
var windowsEnterpriseUnprotectedAgentsReader = func() ([]enterprisehooks.UnprotectedAgent, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	return enterprisehooks.ReadWindowsUnprotectedAgents(layout.ManifestPath)
}

// applyWindowsEnterpriseUnprotectedAgents names every agent the enumerator
// found installed for an eligible user but could not enroll (no verified
// hook contract, below the platform minimum, an install the guardian cannot
// manage, or an unreadable version) and marks the deployment
// security-incomplete. Each is one account's agent, so every action, verify
// included, reports it as a warning for that account: the rest of the host
// stays compliant, and ensure never loops on a state only the user or
// administrator can change. An unreadable record hides which agents they
// are, so verify fails on it.
func applyWindowsEnterpriseUnprotectedAgents(result *enterprisestatus.Result) {
	agents, err := windowsEnterpriseUnprotectedAgentsReader()
	if err != nil {
		// A token that cannot read the protected record reports nothing
		// about it, as for the manifest summary.
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			message := "the enumerator's unprotected-agents record is unreadable: " + err.Error()
			if result.Action == "verify" {
				result.AddError(enterprisehooks.UnprotectedCodeAgentUnprotected, message)
			} else {
				result.AddWarning(enterprisehooks.UnprotectedCodeAgentUnprotected, message)
			}
			result.SecurityComplete = false
		}
		return
	}
	for _, agent := range agents {
		// unverified_versions: refuse that nothing enforces fails verify.
		if agent.Refusal == enterprisehooks.RefusalMissing && result.Action == "verify" {
			result.AddError(agent.Code, agent.Message())
		} else {
			result.AddWarning(agent.Code, agent.Message())
		}
		result.SecurityComplete = false
	}
}

// windowsEnterpriseAmpMachineFolderProblems lists why %ProgramData%\ampcode
// is not held for the administrator; replaceable in tests.
var windowsEnterpriseAmpMachineFolderProblems = func() []string {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return []string{"resolve ProgramData for the Amp machine folder: " + err.Error()}
	}
	return enterprisepolicy.InspectWindowsAmpMachineFolder(enterprisepolicy.Options{GOOS: "windows", WindowsProgramData: programData})
}

// windowsEnterpriseGatewayStartFailure returns the last error the gateway
// service wrote to its log, and that log's path; tests replace it.
var windowsEnterpriseGatewayStartFailure = readWindowsEnterpriseGatewayStartFailure

// windowsEnterpriseGatewayLogTailBytes bounds how much of the gateway log
// status reads.
const windowsEnterpriseGatewayLogTailBytes = 64 << 10

func readWindowsEnterpriseGatewayStartFailure() (string, string) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil || strings.TrimSpace(layout.LogDir) == "" {
		return "", ""
	}
	path := filepath.Join(layout.LogDir, "gateway", "gateway.log")
	file, err := os.Open(path)
	if err != nil {
		return "", path
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", path
	}
	offset := info.Size() - windowsEnterpriseGatewayLogTailBytes
	if offset < 0 {
		offset = 0
	}
	tail := make([]byte, info.Size()-offset)
	if _, err := file.ReadAt(tail, offset); err != nil && !errors.Is(err, io.EOF) {
		return "", path
	}
	reason := ""
	for _, line := range strings.Split(string(tail), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "Error: ") {
			reason = strings.TrimSpace(strings.TrimPrefix(line, "Error: "))
		}
	}
	return reason, path
}

// applyWindowsEnterpriseGatewayStartFailure names, for status and verify,
// why an installed gateway service is not running: a gateway that failed
// on every start was reported only as "not healthy (installer exit 1)". The
// reason is the last error the service logged before it exited.
func applyWindowsEnterpriseGatewayStartFailure(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if (result.Action != "status" && result.Action != "verify") || !report.Installed || report.TransactionPending ||
		strings.TrimSpace(report.GatewayService) == "" || report.GatewayServiceState == "running" {
		return
	}
	reason, logPath := windowsEnterpriseGatewayStartFailure()
	if reason == "" {
		return
	}
	message := fmt.Sprintf("the %s service is not running; the last error it logged: %s (log: %s)",
		report.GatewayService, windowsEnterpriseBoundedDiagnostic(reason), logPath)
	if strings.Contains(reason, "Access is denied") {
		message += "; " + windowsEnterpriseRepairServiceAccess
	}
	result.AddError("gateway_start_failed", message)
}

// windowsEnterpriseRepairServiceAccess is what restores a DefenseClaw
// service's access to its folders.
const windowsEnterpriseRepairServiceAccess = "run defenseclaw enterprise windows repair --profile standalone from an elevated prompt to restore the service's access"

// windowsEnterpriseServiceRightsPattern matches the lifecycle's report that a
// managed path lacks the rights of a service's virtual account, which it
// names only by its S-1-5-80 SID.
var windowsEnterpriseServiceRightsPattern = regexp.MustCompile(
	`managed path is missing required rights for (S-1-5-80(?:-[0-9]+)+) \(required=([^ )]*) actual=([^)]*)\): (.+)$`)

// windowsEnterpriseServiceSIDName returns the service whose virtual account
// (NT SERVICE\<name>) sid is, or "" for any other SID; tests replace it.
var windowsEnterpriseServiceSIDName = func(sid string) string {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return ""
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil || !strings.EqualFold(domain, "NT SERVICE") {
		return ""
	}
	return account
}

// windowsEnterpriseNameServiceRights rewrites a missing-rights report about a
// service SID to name the service; with repair it also says what restores
// the access.
func windowsEnterpriseNameServiceRights(message string, repair bool) string {
	match := windowsEnterpriseServiceRightsPattern.FindStringSubmatchIndex(message)
	if match == nil {
		return message
	}
	sid := message[match[2]:match[3]]
	name := windowsEnterpriseServiceSIDName(sid)
	if name == "" {
		return message
	}
	text := fmt.Sprintf("the %s service (NT SERVICE\\%s, %s) is missing required rights on %s (required %s, has %s)",
		name, name, sid, message[match[8]:match[9]], message[match[4]:match[5]], message[match[6]:match[7]])
	if repair {
		text += "; " + windowsEnterpriseRepairServiceAccess
	}
	return message[:match[0]] + text
}

// windowsEnterpriseManifestAccount is one account the installed manifest
// holds rows for.
type windowsEnterpriseManifestAccount struct {
	User, SID, Home string
	Rows            int
}

// windowsEnterpriseManifestAccounts reads the installed manifest's accounts;
// windowsEnterpriseAccountCreatedDataDir reports an account-created data
// folder, and windowsEnterpriseAccountDeleted a local account SID that no
// longer names an account. Tests replace them.
var (
	windowsEnterpriseManifestAccounts      = readWindowsEnterpriseManifestAccounts
	windowsEnterpriseAccountCreatedDataDir = enterprisehooks.WindowsAccountCreatedDataDir
	windowsEnterpriseAccountDeleted        = func(sid string) bool {
		// A domain or Entra account's lookup also fails while its directory
		// is unreachable; never tell the administrator to remove that
		// profile.
		parsed, err := windows.StringToSid(sid)
		if err != nil || !enterprisehooks.WindowsLocalAccountSID(parsed.String()) {
			return false
		}
		_, _, _, err = parsed.LookupAccount("")
		return errors.Is(err, windows.ERROR_NONE_MAPPED)
	}
)

func readWindowsEnterpriseManifestAccounts() ([]windowsEnterpriseManifestAccount, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ManifestPath, 16<<20)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Targets []struct {
			User     string `yaml:"user"`
			SID      string `yaml:"sid"`
			UserHome string `yaml:"user_home"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	var accounts []windowsEnterpriseManifestAccount
	index := map[string]int{}
	for _, target := range manifest.Targets {
		key := strings.ToUpper(strings.TrimSpace(target.SID))
		if key == "" {
			continue
		}
		if at, seen := index[key]; seen {
			accounts[at].Rows++
			continue
		}
		index[key] = len(accounts)
		accounts = append(accounts, windowsEnterpriseManifestAccount{
			User: target.User, SID: strings.TrimSpace(target.SID), Home: target.UserHome, Rows: 1,
		})
	}
	return accounts, nil
}

// applyWindowsEnterpriseAccountFolders names two accounts the manifest keeps
// rows for that the administrator should know about: one that was deleted
// while its profile folder stays (the enumerator keeps its rows until the
// profile is removed), and one that created its own
// %USERPROFILE%\.defenseclaw before it was enrolled (the guardian adopts
// it at the account's next sign-in; Upgrade and Repair leave it alone).
func applyWindowsEnterpriseAccountFolders(result *enterprisestatus.Result) {
	accounts, err := windowsEnterpriseManifestAccounts()
	if err != nil {
		return
	}
	for _, account := range accounts {
		label := account.SID
		if strings.TrimSpace(account.User) != "" {
			label = fmt.Sprintf("%s (%s)", account.User, account.SID)
		}
		if _, err := os.Lstat(account.Home); err != nil {
			if errors.Is(err, os.ErrNotExist) && windowsEnterpriseAccountDeleted(account.SID) {
				result.AddWarning("deleted_account_rows", fmt.Sprintf(
					"the account %s no longer exists and its profile folder %s was removed; the enumerator drops its %d enrollment row(s) "+
						"at its next pass, and until then the guardian reports them for this account only",
					label, account.Home, account.Rows))
			}
			continue
		}
		switch {
		case windowsEnterpriseAccountDeleted(account.SID):
			result.AddWarning("deleted_account_rows", fmt.Sprintf(
				"the account %s no longer exists; the enumerator drops its %d enrollment row(s) at its next pass although its "+
					"profile folder %s remains (remove it under System Properties > Advanced > User Profiles), and until then "+
					"the guardian reports them for this account only",
				label, account.Rows, account.Home))
		case windowsEnterpriseAccountCreatedDataDir(account.Home, account.SID):
			result.AddWarning("enrollment_pending_account_folder", fmt.Sprintf(
				"the account %s created %s itself, so it has no DefenseClaw runtime (for example when an agent it ran before enrollment "+
					"was refused, or after it moved DefenseClaw's folder away); DefenseClaw takes over that folder when the account next "+
					"signs in, and repair leaves it alone until then",
				label, filepath.Join(account.Home, ".defenseclaw")))
		}
	}
}

// windowsEnterpriseEnrolledConnectors returns the hook connectors the
// installed config enrols, loaded as the guardian loads it; replaceable in
// tests.
var windowsEnterpriseEnrolledConnectors = func() ([]string, error) {
	return windowsEnterpriseConfigConnectors("")
}

// windowsEnterpriseStagedConnectors returns the hook connectors a config
// handed to ensure enrols; replaceable in tests.
var windowsEnterpriseStagedConnectors = windowsEnterpriseConfigConnectors

// windowsEnterpriseConfigConnectors loads path (the installed config when
// empty) as the guardian loads the installed one and returns the hook
// connectors it enrols.
func windowsEnterpriseConfigConnectors(path string) ([]string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		path = layout.ConfigPath
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            path,
		"DEFENSECLAW_HOME":               layout.DataDir,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: layout.ServiceUser,
	})
	defer restore()
	cfg, err := config.LoadManagedFileForLifecycleRecovery(path)
	if err != nil {
		return nil, err
	}
	return enterprisehooks.EffectiveWindowsHookConnectors(cfg), nil
}

// refuseWindowsEnterpriseConnectorlessConfig refuses, before anything
// changes, a config that enrols no connector for a deployment whose
// installed config enrols at least one: applying it took DefenseClaw off
// every agent of every user while the lifecycle and the MDM reported
// success (GAP-0602). A config that cannot be read here is left to the
// lifecycle's own validation. Standalone only.
func refuseWindowsEnterpriseConnectorlessConfig(opts *windowsEnterpriseLifecycleOptions) error {
	path := strings.TrimSpace(opts.configPath)
	if !windowsEnterpriseStandalone(opts) || path == "" {
		return nil
	}
	staged, err := windowsEnterpriseStagedConnectors(path)
	if err != nil || len(staged) != 0 {
		return nil
	}
	installed, err := windowsEnterpriseEnrolledConnectors()
	if err != nil || len(installed) == 0 {
		return nil
	}
	return windowsEnterpriseInvalidArguments(
		"%s enrols no connector under guardrail.connectors, so applying it would stop protecting %s for every user; nothing was changed. "+
			"List the agents to protect (for example guardrail.connectors.claudecode: {}), or uninstall DefenseClaw to remove it",
		path, strings.Join(installed, ", "))
}

// applyWindowsEnterpriseEnrolledConnectors reports an installed config that
// enrols no connector: the enumerator then writes no target, so DefenseClaw
// protects no agent while every service reads healthy. verify fails on it;
// the other actions warn and report the deployment security-incomplete
// (GAP-0221). A config this token cannot load is left to the checks that
// report it.
func applyWindowsEnterpriseEnrolledConnectors(result *enterprisestatus.Result) {
	connectors, err := windowsEnterpriseEnrolledConnectors()
	if err != nil || len(connectors) != 0 {
		return
	}
	const code = "no_connectors_enabled"
	message := "config.yaml enrols no connector under guardrail.connectors, so DefenseClaw protects no agent; " +
		"list the agents to protect (for example guardrail.connectors.claudecode: {}) and run ensure"
	if result.Action == "verify" {
		result.AddError(code, message)
	} else {
		result.AddWarning(code, message)
	}
	result.SecurityComplete = false
}

// applyWindowsEnterpriseAmpMachineFolder reports an Amp machine folder a
// standard account created or can change: every account's Amp reads it.
func applyWindowsEnterpriseAmpMachineFolder(result *enterprisestatus.Result) {
	for _, problem := range windowsEnterpriseAmpMachineFolderProblems() {
		if result.Action == "verify" {
			result.AddError("machine_folder_not_held", problem)
		} else {
			result.AddWarning("machine_folder_not_held", problem)
		}
		result.SecurityComplete = false
	}
}

func windowsEnterpriseMachinePolicy(verified bool) enterprisestatus.MachinePolicyState {
	state := enterprisestatus.MachinePolicyState{Ownership: "merge", Lock: "enforce"}
	if verified {
		state.EffectiveLock = "enforce"
	}
	return state
}

// windowsEnterpriseMessageCode extracts a leading stable code
// ("powershell7_required: ...") or classifies well-known diagnostics.
func windowsEnterpriseMessageCode(message, fallback string) string {
	if strings.Contains(message, windowsEnterpriseLifecycleBusyMarker) {
		return "lifecycle_busy"
	}
	if strings.HasPrefix(message, errWindowsEnterpriseInvalidArguments.Error()+": ") {
		return "invalid_arguments"
	}
	if match := windowsEnterpriseMessageCodePattern.FindStringSubmatch(message); match != nil {
		return match[1]
	}
	for _, known := range windowsEnterpriseKnownCodes {
		if strings.Contains(message, known) {
			return known
		}
	}
	return fallback
}

// windowsEnterpriseKnownCodes are the stable refusal codes the standalone
// installer and module emit.
var windowsEnterpriseKnownCodes = []string{
	"powershell7_required",
	"powershell7_untrusted",
	"powershell_32bit_host",
	"powershell_constrained_language",
	"unsupported_architecture",
	"profile_conflict",
	"downgrade_refused",
	"root_squatted",
}

func windowsEnterpriseFailureCodeFor(result *enterprisestatus.Result) int {
	for _, message := range result.Errors {
		switch message.Code {
		case "lifecycle_busy":
			return enterprisestatus.WindowsExitBusy
		case "invalid_arguments":
			return enterprisestatus.WindowsExitInvalidArgs
		case "elevation_required":
			return enterprisestatus.WindowsExitAccessDenied
		}
	}
	return enterprisestatus.WindowsExitFailure
}

// finishWindowsEnterpriseStandalone records and prints a result and turns
// it into the process exit code.
func finishWindowsEnterpriseStandalone(
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	result *enterprisestatus.Result,
	failureCode int,
) error {
	exitCode := result.Finish("windows", failureCode)
	result.LogPath = windowsEnterpriseStandaloneObserver(result, opts)
	unknownProfile := windowsEnterpriseUnknownProfileRequested(opts) && exitCode != 0 && len(result.Errors) != 0
	// A standard account's refusal ran none of the deployment's checks or
	// changes, so it is one refusal line too, not a FAILED summary and "the
	// standalone enterprise status failed: ..." (GAP-2162). That holds for
	// every action: repair and ensure added "the standalone enterprise
	// <action> failed: elevation_required" after (or, interleaved with
	// stdout, before) the sentence (GAP-2262).
	oneLine := unknownProfile || (exitCode == enterprisestatus.WindowsExitAccessDenied &&
		len(result.Errors) != 0 && result.Errors[0].Code == "elevation_required")
	if opts.jsonOutput {
		if err := newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
			return withExitCode(fmt.Errorf("encode the standalone lifecycle result: %w", err), enterprisestatus.WindowsExitFailure)
		}
		// The JSON result carries every error in errors[] (GAP-2445).
		cmd.SilenceErrors = true
	} else if !oneLine {
		writeWindowsEnterpriseStandaloneSummary(cmd.OutOrStdout(), result)
	}
	if oneLine {
		// An unknown --profile selected no profile: one error line, not a
		// "(standalone): FAILED" summary or "the standalone enterprise ...
		// failed" of a profile never chosen (GAP-2040, GAP-2113).
		return withExitCode(errors.New(result.Errors[0].Message), exitCode)
	}
	if exitCode == 0 {
		return nil
	}
	summary := "the standalone enterprise " + result.Action + " failed"
	if len(result.Errors) != 0 {
		if opts.jsonOutput {
			summary += ": " + result.Errors[0].Message
		} else {
			// The summary above already printed every error in full.
			summary += ": " + result.Errors[0].Code
		}
	}
	return withExitCode(errors.New(summary), exitCode)
}

func writeWindowsEnterpriseStandaloneSummary(output io.Writer, result *enterprisestatus.Result) {
	state := "OK"
	if !result.OK {
		state = "FAILED"
	}
	fmt.Fprintf(output, "DefenseClaw Windows enterprise %s (standalone): %s\n", result.Action, state)
	if result.Noop {
		fmt.Fprintf(output, "  No change: %s\n", result.NoopReason)
	}
	if result.InstalledVersion != "" {
		fmt.Fprintf(output, "  Installed version: %s\n", result.InstalledVersion)
	}
	for _, service := range result.Services {
		fmt.Fprintf(output, "  %s (%s): %s\n", service.Name, service.Kind, service.State)
	}
	if result.Action == "status" || result.Action == "verify" {
		writeWindowsEnterpriseEnrollmentAccounts(output, result.Enrollment.Accounts)
	}
	for _, message := range result.Errors {
		fmt.Fprintf(output, "  error %s: %s\n", message.Code, message.Message)
	}
	// Warnings name what an OK result still leaves undone, such as an
	// installed agent the enumerator could not enroll. The internal
	// security-descriptor detail of a lifecycle_diagnostic stays in --json.
	for _, message := range result.Warnings {
		if message.Code == "lifecycle_diagnostic" {
			continue
		}
		fmt.Fprintf(output, "  warning %s: %s\n", message.Code, message.Message)
	}
	if result.LogPath != "" {
		fmt.Fprintf(output, "  Log: %s\n", result.LogPath)
	}
}

func writeWindowsEnterpriseStandalonePreflightFailure(
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	if opts == nil {
		opts = &windowsEnterpriseLifecycleOptions{}
	}
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	code := "preflight_failed"
	if errors.Is(cause, errWindowsEnterpriseInvalidArguments) {
		code = "invalid_arguments"
	} else {
		code = windowsEnterpriseMessageCode(cause.Error(), code)
	}
	if errors.Is(cause, errPowerShell7Required) {
		code = "powershell7_required"
	}
	if errors.Is(cause, errPowerShell7Untrusted) {
		code = "powershell7_untrusted"
	}
	message := cause.Error()
	switch code {
	case "elevation_required":
		message = strings.TrimPrefix(message, code+": ")
		// A standard account's repair, ensure, install or upgrade --json
		// reported installed=false with no services on a healthy host:
		// report what any account can read, as status and verify do
		// (GAP-2012, GAP-2162).
		applyWindowsEnterpriseRecordedDeployment(result)
	case "invalid_arguments":
		message = strings.TrimPrefix(message, errWindowsEnterpriseInvalidArguments.Error()+": ")
		if windowsEnterpriseUnknownProfileRequested(opts) {
			// Name the value once (GAP-2040); the resolution error keeps
			// the text the Secure Client profile pins.
			message = fmt.Sprintf("invalid --profile %q: use %s or %s",
				strings.TrimSpace(opts.profile), managed.ProfileStandalone, managed.ProfileSecureClient)
			applyWindowsEnterpriseRecordedDeployment(result)
		}
	}
	result.AddError(code, message)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// windowsEnterpriseServiceState is a service's state as the installer
// names it (running, stopped, absent, ...); tests replace it.
var windowsEnterpriseServiceState = windowsEnterpriseSCMServiceState

// applyWindowsEnterpriseRecordedDeployment gives a refused request's result
// the deployment this computer records and its services' states. An unknown
// --profile selects no profile and inspects nothing, so its --json result
// reported an installed computer as installed=false with no services
// (GAP-2113). A standard account cannot read the administrator-only record,
// so for it a record that is present counts as installed with no version;
// the service manager's states are readable by any account (GAP-2162).
// Only the enumerator's and sensor helper's readiness follow from a service
// state (as in a full status); the gateway's and guardian's readiness,
// coverage_complete and security_complete need checks this refusal never
// ran, so a health_not_checked warning says so instead of leaving their
// false values to read as failed checks (GAP-2161).
func applyWindowsEnterpriseRecordedDeployment(result *enterprisestatus.Result) {
	for _, profile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		deployment, err := windowsEnterpriseDeploymentInspector(profile)
		if err != nil {
			continue
		}
		unreadable := deployment.State == winpath.EnterpriseDeploymentUnknown && !windowsEnterpriseIsElevated()
		if deployment.State != winpath.EnterpriseDeploymentInstalled && !unreadable {
			continue
		}
		result.Profile, result.Installed, result.InstalledVersion = profile, true, deployment.ProductVersion
		for _, service := range []struct{ name, kind string }{
			{"DefenseClawGateway", "gateway"},
			{"DefenseClawHookGuardian", "guardian"},
			{"DefenseClawHookEnumerator", "enumerator"},
			{"DefenseClawSensorHelper", "sensor_helper"},
		} {
			state := windowsEnterpriseServiceState(service.name)
			if state == "absent" {
				continue
			}
			result.Services = append(result.Services, enterprisestatus.Service{
				Name: service.name, Kind: service.kind, State: state, Required: true,
			})
			switch service.kind {
			case "enumerator":
				result.Readiness.Enumerator = state == "running"
			case "sensor_helper":
				result.Readiness.SensorHelper = state == "running"
			}
		}
		result.AddWarning("health_not_checked", "this request was refused before any health check ran, so readiness.gateway, readiness.guardian, "+
			"coverage_complete and security_complete were not checked (they read false); only the recorded deployment and the service states are reported. "+
			"For the deployment's health, run `& '"+managedWindowsAdminCLI()+"' enterprise windows verify --profile "+profile+" --json` from an elevated PowerShell prompt")
		return
	}
}

// windowsEnterpriseSCMServiceState reads a service's state from the service
// manager, which any account may query.
func windowsEnterpriseSCMServiceState(name string) string {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(manager)
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "unknown"
	}
	service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "absent"
	}
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return "unknown"
	}
	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "startpending"
	case windows.SERVICE_STOP_PENDING:
		return "stoppending"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return "unknown"
}

// windowsEnterpriseStandaloneFootprintPresent reports any standalone
// metadata, root, or managed service. Only a host with none of them makes
// uninstall a no-op; anything else goes through the authenticated
// uninstall and exact-scope recovery. A path a standard user created (not
// owned by SYSTEM, Administrators, or TrustedInstaller) is not a DefenseClaw
// footprint: no lifecycle ever wrote it.
func windowsEnterpriseStandaloneFootprintPresent() (bool, error) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, err
	}
	for _, path := range []string{roots.MetadataPath, roots.InstallRoot, roots.StateRoot} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			if windowsEnterpriseFootprintUserCreated(path) {
				continue
			}
			return true, nil
		}
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return true, nil
	}
	defer windows.CloseServiceHandle(manager)
	for _, name := range []string{"DefenseClawGateway", "DefenseClawHookGuardian", "DefenseClawHookEnumerator", "DefenseClawSensorHelper"} {
		namePointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return true, nil
		}
		service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_STATUS)
		if err == nil {
			_ = windows.CloseServiceHandle(service)
			return true, nil
		}
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return true, nil
		}
	}
	return false, nil
}

// windowsEnterpriseFootprintOwner reads a path's owner without following a
// reparse point; tests replace it.
var windowsEnterpriseFootprintOwner = func(path string) (*windows.SID, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	pointer, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := descriptor.Owner()
	return owner, err
}

// windowsEnterpriseFootprintUserCreated reports a path whose owner is known
// and is not an administrator. An unreadable owner counts as a footprint.
func windowsEnterpriseFootprintUserCreated(path string) bool {
	owner, err := windowsEnterpriseFootprintOwner(path)
	return err == nil && owner != nil && !windowsEnterpriseAdminSID(owner)
}

// readWindowsEnterpriseStandaloneEnrollment summarizes the installed
// guardian manifest when this token can read it.
func readWindowsEnterpriseStandaloneEnrollment() (enterprisestatus.Enrollment, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	return readWindowsEnterpriseStandaloneEnrollmentAt(layout.ManifestPath, layout.DataDir)
}

// readWindowsEnterpriseStandaloneEnrollmentAt counts the manifest's targets
// and exempt rows, and as pending the targets the guardian's last reconcile
// (in runtimeDir) left waiting for their account's session. Every Windows
// per-user row is written deferred, so that flag does not say which.
func readWindowsEnterpriseStandaloneEnrollmentAt(manifestPath, runtimeDir string) (enterprisestatus.Enrollment, error) {
	body, err := readWindowsEnterpriseBoundedFile(manifestPath, 16<<20)
	if err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	var manifest struct {
		Targets []struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	enrollment := enterprisestatus.Enrollment{Targets: len(manifest.Targets)}
	for _, target := range manifest.Targets {
		if !target.Enabled {
			enrollment.Exempt++
		}
	}
	if state, exists, err := loadEnterpriseHookGuardianState(runtimeDir); err == nil && exists {
		enrollment.Pending = state.PendingCount
		enrollment.Accounts = windowsEnterpriseEnrollmentAccounts(state.Results)
	}
	return enrollment, nil
}

// readWindowsEnterpriseStandaloneAIDefense reports whether the installed
// config enables the optional AI Defense augmentation.
func readWindowsEnterpriseStandaloneAIDefense() (bool, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseConfigProfileLimit)
	if err != nil {
		return false, err
	}
	var document struct {
		Enterprise struct {
			Inspection struct {
				AIDefense struct {
					Enabled bool `yaml:"enabled"`
				} `yaml:"ai_defense"`
			} `yaml:"inspection"`
		} `yaml:"enterprise"`
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		return false, err
	}
	return document.Enterprise.Inspection.AIDefense.Enabled, nil
}

func readWindowsEnterpriseBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return body, nil
}

// ensure ------------------------------------------------------------------

// windowsEnterpriseEnsurePlan is the action ensure selected and why.
type windowsEnterpriseEnsurePlan struct {
	Action string // "", install, upgrade, repair
	Reason string
}

// runWindowsEnterpriseStandaloneEnsure converges the host to the supplied
// payload and config: a pending transaction is repaired, an absent
// deployment is installed, an older one upgraded, drifted binaries or
// config reapplied, a failed verify repaired, and a compliant deployment
// left untouched.
func runWindowsEnterpriseStandaloneEnsure(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
) error {
	defaultWindowsEnterpriseEnsurePayload(opts, script)
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	retry, err := runWindowsEnterpriseStandaloneEnsureOnce(ctx, cmd, opts, script, result, true)
	if !retry {
		return err
	}
	// The plan went stale while ensure waited for the lifecycle lock: a
	// concurrent run installed the host. Re-plan once from a fresh status.
	_, err = runWindowsEnterpriseStandaloneEnsureOnce(ctx, cmd, opts, script, result, false)
	return err
}

// windowsEnterpriseEnsureProbeOptions builds ensure's read-only Status and
// Verify probe options from scratch: only what selects the deployment
// (profile, certification roots and service names) and its payload trust.
// Mutation inputs such as --no-start, --mode/--connector, and sources are
// refused by the installer for Status and Verify.
func windowsEnterpriseEnsureProbeOptions(opts *windowsEnterpriseLifecycleOptions) *windowsEnterpriseLifecycleOptions {
	return &windowsEnterpriseLifecycleOptions{
		installRoot:            opts.installRoot,
		stateRoot:              opts.stateRoot,
		gatewayServiceName:     opts.gatewayServiceName,
		guardianServiceName:    opts.guardianServiceName,
		certificationCodexHome: opts.certificationCodexHome,
		allowUnsigned:          opts.allowUnsigned,
		jsonOutput:             true,
		profile:                opts.profile,
		resolvedProfile:        opts.resolvedProfile,
		trustMode:              opts.trustMode,
		payloadManifest:        opts.payloadManifest,
		allowedSigners:         opts.allowedSigners,
		productVersion:         opts.productVersion,
	}
}

// windowsEnterpriseInstallLostRace reports an Install that found the host
// already installed, which happens when a concurrent lifecycle finished
// while this one waited for the lock.
func windowsEnterpriseInstallLostRace(report *windowsEnterpriseInstallerReport) bool {
	if report == nil || report.OK {
		return false
	}
	for _, message := range append([]string{report.Error}, report.Errors...) {
		if strings.Contains(message, "is already installed; use Upgrade or Repair") {
			return true
		}
	}
	return false
}

// runWindowsEnterpriseStandaloneEnsureOnce plans and runs one ensure pass.
// With allowRetry it returns retry=true, without finishing the result, when
// its Install lost a race with a concurrent install.
func runWindowsEnterpriseStandaloneEnsureOnce(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	result *enterprisestatus.Result,
	allowRetry bool,
) (retry bool, returnErr error) {
	statusReport, statusRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("status", windowsEnterpriseEnsureProbeOptions(opts)))
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	plan, planErr := planWindowsEnterpriseEnsure(statusReport, opts, script)
	if planErr != nil {
		applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
		result.Errors = []enterprisestatus.Message{}
		result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
		return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	if plan.Action == "" {
		verifyReport, verifyRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("verify", windowsEnterpriseEnsureProbeOptions(opts)))
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		if verifyReport.OK {
			applyWindowsEnterpriseInstallerReport(result, opts, verifyReport, verifyRun)
			result.Noop = true
			result.NoopReason = plan.Reason
			return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		plan = windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed"}
	}

	actionOpts := *opts
	actionOpts.jsonOutput = true
	if plan.Action == "repair" {
		// Repair reapplies ACL, service, and environment invariants from the
		// installed payload; it takes no sources and records the installed
		// binaries' version.
		clearWindowsEnterpriseSources(&actionOpts)
		actionOpts = *windowsEnterpriseRepairRecordingOptions("repair", &actionOpts)
	}
	var cleanupManifest func()
	if plan.Action == "install" && strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
		manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, windowsEnterpriseEnsureEnumerationLogger(cmd, opts), actionOpts.configPath)
		if err != nil {
			result.AddError(windowsEnterpriseEnsureStagingErrorCode(err), err.Error())
			return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		cleanupManifest = cleanup
		actionOpts.manifestPath = manifestPath
	}
	if cleanupManifest != nil {
		defer cleanupManifest()
	}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	// A repair that recovers a pending transaction may be followed by an
	// install or upgrade whose report replaces this one; keep its record of
	// the gateway recovery ran.
	addWindowsEnterpriseRecoveryGatewayWarnings(result, report)
	if allowRetry && plan.Action == "install" && windowsEnterpriseInstallLostRace(report) {
		result.AddWarning("concurrent_install", "another lifecycle installed this host while ensure waited for the lifecycle lock; ensure re-planned from a fresh status")
		return true, nil
	}
	if plan.Action == "repair" && plan.Reason == "transaction_pending" && windowsEnterpriseRecoveredFailedInstall(report) {
		// The pending transaction was a failed first install; repair rolled it
		// back to an empty host. Converge by installing, exactly as ensure
		// does on a clean device.
		result.AddWarning("recovered_failed_install", "ensure rolled back a failed initial install before installing")
		installPlan, planErr := planWindowsEnterpriseEnsure(&windowsEnterpriseInstallerReport{}, opts, script)
		if planErr != nil {
			result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
			return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		plan = installPlan
		actionOpts = *opts
		actionOpts.jsonOutput = true
		if strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
			manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, windowsEnterpriseEnsureEnumerationLogger(cmd, opts), actionOpts.configPath)
			if err != nil {
				result.AddError(windowsEnterpriseEnsureStagingErrorCode(err), err.Error())
				return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
			}
			defer cleanup()
			actionOpts.manifestPath = manifestPath
		}
		report, run, err = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
	}
	deferredActivation := report != nil && windowsEnterpriseRecoveryDeferredActivation(report.RecoveryGatewayRuns)
	// A failed repair's report is the installer's failure document, which
	// carries no installed state; the follow-up status probe below reads it.
	if plan.Action == "repair" && plan.Reason == "transaction_pending" && !report.TransactionPending &&
		((report.OK && report.Installed) || deferredActivation) {
		// Repair finished an interrupted transaction on the payload already in
		// place, typically an upgrade whose failed rollback had to be retained.
		// That is not convergence: re-plan from a fresh status exactly as
		// ensure does on a host without a pending transaction, so the upgrade
		// the MDM asked for still runs in this invocation. A recovery that
		// left the restored release stopped because it could not be
		// reactivated fails its repair on purpose: only this
		// Setup's newer release can bring the services back.
		followStatus, _, statusErr := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("status", windowsEnterpriseEnsureProbeOptions(opts)))
		// A follow-up probe that cannot read the host leaves the completed
		// repair as the result, exactly like a probe that failed to launch.
		if statusErr == nil && !followStatus.probeFailed {
			followPlan, planErr := planWindowsEnterpriseEnsure(followStatus, opts, script)
			if planErr != nil {
				applyWindowsEnterpriseInstallerReport(result, opts, report, run)
				result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
				return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
			}
			if followPlan.Action == "upgrade" {
				if deferredActivation {
					result.AddWarning("recovered_pending_transaction", "ensure recovered a pending transaction whose release could not be reactivated, then ran "+followPlan.Action+": "+followPlan.Reason)
				} else {
					result.AddWarning("recovered_pending_transaction", "ensure finished a pending transaction with repair before it ran "+followPlan.Action+": "+followPlan.Reason)
				}
				plan = followPlan
				actionOpts = *opts
				actionOpts.jsonOutput = true
				report, run, err = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
				if err != nil {
					result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
					return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
				}
			}
		}
	}
	report = windowsEnterpriseFailureWithDeploymentState(ctx, cmd, opts, script, report)
	applyWindowsEnterpriseInstallerReport(result, opts, report, run)
	addWindowsEnterpriseNothingInstalledError(result, report, plan.Action)
	result.AddWarning("ensure_"+plan.Action, "ensure ran "+plan.Action+": "+plan.Reason)
	return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// planWindowsEnterpriseEnsure chooses the converging action from the
// current status. An empty action means "verify, then no-op or repair".
func planWindowsEnterpriseEnsure(
	status *windowsEnterpriseInstallerReport,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
) (windowsEnterpriseEnsurePlan, error) {
	absentReason := "not_installed"
	if status.probeFailed {
		failure := windowsEnterpriseEnsureProbeFailure(status)
		if windowsEnterpriseMessageCode(failure.Error(), "") != "root_squatted" {
			// Planning from a document that carries no state would read an
			// installed host as absent and install over it.
			return windowsEnterpriseEnsurePlan{}, failure
		}
		// A standalone root a standard user created cannot hold a
		// deployment; Install moves it aside and installs.
		status = &windowsEnterpriseInstallerReport{OK: true}
		absentReason = "root_squatted"
	}
	if status.TransactionPending {
		return windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}, nil
	}
	if status.Installed {
		if err := refuseWindowsEnterpriseConnectorlessConfig(opts); err != nil {
			return windowsEnterpriseEnsurePlan{}, err
		}
	}
	if !status.Installed {
		if strings.TrimSpace(opts.configPath) == "" && strings.TrimSpace(opts.mode) == "" {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must install and requires --config (or --mode/--connector)")
		}
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must install and requires %s", strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "install", Reason: absentReason}, nil
	}
	switch compareWindowsEnterpriseVersions(opts.productVersion, status.InstalledVersion) {
	case 1:
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must upgrade and requires %s", strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:" + status.InstalledVersion}, nil
	case -1:
		return windowsEnterpriseEnsurePlan{}, fmt.Errorf("downgrade_refused: installed version %s is newer than %s; run upgrade explicitly to downgrade", status.InstalledVersion, opts.productVersion)
	}
	drift, err := windowsEnterpriseEnsureDriftDetector(opts, script)
	if err != nil {
		return windowsEnterpriseEnsurePlan{}, err
	}
	if drift != "" {
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			if windowsEnterpriseStandalone(opts) && len(missing) == len(missingWindowsEnterpriseSources(&windowsEnterpriseLifecycleOptions{})) {
				// The installed CLI carries no payload, so it can never pass
				// the binary flags; naming them sent administrators the wrong
				// way (GAP-0682). Setup is the command that applies a config.
				return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments(
					"the installed CLI cannot apply a changed %s on Windows; nothing was changed. Run the installed release's Setup as LocalSystem or from an elevated prompt: "+
						"DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=<absolute path of an administrator-only config> JSON=1", drift)
			}
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must reapply %s and requires %s", drift, strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:" + drift}, nil
	}
	return windowsEnterpriseEnsurePlan{Reason: "compliant"}, nil
}

// windowsEnterpriseEnsureProbeFailure carries the failed status probe's own
// diagnostic, keeping its stable code when it has one.
func windowsEnterpriseEnsureProbeFailure(status *windowsEnterpriseInstallerReport) error {
	message := strings.TrimSpace(status.Error)
	if message == "" && len(status.Errors) != 0 {
		message = strings.TrimSpace(status.Errors[0])
	}
	if message == "" {
		message = "the installer reported no detail"
	}
	if windowsEnterpriseMessageCode(message, "") != "" {
		return errors.New(message)
	}
	return fmt.Errorf("status_failed: ensure could not read the deployment state: %s", message)
}

func missingWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) []string {
	var missing []string
	for _, source := range []struct{ flag, value string }{
		{"--gateway-binary", opts.gatewayBinary},
		{"--acp-binary", opts.acpBinary},
		{"--hook-binary", opts.hookBinary},
		{"--sensor-helper-binary", opts.sensorHelperBinary},
	} {
		if strings.TrimSpace(source.value) == "" {
			missing = append(missing, source.flag)
		}
	}
	return missing
}

func clearWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) {
	opts.gatewayBinary, opts.acpBinary, opts.hookBinary = "", "", ""
	opts.sensorHelperBinary, opts.cliBinary = "", ""
	opts.configPath, opts.manifestPath, opts.mode, opts.connector = "", "", "", ""
}

// defaultWindowsEnterpriseEnsurePayload fills unset binary sources from the
// installer's own directory, which is how the enterprise Setup and an
// extracted MDM package lay out the payload.
func defaultWindowsEnterpriseEnsurePayload(opts *windowsEnterpriseLifecycleOptions, script string) {
	directory := filepath.Dir(script)
	for _, source := range []struct {
		value *string
		name  string
	}{
		{&opts.gatewayBinary, "defenseclaw-gateway.exe"},
		{&opts.acpBinary, "defenseclaw-acp.exe"},
		{&opts.hookBinary, "defenseclaw-hook.exe"},
		{&opts.sensorHelperBinary, "defenseclaw-sensor-helper.exe"},
		{&opts.cliBinary, "defenseclaw.exe"},
	} {
		if strings.TrimSpace(*source.value) != "" {
			continue
		}
		candidate := filepath.Join(directory, source.name)
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			*source.value = candidate
		}
	}
	// The running image can never replace itself: a CLI launched from the
	// installed bin directory leaves the installed CLI in place.
	if executable, err := windowsEnterpriseExecutableResolver(); err == nil && opts.cliBinary != "" {
		if conflict, err := windowsEnterpriseSelfUpgradeConflict("upgrade", opts.installRoot, executable, opts.cliBinary); err != nil || conflict {
			opts.cliBinary = ""
		}
	}
}

// windowsEnterpriseEnsureDrift compares the supplied sources with the
// installed deployment's recorded digests and config.
func windowsEnterpriseEnsureDrift(opts *windowsEnterpriseLifecycleOptions, script string) (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return "", err
	}
	body, err := readWindowsEnterpriseBoundedFile(roots.MetadataPath, 1<<20)
	if err != nil {
		return "", fmt.Errorf("read standalone deployment metadata: %w", err)
	}
	var metadata struct {
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(trimWindowsJSONBOM(body), &metadata); err != nil {
		return "", fmt.Errorf("parse standalone deployment metadata: %w", err)
	}
	for _, source := range []struct{ key, path string }{
		{"gateway", opts.gatewayBinary},
		{"acp", opts.acpBinary},
		{"hook", opts.hookBinary},
		{"sensor_helper", opts.sensorHelperBinary},
		{"cli", opts.cliBinary},
		{"installer", script},
		{"module", filepath.Join(filepath.Dir(script), "DefenseClawEnterprise.psm1")},
	} {
		if strings.TrimSpace(source.path) == "" {
			continue
		}
		recorded := strings.ToLower(strings.TrimSpace(metadata.Hashes[source.key]))
		if recorded == "" {
			continue
		}
		digest, err := windowsEnterpriseFileSHA256(source.path)
		if err != nil {
			return "", err
		}
		if digest != recorded {
			return source.key, nil
		}
	}
	if path := strings.TrimSpace(opts.configPath); path != "" {
		want, err := windowsEnterpriseFileSHA256(path)
		if err != nil {
			return "", err
		}
		got, err := windowsEnterpriseFileSHA256(layout.ConfigPath)
		if err != nil || got != want {
			return "config", nil
		}
	}
	// An administrator-supplied manifest is drift when the installed
	// guardian manifest no longer carries one of its rows with the same
	// enrollment state (a row edited or removed by hand, or never applied).
	// Rows the enumerator added are not drift.
	if path := strings.TrimSpace(opts.manifestPath); path != "" {
		required, err := enterprisehooks.LoadManifest(path)
		if err != nil {
			return "", fmt.Errorf("read the supplied guardian manifest: %w", err)
		}
		installed, err := enterprisehooks.LoadManifest(layout.ManifestPath)
		if err != nil {
			return "manifest", nil
		}
		if len(windowsEnterpriseManifestUncoveredRows(required.Targets, installed.Targets)) != 0 {
			return "manifest", nil
		}
	}
	return "", nil
}

// compareWindowsEnterpriseVersions orders dotted release versions,
// ignoring a leading "v" and build metadata. A prerelease sorts before its
// release. Unparseable versions compare equal only when identical.
func compareWindowsEnterpriseVersions(left, right string) int {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == right {
		return 0
	}
	l, lPre, lOK := parseWindowsEnterpriseVersion(left)
	r, rPre, rOK := parseWindowsEnterpriseVersion(right)
	if !lOK || !rOK {
		if right == "" {
			return 1
		}
		if left == "" {
			return -1
		}
		// Different unparseable versions (e.g. dev builds): reapply.
		return 1
	}
	if order := compareWindowsVersions(l, r); order != 0 {
		return order
	}
	switch {
	case lPre == rPre:
		return 0
	case lPre == "":
		return 1
	case rPre == "":
		return -1
	case lPre < rPre:
		return -1
	default:
		return 1
	}
}

func parseWindowsEnterpriseVersion(value string) ([]int, string, bool) {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "v"), "V")
	if index := strings.IndexByte(value, '+'); index >= 0 {
		value = value[:index]
	}
	prerelease := ""
	if index := strings.IndexByte(value, '-'); index >= 0 {
		value, prerelease = value[:index], value[index+1:]
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, "", false
	}
	parsed := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, "", false
		}
		parsed = append(parsed, number)
	}
	return parsed, prerelease, true
}

// errWindowsEnterpriseEnsureManifestRequired refuses a first install that
// would enumerate targets.yaml while enterprise.enrollment.mode is manifest.
var errWindowsEnterpriseEnsureManifestRequired = errors.New(
	"enterprise.enrollment.mode is manifest: ensure needs --manifest with the administrator's targets.yaml",
)

// windowsEnterpriseEnsureStagingErrorCode classifies a first-manifest
// staging failure. A missing --manifest in manifest mode is an argument
// error the MDM must fix, not a transient failure to retry.
// windowsEnterpriseEnsureDataDirEnv is the data_dir override the config
// loader honors (config.DefaultDataPath).
const windowsEnterpriseEnsureDataDirEnv = "DEFENSECLAW_HOME"

func windowsEnterpriseEnsureStagingErrorCode(err error) string {
	if errors.Is(err, errWindowsEnterpriseEnsureManifestRequired) {
		return "invalid_arguments"
	}
	return "manifest_staging_failed"
}

// windowsEnterpriseEnsureDiagnosticsLimit bounds the enumerator lines one
// ensure keeps for the lifecycle log.
const windowsEnterpriseEnsureDiagnosticsLimit = 256

// windowsEnterpriseEnsureEnumerationLogger prints the enumerator's
// per-profile lines to stderr for a person, and keeps them for the
// lifecycle log in a JSON ensure, whose output an MDM parses.
func windowsEnterpriseEnsureEnumerationLogger(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions) enterprisehooks.EnumerationLogger {
	if !opts.jsonOutput {
		return enumerationLoggerForStderr(cmd.ErrOrStderr())
	}
	return func(subject, reason string) {
		if len(opts.diagnostics) < windowsEnterpriseEnsureDiagnosticsLimit {
			opts.diagnostics = append(opts.diagnostics, fmt.Sprintf("[hook-enumerator] skipped %s: %s", subject, reason))
		}
	}
}

// stageWindowsEnterpriseEnsureManifest builds the first guardian manifest
// with the same enumerator the installed service runs, from the supplied
// standalone config, in a protected administrator-only directory.
func stageWindowsEnterpriseEnsureManifest(
	ctx context.Context,
	logf enterprisehooks.EnumerationLogger,
	configPath string,
) (string, func(), error) {
	if strings.TrimSpace(configPath) == "" {
		return "", nil, errors.New("ensure needs --config to enumerate the first guardian manifest")
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return "", nil, err
	}
	programData, err := windowsEnterpriseProgramDataResolver()
	if err != nil {
		return "", nil, err
	}
	directory, err := createProtectedWindowsEnterpriseDirectory(
		programData,
		"DefenseClaw-Ensure-",
		"ensure manifest staging directory",
		rand.Read,
		windows.CreateDirectory,
	)
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	// Setup runs the lifecycle with a scratch profile, so the default
	// data_dir (%USERPROFILE%\.defenseclaw) does not exist and the managed
	// data_dir trust check refused every first install ("GetFileAttributesEx
	// ...\scratch\.defenseclaw: The system cannot find the file specified").
	// Enumeration reads only the enterprise settings; point data_dir at this
	// protected administrator-only directory so the check stays strict.
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:             absolute,
		managed.DeploymentModeEnv:         managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:      managed.ProfileStandalone,
		windowsEnterpriseEnsureDataDirEnv: directory,
	})
	cfg, loadErr := windowsEnterpriseEnsureConfigLoader(absolute)
	restore()
	if loadErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("load the standalone config for enumeration: %w", loadErr)
	}
	// In manifest mode the administrator owns targets.yaml and the installed
	// enumerator stays idle, so a manifest staged here from discovery would
	// never be updated or pruned again.
	if strings.EqualFold(strings.TrimSpace(cfg.Enterprise.Enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		cleanup()
		return "", nil, errWindowsEnterpriseEnsureManifestRequired
	}
	manifest, err := enterpriseWindowsEnumerateProfileEnumerator(ctx, cfg, standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{
		Logger: logf,
	}))
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("enumerate local profiles: %w", err)
	}
	path := filepath.Join(directory, "targets.yaml")
	if _, err := enterpriseWindowsEnumerateManifestWriter(path, manifest); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("stage the first guardian manifest: %w", err)
	}
	return path, cleanup, nil
}
