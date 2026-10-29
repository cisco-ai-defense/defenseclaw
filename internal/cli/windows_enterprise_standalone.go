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
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
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
	Output          []byte
	Truncated       bool
	ExitCode        int
	PipeWaitDelayed bool
	PhaseLines      []string
}

// windowsEnterpriseInstallerReport is the subset of the installer's schema-1
// status document the standalone result is built from.
type windowsEnterpriseInstallerReport struct {
	SchemaVersion                     int               `json:"schema_version"`
	OK                                bool              `json:"ok"`
	Action                            string            `json:"action"`
	Installed                         bool              `json:"installed"`
	TransactionPending                bool              `json:"transaction_pending"`
	InstallRoot                       string            `json:"install_root"`
	StateRoot                         string            `json:"state_root"`
	GatewayService                    string            `json:"gateway_service"`
	GuardianService                   string            `json:"guardian_service"`
	GatewayServiceState               string            `json:"gateway_service_state"`
	GuardianServiceState              string            `json:"guardian_service_state"`
	SensorHelperService               string            `json:"sensor_helper_service"`
	SensorHelperServiceState          string            `json:"sensor_helper_service_state"`
	EnumeratorService                 string            `json:"enumerator_service"`
	EnumeratorServiceState            string            `json:"enumerator_service_state"`
	ServiceStartModes                 map[string]string `json:"service_start_modes"`
	GatewayReady                      bool              `json:"gateway_ready"`
	GuardianReady                     bool              `json:"guardian_ready"`
	CodexMachineRequirementsReady     bool              `json:"codex_machine_requirements_ready"`
	CodexMachineRequirementsDisposion string            `json:"codex_machine_requirements_disposition"`
	CodexTargetEnabled                bool              `json:"codex_target_enabled"`
	CursorTargetEnabled               bool              `json:"cursor_target_enabled"`
	ClaudeTargetEnabled               bool              `json:"claude_target_enabled"`
	ClaudeEffectivePolicyVerified     bool              `json:"claude_effective_policy_verified"`
	SecurityComplete                  bool              `json:"security_complete"`
	InstalledVersion                  string            `json:"installed_version"`
	TrustMode                         string            `json:"trust_mode"`
	Error                             string            `json:"error"`
	Errors                            []string          `json:"errors"`
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
	// UserSettingsEdited is a change line for each user agent settings
	// file an uninstall edited (#1290); UserSettingsHooksLeft names each hook
	// command a user's Claude Code settings keep that still names a
	// DefenseClaw launcher ("<file>: <event>: <command>", #1286). Decoded
	// leniently, like the registration lists.
	UserSettingsEdited    json.RawMessage `json:"user_settings_edited"`
	UserSettingsHooksLeft json.RawMessage `json:"user_settings_hooks_left"`
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
	// A linked or unreadable user agent file cannot be captured for rollback.
	// Setup still proceeds with the machine transaction and reports each skip.
	UserNativeOTLPCaptureSkipped json.RawMessage `json:"user_native_otlp_capture_skipped"`

	// StaleLifecycleJournalRemoved is set when the lifecycle removed a
	// stale committed managed-hook lifecycle journal itself (GAP-1322); it
	// holds the retire failure that made the journal stale.
	StaleLifecycleJournalRemoved string `json:"stale_lifecycle_journal_removed"`
	// StaleTeardownJournalRemoved names the managed-hook teardown journal the
	// lifecycle removed because an earlier uninstall that was refused or
	// rolled back left it (GAP-1041).
	StaleTeardownJournalRemoved string `json:"stale_teardown_journal_removed"`
	// Forced is set by Setup /uninstall FORCE=1, which removed the
	// deployment without recovering its transaction; ForcedStateRootKept
	// names the moved-aside managed state it could not delete.
	Forced              bool   `json:"forced"`
	ForcedStateRootKept string `json:"forced_state_root_kept"`
	// CursorAdapterRestored is set when the lifecycle wrote this release's
	// Cursor enterprise adapter back over a changed or deleted one (GAP-2480).
	CursorAdapterRestored bool `json:"cursor_adapter_restored"`
	// TerminatedServiceProcesses names each service process the lifecycle
	// ended because it did not answer a stop ("<service> (pid <n>)").
	TerminatedServiceProcesses []string `json:"terminated_service_processes"`
	// SkippedRuntimeFiles names each runtime file whose access list the
	// lifecycle left as it was because it could not open the file at all
	// (GAP-1220).
	SkippedRuntimeFiles []string `json:"skipped_runtime_files"`
	// SquattedRootNotes says what Install did with each standalone root a
	// standard user created first: a link removed, a folder moved aside.
	SquattedRootNotes []string `json:"squatted_root_notes"`
	// LifecycleRetireSkipped names each account whose old managed runtime
	// generations a retire left because the account's DefenseClaw folder has
	// permissions DefenseClaw could not verify or apply (#1105, GAP-0781).
	// Decoded leniently, like the registration lists.
	LifecycleRetireSkipped json.RawMessage `json:"lifecycle_retire_skipped"`
	// SignedOutUntrustedFolders names each signed-out account whose guardian
	// row failed only on its DefenseClaw folder's owner or permissions, which
	// the lifecycle went on without ("<account>: <folder>", #1105, GAP-0211).
	// Decoded leniently, like the registration lists.
	SignedOutUntrustedFolders json.RawMessage `json:"signed_out_untrusted_folders"`
	// LifecycleGenerationsCollected is how many old managed runtime
	// generations the collect of a compliant ensure removed, and
	// LifecycleCollectError why that collect could not run (GAP-0211).
	LifecycleGenerationsCollected int    `json:"lifecycle_generations_collected"`
	LifecycleCollectError         string `json:"lifecycle_collect_error"`
	// A self-uninstall (the installed CLI removing its own deployment)
	// leaves cleanup to a detached finalizer that runs once the CLI exits:
	// SelfUninstallCleanupPending says so, CanonicalInstallRootAbsent (nil
	// when not reported) whether InstallRoot is already renamed aside to
	// RetiredInstallRoot, and InstallRootRetirementDeferred names the program
	// that still held InstallRoot when the rename was deferred.
	SelfUninstallCleanupPending   bool   `json:"self_uninstall_cleanup_pending"`
	CanonicalInstallRootAbsent    *bool  `json:"canonical_install_root_absent"`
	InstallRootRetirementDeferred string `json:"install_root_retirement_deferred"`
	RetiredInstallRoot            string `json:"retired_install_root"`
	// MdmRotationJournalKept names the MDM kit's credential rotation
	// journal an uninstall that removed the deployment kept (a plain
	// uninstall) or left (a purge that found a journal it must not remove),
	// with the next step (GAP-1913).
	MdmRotationJournalKept string `json:"mdm_rotation_journal_kept"`

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
	// A confirmed bundle can skip ordinary drift planning only while the
	// optional compiler recorded in protected metadata matches Fleet mode.
	windowsEnterpriseConfirmedBundleCompilerDrift = confirmedWindowsBundleCompilerDrift
	// windowsEnterpriseEnsureConfigLoader reads the standalone config ensure
	// enumerates the first guardian manifest from.
	windowsEnterpriseEnsureConfigLoader = config.LoadFromFile

	windowsEnterpriseMessageCodePattern = regexp.MustCompile(`^([a-z][a-z0-9_]{2,63}):\s`)
)

// windowsEnterpriseLifecycleBusyMarker is the installer's lock-contention
// diagnostic (Enter-DefenseClawLifecycleLock).
const windowsEnterpriseLifecycleBusyMarker = "holds the protected file lock"

// windowsEnterpriseUnreadableMetadataMarker opens the module's refusal of a
// deployment.json that is not JSON (ConvertFrom-DefenseClawDeploymentMetadataText),
// which Repair rebuilds.
const windowsEnterpriseUnreadableMetadataMarker = "could not read the installed deployment metadata"

// windowsEnterpriseRemoveReplacementCopies removes the unused replacement
// copies in the production bin folder; replaceable in tests.
var windowsEnterpriseRemoveReplacementCopies = func() []string {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return nil
	}
	return removeWindowsReplacementCopies(filepath.Join(roots.InstallRoot, "bin"))
}

func init() {
	windowsEnterpriseRunningAsLocalSystem = func() bool {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	}
}

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
		env, err := trustedWindowsEnterprisePowerShell7Environment(temp, engine)
		if err != nil {
			return env, err
		}
		return append(env, windowsEnterpriseInstallerRequestEnvironment(ctx, args)...), nil
	}
	stderr := &windowsEnterpriseOutputCapture{}
	console := &windowsEnterprisePhaseFilter{writer: cmd.ErrOrStderr()}
	capture, runErr := runWindowsEnterprisePowerShellEngineWithRunner(
		ctx, cmd, engine.Executable, environment, script, args,
		io.Discard, io.MultiWriter(stderr, console), true, runWindowsEnterprisePowerShellChild,
	)
	if err := console.Flush(); err != nil && runErr == nil {
		runErr = err
	}
	run := windowsEnterpriseStandaloneRun{}
	if capture != nil {
		run.Output = append([]byte(nil), capture.buffer.Bytes()...)
		run.Truncated = capture.truncated
		run.PipeWaitDelayed = capture.pipeWaitDelayed
	}
	run.PhaseLines = windowsEnterprisePhaseLines(stderr.buffer.Bytes())
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
		if detail := windowsEnterpriseExecutionPolicyRefusal(stderr.buffer.Bytes()); detail != "" {
			return run, fmt.Errorf("%s (%w)", detail, runErr)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if phases := windowsEnterpriseTimeoutPhases(stderr.buffer.Bytes()); phases != "" {
				return run, fmt.Errorf("%w; installer phase transcript: %s", runErr, phases)
			}
		}
		return run, runErr
	}
	return run, nil
}

// The phase marker is diagnostic output for the protected lifecycle log.
// Hold only the possible prefix; ordinary stderr streams through promptly.
type windowsEnterprisePhaseFilter struct {
	writer io.Writer
	prefix []byte
	mode   byte // 0: prefix undecided, 1: pass, 2: discard until newline
}

func (filter *windowsEnterprisePhaseFilter) Write(body []byte) (int, error) {
	const marker = "DC_LIFECYCLE_PHASE: "
	visible := make([]byte, 0, len(body))
	for _, b := range body {
		switch filter.mode {
		case 2:
			if b == '\n' {
				filter.mode = 0
			}
		case 1:
			visible = append(visible, b)
			if b == '\n' {
				filter.mode = 0
			}
		default:
			filter.prefix = append(filter.prefix, b)
			if string(filter.prefix) == marker {
				filter.prefix = filter.prefix[:0]
				filter.mode = 2
			} else if !strings.HasPrefix(marker, string(filter.prefix)) {
				visible = append(visible, filter.prefix...)
				filter.prefix = filter.prefix[:0]
				filter.mode = 1
				if b == '\n' {
					filter.mode = 0
				}
			}
		}
	}
	if len(visible) != 0 {
		if _, err := filter.writer.Write(visible); err != nil {
			return 0, err
		}
	}
	return len(body), nil
}

func (filter *windowsEnterprisePhaseFilter) Flush() error {
	if len(filter.prefix) == 0 {
		return nil
	}
	_, err := filter.writer.Write(filter.prefix)
	filter.prefix = filter.prefix[:0]
	return err
}

// Standalone installers can launch native descendants which inherit stdout.
// Keep the job's kill-on-close limit until PowerShell has exited cleanly, so
// cancellation and a delayed pipe wait still terminate the process tree.
func newWindowsEnterprisePowerShellJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func runWindowsEnterprisePowerShellChild(child *exec.Cmd) error {
	child.WaitDelay = 2 * time.Second
	job, err := newWindowsEnterprisePowerShellJob()
	if err != nil {
		return fmt.Errorf("create Windows enterprise installer job: %w", err)
	}
	defer windows.CloseHandle(job) //nolint:errcheck // closes the kill-on-close job.
	child.Cancel = func() error {
		_ = windows.TerminateJobObject(job, 1)
		return child.Process.Kill()
	}
	if err := child.Start(); err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(child.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		_ = windows.CloseHandle(process)
	}
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return fmt.Errorf("assign Windows enterprise installer to kill-on-close job: %w", err)
	}
	if err := child.Wait(); err != nil {
		return err
	}
	// A committed self-uninstall launches a non-inheriting finalizer which
	// must outlive PowerShell and the installed CLI. Only a clean Wait may
	// release descendants from the job's kill-on-close limit.
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("release Windows enterprise installer job after clean exit: %w", err)
	}
	return nil
}

func windowsEnterpriseTimeoutPhases(stderr []byte) string {
	var phases []string
	for _, line := range windowsEnterprisePhaseLines(stderr) {
		phases = append(phases, strings.TrimPrefix(line, "DC_LIFECYCLE_PHASE: "))
	}
	return strings.Join(phases, " | ")
}

func windowsEnterprisePhaseLines(stderr []byte) []string {
	const prefix = "DC_LIFECYCLE_PHASE: "
	var phases []string
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, prefix) && len(line) <= 160 {
			phases = append(phases, line)
		}
	}
	if len(phases) > 12 {
		phases = phases[len(phases)-12:]
	}
	return phases
}

// windowsEnterpriseForcedUninstallVariable carries --force (Setup /uninstall
// FORCE=1) to the standalone installer, which reads it only for Uninstall and
// clears it. It is not an installer parameter: the parameter set of the
// installer is the Secure Client installer command line, which must not change
// (GAP-0920, GAP-1041).
const windowsEnterpriseForcedUninstallVariable = "DEFENSECLAW_STANDALONE_FORCED_UNINSTALL"

type windowsEnterpriseForcedUninstallKey struct{}

func windowsEnterpriseForcedUninstallRequested(ctx context.Context) bool {
	forced, _ := ctx.Value(windowsEnterpriseForcedUninstallKey{}).(bool)
	return forced
}

// windowsEnterpriseCollectGenerationsVariable asks the standalone installer's
// Verify to collect old managed runtime generations: an elevated ensure that
// found the deployment compliant sets it, so the old copies a retire left in
// a per-user folder it could not trust go once the folder is fixed, and the
// folder stays named until then (#1105, GAP-0211). Like the forced uninstall
// it is not an installer parameter.
const windowsEnterpriseCollectGenerationsVariable = "DEFENSECLAW_STANDALONE_COLLECT_RUNTIME_GENERATIONS"

type windowsEnterpriseCollectGenerationsKey struct{}

func windowsEnterpriseCollectGenerationsRequested(ctx context.Context) bool {
	requested, _ := ctx.Value(windowsEnterpriseCollectGenerationsKey{}).(bool)
	return requested
}

// windowsEnterpriseInstallerRequestEnvironment is what a run asks the
// standalone installer for in its environment: a forced uninstall and the
// generation collect of a Verify.
func windowsEnterpriseInstallerRequestEnvironment(ctx context.Context, args []string) []string {
	var env []string
	if windowsEnterpriseForcedUninstallRequested(ctx) {
		env = append(env, windowsEnterpriseForcedUninstallVariable+"=1")
	}
	action := windowsEnterpriseInstallerAction(args)
	if windowsEnterpriseCollectGenerationsRequested(ctx) && action == "Verify" {
		env = append(env, windowsEnterpriseCollectGenerationsVariable+"=1")
	}
	return env
}

// refuseWindowsEnterpriseStandaloneDeferredState refuses the install,
// upgrade and repair requests the installer refuses for the recorded
// deployment before it changes anything (Assert-DefenseClawDeferredInstallIsFresh
// and the deferred-configuration checks of Invoke-DefenseClawInstallLikeLifecycle),
// so they come before the run's first change, the repair of the hook runtime
// access included (q-win-lifecycle review, loop round 3): a deferred install over an installed deployment and, while the
// deployment waits for its deferred configuration, an install or upgrade,
// or a repair without both --config and --manifest or with --no-start. With
// a record of an interrupted lifecycle of this run's scope
// (windowsEnterpriseStandaloneRecoveryPending) the installer recovers it
// first, which can change the record (a first install interrupted before
// its pending transaction cleared rolls back to no deployment), so the
// installer decides; so it does for a deployment record this cannot read.
func refuseWindowsEnterpriseStandaloneDeferredState(action string, opts *windowsEnterpriseLifecycleOptions) error {
	if opts == nil || (action != "install" && action != "upgrade" && action != "repair") {
		return nil
	}
	deployment, err := windowsEnterpriseTargetDeployment(opts)
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || windowsEnterpriseStandaloneRecoveryPending(opts) {
		return nil
	}
	if action == "install" && opts.deferredConfig {
		return windowsEnterpriseInvalidArguments("deferred Install without Config and Manifest requires an empty deployment; " +
			"use Repair or Ensure for the installed deployment (nothing was changed)")
	}
	if !deployment.DeferredConfigPending {
		return nil
	}
	switch {
	case action != "repair":
		return windowsEnterpriseInvalidArguments("this deployment waits for its deferred configuration, which only a repair with "+
			"--config and --manifest completes; the %s was refused (nothing was changed)", action)
	case strings.TrimSpace(opts.configPath) == "" || strings.TrimSpace(opts.manifestPath) == "":
		return windowsEnterpriseInvalidArguments("the repair that completes a deferred configuration needs both --config and --manifest (nothing was changed)")
	case opts.noStart:
		return windowsEnterpriseInvalidArguments("the repair that completes a deferred configuration starts the services and cannot use --no-start (nothing was changed)")
	}
	return nil
}

// refuseWindowsEnterpriseRepairFromAnotherRelease refuses an explicit
// Setup /repair whose payload is another release than the installed one.
// Repair copies the payload's files over the installed ones but records the
// installed version, so a newer Setup left the newer hook program and Codex
// requirements under installed_version of the older release, and a later
// rollback snapshot took them as that release (GAP-2061). Repair stays the
// installed release's Setup; this Setup's /ensure upgrades. The recovery of
// a pending transaction (any release may finish it), the installed CLI
// (no payload) and an unreadable version are left to the installer.
func refuseWindowsEnterpriseRepairFromAnotherRelease(action string, opts *windowsEnterpriseLifecycleOptions) error {
	if action != "repair" || !windowsEnterpriseStandalone(opts) || len(missingWindowsEnterpriseSources(opts)) != 0 {
		return nil
	}
	deployment, err := windowsEnterpriseTargetDeployment(opts)
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || windowsEnterpriseStandaloneRecoveryPending(opts) {
		return nil
	}
	installed, setup := strings.TrimSpace(deployment.ProductVersion), strings.TrimSpace(opts.productVersion)
	if _, _, ok := parseWindowsEnterpriseVersion(installed); !ok {
		return nil
	}
	if _, _, ok := parseWindowsEnterpriseVersion(setup); !ok {
		return nil
	}
	switch compareWindowsEnterpriseVersions(setup, installed) {
	case 1:
		return windowsEnterpriseInvalidArguments("this Setup is release %s and the installed release is %s: repair would put %s files "+
			"under the installed %s. Run the %s Setup with /repair JSON=1, or this Setup with /ensure JSON=1 to upgrade (nothing was changed)",
			setup, installed, setup, installed, installed)
	case -1:
		return windowsEnterpriseInvalidArguments("this Setup is release %s and the installed release is %s: repair would put %s files "+
			"under the installed %s. Run the %s Setup with /repair JSON=1, or this Setup with /upgrade JSON=1 to downgrade (nothing was changed)",
			setup, installed, setup, installed, installed)
	}
	return nil
}

// windowsEnterpriseInstallerAction is the -Action value of installer args.
func windowsEnterpriseInstallerAction(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-Action" {
			return args[i+1]
		}
	}
	return ""
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
	var unsettledBundles []*enterprisebundle.Receipt
	if action == "status" && windowsEnterpriseIsElevated() && windowsEnterpriseStandaloneInstalled() {
		var err error
		if unsettledBundles, err = settleWindowsBundleStatusReport(ctx); err != nil {
			if failure := enterprisebundle.StateWriteError("settle the policy bundle receipt", err); failure.Code == enterprisebundle.CodeDiskFull {
				return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, fmt.Errorf("%s: %s", failure.Code, failure.Detail))
			}
			return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, fmt.Errorf("settle policy bundle receipt: %w", err))
		}
	}
	if action == "upgrade" || action == "repair" {
		if err := refuseWindowsEnterpriseConnectorlessConfig(opts); err != nil {
			return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
		}
		if err := refuseWindowsEnterpriseAPIPortChange(opts); err != nil {
			return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
		}
	}
	// The installer refuses these for the recorded deployment, or for an
	// untrusted scanner runtime it cannot remove, before it changes
	// anything: refused here, they come before this run's first change too.
	if err := refuseWindowsEnterpriseStandaloneDeferredState(action, opts); err != nil {
		return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
	}
	if err := refuseWindowsEnterpriseRepairFromAnotherRelease(action, opts); err != nil {
		return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
	}
	if err := refuseUntrustedWindowsScannerRuntimeBeforeChange(canonicalWindowsEnterpriseAction(action), opts); err != nil {
		return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
	}
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
	// Repair without CONFIG= on a bundle-mode device keeps the confirmed
	// bundle config, not an edit made outside the lifecycle (GAP-0114). The
	// restore comes before anything else this run changes: when it fails,
	// repair stops with bundle_restore_failed and has changed nothing.
	var bundleRestore windowsBundleRestore
	if windowsBundleRestoreRequested(action, opts) {
		if bundleRestore = restoreWindowsBundleConfig(ctx, windowsBundleSettleReplacing(opts)); bundleRestore.failed() {
			result := newWindowsEnterpriseStandaloneResult(action, opts)
			bundleRestore.apply(result)
			applyWindowsEnterpriseRecordedDeployment(result)
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
	}
	hookRuntimeRepaired := ""
	claudeDropInRepaired := ""
	if action == "repair" && windowsEnterpriseIsElevated() {
		hookRuntimeRepaired = repairWindowsEnterpriseHookRuntimeAccess()
		claudeDropInRepaired = repairWindowsEnterpriseClaudeDropIn()
	}
	configReplaced := ""
	if action == "repair" || action == "upgrade" {
		// As ensure does: never load an installed config.yaml that does not
		// parse before the supplied one (GAP-0948).
		kept, err := installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
		if err != nil {
			result := newWindowsEnterpriseStandaloneResult(action, opts)
			result.AddError("preflight_failed", err.Error())
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		if kept != "" {
			configReplaced = windowsEnterpriseUnparseableConfigChange(kept, action)
		}
	}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, args)
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	bundleRestore.apply(result)
	if hookRuntimeRepaired != "" {
		result.Changes = append(result.Changes, hookRuntimeRepaired)
	}
	if claudeDropInRepaired != "" {
		result.Changes = append(result.Changes, claudeDropInRepaired)
	}
	if configReplaced != "" {
		result.Changes = append(result.Changes, configReplaced)
	}
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		if action == "status" || action == "verify" {
			// The lifecycle never ran, so it changed nothing: report the
			// recorded deployment and the service states instead of
			// installed:false for a running deployment (GAP-0770).
			applyWindowsEnterpriseRecordedDeployment(result)
		}
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
	applyWindowsEnterprisePolicy(ctx, result)
	if action == "status" && report.Installed && len(unsettledBundles) > 0 {
		// A receipt no live apply owns: a plain ensure settles it (GAP-0028,
		// GAP-1302).
		result.TransactionPending = true
		result.AddWarning(enterprisebundle.WarnBundlePending, enterprisebundle.UnsettledMessage(unsettledBundles, "enterprise windows ensure --profile standalone"))
	}
	if (action == "status" || action == "verify") && report.Installed {
		appendWindowsEnterpriseStatusAdvisories(ctx, result, report)
	}
	if action == "status" || action == "verify" || action == "repair" {
		settleWindowsEnterpriseHotConfigClosure(ctx, result, action)
	}
	addWindowsEnterpriseNothingInstalledError(result, report, action)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// settleWindowsEnterpriseHotConfigClosure handles the closure a config change
// whose undo was not proven leaves: every standalone hook answers "the
// DefenseClaw gateway is not available" until it is released. A clean
// elevated repair or verify releases it once the gateway proves the installed
// config's policy, as ensure does. Otherwise status warns and verify fails,
// so no result reads healthy while every enrolled user is locked out
// (GAP-1599).
func settleWindowsEnterpriseHotConfigClosure(ctx context.Context, result *enterprisestatus.Result, action string) {
	if !result.Installed {
		return
	}
	if held, err := windowsEnterpriseHotConfigHooksHeld(); err != nil || !held {
		return
	}
	reason := ""
	if action != "status" && windowsEnterpriseIsElevated() && len(result.Errors) == 0 {
		err := windowsEnterpriseReleaseHotConfigClosureIfProven(ctx, result)
		if held, heldErr := windowsEnterpriseHotConfigHooksHeld(); err == nil && heldErr == nil && !held {
			result.Changes = append(result.Changes, "released the standalone hook closure a failed config undo left; the gateway proves the installed config's policy")
			result.Noop, result.NoopReason = false, ""
			return
		}
		if err != nil {
			reason = " (" + windowsEnterpriseBoundedDiagnostic(err.Error()) + ")"
		}
	}
	message := "every standalone hook is forced closed since a config change could not prove its undo, so agents are told the DefenseClaw gateway is not available" + reason +
		". Next step: from an elevated PowerShell prompt run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1; it releases the closure once the gateway proves the installed config"
	if action == "status" {
		result.SecurityComplete = false
		result.AddWarning("hook_closure_held", message)
		return
	}
	result.AddError("hook_closure_held", message)
}

// appendWindowsEnterpriseStatusAdvisories adds the advisories status and
// verify report for an installed deployment beyond its installer report: the
// installed config's literal credentials, the gateway's own warnings and the
// admission issues. A refused config reports
// them too, as the running deployment's (GAP-0103).
func appendWindowsEnterpriseStatusAdvisories(ctx context.Context, result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if layout, err := windowsEnterpriseHotConfigLayout(); err == nil {
		if raw, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes); err == nil {
			if installed, err := config.LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, raw); err == nil {
				if paths := config.ManagedStandaloneUpgradeAdvisories(installed, raw); len(paths) > 0 {
					result.AddWarning("managed_literal_credentials", "installed config uses literals at "+strings.Join(paths, ", ")+"; use {credential: NAME} or {env: NAME} where supported; webhook URLs remain supported")
				}
			}
		}
	}
	if report.CursorTargetEnabled {
		result.AddWarning("cursor_agent_prompt_hook_unavailable", "Cursor Agent CLI 2026.10.01 does not send beforeSubmitPrompt; prompt text is not inspected. Check hook_decision rows for actual coverage")
	}
	// Readiness, not the probe: another process on the port answers
	// /health too (GAP-1029).
	if result.Readiness.Gateway {
		if body, err := enterprisestatus.SettledGatewayHealth(ctx, windowsStandaloneGatewayHealth, 500*time.Millisecond, 8); err == nil {
			appendStandaloneGatewayWarnings(result, body, windowsStandaloneGatewayStatus())
		}
	}
	if layout, err := windowsEnterpriseHotConfigLayout(); err == nil {
		appendAdmissionIssueWarnings(result, layout.DataDir, layout.GuardianAuthDir)
	}
}

// windowsEnterprisePolicyDigest runs the installed CLI with `policy digest`
// under the service pins (windowsEnterpriseServicePins) for every caller:
// ensure, status and verify run in the administrator or SYSTEM console, which
// carries none of them, and the digest call was refused there so the result
// silently omitted policy (GAP-0180). The digest comes from the binary the
// gateway service runs, computed from the config and assets it loads. Its
// stdout is the report even when the exit status is not 0 (a policy that
// cannot be built still reports what the gateway says). A seam for tests.
var windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	command, err := windowsEnterprisePolicyDigestCommand(ctx)
	if err != nil {
		return nil, err
	}
	return command.Output()
}

// windowsEnterpriseInstalledAdminCLI resolves the CLI from the protected
// machine registration. An elevated lifecycle can inherit ProgramFiles from
// a caller, so the path used for a subprocess must not use that environment.
func windowsEnterpriseInstalledAdminCLI() (string, error) {
	return windowsEnterpriseInstalledAdminImage("defenseclaw.exe", "CLI")
}

// windowsEnterpriseInstalledAdminGateway resolves the installed gateway
// image the same way. enterprise hooks readiness proves the guardian's
// protected authorization only when it runs from
// <InstallRoot>\bin\defenseclaw-gateway.exe, as Setup runs it: run from
// defenseclaw.exe it reported authorization_error, so every hook proof of a
// hot config change, of its undo and of a held closure's release failed
// closed whatever was enrolled (GAP-1719).
func windowsEnterpriseInstalledAdminGateway() (string, error) {
	return windowsEnterpriseInstalledAdminImage("defenseclaw-gateway.exe", "gateway")
}

func windowsEnterpriseInstalledAdminImage(image, label string) (string, error) {
	programFiles, err := windowsEnterpriseProgramFilesResolver()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Program Files for installed %s: %w", label, err)
	}
	installed := filepath.Join(programFiles, "Cisco", "DefenseClaw", "bin", image)
	// An elevated lifecycle runs this image with the service pins. Check
	// that only SYSTEM, Administrators and TrustedInstaller can replace it
	// or any folder above it (Program Files\Cisco included), and that its
	// folders are not links, before any process is created (GAP-1493).
	if err := windowsEnterpriseInstalledCLICustody(installed, "installed DefenseClaw "+label); err != nil {
		return "", fmt.Errorf("refuse to run the installed %s: %w", label, err)
	}
	return installed, nil
}

// windowsEnterpriseInstalledCLICustody validates the installed CLI file and
// every folder above it, with no advisory verdict for the installer-owned
// Cisco folders. A seam for tests.
var windowsEnterpriseInstalledCLICustody = managed.ValidateTrustedFilePathStrictAncestors

func windowsEnterprisePolicyDigestCommand(ctx context.Context) (*exec.Cmd, error) {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return nil, err
	}
	installedCLI, err := windowsEnterpriseInstalledAdminCLI()
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, installedCLI, "policy", "digest", "--json", "--check-gateway")
	command.Env = windowsEnterpriseEnvironmentWith(os.Environ(), windowsEnterpriseServicePins(layout))
	return command, nil
}

// applyWindowsEnterprisePolicy fills Result.Policy as the Unix lifecycle
// does: the effective policy digest and config_generation the installed
// config computes to, and whether the running gateway reports the same
// digest. A change action warns when it does not, and records
// policy-state.json beside deployment.json when it does. A gateway that
// rejected a reload and a config.yaml edited outside the lifecycle are
// reported for every action. Nothing is reported while the gateway is not
// ready; when the installed CLI cannot compute it, policy_unverified names why.
func applyWindowsEnterprisePolicy(ctx context.Context, result *enterprisestatus.Result) {
	applyWindowsEnterprisePolicyAs(ctx, result, result.Action != "status" && result.Action != "verify")
}

// applyWindowsEnterprisePolicyAs is applyWindowsEnterprisePolicy for a run
// that changed the deployment (change) or only read it, as a refused config
// does whatever its action (GAP-0103): a read never records
// policy-state.json.
func applyWindowsEnterprisePolicyAs(ctx context.Context, result *enterprisestatus.Result, change bool) {
	if !result.Installed || !result.Readiness.Gateway {
		return
	}
	out, err := windowsEnterprisePolicyDigest(ctx)
	warnings := len(result.Warnings)
	state := applyEnterprisePolicyReport(result, out, change)
	if state != nil && state.ConfigUnrecorded {
		result.SecurityComplete, result.Noop, result.NoopReason = false, false, ""
		result.AddError("lifecycle_error", "config generation is unproven or records a hand edit; run DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=<approved absolute config path> JSON=1 from an elevated prompt")
	}
	if state == nil {
		result.SecurityComplete = false
		if len(result.Warnings) > warnings {
			// A digest response with a build error already named the cause.
			// Verify must fail on that cause rather than echo it as a warning.
			if result.Action == "verify" {
				message := result.Warnings[len(result.Warnings)-1]
				result.Warnings = result.Warnings[:len(result.Warnings)-1]
				result.AddError(message.Code, message.Message)
			}
		} else {
			// Name a check that never returned a digest, including an installed
			// CLI the custody check refused to run (GAP-0594).
			cause := "the installed CLI reported no effective policy digest"
			if err != nil {
				// A custody refusal names the account and the icacls
				// command that clears it, as the folder case does (GAP-0594).
				cause = windowsEnterpriseNamePrincipals(err.Error())
			}
			message := "the effective policy the gateway enforces could not be checked: " + cause
			if result.Action == "verify" {
				result.AddError("policy_unverified", message)
			} else {
				result.AddWarning("policy_unverified", message)
			}
		}
	}
	if state != nil && !state.Applied {
		// The gateway reports another digest or a reload error: the
		// installed policy is not the one it enforces, so nothing certifies
		// security_complete, and status and verify name it (GAP-1329).
		result.SecurityComplete = false
		if !change {
			appendWindowsEnterprisePolicyNotApplied(result, state)
		}
	}
	if state == nil || !state.Applied || !change || len(result.Errors) != 0 {
		return
	}
	if err := writeWindowsEnterprisePolicyState(state); err != nil {
		result.AddWarning("policy_state_unrecorded", "could not record "+enterprisestatus.PolicyStateFileName+": "+err.Error())
	}
}

// appendWindowsEnterprisePolicyNotApplied reports, for a read (status,
// verify), a policy the running gateway has not applied. A reload error the
// report already warned about (policy_reload_rejected) fails verify; another
// digest is a policy_not_applied warning on status and an error on verify.
func appendWindowsEnterprisePolicyNotApplied(result *enterprisestatus.Result, state *enterprisestatus.PolicyState) {
	if state.LastReloadError != "" {
		if result.Action != "verify" {
			return
		}
		for index, message := range result.Warnings {
			if message.Code == "policy_reload_rejected" {
				result.Warnings = append(result.Warnings[:index], result.Warnings[index+1:]...)
				result.AddError(message.Code, message.Message)
				return
			}
		}
		return
	}
	message := fmt.Sprintf(
		"the gateway enforces effective policy %s but the installed config computes to %s; it applies the config on its next reload. If this stays, run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1 from an elevated prompt",
		shortPolicyDigest(state.GatewayReportedDigest), shortPolicyDigest(state.EffectiveDigest))
	if result.Action == "verify" {
		result.AddError("policy_not_applied", message)
		return
	}
	result.AddWarning("policy_not_applied", message)
}

// writeWindowsEnterprisePolicyState records the applied policy in
// policy-state.json beside deployment.json, with the same access control.
// deployment.json itself is not extended: an earlier release decodes it
// strictly and must still read it after a rollback.
func writeWindowsEnterprisePolicyState(state *enterprisestatus.PolicyState) error {
	deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone)
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || deployment.MetadataPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(enterprisestatus.PolicyStateRecord{
		EffectiveDigest:  state.EffectiveDigest,
		ConfigGeneration: state.ConfigGeneration,
		AppliedAt:        time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileKeepingDACL(filepath.Join(filepath.Dir(deployment.MetadataPath), enterprisestatus.PolicyStateFileName), append(data, '\n'), deployment.MetadataPath)
}

// writeFileKeepingDACL replaces path with data, giving the new file the
// DACL of sibling before it is renamed into place, so it is never readable
// by more than sibling is. Each write stages in its own exclusively created
// file beside path: two lifecycle runs that finish at the same time shared
// path+".tmp" before, so one could publish the other's bytes or fail on a
// staging file the other had already renamed (GAP-1404).
func writeFileKeepingDACL(path string, data []byte, sibling string) error {
	restore, err := keepConfigDACL(sibling)
	if err != nil {
		return err
	}
	staging, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporary := staging.Name()
	_, writeErr := staging.Write(data)
	if closeErr := staging.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(temporary)
		return writeErr
	}
	if err := restore(temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// windowsStandaloneGatewayHealth reads /health of the standalone gateway on
// the gateway.api_port of the installed config, the port /status is read on:
// the default port may be another listener (GAP-1351). This advisory read is
// bounded; the installer has already established readiness.
func windowsStandaloneGatewayHealth() ([]byte, error) {
	layout, err := managedScanWindowsLayout()
	if err != nil {
		return nil, err
	}
	base, err := managedWindowsGatewayBase(layout)
	if err != nil {
		return nil, err
	}
	client, err := managedGatewayClientFactory(1500*time.Millisecond, strings.TrimPrefix(base, "http://"), managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(base + "/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway health returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// windowsStandaloneGatewayStatus reads the gateway's /status with the
// gateway token in its data directory, which only an administrator can
// read: the profile warnings name configured groups and accounts, so
// /health gives only their number (GAP-1268). nil when it cannot.
func windowsStandaloneGatewayStatus() []byte {
	base, token, _, err := managedScanGatewayEndpoint()
	if err != nil || token == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, base+"/status", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client, err := managedGatewayClientFactory(5*time.Second, strings.TrimPrefix(base, "http://"), managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return body
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
	if opts != nil && opts.force && windowsEnterpriseInstallerAction(args) == "Uninstall" {
		ctx = context.WithValue(ctx, windowsEnterpriseForcedUninstallKey{}, true)
	}
	if err := retireUntrustedWindowsScannerRuntimeBeforeStart(windowsEnterpriseInstallerAction(args), opts); err != nil {
		return nil, windowsEnterpriseStandaloneRun{}, err
	}
	migrationRecord := readWindowsEnterpriseMigrationRecord()
	run, err := windowsEnterpriseStandaloneRunner(ctx, cmd, script, args)
	if opts != nil {
		if run.PipeWaitDelayed {
			opts.powerShellPipeWaitDelayed = true
		}
		if remaining := windowsEnterpriseEnsureDiagnosticsLimit - len(opts.diagnostics); remaining > 0 {
			opts.diagnostics = append(opts.diagnostics, run.PhaseLines[:min(len(run.PhaseLines), remaining)]...)
		}
	}
	noteWindowsEnterpriseMigration(opts, migrationRecord)
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

// readWindowsEnterpriseMigrationRecord reads the migration-v9.json beside the
// installed config for the result's migration note, or nil when there is
// none or it cannot be read.
func readWindowsEnterpriseMigrationRecord() []byte {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return nil
	}
	raw, _ := readWindowsEnterpriseMigrationRecordAt(layout.ConfigPath)
	return raw
}

// readWindowsEnterpriseMigrationRecordAt reads the migration-v9.json beside
// configPath: nil and no error only when nothing is there. A record that is
// there but cannot be read (access denied, not a plain file, a link or
// reparse point, more than managedMigrationRecordMaxBytes) is an error,
// never no record (readManagedMigrationRecord).
func readWindowsEnterpriseMigrationRecordAt(configPath string) ([]byte, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, errors.New("the standalone layout names no installed config")
	}
	return readManagedMigrationRecord(config.MigrationRecordPath(configPath), managedMigrationRecordMaxBytes)
}

// A compliant ensure still needs the one-time Cursor correction recorded by
// the old v9 migration. The actual write stays inside the installer's repair
// transaction; this read only selects that transaction when every proof and
// signed-bundle guard already accepts it. Only a missing record, or a config
// a signed bundle owns, means no correction: a record that cannot be read or
// decoded (G-small loop 4), or that decodes without the fields every
// migration writes ({} or null, G-small loop round 2,
// config.DecodeMigrationRecord), made ensure report a compliant deployment
// while the Cursor fail mode it proves rewritten stayed open. Ensure reports
// that error as preflight_failed.
var windowsEnterpriseCursorMigrationRepairPending = func() (bool, error) {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return false, err
	}
	recordRaw, recordErr := readWindowsEnterpriseMigrationRecordAt(layout.ConfigPath)
	if recordErr == nil && recordRaw == nil {
		return false, nil
	}
	fromBundle, err := managedStandaloneConfigFromBundle(layout.ConfigPath)
	if err != nil || fromBundle {
		return false, err
	}
	if recordErr != nil {
		return false, recordErr
	}
	raw, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return false, err
	}
	record, err := config.DecodeMigrationRecord(recordRaw)
	if err != nil {
		return false, fmt.Errorf("decode %s: %w", config.MigrationRecordPath(layout.ConfigPath), err)
	}
	_, _, pending := config.RepairMigratedCursorFailMode(raw, record)
	return pending, nil
}

// noteWindowsEnterpriseMigration keeps the audit.db block/allow entries a
// config_version 9 migration left in place, when the installer run wrote a
// new migration-v9.json. The installer migrates in its config step
// (validate-service-config --record-lifecycle, a child process), so the
// record is how the count reaches the result, as the Unix lifecycle reports
// it (GAP-0292). A run that rolled back restored the previous record.
func noteWindowsEnterpriseMigration(opts *windowsEnterpriseLifecycleOptions, before []byte) {
	after := readWindowsEnterpriseMigrationRecord()
	if opts == nil || after == nil || bytes.Equal(before, after) {
		return
	}
	record, err := config.DecodeMigrationRecord(after)
	if err != nil {
		return
	}
	if previous, err := config.DecodeMigrationRecord(before); err == nil && previous.MigratedAt == record.MigratedAt &&
		previous.SourceSHA256 == record.SourceSHA256 && len(record.Repaired) > len(previous.Repaired) {
		// The same migration, with a Cursor fail mode it wrote restored.
		opts.configFailModeRepairs = record.Repaired[len(previous.Repaired):]
		return
	}
	opts.localEnforcementEntriesIgnored = record.ActionsRowsIgnored
	if layout, err := windowsEnterpriseHotConfigLayout(); err == nil {
		opts.configMigration = &record
		opts.configMigrationPath = layout.ConfigPath
	}
}

// addWindowsEnterpriseMissingCredentialWarnings warns credential_missing for
// each protected credential the installed config names that is not stored:
// the judge, the scanners or AI Defense then run without a key, silently,
// while status printed the judge model as if it worked (GAP-0660). Only a
// run that read the deployment says so; a standard account cannot read the
// secrets folder.
func addWindowsEnterpriseMissingCredentialWarnings(result *enterprisestatus.Result) {
	switch result.Action {
	case "status", "verify", "install", "upgrade", "repair", "ensure":
	default:
		return
	}
	if !result.Installed || windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) {
		return
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return
	}
	var document struct {
		Enterprise struct {
			Inspection struct {
				AIDefense struct {
					Enabled    bool   `yaml:"enabled"`
					Credential string `yaml:"credential"`
				} `yaml:"ai_defense"`
				LLM struct {
					Credential string `yaml:"credential"`
				} `yaml:"llm"`
			} `yaml:"inspection"`
		} `yaml:"enterprise"`
	}
	if yaml.Unmarshal(trimWindowsJSONBOM(body), &document) != nil {
		return
	}
	inspection := document.Enterprise.Inspection
	aiDefense := ""
	if inspection.AIDefense.Enabled {
		aiDefense = inspection.AIDefense.Credential
	}
	for _, named := range []struct{ key, name, effect string }{
		{"enterprise.inspection.llm.credential", inspection.LLM.Credential,
			"the LLM judge and the skill, MCP and plugin scanners' LLM analyzers run without a key"},
		{"enterprise.inspection.ai_defense.credential", aiDefense, "Cisco AI Defense inspection runs without a key"},
	} {
		name := strings.TrimSpace(named.name)
		if !managed.ValidCredentialName(name) {
			continue
		}
		if windowsSecretStored(layout.SecretsDir, name) {
			continue
		}
		result.AddWarning("credential_missing", fmt.Sprintf(
			"the config names the protected credential %s (%s) but it is not stored, so %s; store it from an elevated prompt with `defenseclaw.exe enterprise secret set --name %s --from-file <key file>`",
			name, named.key, named.effect, name))
	}
}

// addWindowsEnterpriseMigrationChange says in changes what a migration in
// this run wrote, as the Unix lifecycle does; the Windows result had only an
// ensure_upgrade drift:config warning (GAP-0472). Values that disagreed are
// a warning: migration-v9.json lists what was kept and what was lost.
func addWindowsEnterpriseMigrationChange(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if len(result.Errors) != 0 {
		return
	}
	for _, move := range opts.configFailModeRepairs {
		result.Changes = append(result.Changes, config.MigratedCursorFailModeRepairNote(move))
	}
	migration := opts.configMigration
	if migration == nil {
		return
	}
	path := opts.configMigrationPath
	result.Changes = append(result.Changes, fmt.Sprintf(
		"migrated %s to config_version 9 (%d values moved, %d conflicts; the v8 file is kept as %s%s, the --config a rollback to a config_version 8 release needs)",
		path, len(migration.Moved), len(migration.Conflicts), path, config.ConfigV8BackupSuffix))
	if len(migration.Conflicts) != 0 {
		result.AddWarning("config_migration_conflicts", fmt.Sprintf(
			"%d values disagreed while migrating %s to config_version 9; %s lists what was kept and what was lost",
			len(migration.Conflicts), path, config.MigrationRecordPath(path)))
	}
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
			Name:      service.name,
			Kind:      service.kind,
			State:     service.state,
			StartMode: report.ServiceStartModes[service.name],
			Required:  true,
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
	if report.Installed && result.Action == "status" {
		result.Destinations = readWindowsEnterpriseStandaloneDestinations()
	}
	if report.Installed {
		enrollment, err := readWindowsEnterpriseStandaloneEnrollment()
		if err == nil {
			result.Enrollment = enrollment
			if result.Action == "status" || result.Action == "verify" || result.Action == "ensure" {
				appendWindowsClaudeUserSettingsWarnings(result, enrollment.Accounts)
			}
		}
		aiDefense, err := readWindowsEnterpriseStandaloneAIDefense()
		if err == nil && aiDefense {
			result.Inspection.AIDefense = "unavailable:gateway_not_ready"
			if report.GatewayReady {
				// Status, verify and a hot config apply replace this with
				// the gateway's /health posture (appendStandaloneGatewayWarnings).
				result.Inspection.AIDefense = "unknown"
			}
		}
		applyWindowsEnterpriseUnprotectedAgents(result)
		applyWindowsEnterpriseEnrolledConnectors(result)
		applyWindowsEnterpriseAmpMachineFolder(result)
		applyWindowsEnterpriseInstalledConfigWarnings(result)
		applyWindowsEnterpriseAccountFolders(result)
		if result.Action == "status" || result.Action == "verify" {
			applyWindowsEnterpriseHookRuntimeAccess(result)
			applyWindowsEnterpriseGuardianTargets(result)
			applyWindowsEnterpriseUserCleanupFailures(result)
		}
		applyWindowsEnterpriseDiscoveryHomeDirs(result)
		applyWindowsEnterpriseStatusV2(result)
	}
	applyWindowsEnterpriseGatewayStartFailure(result, report)
	applyWindowsEnterpriseAPIPortHolders(result, opts, report)
	messages := append([]string{}, report.Errors...)
	if len(messages) == 0 && strings.TrimSpace(report.Error) != "" {
		messages = append(messages, report.Error)
	}
	messages = windowsEnterpriseNoStartMessages(result, opts, report, messages)
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
		message = windowsEnterpriseNamePrincipals(message)
		code := windowsEnterpriseMessageCode(message, "lifecycle_error")
		if enumeratorCode != "" {
			code = enumeratorCode
		}
		// A stopped required service is not_ready in verify, as in status:
		// one condition, one code for a monitoring rule (GAP-0750).
		if result.Action == "verify" && code == "lifecycle_error" && strings.Contains(message, " SCM process is not running") {
			code = "not_ready"
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
			message += windowsEnterpriseCommittedJournalNextStep(original, report.Installed)
			message += windowsEnterpriseInvalidRuntimeBundleNextStep(original)
			message += windowsEnterpriseMissingArtifactNextStep(original, opts != nil && strings.TrimSpace(opts.hookBinary) != "")
		}
		result.AddError(code, message)
	}
	addWindowsEnterpriseSelfUninstallCleanup(result, report)
	addWindowsEnterpriseMdmRotationJournalKept(result, report)
	if !report.OK && len(result.Errors) == 0 {
		code := "not_ready"
		if !report.Installed {
			code = "not_installed"
		}
		result.AddError(code, windowsEnterpriseNotHealthyMessage(result.Services, run.ExitCode))
	}
	if report.Installed && (result.Action == "status" || result.Action == "verify") {
		// After the not_ready fallback, so a stopped guardian is still
		// named next to the drop-in drift it leaves unrepaired.
		applyWindowsEnterpriseClaudeDropInDrift(result)
	}
	if lifecycle && !report.OK && len(result.Errors) > firstError {
		configPath := ""
		purge, force := false, false
		if opts != nil {
			configPath = opts.configPath
			purge, force = opts.purge, opts.force
		}
		if next := windowsEnterpriseStandaloneNextStep(
			result.Action,
			configPath,
			purge,
			windowsBundleHasCode(result.Errors[firstError:], "lifecycle_busy"),
			force,
			report.TransactionPending,
			decodeWindowsEnterpriseRecoveryGatewayRuns(report.RecoveryGatewayRuns),
			decodeWindowsEnterpriseRecoveryGatewayRefusal(report.RecoveryGatewayRefusal),
			windowsEnterpriseLiveStandaloneServices(),
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
	addWindowsEnterpriseUserRegistrationWarnings(result, report, opts != nil && opts.purge)
	addWindowsEnterpriseUserSettingsChanges(result, report)
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

// windowsEnterpriseSelfUninstallStrandedMessage is the uninstall_in_use error
// of a self-uninstall whose installer report says InstallRoot is still there
// but carries no error of its own.
const windowsEnterpriseSelfUninstallStrandedMessage = "a program still holds a file in the DefenseClaw install folder, so the uninstall " +
	"could not remove it. DefenseClaw is already uninstalled (its services and hooks are removed); a cleanup that starts when this " +
	"command exits removes the folder and finishes the uninstall cleanup once that program closes the file. Close the program, then " +
	"run the uninstall again to confirm that it finished"

// addWindowsEnterpriseSelfUninstallCleanup carries a self-uninstall's pending
// cleanup into the result. While InstallRoot is still there (a program held a
// file in it past the rename retry) the uninstall is not finished and nothing
// this process can wait for confirms that the finalizer finishes it, so the
// run fails with the retryable uninstall_in_use, whatever ok the installer
// reported: an ok result let an exit-code-driven manager stop retrying with
// InstallRoot and the purge left behind (W2B-G-win review, loop round 2). A
// self-uninstall that retired InstallRoot only waits for this process to exit
// before the retired copy goes, which a warning says.
func addWindowsEnterpriseSelfUninstallCleanup(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if report == nil {
		return
	}
	stranded := strings.TrimSpace(report.InstallRootRetirementDeferred) != "" ||
		(report.CanonicalInstallRootAbsent != nil && !*report.CanonicalInstallRootAbsent)
	if stranded {
		if !windowsEnterpriseResultHasError(result, "uninstall_in_use") {
			message := windowsEnterpriseSelfUninstallStrandedMessage
			if deferred := strings.TrimSpace(report.InstallRootRetirementDeferred); deferred != "" {
				message += " (" + windowsEnterpriseBoundedDiagnostic(deferred) + ")"
			}
			result.AddError("uninstall_in_use", message)
		}
		return
	}
	if report.OK && report.SelfUninstallCleanupPending && strings.TrimSpace(report.RetiredInstallRoot) != "" {
		result.AddWarning("self_uninstall_cleanup_pending", "the retired install folder "+
			strings.TrimSpace(report.RetiredInstallRoot)+" is removed by a cleanup that runs once this command exits")
	}
}

// addWindowsEnterpriseMdmRotationJournalKept names, as a warning, the MDM
// kit's credential rotation journal an uninstall kept or left: an entry can
// hold a copy of an earlier credential, so the administrator who reads only
// the JSON result (an MDM, a script) learns it is still there and what
// removes it (GAP-1913).
func addWindowsEnterpriseMdmRotationJournalKept(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	if report == nil || result.Action != "uninstall" {
		return
	}
	if note := strings.TrimSpace(report.MdmRotationJournalKept); note != "" {
		result.AddWarning("mdm_rotation_journal_kept", windowsEnterpriseBoundedDiagnostic(note))
	}
}

// windowsEnterpriseNoStartGuardianIssues are what the guardian status says
// of a deployment whose guardian has never run.
var windowsEnterpriseNoStartGuardianIssues = map[string]bool{
	"guardian status: hook guardian has not completed a reconcile":      true,
	"guardian status: protected hook guardian authorization is missing": true,
	"guardian status: protected hook guardian activation is missing":    true,
}

// windowsEnterpriseNoStartMessages drops the guardian status issues of an
// install, upgrade or repair that completed with --no-start (NOSTART=1): its
// services stay stopped and disabled as asked, so the guardian has not run
// yet. They made Setup /ensure NOSTART=1 exit 1603 on a deployment installed
// as documented (GAP-1214). One warning names the next step instead; every
// other error stays.
func windowsEnterpriseNoStartMessages(
	result *enterprisestatus.Result,
	opts *windowsEnterpriseLifecycleOptions,
	report *windowsEnterpriseInstallerReport,
	messages []string,
) []string {
	if opts == nil || !opts.noStart || !report.OK || !report.Installed || report.TransactionPending {
		return messages
	}
	switch report.Action {
	case "install", "upgrade", "repair":
	default:
		return messages
	}
	kept := make([]string, 0, len(messages))
	for _, message := range messages {
		if !windowsEnterpriseNoStartGuardianIssues[strings.TrimSpace(message)] {
			kept = append(kept, message)
		}
	}
	// The code Linux and macOS use for a --no-start install.
	result.AddWarning("not_started", "installed with the services stopped and disabled (NOSTART=1, --no-start), so agents are not protected yet; "+
		"run Setup /repair, or /ensure without NOSTART=1, to start them")
	return kept
}

// addWindowsEnterpriseUserStateWarning names each enrolled account whose
// DefenseClaw per-user data a purge removed (in Changes), and each one it
// could not remove, with the reason. What stays holds per-user hook tokens
// that nothing accepts any more.
func addWindowsEnterpriseUserStateWarning(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	for _, entry := range windowsEnterpriseReportStrings(report.UserStatePurged) {
		result.Changes = append(result.Changes, windowsEnterprisePurgedUserStateChange(entry))
	}
	var notLocalSystem, pathEntryKept, keptForRegistrations, remaining []string
	for _, entry := range windowsEnterpriseReportStrings(report.UserStateRemaining) {
		if account, found := strings.CutSuffix(entry, ": "+windowsManagedHooksNotLocalSystemReason); found {
			notLocalSystem = append(notLocalSystem, account)
			continue
		}
		if account, found := strings.CutSuffix(entry, ": "+windowsManagedHooksKeptForRegistrationsReason); found {
			keptForRegistrations = append(keptForRegistrations, account)
			continue
		}
		if account, found := strings.CutSuffix(entry, ": "+windowsManagedHooksSignedOutPathEntryReason); found {
			pathEntryKept = append(pathEntryKept, account)
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
	if len(pathEntryKept) > 0 {
		// The documented signed-out case: the data and binaries went, the
		// Path entry names a folder that is gone and runs nothing (GAP-2231).
		result.AddWarning("per_user_state_remaining", fmt.Sprintf(
			"--purge removed the DefenseClaw per-user data and binaries of %d signed-out enrolled account(s), but each keeps the user Path entry for %%USERPROFILE%%\\.local\\bin the install added: "+
				"a signed-out account's registry hive is not loaded, so its Path cannot be changed. The entry names a folder that no longer exists and runs nothing; "+
				"to remove it, delete it from that account's Path once it signs in. Accounts: %s",
			len(pathEntryKept), windowsEnterpriseBoundedLabels(pathEntryKept)))
	}
	if len(keptForRegistrations) > 0 {
		// Kept on purpose: the registrations that stay (named in
		// user_registrations_pending or user_registrations_failed, which
		// decide whether the purge fails) need the folder's connector_backups
		// to be put back. A decommission with signed-out or disconnected
		// users failed 1603 and blamed an open file (GAP-2231).
		result.AddWarning("per_user_state_remaining", fmt.Sprintf(
			"--purge removed the machine deployment but kept the DefenseClaw folder %%USERPROFILE%%\\.defenseclaw of %d enrolled account(s) whose agent registrations stay: "+
				"its connector_backups restore those registrations, and its per-user hook tokens are accepted by nothing any more. "+
				"To remove them too, %s. Accounts: %s",
			len(keptForRegistrations),
			windowsEnterpriseLocalSystemRemedy("/uninstall PURGE=1"),
			windowsEnterpriseBoundedLabels(keptForRegistrations),
		))
	}
	if len(remaining) > 0 {
		result.AddError("per_user_state_remaining", windowsEnterpriseUserStateRemainingMessage(
			len(remaining), windowsEnterpriseBoundedLabels(remaining), windowsEnterprisePurgeRerunFindsAccounts(report)))
	}
}

// windowsEnterprisePurgeManifestExists is replaceable in tests.
var windowsEnterprisePurgeManifestExists = func(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, os.ErrNotExist)
}

// windowsEnterprisePurgeRerunFindsAccounts reports whether a second
// /uninstall PURGE=1 can still find the enrolled accounts a failed purge
// left: it reads them from StateRoot's hook target manifest, which the
// machine-state purge removes (GAP-2307). A report without a StateRoot keeps
// the rerun advice.
func windowsEnterprisePurgeRerunFindsAccounts(report *windowsEnterpriseInstallerReport) bool {
	stateRoot := strings.TrimSpace(report.StateRoot)
	if stateRoot == "" {
		return true
	}
	return windowsEnterprisePurgeManifestExists(filepath.Join(stateRoot, "hook-guardian", "targets.yaml"))
}

// addWindowsEnterpriseMachineStateWarning names the machine folders outside
// StateRoot that the uninstall could not remove. Every standalone uninstall
// removes them, not only --purge, so the MDM default uninstall reports them
// too (GAP-1734). A retained selector shared with another deployment is
// intentional, and two cleanup steps can report the same path (GAP-0571).
func addWindowsEnterpriseMachineStateWarning(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	var failed, kept []string
	seen := map[string]bool{}
	for _, entry := range windowsEnterpriseReportStrings(report.MachineStateRemaining) {
		path, reason, _ := strings.Cut(entry, ": ")
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		if strings.HasPrefix(reason, "kept: ") {
			kept = append(kept, entry)
		} else {
			failed = append(failed, entry)
		}
	}
	if len(failed) > 0 {
		result.AddWarning("machine_state_remaining", fmt.Sprintf(
			"the uninstall could not remove %d DefenseClaw machine folder(s); remove them from an elevated prompt: %s",
			len(failed),
			windowsEnterpriseBoundedLabels(failed),
		))
	}
	if len(kept) > 0 {
		result.AddWarning("machine_state_kept", fmt.Sprintf(
			"the uninstall kept %d DefenseClaw machine file(s) or folder(s) on purpose; leave them in place: %s",
			len(kept), windowsEnterpriseBoundedLabels(kept),
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
	if skipped := windowsEnterpriseReportStrings(report.UserNativeOTLPCaptureSkipped); len(skipped) != 0 {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "user_native_otlp_capture_skipped",
			Message: "Setup skipped native OTLP rollback preimages for these user paths; the machine operation continued, " +
				"but a rollback cannot restore the skipped paths. Inspect their links or access permissions, " +
				"then run Setup /ensure again: " + windowsEnterpriseBoundedLabels(skipped),
		})
	}
	if removed := strings.TrimSpace(report.StaleLifecycleJournalRemoved); removed != "" {
		// The lifecycle deleted a protected journal on its own; say so in
		// the result and the lifecycle log (GAP-1680).
		message := "Setup removed the stale committed managed-hook lifecycle journal " +
			"(managed-hooks-lifecycle-journal.json in the protected install state) because its retire could not complete: " +
			windowsEnterpriseBoundedDiagnostic(removed)
		if strings.Contains(removed, windowsEnterpriseUntrustedUserFolderText) {
			// The installed release's retire stopped at a per-user folder
			// it could not trust; the upgrade went on (#1105, GAP-0781).
			message += "; " + windowsEnterpriseUntrustedUserFolderRemedy
		}
		warnings = append(warnings, enterprisestatus.Message{
			Code:    "stale_lifecycle_journal_removed",
			Message: message,
		})
	}
	if skipped := windowsEnterpriseReportStrings(report.LifecycleRetireSkipped); len(skipped) != 0 {
		warnings = append(warnings, enterprisestatus.Message{
			Code: windowsEnterpriseUntrustedUserFolderCode,
			Message: fmt.Sprintf("the lifecycle left the old DefenseClaw hook runtime copies of %d account(s) in place and changed nothing in their folders, "+
				"because DefenseClaw could not verify or apply the permissions of each account's DefenseClaw folder; ", len(skipped)) +
				windowsEnterpriseUntrustedUserFolderRemedy + ": " + windowsEnterpriseBoundedLabels(skipped),
		})
	}
	if waiting := windowsEnterpriseReportStrings(report.SignedOutUntrustedFolders); len(waiting) != 0 {
		// The upgrade from 1.0.2 returned 1603 for such an account (GAP-0211).
		warnings = append(warnings, enterprisestatus.Message{
			Code: windowsEnterpriseUntrustedUserFolderCode,
			Message: fmt.Sprintf("%d signed-out account(s) have a DefenseClaw folder whose owner or permissions are not the ones DefenseClaw set; "+
				"the lifecycle went on without them, and the guardian repairs their DefenseClaw hooks only in their own Windows session, "+
				"at their next sign-in. Have an administrator inspect each folder named here and reset its permissions, or remove "+
				"the account with its profile if it no longer uses DefenseClaw: ", len(waiting)) +
				windowsEnterpriseBoundedLabels(waiting),
		})
	}
	if failure := strings.TrimSpace(report.LifecycleCollectError); failure != "" {
		// The collect of a compliant ensure did not run (GAP-0211).
		warnings = append(warnings, enterprisestatus.Message{
			Code: windowsEnterpriseGenerationsNotCollectedCode,
			Message: "ensure could not remove the old DefenseClaw hook runtime copies from the accounts' DefenseClaw folders " +
				"(they are inert; the deployment is not affected): " + windowsEnterpriseBoundedDiagnostic(failure) +
				"; run Setup /ensure again once nothing else changes the deployment",
		})
	}
	if removed := strings.TrimSpace(report.StaleTeardownJournalRemoved); removed != "" {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "stale_lifecycle_journal_removed",
			Message: "Setup removed the stale managed-hook teardown journal " + windowsEnterpriseBoundedDiagnostic(removed) +
				", which an earlier uninstall left when it was refused or rolled back; its rollback had finished, so nothing used it",
		})
	}
	if report.Forced {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "forced_uninstall",
			Message: "FORCE=1 removed the deployment without recovering its pending transaction: the services, the binaries, " +
				"the managed state and the machine-wide hook files; what it could not remove is listed in this result",
		})
	}
	if kept := strings.TrimSpace(report.ForcedStateRootKept); kept != "" {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "forced_state_root_kept",
			Message: "the forced uninstall moved the managed state aside but could not delete it; delete that folder once " +
				"DefenseClaw support has the lifecycle log: " + windowsEnterpriseBoundedDiagnostic(kept),
		})
	}
	for _, note := range report.SquattedRootNotes {
		// The install used to say only "ensure ran install: root_squatted"
		// (GAP-0904).
		warnings = append(warnings, enterprisestatus.Message{
			Code:    "root_squatted",
			Message: "a standard user created a DefenseClaw root before the install: " + windowsEnterpriseBoundedDiagnostic(note),
		})
	}
	if len(report.TerminatedServiceProcesses) != 0 {
		// A hung or suspended service process held up the stop (GAP-0946,
		// GAP-1038).
		warnings = append(warnings, enterprisestatus.Message{
			Code: "service_process_terminated",
			Message: "these DefenseClaw service processes did not answer a stop request within 30 seconds and were ended " +
				"(by the lifecycle, or by Windows for a stuck stop) before it continued: " + windowsEnterpriseBoundedLabels(report.TerminatedServiceProcesses),
		})
	}
	if len(report.SkippedRuntimeFiles) != 0 {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "runtime_file_skipped",
			Message: "the lifecycle could not open these runtime files and left their access lists unchanged: " +
				windowsEnterpriseBoundedLabels(report.SkippedRuntimeFiles),
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

// The text of an account's DefenseClaw folder that a managed-hook retire
// could not trust, the warning code that reports the skipped accounts, and
// what the administrator does about it (#1105, GAP-0781). The copies left
// there are inert: the protected selector names the generation in force.
const (
	windowsEnterpriseUntrustedUserFolderText = "managed runtime generation directory is untrusted"
	windowsEnterpriseUntrustedUserFolderCode = "user_runtime_folder_untrusted"
	// windowsEnterpriseGenerationsNotCollectedCode reports a compliant
	// ensure whose collect of old runtime copies could not run (GAP-0211).
	windowsEnterpriseGenerationsNotCollectedCode = "runtime_generations_not_collected"
	windowsEnterpriseUntrustedUserFolderRemedy   = "the deployment is not affected. Have an administrator inspect each folder named here, " +
		"reset its permissions or remove it if that account no longer uses DefenseClaw, then run Setup /ensure again to remove the old copies"
)

// windowsEnterpriseRollbackLeftoverWarnings names each item a rollback could
// not restore or remove. A native OTLP user preimage needs manual repair;
// an upgrade rollback retains the restored release. For a failed first
// install, a file the account changed after DefenseClaw wrote it is kept
// whole, so only a manual
// edit removes DefenseClaw's entries from it. Everything else is removed by a
// successful install followed by an uninstall, both as LocalSystem while the
// accounts are signed in (an uninstall acts only for signed-in accounts). An
// administrator at an elevated prompt gets LocalSystem from a one-time
// scheduled task, which the remedy names.
// windowsEnterpriseRollbackCreatedFolderLeftover marks a rollback leftover
// that is a per-user folder the rolled back change created
// (Invoke-DefenseClawTargetRuntimeRollbackCleanupOrKeep).
const windowsEnterpriseRollbackCreatedFolderLeftover = ": a per-user DefenseClaw folder this change created; the rollback could not remove it ("
const windowsEnterpriseNativeOTLPRollbackLeftover = "native OTLP user rollback: "

func windowsEnterpriseRollbackLeftoverWarnings(raw json.RawMessage) []enterprisestatus.Message {
	var warnings []enterprisestatus.Message
	for _, leftover := range windowsEnterpriseReportStrings(raw) {
		if detail, ok := strings.CutPrefix(leftover, windowsEnterpriseNativeOTLPRollbackLeftover); ok {
			warnings = append(warnings, enterprisestatus.Message{
				Code: "rollback_leftover",
				Message: "the rollback could not restore " + detail + "; the restored release is running; " +
					"inspect that link or its permissions and restore it by hand",
			})
			continue
		}
		if strings.Contains(leftover, windowsEnterpriseRollbackCreatedFolderLeftover) {
			// A rollback whose per-user runtime cleanup failed went on and
			// put the previous release back (GAP-0856); the folder is not
			// one that release uses.
			warnings = append(warnings, enterprisestatus.Message{
				Code: "rollback_leftover",
				Message: "the rollback left " + leftover + "; the restored release does not use that folder, " +
					"so remove it as an administrator after that account signs out",
			})
			continue
		}
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

// addWindowsEnterpriseUserSettingsChanges lists each user settings file an
// uninstall edited in Changes (#1290), and warns about each hook command a
// user's Claude Code settings keep that still names a DefenseClaw launcher:
// the uninstall removes only the exact per-user hook it registered, so a
// hand-written or differently shaped one stayed silently and Claude Code kept
// running a launcher that was gone (#1286). The exit code is unchanged.
func addWindowsEnterpriseUserSettingsChanges(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	for _, change := range windowsEnterpriseReportStrings(report.UserSettingsEdited) {
		line := windowsEnterpriseBoundedDiagnostic(change)
		if !slices.Contains(result.Changes, line) {
			result.Changes = append(result.Changes, line)
		}
	}
	if left := windowsEnterpriseReportStrings(report.UserSettingsHooksLeft); len(left) > 0 {
		message := fmt.Sprintf(
			"%d hook command(s) in users' Claude Code settings still name a DefenseClaw launcher; the uninstall removes only the hook "+
				"DefenseClaw registered, so Claude Code keeps running these and they fail. Remove each one from the named file as that user: %s",
			len(left),
			windowsEnterpriseBoundedLabels(left),
		)
		for _, existing := range result.Warnings {
			if existing.Code == "claude_settings_hook_left" && existing.Message == message {
				return
			}
		}
		result.AddWarning("claude_settings_hook_left", message)
	}
}

// windowsEnterpriseUserRegistrationListMax bounds how many connector/SID
// labels one warning names.
const windowsEnterpriseUserRegistrationListMax = 20

// addWindowsEnterpriseUserRegistrationWarnings tells the administrator which
// DefenseClaw per-user registrations an uninstall left in place: those of
// users who were signed out, those another account could not clean without
// LocalSystem, and removals that failed. They stay inert (enrollment revoked,
// hook runtime and binary removed).
func addWindowsEnterpriseUserRegistrationWarnings(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport, purge bool) {
	failed := windowsEnterpriseReportStrings(report.UserRegistrationsFailed)
	if pending := windowsEnterpriseReportStrings(report.UserRegistrationsPending); len(pending) > 0 {
		reason := "those accounts " + windowsEnterpriseNoActiveSession
		// "not LocalSystem" means no removal was attempted: the pending
		// warning says so and names the remedy, so it is not also reported
		// as a failed removal (GAP-1568).
		var attempted []string
		notLocalSystem := false
		for _, failure := range failed {
			if strings.HasPrefix(failure, windowsManagedHooksRegistrationsNotRemovedPrefix) {
				reason = "this uninstall did not run as LocalSystem"
				notLocalSystem = true
				continue
			}
			attempted = append(attempted, failure)
		}
		failed = attempted
		message := fmt.Sprintf(
			"uninstall could not act as %d user connector registration(s) because %s; DefenseClaw's inert registration stays in that account's agent configuration. To remove them, %s. Accounts: %s",
			len(pending),
			reason,
			windowsEnterpriseLocalSystemRemedy("/uninstall"),
			windowsEnterpriseBoundedLabels(windowsEnterpriseRegistrationsByAccount(pending)),
		)
		// A purge that did not run as LocalSystem removed none of them and
		// fails (GAP-0075, GAP-1111). The registrations of accounts that had
		// no active session are the documented Windows limit: no process can
		// act as such an account, so a decommission with signed-out or
		// disconnected users finishes with this warning (GAP-2231).
		if purge && notLocalSystem {
			result.AddError("user_registrations_pending", message)
		} else {
			result.AddWarning("user_registrations_pending", message)
		}
	}
	if len(failed) > 0 {
		message := fmt.Sprintf(
			"removing DefenseClaw per-user registrations failed: %s. The entries that stay are inert (the managed install is gone); remove the named DefenseClaw entries from those files as that user, or %s",
			windowsEnterpriseBoundedLabels(failed),
			windowsEnterpriseLocalSystemRemedy("/uninstall"),
		)
		if purge {
			result.AddError("user_registrations_failed", message)
		} else {
			result.AddWarning("user_registrations_failed", message)
		}
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
	if stale := (enterprisehooks.UnprotectedAgentsStaleError{}); errors.As(err, &stale) || errors.Is(err, os.ErrNotExist) {
		age := stale.Age
		if age == "" {
			age = enterprisehooks.UnprotectedAgentsRecordMissing
		}
		result.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, enterprisehooks.UnprotectedAgentsScanPending(age,
			"Restart-Service DefenseClawHookEnumerator (from an elevated prompt)"))
		result.CoverageComplete, result.SecurityComplete = false, false
		// Only the pending scan is a warning. A stale record still names the agents its last scan found; they
		// are reported below, so verify keeps failing on a known gap.
		err = nil
	}
	if err != nil {
		message := "the enumerator's unprotected-agents record is missing or unreadable: " + err.Error()
		if errors.Is(err, os.ErrPermission) {
			message = "this token cannot inspect the enumerator's protected unprotected-agents record; run status or verify from an elevated Administrator prompt: " + err.Error()
		}
		if result.Action == "verify" {
			result.AddError(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		} else {
			result.AddWarning(enterprisehooks.UnprotectedCodeInstallScanIncomplete, message)
		}
		result.CoverageComplete, result.SecurityComplete = false, false
		return
	}
	for _, agent := range agents {
		if agent.Code == enterprisehooks.UnprotectedCodeHookContractUnverified ||
			agent.Code == enterprisehooks.UnprotectedCodeInstallScanIncomplete ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroCLIBelowHookFloor ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor {
			// No contract, an incomplete install scan, a headless CLI path
			// without hooks, or an IDE that cannot read global hooks: the
			// deployment does not cover it (GAP-0151).
			result.CoverageComplete = false
		}
		// unverified_versions: refuse that nothing enforces fails verify.
		if result.Action == "verify" && (agent.Refusal == enterprisehooks.RefusalMissing ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroCLIBelowHookFloor ||
			agent.Code == enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor) {
			result.AddError(agent.Code, agent.Message())
		} else {
			result.AddWarning(agent.Code, agent.Message())
		}
		result.SecurityComplete = false
		if agent.InstallPath != "" && (result.Action == "status" || result.Action == "verify") {
			if err := windowsManagedInstallAudit(agent); err != nil {
				result.AddWarning(windowsManagedLaunchAuditUnavailable, "could not audit the unprotected "+agent.Connector+" install: "+err.Error())
			}
		}
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

// windowsEnterpriseDiscoveryHomeDirs reads ai_discovery.home_dirs of the
// installed config; tests replace it.
var windowsEnterpriseDiscoveryHomeDirs = func() ([]string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseConfigProfileLimit)
	if err != nil {
		return nil, err
	}
	var document struct {
		AIDiscovery struct {
			HomeDirs []string `yaml:"home_dirs"`
		} `yaml:"ai_discovery"`
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil, err
	}
	return document.AIDiscovery.HomeDirs, nil
}

// applyWindowsEnterpriseDiscoveryHomeDirs warns about each
// ai_discovery.home_dirs entry that is neither an enrolled account's profile
// nor a folder inside one. The gateway scans every enrolled profile without
// it; an entry only adds a folder, whose findings name no user, and an
// excluded account's profile is never scanned (GAP-0969).
func applyWindowsEnterpriseDiscoveryHomeDirs(result *enterprisestatus.Result) {
	homes, err := windowsEnterpriseDiscoveryHomeDirs()
	if err != nil || len(homes) == 0 {
		return
	}
	accounts, err := windowsEnterpriseManifestAccounts()
	if err != nil {
		return
	}
	for _, home := range homes {
		home = strings.TrimSpace(home)
		if home == "" || windowsEnterpriseInsideEnrolledProfile(accounts, home) {
			continue
		}
		result.AddWarning("ai_discovery_home_dir_not_enrolled", fmt.Sprintf(
			"ai_discovery.home_dirs names %s, which is not the profile of an enrolled account; AI Discovery scans every "+
				"enrolled profile without home_dirs, so this entry only adds a folder whose findings name no user, and the "+
				"profile of an account enterprise.enrollment.exclude_users names is never scanned: remove the entry unless "+
				"the folder is meant as an extra scan root", home))
	}
}

func windowsEnterpriseInsideEnrolledProfile(accounts []windowsEnterpriseManifestAccount, path string) bool {
	path = filepath.Clean(path)
	for _, account := range accounts {
		profile := filepath.Clean(strings.TrimSpace(account.Home))
		if profile == "." {
			continue
		}
		if strings.EqualFold(path, profile) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(profile)+`\`) {
			return true
		}
	}
	return false
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
	cfg, err := loadWindowsEnterpriseStandaloneConfig(path)
	if err != nil {
		return nil, err
	}
	return enterprisehooks.EffectiveWindowsStandaloneHookConnectors(cfg), nil
}

// loadWindowsEnterpriseStandaloneConfig loads path (the installed config
// when empty) the way the guardian loads the installed one.
func loadWindowsEnterpriseStandaloneConfig(path string) (*config.Config, error) {
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
	return config.LoadManagedFileForLifecycleRecovery(path)
}

// windowsEnterpriseConfigAPIPort returns the gateway.api_port of path (the
// installed config when empty); replaceable in tests.
var windowsEnterpriseConfigAPIPort = func(path string) (int, error) {
	cfg, err := loadWindowsEnterpriseStandaloneConfig(path)
	if err != nil {
		return 0, err
	}
	return cfg.Gateway.APIPort, nil
}

// refuseWindowsEnterpriseAPIPortChange refuses, before any service stops, a
// config that moves gateway.api_port of an installed deployment. Every
// user's hook registrations and the Cursor machine hooks name the installed
// port, so the upgrade transaction stopped and restarted every service
// twice, failed 1603 after about five minutes on the Cursor machine
// identity and rolled back (GAP-0865). A config either side cannot load is
// left to the checks that report it.
func refuseWindowsEnterpriseAPIPortChange(opts *windowsEnterpriseLifecycleOptions) error {
	path := strings.TrimSpace(opts.configPath)
	if !windowsEnterpriseStandalone(opts) || path == "" {
		return nil
	}
	staged, err := windowsEnterpriseConfigAPIPort(path)
	if err != nil || staged == 0 {
		return nil
	}
	installed, err := windowsEnterpriseConfigAPIPort("")
	if err != nil || installed == 0 || installed == staged {
		return nil
	}
	return windowsEnterpriseInvalidArguments(
		"%s changes gateway.api_port from %d to %d; the port of an installed managed deployment cannot be changed, "+
			"because every user's agent hooks and the Cursor machine hooks are bound to it, so nothing was changed and no service was stopped. "+
			"Keep gateway.api_port: %d in the config, or uninstall DefenseClaw and install it again with the new port",
		path, installed, staged, installed)
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

// windowsEnterpriseBundleRefusalCodes are the bundle refusals a retry of the
// same delivery cannot get past: they exit 1603 even with the
// bundle_apply_failed that follows them, so the MDM does not spend its
// 1618 retries on them.
var windowsEnterpriseBundleRefusalCodes = []string{
	"fleet_setup_required",
	"bundle_config_validation_failed",
	"bundle_install_options_changed",
}

func windowsEnterpriseFailureCodeFor(result *enterprisestatus.Result) int {
	for _, message := range result.Errors {
		if containsString(windowsEnterpriseBundleRefusalCodes, message.Code) {
			return enterprisestatus.WindowsExitFailure
		}
	}
	for _, message := range result.Errors {
		switch message.Code {
		case "lifecycle_busy", string(enterprisebundle.CodeRestartDeferred), string(enterprisebundle.CodeNotConfirmed):
			return enterprisestatus.WindowsExitBusy
		case "bundle_apply_failed", "bundle_policy_not_adopted", "bundle_post_verify_failed", "bundle_targets_refresh_failed":
			return enterprisestatus.WindowsExitBusy
		case "hook_calls_running", "hook_in_use":
			// The lifecycle deferred before it changed anything, while hook
			// calls of the installed release still run (GAP-1124) or another
			// program holds the installed hook open (GAP-2001).
			return enterprisestatus.WindowsExitBusy
		case "scanner_runtime_unavailable":
			if strings.HasSuffix(message.Message, windowsScannerPrepareRetryNotice) {
				// A prepare that hit its bound is finished by a retry of the
				// same command (GAP-1687).
				return enterprisestatus.WindowsExitBusy
			}
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
	if len(opts.recoveryChanges) != 0 {
		// The recovery before the config check changed the host: not a
		// no-op, whatever the run decided after it.
		result.Changes = append(append([]string{}, opts.recoveryChanges...), result.Changes...)
		result.Noop, result.NoopReason = false, ""
	}
	if windowsBundleHasCode(result.Errors, "powershell7_untrusted") {
		for i := range result.Warnings {
			if result.Warnings[i].Code == windowsEnterpriseHealthNotChecked {
				result.Warnings[i].Message = windowsEnterpriseUncheckedHealthMessage(result.Profile, true)
			}
		}
	}
	addWindowsEnterprisePipeWaitWarning(result, opts)
	deliveredBundle := opts.bundle != nil && opts.bundle.prepared != nil && opts.bundle.prepared.Receipt != nil
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if result.Bundle != nil && result.Bundle.State == enterprisebundle.StateApplied &&
		windowsBundleHasCode(result.Errors, string(enterprisebundle.CodeNotConfirmed)) {
		failureCode = enterprisestatus.WindowsExitBusy
	}
	addWindowsBundleEnforcementError(result, opts, deliveredBundle)
	if result.Noop && windowsBundleHasCode(result.Warnings, "bundle_config_restored") {
		// The plan after the restore found nothing to do, but the run put the
		// bundle config back: that is a repair, not a no-op.
		result.Noop, result.NoopReason = false, ""
	}
	applyWindowsStandaloneScannerRuntime(result, opts)
	addWindowsEnterpriseMigrationChange(result, opts)
	addWindowsEnterpriseMissingCredentialWarnings(result)
	applyWindowsEnterpriseAgentSessions(result, opts)
	applyWindowsEnterpriseLaunchCoverage(result)
	applyWindowsEnterpriseAgentSettings(result)
	if opts.localEnforcementEntriesIgnored > 0 {
		result.AddWarning(config.LocalEnforcementEntriesIgnored, fmt.Sprintf(
			"%d local block/allow entries in audit.db are ignored; the administrator config is the policy",
			opts.localEnforcementEntriesIgnored))
	}
	if opts.runningDeploymentLabel {
		// The refused config changed nothing: each advisory is the running
		// deployment's, except those about this request (GAP-0564, GAP-0103).
		result.LabelRunningDeployment(opts.runningDeploymentWarningsFrom,
			windowsEnterpriseHealthNotChecked, "installer_pipe_wait_delayed")
	}
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

func addWindowsEnterprisePipeWaitWarning(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if opts != nil && opts.powerShellPipeWaitDelayed {
		result.AddWarning("installer_pipe_wait_delayed", "PowerShell exited successfully, but a descendant held an output pipe open; Setup closed the installer job and ended the descendant")
	}
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
	writeWindowsEnterpriseScanners(output, result.Scanners)
	if result.Policy != nil {
		fmt.Fprintf(output, "  %s\n", result.PolicyLine())
	}
	enterprisestatus.WriteDestinations(output, result.Destinations)
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
	if result.Bundle != nil && result.Bundle.SessionsRestartRequired != nil {
		enterprisestatus.WriteSessionEntries(output, *result.Bundle.SessionsRestartRequired)
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
	return writeWindowsEnterpriseStandaloneRefusal(cmd, action, opts, cause, applyWindowsEnterpriseRecordedDeployment)
}

// writeWindowsEnterpriseStandaloneConfigRefusal answers an install or ensure
// whose config the gateway could not load. It changed nothing, so the result
// is the status of the host as it is, as an ensure refused by its plan
// reports it: installed, version, services and readiness of the running
// deployment. Reporting installed false with every readiness flag false made
// an MDM compliance rule read a healthy host as uninstalled (GAP-0181). A
// probe that cannot read the host leaves the recorded deployment. Each
// warning of that host, such as its security_incomplete advisory, is
// labelled as the running deployment's, as on Linux and macOS, so it does
// not read as a problem of the refused file (GAP-0564, #1201).
func writeWindowsEnterpriseStandaloneConfigRefusal(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	cause error,
) error {
	return writeWindowsEnterpriseStandaloneRefusal(cmd, action, opts, cause, func(result *enterprisestatus.Result) {
		// The finish labels every warning from here on, its own (credential,
		// scanner and agent advisories) included (GAP-0103).
		opts.runningDeploymentLabel = true
		opts.runningDeploymentWarningsFrom = len(result.Warnings)
		status, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script,
			windowsEnterprisePowerShellArgs("status", windowsEnterpriseEnsureProbeOptions(opts)))
		if err != nil || status.probeFailed {
			applyWindowsEnterpriseRecordedDeployment(result)
			return
		}
		// The host as status reports it: its policy and its advisories.
		applyWindowsEnterpriseInstallerReport(result, opts, status, run)
		applyWindowsEnterprisePolicyAs(ctx, result, false)
		if status.Installed {
			appendWindowsEnterpriseStatusAdvisories(ctx, result, status)
		}
		result.Errors = []enterprisestatus.Message{}
	})
}

// refuseWindowsEnterpriseStandaloneSuppliedConfig refuses a request whose
// supplied config the gateway could not load, and reports refused=false
// when the config passes. An interrupted upgrade leaves a pending
// transaction with the services stopped, and only a lifecycle run recovers
// it: refusing a supplied config before that run left the host stopped on
// every MDM retry (GAP-1433, GAP-0705). Each action first recovers a pending
// transaction, which restores the previous deployment and its services, and
// checks the config again: the restored rule packs can make it load. Ensure
// and upgrade recover with the source-free repair GAP-1433 gave them. A
// repair recovers with the transaction recovery alone (Recover): the full
// repair went on past the recovery and changed services, access lists and
// hooks for a request it then refused, which the 1.0.3 lifecycle never did
// for a repair; the requested repair runs only once its config passes. A
// config still refused is refused, and the refusal reports the restored
// host. The result reports what the recovery changed, whichever way the run
// goes on (noteWindowsEnterpriseRefusalRecovery).
func refuseWindowsEnterpriseStandaloneSuppliedConfig(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
) (bool, error) {
	// A config profile resolution found unparseable is refused with the
	// gateway's reason it already has (GAP-0103).
	err := opts.suppliedConfigRefusal
	if err == nil {
		err = windowsEnterpriseStandaloneConfigPreflight(opts.configPath)
	}
	if err != nil && (action == "ensure" || action == "upgrade" || action == "repair") && windowsEnterpriseStandaloneTransactionPending() {
		recoveryArgs := windowsEnterprisePowerShellArgs("recover", windowsEnterpriseEnsureProbeOptions(opts))
		if action != "repair" {
			recovery := *opts
			recovery.jsonOutput = true
			clearWindowsEnterpriseSources(&recovery)
			recoveryArgs = windowsEnterprisePowerShellArgs("repair", windowsEnterpriseRepairRecordingOptions("repair", &recovery))
		}
		// A recovery that failed leaves transaction_pending, which the
		// refusal's probe of the host reports.
		_, _, _ = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, recoveryArgs)
		noteWindowsEnterpriseRefusalRecovery(opts, windowsEnterpriseInstallerAction(recoveryArgs))
		if opts.suppliedConfigRefusal == nil {
			err = windowsEnterpriseStandaloneConfigPreflight(opts.configPath)
		}
	}
	if err == nil {
		return false, nil
	}
	if !opts.suppliedConfigUnreadable {
		err = fmt.Errorf("%w: %w", errWindowsEnterpriseInvalidArguments, err)
	}
	return true, writeWindowsEnterpriseStandaloneConfigRefusal(ctx, cmd, action, opts, script, err)
}

// noteWindowsEnterpriseRefusalRecovery records, for the result of the run
// (finishWindowsEnterpriseStandalone), that the recovery before a config
// check settled the pending transaction, whether the run then refuses the
// config or goes on with it. A recovery that left the transaction pending
// changed nothing this can name; the result reports transaction_pending.
func noteWindowsEnterpriseRefusalRecovery(opts *windowsEnterpriseLifecycleOptions, moduleAction string) {
	if windowsEnterpriseStandaloneTransactionPending() {
		return
	}
	change := "recovered the interrupted lifecycle transaction before checking the supplied config, which restored the previous deployment and its services"
	if moduleAction == "Repair" {
		change += ", and repaired it without new sources"
	}
	opts.recoveryChanges = append(opts.recoveryChanges, change)
}

// writeWindowsEnterpriseStandaloneRefusal writes the schema-2 result of a
// request refused before it changed anything. describeHost fills the host
// as it is into a refusal for invalid arguments.
func writeWindowsEnterpriseStandaloneRefusal(
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	cause error,
	describeHost func(*enterprisestatus.Result),
) error {
	if cause == nil {
		return nil
	}
	if opts == nil {
		opts = &windowsEnterpriseLifecycleOptions{}
	}
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	code := "preflight_failed"
	invalid := errors.Is(cause, errWindowsEnterpriseInvalidArguments)
	if invalid {
		code = "invalid_arguments"
		// A rule pack the gateway service cannot read has its own code,
		// as the enumerator's report has; the exit stays 1639 (GAP-0314).
		if strings.Contains(cause.Error(), standaloneRulePackUnreadableText) {
			code = "rule_pack_unreadable"
		}
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
	case "invalid_arguments", "rule_pack_unreadable":
		message = strings.TrimPrefix(message, errWindowsEnterpriseInvalidArguments.Error()+": ")
		if windowsEnterpriseUnknownProfileRequested(opts) {
			// Name the value once (GAP-2040); the resolution error keeps
			// the text the Secure Client profile pins.
			message = fmt.Sprintf("invalid --profile %q: use %s or %s",
				strings.TrimSpace(opts.profile), managed.ProfileStandalone, managed.ProfileSecureClient)
		}
		describeHost(result)
	default:
		// Every refusal changed nothing, so it reports the host as it is.
		// An ensure whose --config did not exist reported a healthy
		// deployment as installed=false with no services (GAP-0036).
		describeHost(result)
	}

	result.AddError(code, message)
	failure := windowsEnterpriseFailureCodeFor(result)
	if invalid {
		failure = enterprisestatus.WindowsExitInvalidArgs
	}
	return finishWindowsEnterpriseStandalone(cmd, opts, result, failure)
}

// windowsEnterpriseHealthNotChecked is the warning of a request refused
// before any health check ran: its result reports only the recorded
// deployment and the service states.
const windowsEnterpriseHealthNotChecked = "health_not_checked"

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
		for _, service := range windowsEnterpriseStandaloneServiceRoster {
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
		result.AddWarning(windowsEnterpriseHealthNotChecked, windowsEnterpriseUncheckedHealthMessage(profile, false))
		return
	}
}

// windowsEnterpriseLiveStandaloneServices are the standalone DefenseClaw
// services that exist, with their states as the service manager reports them
// now. A failed lifecycle's report can name none of them, and a rollback can
// have restarted them after its report was taken.
func windowsEnterpriseLiveStandaloneServices() []enterprisestatus.Service {
	var services []enterprisestatus.Service
	for _, service := range windowsEnterpriseStandaloneServiceRoster {
		if state := windowsEnterpriseServiceState(service.name); state != "absent" {
			services = append(services, enterprisestatus.Service{
				Name: service.name, Kind: service.kind, State: state, Required: true,
			})
		}
	}
	return services
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

// readWindowsEnterpriseStandaloneDestinations lists, for status, the
// observability destinations the installed config.yaml compiles to with each
// one's effective redaction profiles. `defenseclaw observability plan` is a
// per-user command managed Windows does not offer (GAP-1105). A config that
// does not compile leaves the list out.
func readWindowsEnterpriseStandaloneDestinations() []enterprisestatus.Destination {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil
	}
	raw, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, 8<<20)
	if err != nil {
		return nil
	}
	summaries, err := config.SummarizeObservabilityV8Destinations(layout.ConfigPath, raw, layout.DataDir)
	if err != nil {
		return nil
	}
	return enterprisestatus.DestinationsFromSummaries(summaries)
}

// readWindowsEnterpriseStandaloneEnrollment summarizes the installed
// guardian manifest when this token can read it.
func readWindowsEnterpriseStandaloneEnrollment() (enterprisestatus.Enrollment, error) {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	return readWindowsEnterpriseStandaloneEnrollmentAt(layout.ManifestPath, layout.DataDir)
}

// readWindowsEnterpriseStandaloneEnrollmentAt counts the manifest's targets
// and exempt rows, and as pending the targets the guardian's last reconcile
// (in runtimeDir) left waiting for their account's session: those never
// enrolled, and those an earlier release protected that the guardian repairs
// at the account's next sign-in (GAP-0644). Every Windows per-user row is
// written deferred, so that flag does not say which.
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
		for _, row := range state.Results {
			if enterpriseHookAwaitingSignInError(row) {
				enrollment.Pending++
			}
		}
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

var windowsEnterpriseEnsureTimeout = 12 * time.Minute

// windowsEnterpriseEnsureMaximumTimeoutSeconds is the longest
// --timeout-seconds, Setup's longest TIMEOUTSECONDS.
const windowsEnterpriseEnsureMaximumTimeoutSeconds = 2 * 60 * 60

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
	// GAP-2265: under Setup the deadline is Setup's TIMEOUTSECONDS budget
	// (default 30 minutes), passed as --timeout-seconds; a fixed 12 minutes
	// here failed an upgrade on a busy host long before the limit an
	// administrator set or was told to raise.
	timeout := windowsEnterpriseEnsureTimeout
	if opts.timeoutSeconds != 0 {
		if opts.timeoutSeconds < 60 || opts.timeoutSeconds > windowsEnterpriseEnsureMaximumTimeoutSeconds {
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			result.AddError("invalid_arguments", fmt.Sprintf("--timeout-seconds must be between 60 and %d", windowsEnterpriseEnsureMaximumTimeoutSeconds))
			return finishWindowsEnterpriseStandalone(cmd, opts, result, enterprisestatus.WindowsExitInvalidArgs)
		}
		timeout = time.Duration(opts.timeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if opts.bundle != nil {
		// A failed bundle's nested rollback uses the remaining ensure budget.
		opts.bundle.ctx = ctx
	}
	defaultWindowsEnterpriseEnsurePayload(opts, script)
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	// An ensure without CONFIG= or BUNDLE= on a bundle-mode device puts the
	// confirmed bundle config back before it plans: the repair it may run
	// starts the gateway on the installed config (GAP-0114). A restore that
	// fails stops here, before any service starts on the edited file.
	if windowsBundleRestoreRequested("ensure", opts) {
		restore := restoreWindowsBundleConfig(ctx, windowsBundleSettleReplacing(opts))
		restore.apply(result)
		if restore.failed() {
			applyWindowsEnterpriseRecordedDeployment(result)
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
	}
	retry, err := runWindowsEnterpriseStandaloneEnsureOnce(ctx, cmd, opts, script, result, true)
	if !retry {
		return err
	}
	// The plan went stale while ensure waited for the lifecycle lock: a
	// concurrent run installed the host. Re-plan once from a fresh status.
	_, err = runWindowsEnterpriseStandaloneEnsureOnce(ctx, cmd, opts, script, result, false)
	return err
}

var windowsEnterpriseRestoreStartModes = restoreWindowsEnterpriseStartModes
var windowsEnterpriseRestoreServiceName = regexp.MustCompile(`^DefenseClaw[A-Za-z0-9_]+$`)

// restoreWindowsEnterpriseStartModes is the last-resort startup-mode cleanup
// when an installer child was terminated before its transaction rollback.
// The read-only status report is the preimage; only its recorded services are
// changed, and no service is started outside the installer's coverage gates.
func restoreWindowsEnterpriseStartModes(report *windowsEnterpriseInstallerReport) error {
	if report == nil || !report.Installed || len(report.ServiceStartModes) == 0 {
		return nil
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open Windows service manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	var failures []error
	for _, name := range []string{report.GuardianService, report.GatewayService, report.EnumeratorService, report.SensorHelperService} {
		mode := strings.ToLower(strings.TrimSpace(report.ServiceStartModes[name]))
		if mode != "auto" && mode != "manual" {
			continue
		}
		if !windowsEnterpriseRestoreServiceName.MatchString(name) {
			failures = append(failures, fmt.Errorf("refusing unrecognized service name %q", name))
			continue
		}
		namePointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			failures = append(failures, fmt.Errorf("service %s name: %w", name, err))
			continue
		}
		handle, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_CHANGE_CONFIG)
		if err != nil {
			failures = append(failures, fmt.Errorf("open service %s: %w", name, err))
			continue
		}
		service := &mgr.Service{Name: name, Handle: handle}
		current, configErr := service.Config()
		startType, restore := windowsEnterpriseStartModeToRestore(mode, current.StartType)
		if configErr == nil && restore {
			configErr = windows.ChangeServiceConfig(handle, windows.SERVICE_NO_CHANGE, startType,
				windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil)
			if configErr == nil {
				current, configErr = service.Config()
				if configErr == nil && current.StartType != startType {
					configErr = fmt.Errorf("service manager still reports startup mode %d", current.StartType)
				}
			}
		}
		_ = service.Close()
		if configErr != nil {
			failures = append(failures, fmt.Errorf("restore service %s startup mode to %s: %w", name, mode, configErr))
		}
	}
	return errors.Join(failures...)
}

func windowsEnterpriseStartModeToRestore(recorded string, current uint32) (uint32, bool) {
	if current != windows.SERVICE_DISABLED {
		return 0, false
	}
	switch recorded {
	case "auto":
		return windows.SERVICE_AUTO_START, true
	case "manual":
		return windows.SERVICE_DEMAND_START, true
	default:
		return 0, false
	}
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
// A warning-only verify can report security_incomplete while its checks and
// gateway succeeded. That warning is not an installer failure to repair by
// stopping services. Errors and an unavailable gateway still require repair.
func windowsEnterpriseVerifyAcceptable(report *windowsEnterpriseInstallerReport) bool {
	return report != nil && report.Installed && report.GatewayReady && !report.TransactionPending &&
		len(report.Errors) == 0 && report.Error == ""
}

// A repeated confirmed bundle checks the installed deployment with its own
// installer. Setup's staged module and hash-pinned manifest describe the
// incoming package, not the installed release. Passing that manifest into
// Verify also prevents PowerShell from loading the installed release's
// recorded payload pins, so a package-specific failure could trigger repair.
func windowsEnterpriseConfirmedBundleProbe(opts *windowsEnterpriseLifecycleOptions, run *windowsBundleRun) (string, *windowsEnterpriseLifecycleOptions, error) {
	if run == nil || strings.TrimSpace(run.layout.InstallRoot) == "" {
		return "", nil, errors.New("installed bundle layout has no install root")
	}
	installed := filepath.Join(run.layout.InstallRoot, "libexec", "install-enterprise.ps1")
	script, err := windowsEnterpriseScriptFinder(installed)
	if err != nil {
		return "", nil, fmt.Errorf("read the installed enterprise installer: %w", err)
	}
	probe := windowsEnterpriseEnsureProbeOptions(opts)
	probe.trustMode = windowsEnterpriseTrustAuthenticode
	probe.payloadManifest = ""
	probe.allowedSigners = nil
	return script, probe, nil
}

func windowsEnterpriseVerifyFailureDetail(report *windowsEnterpriseInstallerReport, hookDrift string) string {
	if report != nil {
		for _, message := range append(append([]string{}, report.Errors...), report.Error) {
			if detail := strings.TrimSpace(message); detail != "" {
				return windowsEnterpriseBoundedDiagnostic(detail)
			}
		}
		if !report.Installed {
			return "the deployment is not installed"
		}
		if report.TransactionPending {
			return "a lifecycle transaction is pending"
		}
		if !report.GatewayReady {
			return "the gateway is not ready"
		}
	}
	if hookDrift != "" {
		return windowsEnterpriseBoundedDiagnostic(hookDrift)
	}
	return "the installed deployment failed verification without a diagnostic"
}

// windowsEnterpriseCodexTargetTransactionReason is how the ensure result
// says why a config change ran the upgrade transaction.
const windowsEnterpriseCodexTargetTransactionReason = "the config turns Codex protection on or off, or its Codex target differs from the protected deployment record, and only the lifecycle transaction installs and removes Codex's machine policy, so every service was restarted"

func runWindowsEnterpriseStandaloneEnsureOnce(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	result *enterprisestatus.Result,
	allowRetry bool,
) (bool, error) {
	statusReport, statusRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("status", windowsEnterpriseEnsureProbeOptions(opts)))
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		// Nothing ran: keep the recorded deployment in the result (GAP-0770).
		applyWindowsEnterpriseRecordedDeployment(result)
		return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	serviceMutationAttempted := false
	lastMutationCommitted := false
	// childTerminated is whether the last installer run that changed the
	// host ended without a report: it timed out or was killed before its
	// own rollback ran. Only then does ensure put the startup modes back. A
	// parsed report, even a failed one or a recovery that deliberately left
	// a release it could not reactivate stopped and disabled, is the
	// installer's decision and stays as it is.
	childTerminated := false
	// Restore before Finish writes JSON and the lifecycle log, so an SCM
	// failure is visible to the caller that must arrange further recovery.
	finishEnsure := func(code int) error {
		if serviceMutationAttempted && !lastMutationCommitted && childTerminated &&
			statusReport != nil && !statusReport.probeFailed {
			if err := windowsEnterpriseRestoreStartModes(statusReport); err != nil {
				result.AddError("startup_mode_restore_failed", "restore prior service startup modes: "+err.Error())
				code = windowsEnterpriseFailureCodeFor(result)
			}
		}
		// Every exit passes windowsEnterpriseFailureCodeFor, which is nonzero
		// even for a clean run, so the closure is settled on the error list
		// as repair and verify settle it: released once the gateway proves
		// the installed config, otherwise named (GAP-2087).
		errorsBefore := len(result.Errors)
		settleWindowsEnterpriseHotConfigClosure(ctx, result, "ensure")
		if len(result.Errors) != errorsBefore {
			code = windowsEnterpriseFailureCodeFor(result)
		}
		return finishWindowsEnterpriseStandalone(cmd, opts, result, code)
	}
	configStateRepaired, stateErr := windowsEnterpriseConfigGenerationRepair(ctx, opts, statusReport)
	if stateErr != nil {
		applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
		result.AddError("lifecycle_error", stateErr.Error())
		return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
	}
	if configStateRepaired {
		result.Changes = append(result.Changes, "recovered config generation from the approved config and proven previous counter")
	}
	alreadyAppliedNeedsRepair := false
	verifyFailure := ""
	if run := opts.bundle; !configStateRepaired && run != nil && run.prepared != nil && run.prepared.AlreadyApplied &&
		statusReport.Installed && !statusReport.TransactionPending &&
		compareWindowsEnterpriseVersions(opts.productVersion, statusReport.InstalledVersion) == 0 &&
		windowsBundleInstalledSHA(run.layout.ConfigPath) == run.prepared.ConfigSHA256 {
		verifyScript, verifyOpts, probeErr := windowsEnterpriseConfirmedBundleProbe(opts, run)
		if probeErr != nil {
			verifyFailure = windowsEnterpriseBoundedDiagnostic(probeErr.Error())
		}
		var verifyReport *windowsEnterpriseInstallerReport
		var verifyRun windowsEnterpriseStandaloneRun
		var verifyErr error
		if probeErr == nil {
			verifyReport, verifyRun, verifyErr = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, verifyScript,
				windowsEnterprisePowerShellArgs("verify", verifyOpts))
		}
		if verifyErr != nil {
			result.AddError(windowsEnterpriseMessageCode(verifyErr.Error(), "lifecycle_launch_failed"), verifyErr.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		_, drifted := windowsEnterpriseHookRuntimeDrift()
		compilerDrift := false
		verified := probeErr == nil && windowsEnterpriseVerifyAcceptable(verifyReport) && drifted == ""
		if verified {
			compilerDrift, err = windowsEnterpriseConfirmedBundleCompilerDrift(run)
			if err != nil {
				accepted := *verifyReport
				accepted.OK = true
				applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
				result.AddError("bundle_state_invalid", "cannot verify Fleet compiler state for the confirmed bundle: "+windowsEnterpriseBoundedDiagnostic(err.Error()))
				return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
			}
			if compilerDrift && strings.TrimSpace(opts.policyCompiler) == "" {
				accepted := *verifyReport
				accepted.OK = true
				applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
				result.AddError("fleet_setup_required", "Fleet compiler state differs from the confirmed bundle; use signed standalone Setup to install or remove the compiler")
				return false, finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
			}
		}
		if verified && !compilerDrift {
			pending := false
			if windowsEnterpriseIsElevated() {
				pending, err = windowsEnterpriseCursorMigrationRepairPending()
				if err != nil {
					result.AddError("preflight_failed", "check the recorded Cursor fail-mode repair: "+err.Error())
					return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
				}
			}
			if !pending {
				// The module can set ok:false for security_incomplete with no
				// failed check. Keep its warning, without turning that into a
				// synthetic not_ready error during result translation.
				accepted := *verifyReport
				accepted.OK = true
				applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
				result.Noop = true
				result.NoopReason = "already_applied"
				applyWindowsEnterprisePolicy(ctx, result)
				return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
			}
			verifyFailure = "recorded Cursor fail-mode repair"
		}
		if !compilerDrift {
			alreadyAppliedNeedsRepair = true
			if verifyFailure == "" {
				verifyFailure = windowsEnterpriseVerifyFailureDetail(verifyReport, drifted)
			}
		}
	}
	plan := windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed", Detail: verifyFailure}
	var planErr error
	switch {
	case configStateRepaired:
		plan, planErr = planWindowsEnterpriseEnsureAfterGenerationRecovery(func() (windowsEnterpriseEnsurePlan, error) {
			return planWindowsEnterpriseEnsure(statusReport, opts, script)
		})
	case !alreadyAppliedNeedsRepair:
		plan, planErr = planWindowsEnterpriseEnsure(statusReport, opts, script)
	}
	if planErr != nil {
		applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
		result.Errors = []enterprisestatus.Message{}
		result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
		return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
	}
	if plan.Action == "" {
		// A compliant deployment can still owe the one-time Cursor fail-mode
		// correction the old v9 migration recorded. Its repair is selected
		// only after Verify accepts the deployment, and it meets the rule-pack
		// preflight below like any repair, before anything stops.
		cursorRepairPending := false
		if windowsEnterpriseIsElevated() {
			pending, repairErr := windowsEnterpriseCursorMigrationRepairPending()
			if repairErr != nil {
				applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
				result.AddError("preflight_failed", "check the recorded Cursor fail-mode repair: "+repairErr.Error())
				return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
			}
			cursorRepairPending = pending
		}
		verifyCtx := ctx
		if windowsEnterpriseIsElevated() && !cursorRepairPending {
			// A compliant deployment runs no retire, so this Verify collects
			// the old runtime copies a retire left and names each per-user
			// folder still untrusted (#1105, GAP-0211).
			verifyCtx = context.WithValue(ctx, windowsEnterpriseCollectGenerationsKey{}, true)
		}
		verifyReport, verifyRun, err := runWindowsEnterpriseStandaloneInstaller(verifyCtx, cmd, opts, script, windowsEnterprisePowerShellArgs("verify", windowsEnterpriseEnsureProbeOptions(opts)))
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		_, drifted := windowsEnterpriseHookRuntimeDrift()
		verified := windowsEnterpriseVerifyAcceptable(verifyReport) && drifted == ""
		switch {
		case verified && cursorRepairPending:
			plan = windowsEnterpriseEnsurePlan{Action: "repair", Reason: "recorded_cursor_fail_mode"}
		case verified:
			accepted := *verifyReport
			accepted.OK = true
			applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
			if windowsEnterpriseIsElevated() {
				// A copy an earlier upgrade kept of a binary an editor still
				// ran goes once nothing runs it (GAP-0934).
				for _, removed := range windowsEnterpriseRemoveReplacementCopies() {
					result.Changes = append(result.Changes, "removed "+removed+", which no program runs any more")
				}
			}
			if collected := verifyReport.LifecycleGenerationsCollected; collected > 0 {
				result.Changes = append(result.Changes, fmt.Sprintf(
					"removed %d old DefenseClaw hook runtime copies from the accounts' DefenseClaw folders", collected))
			}
			result.Noop = true
			result.NoopReason = plan.Reason
			applyWindowsEnterprisePolicy(ctx, result)
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		default:
			// Name the failed check: a compliant-looking host that ensure
			// repaired said only "ensure_repair: verify_failed" (#1282).
			plan = windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed",
				Detail: windowsEnterpriseVerifyFailureDetail(verifyReport, drifted)}
		}
	}

	// An upgrade that keeps the installed config: this release's gateway must
	// load it before the lifecycle stops the services (GAP-0188). A
	// drift:config upgrade replaces the edited file instead.
	if plan.Action == "upgrade" && plan.Reason != "drift:config" && windowsEnterpriseKeepsInstalledConfig(opts) {
		if err := windowsEnterpriseStandaloneKeptConfigPreflight(); err != nil {
			applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
			result.Errors = []enterprisestatus.Message{}
			result.AddError("preflight_failed", err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
	}

	// A repair restarts the gateway on the installed config: refuse one whose
	// rule packs the gateway would not load, before anything stops (GAP-0672).
	// Every repair ensure selects here restarts it (verify_failed and the
	// recorded Cursor correction alike); a pending transaction is left to its
	// recovery, which restores the packs the deployment had.
	if plan.Action == "repair" && plan.Reason != "transaction_pending" {
		if err := windowsEnterpriseStandaloneRepairRulePackPreflight(opts.configPath); err != nil {
			applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
			result.Errors = []enterprisestatus.Message{}
			result.AddError("preflight_failed", err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
	}

	keptConfig := ""
	var startOnlyKeys []string
	if plan.Action == "upgrade" && (plan.Reason == "drift:config" || plan.Reason == "drift:bundle") {
		applied, keys := windowsEnterpriseHotConfigApply(ctx, cmd, opts, script, statusReport, result)
		if applied || opts.hotConfigRestoreFailed {
			// A failed apply whose restore could not be proven stops here:
			// the transaction would snapshot the config it left behind
			// (GAP-1178).
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		// A signed bundle has no transaction fallback after a hot apply that
		// failed; one that turns Codex protection on or off never started
		// one and is applied by the transaction (GAP-0033).
		if plan.Reason == "drift:bundle" && !opts.codexTargetTransaction {
			result.AddError("bundle_apply_failed", "the policy bundle apply did not complete; check the preceding bundle error and gateway health")
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		startOnlyKeys = keys
		keptConfig = keepInstalledWindowsEnterpriseEditedConfig()
		if opts.codexTargetTransaction {
			plan.Action = windowsEnterpriseCodexTargetAction(opts)
		}
	}
	if (plan.Action == "upgrade" || plan.Action == "repair") && !statusReport.TransactionPending {
		// The transaction must not load an installed config.yaml that does
		// not parse before it uses the supplied one (GAP-0948).
		kept, err := installWindowsEnterpriseSuppliedConfigOverUnparseable(opts.configPath)
		if err != nil {
			applyWindowsEnterpriseInstallerReport(result, opts, statusReport, statusRun)
			result.Errors = []enterprisestatus.Message{}
			result.AddError("preflight_failed", err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		if kept != "" {
			keptConfig = kept
			result.Changes = append(result.Changes, windowsEnterpriseUnparseableConfigChange(kept, plan.Action))
		}
	}

	actionOpts := *opts
	actionOpts.jsonOutput = true
	if plan.Action == "repair" {
		// Repair reapplies ACL, service, and environment invariants from the
		// installed payload and records the installed binaries' version. A
		// repair after a failed verify keeps this run's payload: the planner
		// found every supplied source byte-identical to the recorded one
		// (no drift), so it is the installed release, and it is the only
		// copy of a payload file an antivirus quarantine removed. Without it
		// ensure refused "recorded managed artifact is missing" where Setup
		// /repair healed the same host (GAP-0935).
		if plan.Reason != "verify_failed" {
			clearWindowsEnterpriseSources(&actionOpts)
			if opts.codexTargetTransaction {
				// The repair installs the supplied config on the installed
				// binaries (windowsEnterpriseCodexTargetAction).
				actionOpts.configPath = opts.configPath
			}
		}
		if alreadyAppliedNeedsRepair {
			actionOpts.configPath = ""
		}
		actionOpts = *windowsEnterpriseRepairRecordingOptions("repair", &actionOpts)
		if repaired := repairWindowsEnterpriseHookRuntimeAccess(); repaired != "" {
			result.Changes = append(result.Changes, repaired)
		}
		if repaired := repairWindowsEnterpriseClaudeDropIn(); repaired != "" {
			result.Changes = append(result.Changes, repaired)
		}
	}
	var cleanupManifest func()
	if plan.Action == "install" && strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
		manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, windowsEnterpriseEnsureEnumerationLogger(cmd, opts), actionOpts.configPath)
		if err != nil {
			result.AddError(windowsEnterpriseEnsureStagingErrorCode(err), err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		cleanupManifest = cleanup
		actionOpts.manifestPath = manifestPath
		if err := windowsEnterpriseStandaloneProfilesPreflight(manifestPath); err != nil {
			cleanup()
			result.AddError("preflight_failed", err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
	}
	if cleanupManifest != nil {
		defer cleanupManifest()
	}
	beforeGatewayPID := uint32(0)
	if opts.bundle != nil && windowsBundleConfigChange(opts.bundle.prepared) {
		beforeGatewayPID = windowsStandaloneGatewayPID()
	}
	serviceMutationAttempted = true
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
	lastMutationCommitted = err == nil && report != nil && report.OK && !report.TransactionPending && run.ExitCode == 0
	childTerminated = err != nil && report == nil
	if beforeGatewayPID != 0 {
		if afterGatewayPID := windowsStandaloneGatewayPID(); afterGatewayPID != 0 && beforeGatewayPID != afterGatewayPID {
			opts.bundle.gatewayRestarted = true
		}
	}
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
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
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
		}
		plan = installPlan
		actionOpts = *opts
		actionOpts.jsonOutput = true
		if strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
			manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, windowsEnterpriseEnsureEnumerationLogger(cmd, opts), actionOpts.configPath)
			if err != nil {
				result.AddError(windowsEnterpriseEnsureStagingErrorCode(err), err.Error())
				return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
			}
			defer cleanup()
			actionOpts.manifestPath = manifestPath
		}
		report, run, err = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
		lastMutationCommitted = err == nil && report != nil && report.OK && !report.TransactionPending && run.ExitCode == 0
		childTerminated = err != nil && report == nil
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
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
				return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
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
				lastMutationCommitted = err == nil && report != nil && report.OK && !report.TransactionPending && run.ExitCode == 0
				childTerminated = err != nil && report == nil
				if err != nil {
					result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
					return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
				}
			} else if !deferredActivation {
				// The recovery rolled the deployment back and this release
				// cannot finish the change it interrupted: say so and name the
				// next step instead of a plain "repaired" (GAP-0767).
				result.AddWarning("recovered_pending_transaction", windowsEnterpriseRolledBackMessage(followStatus.InstalledVersion))
			}
		}
	}
	if beforeGatewayPID != 0 {
		if afterGatewayPID := windowsStandaloneGatewayPID(); afterGatewayPID != 0 && beforeGatewayPID != afterGatewayPID {
			opts.bundle.gatewayRestarted = true
		}
	}
	report = windowsEnterpriseFailureWithDeploymentState(ctx, cmd, opts, script, report)
	applyWindowsEnterpriseInstallerReport(result, opts, report, run)
	addWindowsEnterpriseNothingInstalledError(result, report, plan.Action)
	if keptConfig != "" && len(result.Errors) == 0 {
		result.AddWarning("config_reverted", "config.yaml had been changed outside the lifecycle; ensure put the managed config back and kept the edited file at "+keptConfig)
	}
	applyWindowsEnterprisePolicy(ctx, result)
	reason := plan.Reason
	if len(startOnlyKeys) > 0 {
		// Say why a config-only change stopped the services (GAP-0719).
		reason += " (the services read " + strings.Join(startOnlyKeys, ", ") + " only at start, so every service was restarted)"
	} else if opts.codexTargetTransaction {
		reason += " (" + windowsEnterpriseCodexTargetTransactionReason + ")"
	}
	if plan.Reason == "verify_failed" && plan.Detail != "" {
		reason += ": " + plan.Detail
	}
	result.AddWarning("ensure_"+plan.Action, "ensure ran "+plan.Action+": "+reason)
	return false, finishEnsure(windowsEnterpriseFailureCodeFor(result))
}

func windowsEnterpriseReleaseHotConfigClosureIfProven(ctx context.Context, result *enterprisestatus.Result) error {
	// Finish sets result.OK only after this runs, and no exit code is final
	// before it either, so the error list is the verdict: gating on OK
	// (GAP-1599) or on the failure code (GAP-2087) kept every closure.
	if len(result.Errors) != 0 || !result.Installed {
		return nil
	}
	// A failed hot-config undo left this administrator-owned closure across
	// runs. A successful repair or no-op Verify may release it only after the
	// live gateway proves the installed policy again.
	held, err := windowsEnterpriseHotConfigHooksHeld()
	if err != nil || !held {
		return err
	}
	// An unavailable CLI proves nothing either: the closure stays.
	if enforced, _ := windowsEnterpriseHotConfigEnforcesInstalled(ctx, windowsEnterpriseHotConfigTimeout); !enforced {
		return errors.New("the gateway has not proven the installed config's policy")
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return err
	}
	return windowsEnterpriseHotConfigReleaseHooks(layout)
}

// windowsEnterpriseStandaloneProfilesPreflight refuses a first install, in
// seconds and before it changes anything, when a target profile holds a
// .defenseclaw folder the install plan would refuse (a per-user install
// left it). The refusal names the folder and the next step. Any other
// inspection failure is left to the install, which reports it. Tests
// replace it.
var windowsEnterpriseStandaloneProfilesPreflight = func(manifestPath string) error {
	manifest, _, err := loadWindowsTargetRuntimeManifest(manifestPath)
	if err != nil {
		return nil
	}
	return windowsEnterpriseProfilesPreflightRefusal(enterprisehooks.PreflightWindowsManagedRuntimeRoots(manifest))
}

// windowsEnterpriseProfilesPreflightRefusal turns the profile inspection
// into the preflight refusal, or nil.
func windowsEnterpriseProfilesPreflightRefusal(err error) error {
	if err == nil || !strings.Contains(err.Error(), "reject noncanonical managed runtime baseline") {
		return nil
	}
	original := err.Error()
	message := original
	if text, internal := windowsEnterpriseStandaloneErrorText(message); internal {
		message = text
	}
	return errors.New(message + windowsEnterprisePerUserDataDirNextStep(original, message) + " Nothing was changed.")
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
		if err := refuseWindowsEnterpriseAPIPortChange(opts); err != nil {
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
	if drift == "codex_target" {
		opts.codexTargetTransaction = true
		return windowsEnterpriseEnsurePlan{Action: windowsEnterpriseCodexTargetAction(opts), Reason: "drift:codex_target"}, nil
	}
	// Equal config bytes still need the new bundle's generation and identity
	// recorded and adopted; only a confirmed repeat can be a no-op (GAP-0359).
	if drift == "" && opts.bundle != nil && opts.bundle.prepared != nil &&
		opts.bundle.prepared.Receipt != nil && !opts.bundle.prepared.AlreadyApplied {
		drift = "bundle"
	}
	if drift == "config" && windowsBundleRollbackWithoutPayload(opts) {
		// The rollback of a bundle the installed CLI applied puts the last
		// good config back on the running deployment, as the bundle was
		// applied; refusing it for the missing payload left the refused
		// bundle config enforcing (GAP-0008).
		drift = "bundle"
	}
	if drift != "" {
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 && drift != "bundle" {
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
	if strings.Contains(message, windowsEnterpriseUnreadableMetadataMarker) {
		return fmt.Errorf("ensure_refused: %s", message)
	}
	return fmt.Errorf("status_failed: ensure could not read the deployment state: %s", message)
}

// windowsEnterpriseCodexTargetAction is the transaction that applies a
// config turning Codex protection on or off (GAP-0033): the upgrade when the
// run carries the payload (Setup CONFIG= or BUNDLE=), and otherwise a repair
// with the supplied config. The installed CLI (`enterprise bundle apply`)
// carries no payload, and the installer refuses an Upgrade without one; the
// repair runs the same transaction on the installed binaries, Codex's
// machine policy included.
func windowsEnterpriseCodexTargetAction(opts *windowsEnterpriseLifecycleOptions) string {
	if len(missingWindowsEnterpriseSources(opts)) != 0 {
		return "repair"
	}
	return "upgrade"
}

func missingWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) []string {
	var missing []string
	// The installer admits policy_compiler.py separately after its trusted
	// config probe says Fleet is enabled. Core installs never need this source.
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

// windowsBundleRollbackWithoutPayload reports the nested ensure that puts
// the last good config back after a bundle `enterprise bundle apply`
// (the installed CLI) could not confirm: it carries no payload, so only the
// running deployment can take the config, the way the bundle was applied.
func windowsBundleRollbackWithoutPayload(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && opts.bundleRollback && len(missingWindowsEnterpriseSources(opts)) != 0
}

// windowsEnterpriseKeepsInstalledConfig reports a request that names no
// config: an upgrade keeps the installed config.yaml.
func windowsEnterpriseKeepsInstalledConfig(opts *windowsEnterpriseLifecycleOptions) bool {
	return strings.TrimSpace(opts.configPath) == "" && strings.TrimSpace(opts.mode) == ""
}

func clearWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) {
	opts.gatewayBinary, opts.acpBinary, opts.hookBinary = "", "", ""
	opts.sensorHelperBinary, opts.cliBinary = "", ""
	opts.policyCompiler = ""
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
		{&opts.policyCompiler, "policy_compiler.py"},
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
		{"compiler", opts.policyCompiler},
		{"cli", opts.cliBinary},
		{"installer", script},
		{"module", filepath.Join(filepath.Dir(script), "DefenseClawEnterprise.psm1")},
	} {
		if strings.TrimSpace(source.path) == "" {
			continue
		}
		recorded := strings.ToLower(strings.TrimSpace(metadata.Hashes[source.key]))
		if source.key == "compiler" {
			// Setup always carries the optional Fleet source, including when
			// Fleet is off. Only a Fleet-enabled target config makes it an
			// installed artifact whose bytes can cause ensure drift.
			drift, err := windowsEnterpriseCompilerSourceDrift(recorded, source.path, opts, layout.ConfigPath)
			if err != nil {
				return "", err
			}
			if drift {
				return source.key, nil
			}
			continue
		}
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
		supplied, err := readWindowsEnterpriseBoundedFile(path, windowsEnterpriseHotConfigMaxBytes)
		if err != nil {
			return "", err
		}
		if windowsConfigCodexTargetNeedsReconcile(supplied, trimWindowsJSONBOM(body)) {
			return "codex_target", nil
		}
		want, err := windowsEnterpriseFileSHA256(path)
		if err != nil {
			return "", err
		}
		got, err := windowsEnterpriseFileSHA256(layout.ConfigPath)
		// A config_version 8 source is installed as its v9 migration, so the
		// same source is not drift while the installed file is that result.
		if err != nil || (got != want && !config.MigratedFrom(layout.ConfigPath, want, got)) {
			if opts.bundle != nil && windowsBundleConfigChange(opts.bundle.prepared) {
				return "bundle", nil
			}
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

// confirmedWindowsBundleCompilerDrift checks the one optional artifact that
// Verify cannot require solely from metadata: older Fleet-enabled installs
// may have no compiler hash at all. A confirmed bundle replay must not skip
// the installer when its Fleet mode and recorded compiler disagree.
func confirmedWindowsBundleCompilerDrift(run *windowsBundleRun) (bool, error) {
	if run == nil || run.prepared == nil || len(run.prepared.Config) == 0 {
		return false, errors.New("confirmed bundle config is missing")
	}
	if sha256HexBytes(run.prepared.Config) != run.prepared.ConfigSHA256 {
		return false, errors.New("confirmed bundle config hash is invalid")
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, err
	}
	metadata, err := readWindowsEnterpriseBoundedFile(roots.MetadataPath, 1<<20)
	if err != nil {
		return false, fmt.Errorf("read standalone deployment metadata: %w", err)
	}
	return windowsEnterpriseBundleCompilerDriftFromDocuments(run.layout.ConfigPath, run.prepared.Config, metadata)
}

func windowsEnterpriseBundleCompilerDriftFromDocuments(configPath string, rawConfig, rawMetadata []byte) (bool, error) {
	enabled, err := config.FleetEnabledFromSource(configPath, rawConfig)
	if err != nil {
		return false, err
	}
	var metadata struct {
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(trimWindowsJSONBOM(rawMetadata), &metadata); err != nil {
		return false, fmt.Errorf("parse standalone deployment metadata: %w", err)
	}
	if metadata.Hashes == nil {
		return false, errors.New("standalone deployment metadata has no artifact hashes")
	}
	return enabled != (strings.TrimSpace(metadata.Hashes["compiler"]) != ""), nil
}

// windowsEnterpriseCompilerSourceDrift uses the same bounded, duplicate-key
// rejecting config parser as the signed installer's Fleet preflight. The
// compiler in Setup's payload must not force a Fleet-off ensure to upgrade.
func windowsEnterpriseCompilerSourceDrift(recorded, source string, opts *windowsEnterpriseLifecycleOptions, installedConfig string) (bool, error) {
	configPath := strings.TrimSpace(opts.configPath)
	if configPath == "" {
		configPath = installedConfig
	}
	raw, err := readConfigV8Source(configPath)
	if err != nil {
		return false, fmt.Errorf("inspect standalone Fleet config: %w", err)
	}
	enabled, err := config.FleetEnabledFromSource(configPath, raw)
	if err != nil {
		return false, fmt.Errorf("inspect standalone Fleet config: %w", err)
	}
	if !enabled {
		// An older deployment can still record an active compiler after Fleet
		// was disabled. Reapply the release so the installer removes it and
		// writes metadata without a compiler hash.
		return recorded != "", nil
	}
	if recorded == "" {
		return true, nil // adopt compiler for an older Fleet-enabled deployment
	}
	digest, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		return false, err
	}
	return digest != recorded, nil
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
	default:
		return compareWindowsEnterprisePrerelease(lPre, rPre)
	}
}

// compareWindowsEnterprisePrerelease orders two prerelease strings as semver
// does: dot-separated identifiers left to right, numeric ones as numbers and
// below alphanumeric ones, a shorter list first when it is a prefix. Compared
// as text, rc.4 was newer than rc.10 and ensure refused that upgrade as a
// downgrade (GAP-1516).
func compareWindowsEnterprisePrerelease(left, right string) int {
	l, r := strings.Split(left, "."), strings.Split(right, ".")
	for i := 0; i < len(l) && i < len(r); i++ {
		ln, lErr := strconv.ParseUint(l[i], 10, 64)
		rn, rErr := strconv.ParseUint(r[i], 10, 64)
		switch {
		case lErr == nil && rErr == nil:
			if ln != rn {
				if ln < rn {
					return -1
				}
				return 1
			}
		case lErr == nil:
			return -1
		case rErr == nil:
			return 1
		case l[i] != r[i]:
			if l[i] < r[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(l) < len(r):
		return -1
	case len(l) > len(r):
		return 1
	}
	return 0
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
