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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	windowsEnterpriseInstallerEnv     = "DEFENSECLAW_WINDOWS_ENTERPRISE_INSTALLER"
	windowsEnterpriseTempSDDL         = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	windowsEnterpriseOutputCaptureMax = 1 << 20
	windowsEnterpriseDiagnosticMax    = 4096
	// 1603 is the fatal-install result Windows deployment systems act on.
	// Never report 3010 from a failure: that means installed and awaiting a
	// reboot, and it would mark an incomplete deployment as done.
	windowsEnterpriseFailureExitCode = 1603
)

type windowsEnterpriseLifecycleOptions struct {
	brokerBinary       string
	gatewayBinary      string
	acpBinary          string
	hookBinary         string
	sensorHelperBinary string
	policyCompiler     string
	cliBinary          string
	configPath         string
	manifestPath       string
	installerPath      string
	// resolvedInstaller is the install-enterprise.ps1 the standalone
	// lifecycle runs; the payload's scanner runtime is staged beside it.
	resolvedInstaller             string
	installRoot                   string
	stateRoot                     string
	gatewayServiceName            string
	guardianServiceName           string
	certificationCodexHome        string
	coreHardeningCertification    bool
	attestAgentApplicationControl bool
	attestClaudeEffectivePolicy   bool
	noStart                       bool
	purge                         bool
	// force is the standalone uninstall last resort: remove the deployment
	// without recovering a pending transaction (GAP-0920, GAP-1041).
	force         bool
	allowUnsigned bool
	// deferredConfig stages a protected installed deployment with every
	// managed service disabled. A later Repair with both authenticated
	// policy files prepares user runtimes and performs guardian-first
	// activation; direct file publication or SCM start is not supported.
	deferredConfig bool
	// bootstrapParent forwards the outer signed DefenseClawSetup EXE's
	// protected %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch
	// path to install-enterprise.ps1's -BootstrapParent, so the
	// installer's one-shot bootstrap directory lives inside an admin-
	// only ancestor chain rather than C:\Windows\Temp. Required on
	// Azure-AD-joined hosts, where C:\Windows\Temp carries an inherited
	// Allow ACE for the interactive AAD principal with Delete rights;
	// the module's later trusted-ancestor walk on rendered config /
	// targets YAML would reject it otherwise. Empty falls back to
	// C:\Windows\Temp for direct-caller compatibility on stock Windows.
	bootstrapParent string
	// mode / connector are the macOS-parity QA shorthand. When both
	// are supplied (and configPath / manifestPath are empty),
	// install-enterprise.ps1 renders a minimal managed_enterprise
	// config.yaml + per-user targets.yaml into its protected bootstrap
	// directory before invoking the lifecycle transaction.
	mode            string
	connector       string
	jsonOutput      bool
	providerLibrary string
	// profile selects the enterprise profile (secure_client or
	// standalone). Empty resolves from the supplied config, then the
	// profile this host records, then Secure Client; resolvedProfile holds
	// the result. The trust, signer, and version options apply only to
	// the standalone profile.
	profile         string
	resolvedProfile string
	trustMode       string
	payloadManifest string
	allowedSigners  []string
	productVersion  string
	// suppliedConfigRefusal is why the supplied --config cannot be loaded
	// when profile resolution found it unparseable. An install, ensure,
	// upgrade or repair is refused with it once its installer is found and
	// trusted, so the refusal reports the running deployment as a refused
	// config that parses does (GAP-0103).
	suppliedConfigRefusal error
	// suppliedConfigUnreadable marks a suppliedConfigRefusal for a file
	// that could not be opened or read: a preflight failure (1603), not
	// invalid arguments.
	suppliedConfigUnreadable bool
	// runningDeploymentLabel marks a run that refused its config before it
	// changed anything: every warning from index
	// runningDeploymentWarningsFrom on, those the finish adds included, is
	// the running deployment's (GAP-0564, GAP-0103).
	runningDeploymentLabel        bool
	runningDeploymentWarningsFrom int
	// payloadPins are the payload manifest's SHA-256 pins, read when a
	// hash_pinned run verifies its installer. The scanner runtime the
	// lifecycle installs itself is admitted by them too.
	payloadPins map[string]string
	// bundlePath is the signed policy bundle ensure applies (--bundle,
	// Setup BUNDLE=) and trustAnchors the anchor file it installs first
	// (--trust-anchors, Setup TRUSTANCHORS=). Standalone ensure only.
	bundlePath           string
	trustAnchors         string
	refuseCapabilityLoss bool
	// deferRestart refuses a bundle whose config change restarts the
	// gateway (enterprise bundle apply --defer-restart).
	deferRestart bool
	// bundleLockWait is how long the run waits for another bundle run to
	// release bundle.lock (`enterprise bundle apply --lock-wait`); 0 tries
	// once, as Setup and `enterprise windows ensure` do.
	bundleLockWait time.Duration
	// bundleDeliveryID is the `enterprise bundle apply --delivery-id` the
	// bundle receipt records ("" for none, and for Setup BUNDLE= and
	// `enterprise windows ensure --bundle`).
	bundleDeliveryID string
	// bundle is the bundle state of the run; bundleRollback marks the
	// internal ensure that puts the last good config back.
	bundle         *windowsBundleRun
	bundleRollback bool
	// bundleRollbackTo is the confirmed bundle a rollback puts back (nil
	// when the last good config is the one installed before any bundle),
	// so the rollback write records that bundle's provenance again.
	bundleRollbackTo *windowsBundleRollbackTarget
	// bundleSettle is what a changing run that delivers no bundle settled
	// of the receipts a killed bundle run left (GAP-1302).
	bundleSettle *windowsBundleSettle
	// codexTargetTransaction is set by the config apply path when the
	// supplied config turns Codex protection on or off. The lifecycle
	// transaction owns Codex's machine policy, so the change, a signed
	// bundle's included, goes to that transaction (GAP-0033).
	codexTargetTransaction bool
	// hotConfigRestoreFailed is set when a failed hot config apply could not
	// put the previous config or its enrolled targets back; ensure stops
	// instead of starting the upgrade transaction.
	hotConfigRestoreFailed bool
	// ignoredDeploymentRecords lists deployment records profile resolution
	// found but ignored because an administrator did not write them. Only
	// the standalone result reports them.
	ignoredDeploymentRecords []string
	// localEnforcementEntriesIgnored counts the audit.db block/allow entries
	// a config_version 9 migration in this run left in place (the
	// actions_rows_ignored of the migration-v9.json it wrote). The standalone
	// result reports them as local_enforcement_entries_ignored.
	localEnforcementEntriesIgnored int
	// configMigration is the migration-v9.json a config_version 9
	// migration in this run wrote, and configMigrationPath the config it
	// migrated; the standalone result reports it in changes (GAP-0472).
	configMigration     *config.MigrationRecord
	configMigrationPath string
	// configFailModeRepairs are the Cursor fail modes this run restored to
	// closed in migration-v9.json (config.RepairMigratedCursorFailMode).
	configFailModeRepairs []config.MigrationMove
	// deploymentTrustMode is the payload trust the deployment records
	// (deployment.json trust_mode), taken from the installer report the
	// standalone result was built from. The marker publishes it rather than
	// trustMode, which defaults to authenticode when no flag is given.
	deploymentTrustMode string
	// diagnostics holds the enumerator's per-profile lines from a JSON
	// ensure. They go to the lifecycle log, not next to the JSON result an
	// MDM parses.
	diagnostics []string
	// Set by a standalone PowerShell run whose own exit succeeded while a
	// descendant still held an inherited output pipe.
	powerShellPipeWaitDelayed bool
	// scannerRuntimeRetired names the untrusted scanner runtime this run
	// removed before the services started (GAP-0490).
	scannerRuntimeRetired string
	// recoveryChanges is what the recovery of a pending transaction before
	// the check of a supplied config changed
	// (noteWindowsEnterpriseRefusalRecovery).
	recoveryChanges []string
	// activationStartedAt is when a standalone change action started, and
	// installedBeforeRun whether a deployment was installed then: a run
	// that installs one records its activation (GAP-0967), dated when the
	// run finished (windowsEnterpriseActivationNow).
	activationStartedAt     time.Time
	installedBeforeRun      bool
	previousConnectors      []string
	previousConnectorsKnown bool
	// previousTargets are the targets the guardian manifest enrolled before
	// the run, keyed as windowsEnterpriseManifestRowKey (GAP-1435).
	previousTargets      map[string]bool
	previousTargetsKnown bool
}

type windowsEnterpriseACLHeader struct {
	revision  uint8
	reserved  uint8
	size      uint16
	aceCount  uint16
	reserved2 uint16
}

type windowsEnterpriseLifecyclePreflightFailure struct {
	SchemaVersion int      `json:"schema_version"`
	Action        string   `json:"action"`
	OK            bool     `json:"ok"`
	Error         string   `json:"error"`
	Errors        []string `json:"errors"`
}

type windowsEnterpriseOutputCapture struct {
	buffer          bytes.Buffer
	truncated       bool
	pipeWaitDelayed bool
}

func (capture *windowsEnterpriseOutputCapture) Write(body []byte) (int, error) {
	written := len(body)
	remaining := windowsEnterpriseOutputCaptureMax - capture.buffer.Len()
	if remaining <= 0 {
		capture.truncated = true
		return written, nil
	}
	if len(body) > remaining {
		body = body[:remaining]
		capture.truncated = true
	}
	_, _ = capture.buffer.Write(body)
	return written, nil
}

type windowsServiceConfigValidation struct {
	SchemaVersion  int    `json:"schema_version"`
	OK             bool   `json:"ok"`
	ConfigPath     string `json:"config_path"`
	DataDir        string `json:"data_dir"`
	DeploymentMode string `json:"deployment_mode"`
	APIBind        string `json:"api_bind"`
	GuardrailBind  string `json:"guardrail_bind,omitempty"`
	// Profile is reported only for the standalone profile so the Secure
	// Client report keeps its original shape.
	Profile string `json:"profile,omitempty"`
}

var (
	windowsEnterpriseCommandRunner           = runWindowsEnterprisePowerShell
	windowsEnterpriseScriptFinder            = findWindowsEnterpriseInstaller
	windowsEnterprisePayloadStager           = stageWindowsEnterprisePayload
	windowsEnterpriseTrustValidator          = validateWindowsEnterpriseInstallerTrust
	windowsEnterpriseExecutableResolver      = os.Executable
	windowsEnterpriseProgramFilesResolver    = trustedWindowsEnterpriseProgramFiles
	windowsEnterpriseProgramDataResolver     = trustedWindowsEnterpriseProgramData
	windowsEnterpriseMachineRootsResolver    = resolveWindowsEnterpriseMachineRoots
	windowsEnterpriseProviderLibraryResolver = managed.DiscoverCMIDLibrary
	windowsEnterpriseStandaloneHostValidator = validateWindowsEnterpriseStandaloneHost
)

type windowsEnterprisePowerShellTempOps struct {
	isElevated       func() bool
	userTemp         func() (string, error)
	elevatedTempRoot func() (string, error)
	randomRead       func([]byte) (int, error)
	createDirectory  func(*uint16, *windows.SecurityAttributes) error
	validate         func(string) error
	remove           func(string) error
	removeAll        func(string) error
}

var enterpriseWindowsCmd = &cobra.Command{
	Use:   "windows",
	Short: "Manage the native Windows managed-enterprise services",
	Long: `Install, upgrade, repair, inspect, verify, or remove the native
Windows managed-enterprise gateway and hook-guardian services.

These commands delegate filesystem and SCM mutations to the signed enterprise
installer transaction. They do not affect the existing per-user Windows
daemon unless an administrator explicitly invokes a lifecycle action.`,
	// Lifecycle commands must work before a user config or audit database
	// exists. The installer performs its own elevation and trust preflight.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },
}

func init() {
	for _, action := range []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall", "ensure"} {
		enterpriseWindowsCmd.AddCommand(newWindowsEnterpriseLifecycleCommand(action))
	}
	recovery := newWindowsEnterpriseLifecycleCommand("recover")
	recovery.Hidden = true // Setup uses this once after a timed-out lifecycle child.
	enterpriseWindowsCmd.AddCommand(recovery)
	enterpriseWindowsCmd.AddCommand(newWindowsServiceConfigValidationCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsStandaloneFleetInspectCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsCodexRequirementsCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsManagedHooksTeardownCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsManagedHooksLifecycleCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsTargetRuntimeCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsNamespacePurgeCommand())
	enterpriseWindowsCmd.AddCommand(newWindowsManagedHookContractCleanupCommand())
	// Hook-enumerator subcommand. Windows-only; the
	// whole file is //go:build windows so a non-Windows build never
	// reaches this registration.
	enterpriseWindowsCmd.AddCommand(newEnterpriseWindowsEnumerateCommand())
	// #1164: the stdio relay the scanner runtime starts for an enrolled
	// user's MCP server, which the enumerator starts as that user.
	enterpriseWindowsCmd.AddCommand(newEnterpriseWindowsMCPRelayCommand())
	enterpriseCmd.AddCommand(enterpriseWindowsCmd)
}

func newWindowsEnterpriseLifecycleCommand(action string) *cobra.Command {
	opts := &windowsEnterpriseLifecycleOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        windowsEnterpriseLifecycleSummary(action),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withExitCode(
				runWindowsEnterpriseLifecycle(cmd.Context(), cmd, action, opts),
				windowsEnterpriseFailureExitCode,
			)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.brokerBinary, "broker-binary", "", "source defenseclaw-cmid-broker.exe")
	flags.StringVar(&opts.gatewayBinary, "gateway-binary", "", "source defenseclaw-gateway.exe")
	flags.StringVar(&opts.acpBinary, "acp-binary", "", "source defenseclaw-acp.exe")
	flags.StringVar(&opts.hookBinary, "hook-binary", "", "source defenseclaw-hook.exe")
	flags.StringVar(&opts.sensorHelperBinary, "sensor-helper-binary", "", "source defenseclaw-sensor-helper.exe")
	flags.StringVar(&opts.policyCompiler, "policy-compiler", "", "standalone source policy_compiler.py")
	flags.StringVar(&opts.cliBinary, "cli-binary", "", "optional source defenseclaw.exe")
	flags.StringVar(&opts.configPath, "config", "", "administrator-approved managed config.yaml")
	flags.StringVar(&opts.manifestPath, "manifest", "", "administrator-approved guardian targets.yaml")
	flags.StringVar(&opts.installerPath, "installer", "", "explicit install-enterprise.ps1 path")
	flags.StringVar(&opts.installRoot, "install-root", "", "certification-only exact protected binary root override")
	flags.StringVar(&opts.stateRoot, "state-root", "", "certification-only exact protected managed-state root override")
	flags.StringVar(&opts.gatewayServiceName, "gateway-service-name", "", "certification-only exact gateway SCM service name")
	flags.StringVar(&opts.guardianServiceName, "guardian-service-name", "", "certification-only exact guardian SCM service name")
	flags.StringVar(&opts.certificationCodexHome, "certification-codex-home", "", "exact local fixed-NTFS scope marker required by controlled unsigned certification")
	flags.BoolVar(&opts.coreHardeningCertification, "core-hardening-certification", false, "run the unsigned core-only certification profile without production attestations")
	flags.BoolVar(&opts.attestAgentApplicationControl, "attest-agent-application-control", false, "attest that approved-client WDAC or AppLocker rules are live")
	flags.BoolVar(&opts.attestClaudeEffectivePolicy, "attest-claude-effective-policy", false, "refresh live proof that DefenseClaw is Claude's effective managed-policy source")
	flags.BoolVar(&opts.noStart, "no-start", false, "stage with both services disabled and stopped; activate with a later repair")
	flags.BoolVar(&opts.purge, "purge", false, "also remove managed state (Secure Client; a standalone uninstall always removes it) and each enrolled account's %USERPROFILE%\\.defenseclaw and per-user binaries in %USERPROFILE%\\.local\\bin, naming each account in the result (authenticated purge or fail-closed exact-scope recovery)")
	// Every change action takes the bundle flags so that the lifecycle, not
	// cobra, refuses them on install, upgrade and repair: invalid_arguments,
	// exit 1639 and the refused anchor install recorded (GAP-0608). Only
	// ensure shows them in its help.
	if windowsEnterpriseMutationAction(action) {
		flags.StringVar(&opts.bundlePath, "bundle", "",
			"standalone: apply this signed policy bundle (.dcbundle file); the bundle carries the config, so not with --config")
		flags.BoolVar(&opts.refuseCapabilityLoss, "refuse-capability-loss", false, "refuse a bundle that disables a currently enforced capability")
		flags.StringVar(&opts.trustAnchors, "trust-anchors", "",
			"standalone: install this administrator-only bundle trust anchor file (bundle-anchors.json) first")
		if action != "ensure" {
			for _, name := range []string{"bundle", "refuse-capability-loss", "trust-anchors"} {
				_ = flags.MarkHidden(name)
			}
		}
	}
	if action == "uninstall" {
		flags.BoolVar(&opts.force, "force", false,
			"standalone, last resort: remove the deployment without recovering a pending transaction that no ensure, repair or uninstall can recover; run it from Setup (FORCE=1) as LocalSystem")
	}
	flags.BoolVar(&opts.allowUnsigned, "allow-unsigned", false, "allow unsigned artifacts only for controlled test builds")
	// UCB-friendly late-config install.
	// Requires managed-enterprise deployment mode; enforced by the
	// installer, not here (this flag is a passthrough).
	flags.BoolVar(&opts.deferredConfig, "deferred-config", false,
		"stage services disabled; activate later with repair plus both config.yaml and targets.yaml")
	flags.StringVar(&opts.bootstrapParent, "bootstrap-parent", "",
		"protected admin-only parent directory for the installer's one-shot bootstrap dir (outer signed Setup EXE passes its own %ProgramData%\\DefenseClaw-Enterprise-Setup-<hex>\\scratch path here)")
	flags.StringVar(&opts.mode, "mode", "",
		"QA shorthand: observe|action (paired with --connector; the installed install-enterprise.ps1 renders config.yaml + targets.yaml)")
	flags.StringVar(&opts.connector, "connector", "",
		"QA shorthand: comma-separated connector list (paired with --mode)")
	flags.BoolVar(&opts.jsonOutput, "json", false, "emit machine-readable JSON")
	flags.StringVar(&opts.profile, "profile", "",
		"enterprise profile: secure_client or standalone (default: the supplied config's enterprise.profile, then the installed profile, then secure_client)")
	flags.StringVar(&opts.trustMode, "trust-mode", "",
		"standalone payload trust: authenticode (default) or hash_pinned")
	flags.StringVar(&opts.payloadManifest, "payload-manifest", "",
		"standalone hash_pinned trust anchor: administrator-owned JSON of payload SHA-256 digests")
	flags.StringArrayVar(&opts.allowedSigners, "allowed-signer", nil,
		"standalone: SHA-256 thumbprint of an accepted Authenticode signer certificate (repeatable)")
	flags.StringVar(&opts.productVersion, "product-version", "",
		"standalone: version recorded for this deployment (default: this CLI's version)")
	// GAP-2448: with --json an argument error (an unknown flag, a malformed
	// value; on ensure also a stray argument) prints one lifecycle result
	// with invalid_arguments, exit 1639. ensure records a refused anchor
	// install (windowsAnchorsArgumentRefusal); the other verbs keep their own
	// positional-argument handling (usageArgsExemptGroups).
	flagError := lifecycleFlagError
	if action == "ensure" {
		flagError = windowsAnchorsArgumentRefusal
		cmd.Args = func(c *cobra.Command, args []string) error {
			if err := strayArgumentError(c, args); err != nil {
				return lifecycleArgumentError(c, action, opts.jsonOutput, flagError(c, err))
			}
			return nil
		}
	}
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return lifecycleArgumentError(c, action, opts.jsonOutput, flagError(c, err))
	})
	if action == "status" || action == "verify" {
		// Status and verify only read the deployment. The install,
		// upgrade, uninstall and certification inputs stay accepted but
		// out of their help (GAP-1073).
		for _, name := range windowsEnterpriseInspectionHiddenFlags {
			_ = flags.MarkHidden(name)
		}
	}
	return cmd
}

// windowsEnterpriseInspectionHiddenFlags are the lifecycle flags status and
// verify leave out of their help.
var windowsEnterpriseInspectionHiddenFlags = []string{
	"broker-binary", "gateway-binary", "acp-binary", "hook-binary", "sensor-helper-binary", "policy-compiler", "cli-binary",
	"install-root", "state-root", "gateway-service-name", "guardian-service-name",
	"certification-codex-home", "core-hardening-certification",
	"attest-agent-application-control", "attest-claude-effective-policy",
	"no-start", "purge", "deferred-config", "mode", "connector", "product-version",
}

func windowsEnterpriseLifecycleSummary(action string) string {
	switch action {
	case "install":
		return "Install protected Windows gateway and guardian services"
	case "upgrade":
		return "Upgrade the protected Windows deployment transactionally"
	case "repair":
		return "Reapply ACL, service, environment, and recovery invariants"
	case "reconcile":
		return "Restart the LocalSystem guardian and wait for a fresh reconcile"
	case "status":
		return "Report SCM process state separately from application readiness"
	case "verify":
		return "Verify files, DACLs, service policy, mode pin, and readiness"
	case "uninstall":
		return "Remove enterprise services, hooks and (standalone) machine state; users keep their data unless --purge"
	case "ensure":
		return "Converge a standalone deployment: install, upgrade, repair, or no-op"
	default:
		return "Manage Windows enterprise services"
	}
}

func runWindowsEnterpriseLifecycle(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
) error {
	failPreflight := func(err error) error {
		jsonOutput := opts != nil && opts.jsonOutput
		return writeWindowsEnterpriseLifecyclePreflightFailure(
			cmd,
			action,
			jsonOutput,
			err,
		)
	}
	if opts == nil {
		return failPreflight(errors.New("Windows enterprise lifecycle options are unavailable"))
	}
	// On a standalone host, a standard account cannot change the managed
	// deployment whatever file it passes, so the elevation refusal comes
	// before --config is read, parsed or compiled (GAP-0120). Uninstall
	// likewise refuses before loading the installer module (GAP-0640), and
	// so does reconcile, which ran the module and answered 1603 with
	// installed:false for a deployment that exists (GAP-0931).
	if (windowsEnterpriseMutationAction(action) || action == "uninstall" || action == "reconcile" || action == "recover") && !windowsEnterpriseIsElevated() &&
		managed.IsStandaloneProfile(opts.profile) {
		// A trusted Secure Client record already makes this request invalid.
		// Preserve its profile refusal before the standalone elevation check.
		// A standalone host still refuses before reading the caller's --config.
		if !windowsEnterpriseCertificationScope(opts) {
			deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileSecureClient)
			if err != nil || deployment.State == winpath.EnterpriseDeploymentInstalled ||
				deployment.State == winpath.EnterpriseDeploymentUnknown {
				if err := resolveWindowsEnterpriseLifecycleProfile(action, opts); err != nil {
					return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
				}
			}
		}
		return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts,
			errors.New("elevation_required: "+windowsEnterpriseStandardUserMutationAnswer(action, windowsEnterpriseRequestedAttestations(opts)...)))
	}
	if windowsEnterpriseMutationAction(action) {
		// The run and the installer it starts leave the CPU to the hooks
		// that must answer each tool call in time (GAP-0155).
		windowsLifecycleYieldToHooks()
	}
	if err := resolveWindowsEnterpriseLifecycleProfile(action, opts); err != nil {
		recordWindowsAnchorsProfileRefusal(cmd, opts, err)
		if windowsEnterpriseStandaloneRequested(opts) || windowsEnterpriseUnknownProfileRequested(opts) {
			return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
		}
		return failPreflight(err)
	}
	if (opts.bundlePath != "" || opts.trustAnchors != "") && !windowsEnterpriseStandalone(opts) {
		return failPreflight(errors.New("--bundle and --trust-anchors are valid only with --profile standalone"))
	}
	if windowsEnterpriseStandalone(opts) {
		failPreflight = func(err error) error {
			return writeWindowsEnterpriseStandalonePreflightFailure(cmd, action, opts, err)
		}
		if err := windowsEnterpriseStandaloneHostValidator(); err != nil {
			return failPreflight(err)
		}
		if action == "install" || action == "upgrade" || action == "repair" || action == "ensure" {
			opts.activationStartedAt = time.Now().UTC()
			opts.installedBeforeRun = windowsEnterpriseStandaloneInstalled()
			if opts.installedBeforeRun {
				connectors, connectorErr := windowsEnterpriseEnrolledConnectors()
				opts.previousConnectors, opts.previousConnectorsKnown = connectors, connectorErr == nil
				targets, targetsErr := windowsEnterpriseEnrolledTargets()
				opts.previousTargets, opts.previousTargetsKnown = targets, targetsErr == nil
			}
		}
	}
	if windowsEnterpriseStandalone(opts) {
		// Before --config is read: a bundle supplies it, and bundle mode
		// refuses one that is not the current bundle config.
		if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, action, opts); done {
			return err
		}
		if opts.bundle != nil {
			defer opts.bundle.release()
		}
	}
	// The Secure Client profile keeps its historical preflight text exactly;
	// only the standalone profile classifies misuse as invalid arguments
	// (1639) and accepts ensure.
	if opts.purge && action != "uninstall" {
		if windowsEnterpriseStandalone(opts) {
			return failPreflight(windowsEnterpriseInvalidArguments("--purge is valid only with enterprise windows uninstall"))
		}
		return failPreflight(errors.New("--purge is valid only with enterprise windows uninstall"))
	}
	if opts.force && !windowsEnterpriseStandalone(opts) {
		return failPreflight(errors.New("--force is valid only with enterprise windows uninstall --profile standalone"))
	}
	if opts.noStart && action != "install" && action != "upgrade" && action != "repair" {
		if !windowsEnterpriseStandalone(opts) {
			return failPreflight(errors.New("--no-start is valid only with install, upgrade, or repair"))
		}
		if action != "ensure" {
			return failPreflight(windowsEnterpriseInvalidArguments("--no-start is valid only with install, upgrade, repair, or ensure"))
		}
	}
	if err := validateWindowsEnterpriseLifecycleSecurityOptions(cmd, action, opts); err != nil {
		if windowsEnterpriseStandalone(opts) {
			err = fmt.Errorf("%w: %w", errWindowsEnterpriseInvalidArguments, err)
		}
		return failPreflight(err)
	}
	mutation := action == "install" || action == "upgrade" || action == "repair"
	if mutation && !windowsEnterpriseStandalone(opts) && strings.TrimSpace(opts.brokerBinary) != "" {
		// A full XDR installation sequences Cloud Management last, so
		// cmidapi.dll is routinely absent while DefenseClaw installs.
		// That is no longer a preflight failure: the deployment completes
		// without the library and the credential broker discovers it at
		// runtime, enabling the CMID lane once Cloud Management lands. An
		// already-installed library is still pinned here so nothing
		// changes for the Cloud-Management-first order.
		opts.providerLibrary = strings.TrimSpace(windowsEnterpriseProviderLibraryResolver())
	}
	script, err := windowsEnterpriseScriptFinder(opts.installerPath)
	if err != nil {
		// A release that ships a lone executable has no installer to find, so
		// the embedded copy answers discovery alone. A named installer that is
		// missing or untrusted stays an error.
		if !errors.Is(err, errWindowsEnterpriseInstallerNotFound) ||
			windowsEnterpriseInstallerOverride(opts.installerPath) != "" {
			return failPreflight(err)
		}
		staged, cleanup, stageErr := windowsEnterprisePayloadStager()
		if stageErr != nil {
			return failPreflight(errors.Join(err, stageErr))
		}
		defer func() { _ = cleanup() }()
		script = staged
	}
	if windowsEnterpriseStandalone(opts) && opts.trustMode == windowsEnterpriseTrustHashPinned {
		pins, err := verifyWindowsEnterpriseHashPinnedInstaller(script, opts.payloadManifest)
		if err != nil {
			return failPreflight(err)
		}
		opts.payloadPins = pins
	}
	if windowsEnterpriseStandalone(opts) && (action == "install" || action == "ensure" || action == "upgrade" ||
		(action == "repair" && strings.TrimSpace(opts.configPath) != "")) {
		if refused, err := refuseWindowsEnterpriseStandaloneSuppliedConfig(ctx, cmd, action, opts, script); refused {
			return err
		}
	}
	if windowsEnterpriseStandalone(opts) && action == "upgrade" && windowsEnterpriseKeepsInstalledConfig(opts) {
		if err := windowsEnterpriseStandaloneKeptConfigPreflight(); err != nil {
			return writeWindowsEnterpriseStandaloneConfigRefusal(ctx, cmd, action, opts, script, err)
		}
	}
	if windowsEnterpriseStandalone(opts) && action == "repair" {
		if err := windowsEnterpriseStandaloneRepairRulePackPreflight(opts.configPath); err != nil {
			return writeWindowsEnterpriseStandaloneConfigRefusal(ctx, cmd, action, opts, script, err)
		}
	}
	opts.resolvedInstaller = script
	if action == "ensure" {
		return runWindowsEnterpriseStandaloneEnsure(ctx, cmd, opts, script)
	}
	args := windowsEnterprisePowerShellArgs(action, windowsEnterpriseRepairRecordingOptions(action, opts))
	executable, executableErr := windowsEnterpriseExecutableResolver()
	if executableErr != nil {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "uninstall" ||
			(normalizedAction == "upgrade" && strings.TrimSpace(opts.cliBinary) != "") {
			return failPreflight(fmt.Errorf(
				"resolve the running Windows enterprise CLI executable: %w",
				executableErr,
			))
		}
	} else {
		if strings.EqualFold(strings.TrimSpace(action), "uninstall") {
			args = append(args, "-NativeCleanupBinary", executable)
		}
		selfUpgradeConflict, conflictErr := windowsEnterpriseSelfUpgradeConflict(
			action,
			opts.installRoot,
			executable,
			opts.cliBinary,
		)
		if conflictErr != nil {
			return failPreflight(conflictErr)
		}
		if selfUpgradeConflict {
			return failPreflight(errors.New(
				"the installed Windows enterprise CLI cannot replace its own running image; " +
					"run upgrade from the new release's protected staged defenseclaw.exe, " +
					"or omit --cli-binary",
			))
		}
		if windowsEnterpriseStandalone(opts) &&
			windowsEnterpriseInstalledNonCLIUninstallCaller(action, script, executable) {
			return failPreflight(windowsEnterpriseInvalidArguments(
				"only the installed CLI can uninstall from its own folder: %s would keep that folder "+
					"in use, so the uninstall would stop halfway. From a prompt whose folder is outside %s "+
					"(for example, cd /d C:\\ first), run \"%s\" enterprise windows uninstall --profile standalone, "+
					"or run DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall",
				filepath.Base(executable),
				filepath.Dir(filepath.Dir(executable)),
				filepath.Join(filepath.Dir(executable), "defenseclaw.exe"),
			))
		}
		if callerPID, ok := windowsEnterpriseSelfUninstallCaller(
			action,
			script,
			executable,
			os.Getpid(),
		); ok {
			if windowsEnterpriseStandalone(opts) {
				installRoot := filepath.Dir(filepath.Dir(executable))
				started, _ := os.Getwd()
				if err := windowsEnterpriseLeaveInstallRoot(installRoot); err != nil {
					return failPreflight(err)
				}
				if err := windowsEnterpriseInstallRootStillInUse(installRoot, started); err != nil {
					return failPreflight(err)
				}
			}
			args = append(
				args,
				"-SelfUninstallCallerPID",
				strconv.FormatUint(uint64(callerPID), 10),
			)
		}
	}
	if windowsEnterpriseStandalone(opts) {
		return runWindowsEnterpriseStandaloneAction(ctx, cmd, action, opts, script, args)
	}
	return windowsEnterpriseCommandRunner(ctx, cmd, script, args)
}

func writeWindowsEnterpriseLifecyclePreflightFailure(
	cmd *cobra.Command,
	action string,
	jsonOutput bool,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	if !jsonOutput {
		return cause
	}
	if cmd == nil {
		return fmt.Errorf(
			"Windows enterprise %s preflight failed and no command output is available: %w",
			strings.ToLower(strings.TrimSpace(action)),
			cause,
		)
	}
	report := windowsEnterpriseLifecyclePreflightFailure{
		SchemaVersion: 1,
		Action:        strings.ToLower(strings.TrimSpace(action)),
		OK:            false,
		Error:         cause.Error(),
		Errors:        []string{cause.Error()},
	}
	if err := newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
		return fmt.Errorf(
			"Windows enterprise %s preflight failed and its JSON report could not be encoded: %w",
			report.Action,
			err,
		)
	}
	// A coded caller error (naming the Secure Client profile on a standalone
	// computer, exit 1639) is answered by this JSON alone, as the standalone
	// results are (GAP-2445). Uncoded Secure Client failures keep their
	// historical stderr line.
	silenceJSONReportedError(cmd, true, cause)
	return cause
}

func windowsEnterpriseSelfUpgradeConflict(
	action string,
	installRoot string,
	executable string,
	cliBinary string,
) (bool, error) {
	if !strings.EqualFold(strings.TrimSpace(action), "upgrade") ||
		strings.TrimSpace(cliBinary) == "" {
		return false, nil
	}
	resolvedInstallRoot, err := resolveWindowsEnterpriseSelfUpgradeInstallRoot(installRoot)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(executable) == "" {
		return false, errors.New("the running Windows enterprise CLI executable path is empty")
	}
	cleanExecutable, err := filepath.Abs(strings.TrimSpace(executable))
	if err != nil {
		return false, fmt.Errorf(
			"resolve the running Windows enterprise CLI executable: %w",
			err,
		)
	}
	expectedExecutable := filepath.Join(
		resolvedInstallRoot,
		"bin",
		"defenseclaw.exe",
	)
	if strings.EqualFold(
		filepath.Clean(cleanExecutable),
		filepath.Clean(expectedExecutable),
	) {
		return true, nil
	}
	executableInfo, executableErr := os.Stat(cleanExecutable)
	if executableErr != nil {
		return false, fmt.Errorf(
			"inspect the running Windows enterprise CLI executable: %w",
			executableErr,
		)
	}
	expectedInfo, expectedErr := os.Stat(expectedExecutable)
	if expectedErr != nil {
		if errors.Is(expectedErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf(
			"inspect the installed Windows enterprise CLI destination: %w",
			expectedErr,
		)
	}
	return os.SameFile(executableInfo, expectedInfo), nil
}

func resolveWindowsEnterpriseSelfUpgradeInstallRoot(explicit string) (string, error) {
	root := strings.TrimSpace(explicit)
	if root != "" {
		if !filepath.IsAbs(root) {
			return "", errors.New(
				"the Windows enterprise install root must be an absolute path",
			)
		}
	} else {
		programFiles, err := windowsEnterpriseProgramFilesResolver()
		if err != nil {
			return "", fmt.Errorf(
				"resolve the trusted default Windows Program Files directory: %w",
				err,
			)
		}
		if strings.TrimSpace(programFiles) == "" {
			return "", errors.New(
				"the trusted default Windows Program Files directory is empty",
			)
		}
		if !filepath.IsAbs(programFiles) {
			return "", errors.New(
				"the trusted default Windows Program Files directory is not an absolute path",
			)
		}
		root = filepath.Join(programFiles, "Cisco", "DefenseClaw")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve the Windows enterprise install root: %w", err)
	}
	return filepath.Clean(root), nil
}

func windowsEnterpriseSelfUninstallCaller(
	action string,
	installer string,
	executable string,
	processID int,
) (uint32, bool) {
	if !strings.EqualFold(strings.TrimSpace(action), "uninstall") ||
		processID <= 0 ||
		uint64(processID) > uint64(^uint32(0)) {
		return 0, false
	}
	cleanInstaller, err := filepath.Abs(strings.TrimSpace(installer))
	if err != nil ||
		!strings.EqualFold(filepath.Base(cleanInstaller), "install-enterprise.ps1") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(cleanInstaller)), "libexec") {
		return 0, false
	}
	cleanExecutable, err := filepath.Abs(strings.TrimSpace(executable))
	if err != nil {
		return 0, false
	}
	installRoot := filepath.Dir(filepath.Dir(cleanInstaller))
	expectedExecutable := filepath.Join(installRoot, "bin", "defenseclaw.exe")
	if !strings.EqualFold(
		filepath.Clean(cleanExecutable),
		filepath.Clean(expectedExecutable),
	) {
		return 0, false
	}
	return uint32(processID), true
}

// windowsEnterpriseInstalledNonCLIUninstallCaller reports an uninstall that
// runs from an installed image other than bin\defenseclaw.exe, such as
// bin\defenseclaw-gateway.exe. Only the installed CLI hands its running image
// to the detached self-uninstall finalizer; any other running image inside
// InstallRoot keeps the folder from being retired, so the uninstall committed
// and then failed 1603 halfway (GAP-1679).
func windowsEnterpriseInstalledNonCLIUninstallCaller(action, installer, executable string) bool {
	if !strings.EqualFold(strings.TrimSpace(action), "uninstall") {
		return false
	}
	cleanInstaller, err := filepath.Abs(strings.TrimSpace(installer))
	if err != nil ||
		!strings.EqualFold(filepath.Base(cleanInstaller), "install-enterprise.ps1") ||
		!strings.EqualFold(filepath.Base(filepath.Dir(cleanInstaller)), "libexec") {
		return false
	}
	cleanExecutable, err := filepath.Abs(strings.TrimSpace(executable))
	if err != nil {
		return false
	}
	installRoot := filepath.Dir(filepath.Dir(cleanInstaller))
	if !windowsEnterprisePathWithin(cleanExecutable, installRoot) {
		return false
	}
	return !strings.EqualFold(
		filepath.Clean(cleanExecutable),
		filepath.Join(installRoot, "bin", "defenseclaw.exe"),
	)
}

// windowsEnterprisePathWithin reports whether path is root or inside it.
func windowsEnterprisePathWithin(path, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// windowsEnterpriseUninstallWorkingDirectory is replaceable in tests.
var windowsEnterpriseUninstallWorkingDirectory = trustedWindowsEnterpriseWorkingDirectory

// windowsEnterpriseLeaveInstallRoot moves the CLI's working directory out of
// installRoot before a self-uninstall. A working directory inside InstallRoot
// (the MDM uninstall script started the CLI in its bin folder, or an
// administrator ran it from there) is an open handle that keeps the folder
// from being renamed aside, so the uninstall committed and then failed 1603
// (GAP-1684).
func windowsEnterpriseLeaveInstallRoot(installRoot string) error {
	current, err := os.Getwd()
	if err != nil || !windowsEnterprisePathWithin(current, installRoot) {
		return nil
	}
	directory, err := windowsEnterpriseUninstallWorkingDirectory()
	if err != nil {
		return err
	}
	if err := os.Chdir(directory); err != nil {
		return fmt.Errorf("leave the install folder before the uninstall: %w", err)
	}
	return nil
}

// windowsEnterpriseDirectoryInUse is replaceable in tests.
var windowsEnterpriseDirectoryInUse = windowsDirectoryOpenWithoutDeleteSharing

// windowsEnterpriseInstallRootStillInUse refuses a self-uninstall started in a
// folder inside installRoot that another process still uses once the CLI has
// left it. That is usually the prompt it was typed into (cmd.exe after
// cd /d ...\bin): the CLI can move only its own working folder, and the
// prompt's keeps InstallRoot from being renamed aside, so the uninstall
// committed and then failed 1603, and so did every retry from that prompt
// (GAP-1794). Nothing has changed yet when this refuses.
func windowsEnterpriseInstallRootStillInUse(installRoot, started string) error {
	if started == "" || !windowsEnterprisePathWithin(started, installRoot) || !windowsEnterpriseDirectoryInUse(started) {
		return nil
	}
	return windowsEnterpriseInvalidArguments(
		"another program, usually the prompt this was run from, is using %s as its working folder, "+
			"so the uninstall could not remove %s and would stop halfway. Nothing was changed. "+
			"Change that prompt to a folder outside %s (for example, cd /d C:\\) and run the uninstall again",
		started,
		installRoot,
		installRoot,
	)
}

// windowsDirectoryOpenWithoutDeleteSharing reports whether another handle to
// the directory denies delete sharing, as a process's working-folder handle
// does. Any other failure (access denied, missing) is not reported as in use.
func windowsDirectoryOpenWithoutDeleteSharing(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		name,
		windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
	}
	_ = windows.CloseHandle(handle)
	return false
}

func windowsEnterprisePowerShellArgs(action string, opts *windowsEnterpriseLifecycleOptions) []string {
	args := []string{"-Action", canonicalWindowsEnterpriseAction(action)}
	appendValue := func(flag, value string) {
		if strings.TrimSpace(value) != "" {
			args = append(args, flag, value)
		}
	}
	appendValue("-BrokerBinary", opts.brokerBinary)
	appendValue("-ProviderLibrary", opts.providerLibrary)
	appendValue("-GatewayBinary", opts.gatewayBinary)
	appendValue("-ACPBinary", opts.acpBinary)
	appendValue("-HookBinary", opts.hookBinary)
	appendValue("-SensorHelperBinary", opts.sensorHelperBinary)
	appendValue("-PolicyCompiler", opts.policyCompiler)
	appendValue("-CLIBinary", opts.cliBinary)
	appendValue("-Config", opts.configPath)
	appendValue("-Manifest", opts.manifestPath)
	appendValue("-Mode", opts.mode)
	appendValue("-Connector", opts.connector)
	appendValue("-InstallRoot", opts.installRoot)
	appendValue("-StateRoot", opts.stateRoot)
	appendValue("-GatewayServiceName", opts.gatewayServiceName)
	appendValue("-GuardianServiceName", opts.guardianServiceName)
	appendValue("-CertificationCodexHome", opts.certificationCodexHome)
	appendValue("-BootstrapParent", opts.bootstrapParent)
	if opts.coreHardeningCertification {
		args = append(args, "-CoreHardeningCertification")
	}
	if opts.attestAgentApplicationControl {
		args = append(args, "-AttestAgentApplicationControl")
	}
	if opts.attestClaudeEffectivePolicy {
		args = append(args, "-AttestClaudeEffectivePolicy")
	}
	if opts.noStart {
		args = append(args, "-NoStart")
	}
	if opts.purge {
		args = append(args, "-Purge")
	}
	if opts.allowUnsigned {
		args = append(args, "-AllowUnsigned")
	}
	if opts.deferredConfig {
		args = append(args, "-DeferredConfig")
	}
	if opts.jsonOutput {
		args = append(args, "-Json")
	}
	return append(args, windowsEnterpriseStandalonePowerShellArgs(opts)...)
}

func validateWindowsEnterpriseLifecycleSecurityOptions(
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
) error {
	if opts == nil {
		return errors.New("Windows enterprise lifecycle options are unavailable")
	}
	mutationAction := action == "install" || action == "upgrade" || action == "repair" || action == "recover"
	mutationSecurityOptionUsed := opts.attestAgentApplicationControl ||
		opts.attestClaudeEffectivePolicy ||
		opts.coreHardeningCertification
	for _, name := range []string{
		"attest-agent-application-control",
		"attest-claude-effective-policy",
		"core-hardening-certification",
	} {
		if cmd != nil && cmd.Flags().Changed(name) {
			mutationSecurityOptionUsed = true
		}
	}
	if mutationSecurityOptionUsed && !mutationAction {
		return errors.New(
			"Windows enterprise security attestations and core certification are valid only with install, upgrade, or repair",
		)
	}
	hasCertificationHome := strings.TrimSpace(opts.certificationCodexHome) != ""
	if opts.allowUnsigned && !hasCertificationHome {
		return errors.New(
			"--allow-unsigned requires --certification-codex-home in the exact disposable certification scope",
		)
	}
	if hasCertificationHome && !opts.allowUnsigned {
		return errors.New(
			"--certification-codex-home is valid only with --allow-unsigned",
		)
	}
	if opts.coreHardeningCertification {
		if !opts.allowUnsigned || !hasCertificationHome {
			return errors.New(
				"--core-hardening-certification requires --allow-unsigned and --certification-codex-home",
			)
		}
		if opts.attestAgentApplicationControl ||
			opts.attestClaudeEffectivePolicy {
			return errors.New(
				"--core-hardening-certification cannot be combined with production application-control or Claude-policy attestations",
			)
		}
	}
	// The flag marks only the initial staged install. Protected deployment
	// metadata later selects the complete Repair activation path.
	if opts.deferredConfig && action != "install" {
		return fmt.Errorf(
			"--deferred-config is valid only with install (got: %s)", action,
		)
	}
	// QA shorthand pair. Matches install-enterprise.ps1's
	// -Mode / -Connector validation so a bad grammar surfaces at the
	// CLI boundary rather than deep inside the PowerShell transaction.
	modeSupplied := strings.TrimSpace(opts.mode) != ""
	connectorSupplied := strings.TrimSpace(opts.connector) != ""
	if modeSupplied != connectorSupplied {
		return errors.New(
			"--mode and --connector must be supplied together (they are the QA shorthand pair)",
		)
	}
	if modeSupplied && (strings.TrimSpace(opts.configPath) != "" ||
		strings.TrimSpace(opts.manifestPath) != "") {
		return errors.New(
			"--mode / --connector are mutually exclusive with --config / --manifest",
		)
	}
	if modeSupplied && opts.deferredConfig {
		return errors.New(
			"--mode / --connector cannot be combined with --deferred-config",
		)
	}
	if modeSupplied {
		mode := strings.ToLower(strings.TrimSpace(opts.mode))
		if mode != "observe" && mode != "action" {
			return errors.New("--mode must be observe or action")
		}
		opts.mode = mode
		// Standalone ensure installs from the same shorthand when the host has
		// no deployment yet, which is how an MDM first reaches a clean device.
		standaloneEnsure := action == "ensure" && windowsEnterpriseStandalone(opts)
		if action != "install" && action != "upgrade" && action != "repair" && !standaloneEnsure {
			return fmt.Errorf(
				"--mode / --connector are valid only with install, upgrade, or repair (got: %s)",
				action,
			)
		}
		// Keep this closed set aligned with the native Windows lifecycle. Each
		// entry must have reconcile, trusted-runtime, rollback, and teardown
		// coverage before it is accepted at this boundary. Secure Client also
		// manages GitHub Copilot (the CLI and the GitHub Copilot app).
		supportedOnWindows := map[string]bool{"codex": true, "claudecode": true, "cursor": true}
		supported := "codex, claudecode, cursor"
		if !windowsEnterpriseStandalone(opts) {
			supportedOnWindows["copilot"] = true
			supported += ", copilot (GitHub Copilot)"
		}
		for _, entry := range strings.Split(opts.connector, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(entry))
			if trimmed == "" {
				continue
			}
			if !supportedOnWindows[trimmed] {
				return fmt.Errorf(
					"--connector entry %q is not supported on Windows managed_enterprise; "+
						"supported: %s.",
					trimmed,
					supported,
				)
			}
		}
	}
	return nil
}

func canonicalWindowsEnterpriseAction(action string) string {
	if action == "" {
		return ""
	}
	return strings.ToUpper(action[:1]) + strings.ToLower(action[1:])
}

// windowsEnterpriseInstallerOverride reports the operator's chosen installer,
// if any. An override is honoured exactly: a release that carries the scripts
// internally still must not quietly answer a request for a specific file.
func windowsEnterpriseInstallerOverride(explicit string) string {
	if value := strings.TrimSpace(explicit); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(windowsEnterpriseInstallerEnv))
}

func findWindowsEnterpriseInstaller(explicit string) (string, error) {
	var candidates []string
	if override := windowsEnterpriseInstallerOverride(explicit); override != "" {
		candidates = append(candidates, override)
	} else {
		executable, err := os.Executable()
		if err == nil {
			binDir := filepath.Dir(executable)
			candidates = append(candidates,
				filepath.Join(filepath.Dir(binDir), "libexec", "install-enterprise.ps1"),
				filepath.Join(binDir, "install-enterprise.ps1"),
			)
		}
	}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		info, err := os.Lstat(absolute)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := windowsEnterpriseTrustValidator(absolute); err != nil {
			return "", err
		}
		return filepath.Clean(absolute), nil
	}
	return "", fmt.Errorf(
		"%w; pass --installer or set %s",
		errWindowsEnterpriseInstallerNotFound,
		windowsEnterpriseInstallerEnv,
	)
}

func validateWindowsEnterpriseInstallerTrust(installer string) error {
	if err := managed.ValidateTrustedFilePath(installer, "Windows enterprise installer"); err != nil {
		return fmt.Errorf("refusing untrusted Windows enterprise installer: %w", err)
	}
	module := filepath.Join(filepath.Dir(installer), "DefenseClawEnterprise.psm1")
	info, err := os.Lstat(module)
	if err != nil {
		return fmt.Errorf("inspect adjacent Windows enterprise installer module: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("adjacent Windows enterprise installer module is not a regular non-link file: %s", module)
	}
	if err := managed.ValidateTrustedFilePath(module, "Windows enterprise installer module"); err != nil {
		return fmt.Errorf("refusing untrusted Windows enterprise installer module: %w", err)
	}
	return nil
}

func runWindowsEnterprisePowerShell(
	ctx context.Context,
	cmd *cobra.Command,
	script string,
	args []string,
) error {
	powerShell, err := findWindowsPowerShell()
	if err != nil {
		return err
	}
	_, err = runWindowsEnterprisePowerShellEngine(
		ctx,
		cmd,
		powerShell,
		trustedWindowsEnterpriseEnvironment,
		script,
		args,
		cmd.OutOrStdout(),
		cmd.ErrOrStderr(),
	)
	return err
}

// runWindowsEnterprisePowerShellEngine runs the installer on one validated
// engine with a strict environment. stdout receives the installer's output
// as it is produced; the bounded capture is returned for diagnostics.
func runWindowsEnterprisePowerShellEngine(
	ctx context.Context,
	cmd *cobra.Command,
	powerShell string,
	environment func(string) ([]string, error),
	script string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (*windowsEnterpriseOutputCapture, error) {
	return runWindowsEnterprisePowerShellEngineWithRunner(ctx, cmd, powerShell, environment, script, args,
		stdout, stderr, false, (*exec.Cmd).Run)
}

func runWindowsEnterprisePowerShellEngineWithRunner(
	ctx context.Context,
	cmd *cobra.Command,
	powerShell string,
	environment func(string) ([]string, error),
	script string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	standalone bool,
	runner func(*exec.Cmd) error,
) (*windowsEnterpriseOutputCapture, error) {
	commandArgs := []string{
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", script,
	}
	commandArgs = append(commandArgs, args...)
	child := exec.CommandContext(ctx, powerShell, commandArgs...)
	powerShellTemp, cleanupTemp, err := prepareWindowsEnterprisePowerShellTemp()
	if err != nil {
		return nil, err
	}
	cleanupPending := true
	defer func() {
		if cleanupPending {
			_ = cleanupTemp()
		}
	}()
	childEnvironment, err := environment(powerShellTemp)
	if err != nil {
		return nil, err
	}
	workingDirectory, err := trustedWindowsEnterpriseWorkingDirectory()
	if err != nil {
		return nil, err
	}
	child.Env = childEnvironment
	child.Dir = workingDirectory
	child.Stdin = cmd.InOrStdin()
	childOutput := &windowsEnterpriseOutputCapture{}
	child.Stdout = io.MultiWriter(stdout, childOutput)
	child.Stderr = stderr
	runErr := runner(child)
	if standalone && errors.Is(runErr, exec.ErrWaitDelay) && child.ProcessState != nil && child.ProcessState.Success() {
		childOutput.pipeWaitDelayed = true
		runErr = nil
	}
	cleanupErr := cleanupTemp()
	cleanupPending = false
	if runErr != nil || cleanupErr != nil {
		if standalone && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return childOutput, fmt.Errorf("lifecycle_timeout: Windows enterprise installer did not finish before the ensure deadline: %w", ctx.Err())
		}
		var failures []error
		if runErr != nil {
			// The child's own code is the first thing an operator needs, and
			// "exit status N" alone does not say who exited.
			var exit *exec.ExitError
			if errors.As(runErr, &exit) {
				if action, detail, ok := windowsEnterpriseInstallerFailureDiagnostic(
					childOutput.buffer.Bytes(),
					childOutput.truncated,
				); ok {
					failures = append(failures, fmt.Errorf(
						"Windows enterprise installer %s failed: %s (exit code %d)",
						action,
						detail,
						exit.ExitCode(),
					))
				} else {
					failures = append(failures, windowsEnterpriseInstallerExitFailure(exit.ExitCode()))
				}
			} else {
				failures = append(failures, fmt.Errorf("Windows enterprise installer: %w", runErr))
			}
		}
		if cleanupErr != nil {
			failures = append(failures, fmt.Errorf("remove protected Windows enterprise PowerShell temp: %w", cleanupErr))
		}
		return childOutput, errors.Join(failures...)
	}
	return childOutput, nil
}

func windowsEnterpriseInstallerFailureDiagnostic(
	body []byte,
	truncated bool,
) (action, detail string, ok bool) {
	if truncated {
		return "", "", false
	}
	var report struct {
		SchemaVersion int      `json:"schema_version"`
		Action        string   `json:"action"`
		OK            bool     `json:"ok"`
		Error         string   `json:"error"`
		Errors        []string `json:"errors"`
	}
	trimmed := trimWindowsJSONBOM(bytes.TrimSpace(body))
	if len(trimmed) == 0 || len(trimmed) > windowsEnterpriseOutputCaptureMax ||
		json.Unmarshal(trimmed, &report) != nil || report.SchemaVersion != 1 ||
		report.OK {
		return "", "", false
	}
	rawDetail := strings.TrimSpace(report.Error)
	if rawDetail == "" {
		for _, candidate := range report.Errors {
			if rawDetail = strings.TrimSpace(candidate); rawDetail != "" {
				break
			}
		}
	}
	if rawDetail == "" {
		return "", "", false
	}
	action = strings.ToLower(strings.TrimSpace(report.Action))
	if action == "" || strings.IndexFunc(action, func(value rune) bool {
		return value < 'a' || value > 'z'
	}) >= 0 {
		action = "lifecycle"
	}
	detail = strings.Map(func(value rune) rune {
		if value < 0x20 || value == 0x7f {
			return ' '
		}
		return value
	}, rawDetail)
	if len(detail) > windowsEnterpriseDiagnosticMax {
		detail = detail[:windowsEnterpriseDiagnosticMax] + "..."
	}
	return action, detail, true
}

func trustedWindowsEnterpriseEnvironment(powerShellTemp string) ([]string, error) {
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, fmt.Errorf("resolve the trusted Windows directory: %w", err)
	}
	machineRoots, err := windowsEnterpriseMachineRootsResolver()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted Windows machine roots: %w", err)
	}
	if strings.TrimSpace(powerShellTemp) == "" {
		return nil, errors.New("trusted Windows enterprise PowerShell temporary directory is empty")
	}
	system32 := filepath.Join(windowsDirectory, "System32")
	// Build a strict allowlist instead of rewriting selected entries in the
	// caller environment. CLR profilers/startup hooks, PowerShell policy,
	// compatibility shims, debugger hooks, and other loader variables are
	// consumed before the installer script can defend itself.
	allowed := map[string]string{
		"SystemRoot":      windowsDirectory,
		"windir":          windowsDirectory,
		"SystemDrive":     filepath.VolumeName(windowsDirectory),
		"ComSpec":         filepath.Join(system32, "cmd.exe"),
		"ProgramFiles":    machineRoots.ProgramFiles,
		"ProgramW6432":    machineRoots.ProgramFiles,
		"ProgramData":     machineRoots.ProgramData,
		"ALLUSERSPROFILE": machineRoots.ProgramData,
		"TEMP":            powerShellTemp,
		"TMP":             powerShellTemp,
		"LOCALAPPDATA":    powerShellTemp,
		"APPDATA":         powerShellTemp,
		"USERPROFILE":     powerShellTemp,
		"HOME":            powerShellTemp,
		"HOMEDRIVE":       filepath.VolumeName(powerShellTemp),
		"HOMEPATH":        strings.TrimPrefix(powerShellTemp, filepath.VolumeName(powerShellTemp)),
		"PSModulePath": filepath.Join(
			system32,
			"WindowsPowerShell",
			"v1.0",
			"Modules",
		),
		"PATH": strings.Join([]string{
			system32,
			windowsDirectory,
			filepath.Join(system32, "Wbem"),
			filepath.Join(system32, "WindowsPowerShell", "v1.0"),
		}, string(os.PathListSeparator)),
	}
	allowed["ProgramFiles(x86)"] = machineRoots.ProgramFilesX86

	environment := make([]string, 0, len(allowed))
	for key, value := range allowed {
		environment = append(environment, key+"="+value)
	}
	return environment, nil
}

func prepareWindowsEnterprisePowerShellTemp() (string, func() error, error) {
	return prepareWindowsEnterprisePowerShellTempWithOps(
		windowsEnterprisePowerShellTempOps{
			isElevated: func() bool {
				return windows.GetCurrentProcessToken().IsElevated()
			},
			userTemp: trustedWindowsEnterpriseUserTempDirectory,
			elevatedTempRoot: func() (string, error) {
				// ProgramData permits create-only access at its root without
				// granting unprivileged callers replacement access to this child.
				return windowsEnterpriseProgramDataResolver()
			},
			randomRead:      rand.Read,
			createDirectory: windows.CreateDirectory,
			validate:        validateWindowsEnterprisePowerShellTemp,
			remove:          os.Remove,
			removeAll:       os.RemoveAll,
		},
	)
}

func prepareWindowsEnterprisePowerShellTempWithOps(
	ops windowsEnterprisePowerShellTempOps,
) (string, func() error, error) {
	if !ops.isElevated() {
		path, err := ops.userTemp()
		return path, func() error { return nil }, err
	}

	parent, err := ops.elevatedTempRoot()
	if err != nil {
		return "", nil, fmt.Errorf("resolve the trusted ProgramData directory: %w", err)
	}
	path, err := createProtectedWindowsEnterpriseDirectory(
		parent,
		"DefenseClaw-PowerShell-",
		"Windows enterprise PowerShell temp",
		ops.randomRead,
		ops.createDirectory,
	)
	if err != nil {
		return "", nil, err
	}
	removeEmptyOnError := func(cause error) (string, func() error, error) {
		removeErr := ops.remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cause = errors.Join(cause, fmt.Errorf("remove rejected protected temp %s: %w", path, removeErr))
		}
		return "", nil, cause
	}
	if err := ops.validate(path); err != nil {
		return removeEmptyOnError(err)
	}
	cleanup := func() error {
		if err := ops.validate(path); err != nil {
			// An uninstall can remove the folder with the rest of
			// DefenseClaw's ProgramData state; nothing is left to clean.
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("refusing unsafe temp cleanup: %w", err)
		}
		for attempt := 0; ; attempt++ {
			err := ops.removeAll(path)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if attempt == 2 || (!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
				!errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
				return err
			}
			// A just-terminated descendant can briefly retain a temp file.
			time.Sleep(50 * time.Millisecond)
		}
	}
	return filepath.Clean(path), cleanup, nil
}

// createProtectedWindowsEnterpriseDirectory creates a freshly named child of
// parent whose DACL admits only SYSTEM and Administrators. The random name
// keeps an unprivileged caller from planting the directory first and owning
// what lands inside it.
func createProtectedWindowsEnterpriseDirectory(
	parent string,
	prefix string,
	label string,
	randomRead func([]byte) (int, error),
	createDirectory func(*uint16, *windows.SecurityAttributes) error,
) (string, error) {
	descriptor, err := windows.SecurityDescriptorFromString(windowsEnterpriseTempSDDL)
	if err != nil {
		return "", fmt.Errorf("build protected %s descriptor: %w", label, err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for attempt := 0; attempt < 4; attempt++ {
		capability := make([]byte, 16)
		if _, err := randomRead(capability); err != nil {
			return "", fmt.Errorf("generate protected %s name: %w", label, err)
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(capability))
		pathPtr, err := winpath.UTF16Ptr(path)
		if err != nil {
			return "", fmt.Errorf("encode protected %s path: %w", label, err)
		}
		createErr := createDirectory(pathPtr, attributes)
		if createErr == nil {
			return path, nil
		}
		if createErr != windows.ERROR_ALREADY_EXISTS {
			return "", fmt.Errorf("create protected %s: %w", label, createErr)
		}
	}
	return "", fmt.Errorf("create protected %s: random path collisions exhausted", label)
}

func trustedWindowsEnterpriseUserTempDirectory() (string, error) {
	// A read-only Status command is intentionally available without elevation.
	// Resolve that same token's temp directory through a Known Folder instead
	// of inheriting TEMP/TMP. It cannot create an elevation boundary because
	// both launcher and child retain the same non-elevated token.
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		return "", fmt.Errorf("resolve the current-user LocalAppData folder: %w", err)
	}
	path := filepath.Join(localAppData, "Temp")
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect the current-user PowerShell temporary directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("current-user PowerShell temporary path is not a regular non-link directory: %s", path)
	}
	return filepath.Clean(path), nil
}

func windowsEnterpriseExactDescriptorMatch(
	actual, expected *windows.SECURITY_DESCRIPTOR,
) (bool, error) {
	if actual == nil || expected == nil {
		return false, nil
	}
	actualControl, actualRevision, err := actual.Control()
	if err != nil {
		return false, err
	}
	expectedControl, expectedRevision, err := expected.Control()
	if err != nil {
		return false, err
	}
	ignored := windows.SECURITY_DESCRIPTOR_CONTROL(windows.SE_DACL_AUTO_INHERITED)
	if actualRevision != expectedRevision ||
		actualControl&^ignored != expectedControl&^ignored {
		return false, nil
	}
	actualOwner, _, err := actual.Owner()
	if err != nil {
		return false, err
	}
	expectedOwner, _, err := expected.Owner()
	if err != nil {
		return false, err
	}
	if !windowsEnterpriseSIDEqual(actualOwner, expectedOwner) {
		return false, nil
	}
	actualGroup, _, err := actual.Group()
	if err != nil {
		return false, err
	}
	expectedGroup, _, err := expected.Group()
	if err != nil {
		return false, err
	}
	if !windowsEnterpriseSIDEqual(actualGroup, expectedGroup) {
		return false, nil
	}
	actualDACL, err := windowsEnterpriseRawDACL(actual)
	if err != nil {
		return false, err
	}
	expectedDACL, err := windowsEnterpriseRawDACL(expected)
	if err != nil {
		return false, err
	}
	return bytes.Equal(actualDACL, expectedDACL), nil
}

func windowsEnterpriseSIDEqual(left, right *windows.SID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equals(right)
}

func windowsEnterpriseRawDACL(descriptor *windows.SECURITY_DESCRIPTOR) ([]byte, error) {
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return nil, nil
	}
	header := (*windowsEnterpriseACLHeader)(unsafe.Pointer(dacl))
	minimum := uint16(unsafe.Sizeof(windowsEnterpriseACLHeader{}))
	if header.size < minimum || header.aceCount != dacl.AceCount {
		return nil, fmt.Errorf("invalid DACL header")
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(dacl)), int(header.size)), nil
}

func validateWindowsEnterprisePowerShellTemp(path string) error {
	if err := managed.ValidateTrustedRuntimeDir(
		path,
		"elevated Windows enterprise PowerShell temporary directory",
	); err != nil {
		return fmt.Errorf("trusted elevated PowerShell temporary directory validation: %w", err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("encode protected Windows enterprise PowerShell temp path: %w", err)
	}
	actual, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect protected Windows enterprise PowerShell temp descriptor: %w", err)
	}
	expected, err := windows.SecurityDescriptorFromString(windowsEnterpriseTempSDDL)
	if err != nil {
		return fmt.Errorf("build expected protected Windows enterprise PowerShell temp descriptor: %w", err)
	}
	matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
	if err != nil {
		return fmt.Errorf("compare protected Windows enterprise PowerShell temp descriptor: %w", err)
	}
	if !matches {
		actualString := "<nil>"
		if actual != nil {
			actualString = actual.String()
		}
		return fmt.Errorf(
			"protected Windows enterprise PowerShell temp descriptor mismatch: got %q, want %q",
			actualString,
			expected.String(),
		)
	}
	return nil
}

func trustedWindowsEnterpriseWorkingDirectory() (string, error) {
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve the trusted Windows directory: %w", err)
	}
	system32 := filepath.Join(windowsDirectory, "System32")
	info, err := os.Lstat(system32)
	if err != nil {
		return "", fmt.Errorf("inspect the trusted Windows System32 directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("trusted Windows System32 is not a regular non-link directory: %s", system32)
	}
	if err := managed.ValidateTrustedRuntimeDir(
		system32,
		"Windows enterprise PowerShell working directory",
	); err != nil {
		return "", fmt.Errorf("trusted Windows PowerShell working directory validation: %w", err)
	}
	return filepath.Clean(system32), nil
}

func findWindowsPowerShell() (string, error) {
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve the trusted Windows directory: %w", err)
	}
	path := filepath.Join(
		windowsDirectory,
		"System32",
		"WindowsPowerShell",
		"v1.0",
		"powershell.exe",
	)
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("trusted Windows PowerShell is unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("trusted Windows PowerShell is not a regular non-link file: %s", path)
	}
	if err := managed.ValidateTrustedFilePath(path, "Windows PowerShell"); err != nil {
		return "", fmt.Errorf("trusted Windows PowerShell path validation: %w", err)
	}
	return filepath.Clean(path), nil
}

func newWindowsServiceConfigValidationCommand() *cobra.Command {
	var (
		configPath     string
		dataDir        string
		serviceAccount string
		jsonOutput     bool
		record         bool
		recordRestored bool
		repairRollback bool
	)
	cmd := &cobra.Command{
		Use:          "validate-service-config",
		Short:        "Validate the installed config and runtime trust boundary",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if repairRollback && (record || recordRestored) {
				return errors.New("repair-rollback is read-only and cannot record a config generation")
			}
			if recordRestored {
				return recordRestoredWindowsServiceConfig(cmd, configPath, dataDir, serviceAccount, jsonOutput)
			}
			var report windowsServiceConfigValidation
			var err error
			if repairRollback {
				report, err = validateWindowsRepairRollbackConfig(configPath, dataDir, serviceAccount)
			} else {
				report, err = validateWindowsServiceConfig(configPath, dataDir, serviceAccount, record)
			}
			if jsonOutput {
				if err != nil {
					_ = newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(map[string]any{
						"schema_version": 1,
						"ok":             false,
						"error":          err.Error(),
					})
					return errors.New("Windows enterprise service config validation failed")
				}
				return newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(report)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "managed Windows service config verified: %s\n", report.ConfigPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "installed managed config path")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "expected protected runtime directory")
	cmd.Flags().StringVar(&serviceAccount, "service-account", "", "gateway NT SERVICE virtual account")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	cmd.Flags().BoolVar(&record, "record-lifecycle", false,
		"migrate a config_version 8 config and record the installed config generation (install-like lifecycle only)")
	cmd.Flags().BoolVar(&recordRestored, "record-restored", false,
		"record the config a lifecycle rollback restored as a new generation, without validating or migrating it")
	cmd.Flags().BoolVar(&repairRollback, "repair-rollback", false,
		"read-only rollback preflight for Repair; ACL trust is checked after Repair restamps managed paths")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("data-dir")
	return cmd
}

// validateWindowsRepairRollbackConfig checks the config a running gateway
// would have to restart on if Repair rolls back. It checks content and paths
// outside Repair's ACL scope before stopping the service. Managed ACLs are
// left to the journaled Repair and checked again after restamping.
func validateWindowsRepairRollbackConfig(configPath, expectedDataDir, serviceAccount string) (windowsServiceConfigValidation, error) {
	var report windowsServiceConfigValidation
	configPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return report, fmt.Errorf("resolve config path: %w", err)
	}
	expectedDataDir, err = filepath.Abs(strings.TrimSpace(expectedDataDir))
	if err != nil {
		return report, fmt.Errorf("resolve data dir: %w", err)
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            configPath,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.WindowsServiceAccountEnv: strings.TrimSpace(serviceAccount),
		"DEFENSECLAW_HOME":               expectedDataDir,
	})
	defer restore()
	loaded, err := compileStandaloneGatewayRepairRollbackConfig(configPath, expectedDataDir)
	if err != nil {
		return report, err
	}
	loadedDataDir, err := filepath.Abs(loaded.DataDir)
	if err != nil {
		return report, fmt.Errorf("resolve loaded data_dir: %w", err)
	}
	if !strings.EqualFold(filepath.Clean(loadedDataDir), filepath.Clean(expectedDataDir)) {
		return report, fmt.Errorf("managed data_dir %q does not match protected runtime %q", loadedDataDir, expectedDataDir)
	}
	apiBind := strings.TrimSpace(loaded.Gateway.APIBind)
	if apiBind == "" {
		apiBind = "127.0.0.1"
	}
	report = windowsServiceConfigValidation{
		SchemaVersion:  1,
		OK:             true,
		ConfigPath:     filepath.Clean(configPath),
		DataDir:        filepath.Clean(loadedDataDir),
		DeploymentMode: loaded.DeploymentMode,
		APIBind:        apiBind,
		Profile:        managed.ProfileStandalone,
	}
	if loaded.Guardrail.Enabled {
		report.GuardrailBind = loaded.Guardrail.EffectiveHost()
	}
	return report, nil
}

// The signed standalone installer asks its authenticated gateway whether the
// candidate config opts into Fleet before admitting or copying the compiler.
// The answer is one exact boolean line, with any parser error on stderr.
// Only a Fleet opt-in has to come from an admin-protected path: a Fleet-off
// answer installs nothing, so a 1.0.1 config in an Intune cache or an
// admin-made ProgramData folder upgrades as it did before Fleet existed.
func newWindowsStandaloneFleetInspectCommand() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:          "inspect-standalone-fleet",
		Hidden:       true,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := readConfigV8Source(configPath)
			if err != nil {
				return err
			}
			enabled, err := config.StandaloneFleetSourceEnabled(configPath, raw, func() error {
				if err := managed.ValidateTrustedFilePath(configPath, "standalone config"); err != nil {
					return fmt.Errorf("standalone config source is untrusted: %w", err)
				}
				return nil
			})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), enabled)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "authenticated source config path")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// recordRestoredWindowsServiceConfig is the rollback step of the standalone
// lifecycle: see recordRestoredManagedStandaloneConfig.
func recordRestoredWindowsServiceConfig(cmd *cobra.Command, configPath, dataDir, serviceAccount string, jsonOutput bool) error {
	configPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            configPath,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: strings.TrimSpace(serviceAccount),
		"DEFENSECLAW_HOME":               strings.TrimSpace(dataDir),
	})
	defer restore()
	err = recordRestoredManagedStandaloneConfig(cmd.Context(), configPath)
	if jsonOutput {
		_ = newEnterpriseJSONEncoder(cmd.OutOrStdout()).Encode(map[string]any{"schema_version": 1, "ok": err == nil})
	}
	return err
}

// validateWindowsServiceConfig checks the installed config. Only the
// install-like lifecycle passes record, inside its transaction: verify and
// status run the same check read-only, so a hand edit is never recorded as
// a lifecycle generation and a v8 file is not migrated without a snapshot.
func validateWindowsServiceConfig(
	configPath string,
	expectedDataDir string,
	serviceAccount string,
	record bool,
) (windowsServiceConfigValidation, error) {
	var report windowsServiceConfigValidation
	configPath, err := filepath.Abs(strings.TrimSpace(configPath))
	if err != nil {
		return report, fmt.Errorf("resolve config path: %w", err)
	}
	expectedDataDir, err = filepath.Abs(strings.TrimSpace(expectedDataDir))
	if err != nil {
		return report, fmt.Errorf("resolve data dir: %w", err)
	}

	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            configPath,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.WindowsServiceAccountEnv: strings.TrimSpace(serviceAccount),
		"DEFENSECLAW_HOME":               expectedDataDir,
	})
	defer restore()

	loaded, err := config.LoadFromFile(configPath)
	if err != nil {
		return report, err
	}
	if loaded == nil {
		return report, errors.New("config loader returned no configuration")
	}
	if !managed.IsManagedEnterprise(loaded.DeploymentMode) {
		return report, fmt.Errorf("deployment_mode=%q is not managed_enterprise", loaded.DeploymentMode)
	}
	loadedDataDir, err := filepath.Abs(loaded.DataDir)
	if err != nil {
		return report, fmt.Errorf("resolve loaded data_dir: %w", err)
	}
	if !strings.EqualFold(filepath.Clean(loadedDataDir), filepath.Clean(expectedDataDir)) {
		return report, fmt.Errorf(
			"managed data_dir %q does not match protected runtime %q",
			loadedDataDir,
			expectedDataDir,
		)
	}

	apiBind := strings.TrimSpace(loaded.Gateway.APIBind)
	if apiBind == "" {
		apiBind = "127.0.0.1"
	}
	report = windowsServiceConfigValidation{
		SchemaVersion:  1,
		OK:             true,
		ConfigPath:     filepath.Clean(configPath),
		DataDir:        filepath.Clean(loadedDataDir),
		DeploymentMode: loaded.DeploymentMode,
		APIBind:        apiBind,
	}
	if loaded.Guardrail.Enabled {
		report.GuardrailBind = loaded.Guardrail.EffectiveHost()
	}
	// The lifecycle pins DEFENSECLAW_ENTERPRISE_PROFILE for standalone
	// helpers exactly as it pins the services; the loader has already
	// rejected a config that contradicts the pin.
	if managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv)) {
		if !loaded.StandaloneEnterprise() {
			return windowsServiceConfigValidation{}, fmt.Errorf(
				"managed config resolves the %q enterprise profile, not %s",
				loaded.EnterpriseProfile(), managed.ProfileStandalone,
			)
		}
		report.Profile = managed.ProfileStandalone
		// In the lifecycle transaction a config_version 8 administrator
		// config becomes 9 here, and the installed config is recorded in
		// config.generation.json.
		if record {
			if err := migrateManagedStandaloneConfig(context.Background(), configPath); err != nil {
				return windowsServiceConfigValidation{}, err
			}
		}
		// The gateway service compiles this file strictly at start; prove
		// it can before the lifecycle starts it. Secure Client
		// keeps its historical validation.
		if err := validateStandaloneGatewayConfig(configPath, expectedDataDir, ""); err != nil {
			return windowsServiceConfigValidation{}, err
		}
	}
	return report, nil
}

func setTemporaryEnvironment(values map[string]string) func() {
	type previousValue struct {
		value string
		set   bool
	}
	previous := make(map[string]previousValue, len(values))
	for key, value := range values {
		old, set := os.LookupEnv(key)
		previous[key] = previousValue{value: old, set: set}
		if value == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, value)
		}
	}
	return func() {
		for key, old := range previous {
			if old.set {
				_ = os.Setenv(key, old.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}
