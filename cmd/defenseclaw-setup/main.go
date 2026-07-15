// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"golang.org/x/mod/semver"
)

//go:embed payload/*
var embeddedPayload embed.FS

const (
	productName                  = "DefenseClaw"
	setupArtifactName            = "DefenseClawSetup-x64.exe"
	defaultPublisher             = "Cisco Systems, Inc."
	userExitCode                 = 1602
	installAlreadyRunningCode    = 1618
	installTreeRenameMaxAttempts = 40
	installTreeRenameRetryDelay  = 100 * time.Millisecond
	// 1603 is the standard fatal-install result. Never use 3010 here: Windows
	// deployment systems interpret it as a successful install requiring reboot,
	// while these paths leave the requested operation incomplete and need retry.
	retryRequiredCode          = 1603
	maxZipFiles                = 100000
	maxZipExpandedBytes        = int64(2 << 30)
	setupControlCommandTimeout = 2 * time.Minute
	setupValidationTimeout     = 30 * time.Second
	setupConfigurationTimeout  = 5 * time.Minute
	setupMigrationTimeout      = 15 * time.Minute
	maxRunCommandUTF16Units    = 260
)

var errInstalledProcessRunning = errors.New("an installed DefenseClaw process is still running")

func newCapturedSetupCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return processutil.CommandContext(ctx, name, args...)
}

func runCapturedSetupCommand(timeout time.Duration, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := newCapturedSetupCommand(ctx, name, args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return output, fmt.Errorf("command timed out after %s: %w", timeout, ctxErr)
	}
	return output, err
}

func gatewayAutoStartCommand(gatewayPath string) string {
	startupPath := filepath.Join(filepath.Dir(gatewayPath), "defenseclaw-startup.exe")
	return `"` + startupPath + `"`
}

func legacyGatewayAutoStartCommand(gatewayPath string) string {
	return `"` + gatewayPath + `" start`
}

func runCommandUTF16Units(command string) int {
	return len(utf16.Encode([]rune(command)))
}

func validateRunCommand(command string) error {
	if strings.ContainsRune(command, '\x00') {
		return errors.New("windows Run command contains an embedded NUL")
	}
	units := runCommandUTF16Units(command)
	if units > maxRunCommandUTF16Units {
		return fmt.Errorf(
			"windows Run command is %d UTF-16 code units; the supported maximum is %d",
			units,
			maxRunCommandUTF16Units,
		)
	}
	return nil
}

type options struct {
	Action          string
	Quiet           bool
	NoRestart       bool // Standard installer property; setup never initiates an OS reboot.
	InstallScope    string
	Connector       string
	Mode            string
	StartGateway    bool
	DeleteUserData  bool
	ConnectorSet    bool
	ModeSet         bool
	StartGatewaySet bool
	WaitPID         uint32
	FromVersion     string
	CodexHome       string
	ClaudeConfigDir string
	// PreserveConnectorConfiguration is internal transaction intent, never a
	// command-line property. Servicing an existing install without an explicit
	// connector or mode selection must refresh its owned registrations in place
	// instead of collapsing connector changes made later through the CLI.
	PreserveConnectorConfiguration bool
}

type payloadManifest struct {
	SchemaVersion      int               `json:"schema_version"`
	Version            string            `json:"version"`
	SourceCommit       string            `json:"source_commit"`
	DistributionFlavor string            `json:"distribution_flavor"`
	PythonVersion      string            `json:"python_version"`
	GatewayArchive     string            `json:"gateway_archive"`
	Wheel              string            `json:"wheel"`
	PythonEmbed        string            `json:"python_embed"`
	YaraCompatWheel    string            `json:"yara_compat_wheel"`
	UpgradeManifest    string            `json:"upgrade_manifest"`
	SitePackages       string            `json:"site_packages"`
	Launcher           string            `json:"launcher"`
	StartupLauncher    string            `json:"startup_launcher"`
	CosignVerifier     string            `json:"cosign_verifier"`
	Unsigned           bool              `json:"unsigned"`
	Toolchain          map[string]string `json:"toolchain"`
	Files              map[string]string `json:"files"`
}

type installState struct {
	SchemaVersion          int               `json:"schema_version"`
	Version                string            `json:"version"`
	SourceCommit           string            `json:"source_commit"`
	DistributionFlavor     string            `json:"distribution_flavor"`
	InstallKind            string            `json:"install_kind"`
	InstallScope           string            `json:"install_scope"`
	InstallRoot            string            `json:"install_root"`
	CommandDir             string            `json:"command_dir"`
	DataRoot               string            `json:"data_root"`
	Runtime                string            `json:"runtime"`
	MaintenancePath        string            `json:"maintenance_path"`
	PathEntryOwned         bool              `json:"path_entry_owned"`
	PathSeparatorReused    bool              `json:"path_separator_reused,omitempty"`
	PathValueCreated       bool              `json:"path_value_created,omitempty"`
	Connector              string            `json:"connector"`
	Mode                   string            `json:"mode"`
	CodexHome              string            `json:"codex_home,omitempty"`
	ClaudeConfigDir        string            `json:"claude_config_dir,omitempty"`
	UnsignedLocalArtifact  bool              `json:"unsigned_local_artifact"`
	ReleaseSigningRequired bool              `json:"release_signing_required"`
	Toolchain              map[string]string `json:"toolchain"`
	InstalledAtUTC         string            `json:"installed_at_utc"`
	TransactionID          string            `json:"transaction_id,omitempty"`
}

func main() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "DefenseClawSetup-x64.exe is only supported on native Windows x64")
		os.Exit(1)
	}
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "DefenseClawSetup-x64.exe supports only Windows x64 (amd64)")
		os.Exit(1)
	}

	code, err := run(opts)
	if err != nil {
		// Silent mode suppresses interactive UI, not diagnostics. Automation and
		// enterprise deployment tools need the concrete failure on their captured
		// stderr stream; a windowsgui process still receives redirected standard
		// handles when its parent explicitly provides them.
		fmt.Fprintf(os.Stderr, "DefenseClaw setup failed: %v\n", err)
		showSetupLaunchContextFailure(err, opts.Quiet)
		if code != 0 {
			os.Exit(code)
		}
		os.Exit(1)
	}
	os.Exit(code)
}

var acquireSetupOperationLock = acquireSetupLock

func run(opts options) (int, error) {
	// Help is intentionally available in every context: it is read-only and lets
	// an administrator or deployment service discover the supported per-user
	// invocation without starting an installation transaction.
	if opts.Action == "help" {
		printUsage()
		return 0, nil
	}
	// INS-32: this read-only token/session/desktop gate must remain the first
	// operation for every state-changing action. The setup mutex, known-folder
	// resolution, registry, and filesystem transaction code below are all
	// intentionally unreachable from an elevated, service, session-zero, or
	// otherwise non-interactive launch.
	if err := requireCurrentUserInteractiveSetup(); err != nil {
		return retryRequiredCode, err
	}
	if err := waitForProcessExit(opts.WaitPID, 2*time.Minute); err != nil {
		return retryRequiredCode, err
	}
	releaseSetupLock, err := acquireSetupOperationLock()
	if err != nil {
		return installAlreadyRunningCode, err
	}
	defer func() {
		_ = releaseSetupLock()
	}()

	installRoot, err := defaultInstallRoot()
	if err != nil {
		return 1, err
	}
	dataRoot, err := defaultDataRoot()
	if err != nil {
		return 1, err
	}
	if err := validateManagedRoot(installRoot); err != nil {
		return 1, err
	}
	if err := preflightInstalledClients(installRoot); err != nil {
		if errors.Is(err, errInstalledProcessRunning) {
			return retryRequiredCode, err
		}
		return 1, err
	}
	if opts.Action == "uninstall" {
		if !opts.Quiet {
			return runInteractiveWizard(opts, installRoot, dataRoot)
		}
		return runUninstall(opts, installRoot, dataRoot)
	}
	if !opts.Quiet {
		return runInteractiveWizard(opts, installRoot, dataRoot)
	}
	return runInstall(opts, installRoot, dataRoot)
}

func runInstall(opts options, installRoot, dataRoot string) (int, error) {
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return 1, err
	}
	if err := validateManagedRoot(filepath.Dir(maintenancePath)); err != nil {
		return 1, err
	}
	hadInstall := pathExists(installRoot)
	if err := recoverPendingSetupTransaction(installRoot, dataRoot); err != nil {
		return retryRequiredCode, err
	}
	payloadTempRoot, err := defaultPayloadTempRoot()
	if err != nil {
		return 1, err
	}
	if err := cleanupStalePayloadTemps(payloadTempRoot); err != nil {
		return retryRequiredCode, fmt.Errorf("clean stale installer payloads: %w", err)
	}
	oldState, err := loadExistingInstallState(installRoot)
	if err != nil {
		return 1, err
	}
	// Recovery may publish, restore, or remove a transaction-owned tree.
	hadInstall = pathExists(installRoot)
	if hadInstall && oldState == nil {
		return 1, fmt.Errorf("refusing to replace an existing directory without valid DefenseClaw installer state: %s", installRoot)
	}
	if oldState != nil {
		if !opts.ConnectorSet && validConnector(oldState.Connector) {
			opts.Connector = oldState.Connector
			opts.PreserveConnectorConfiguration = !opts.ModeSet
		}
		if !opts.ModeSet && validMode(oldState.Mode) {
			opts.Mode = oldState.Mode
		}
		if opts.Action == "upgrade" && opts.FromVersion == "" {
			opts.FromVersion = oldState.Version
		}
	}
	// Every install/repair/upgrade refreshes either the explicit selection or the
	// existing owned connector roster. Existing data alone is not evidence that
	// hooks are configured: it also covers legacy and data-preserving installs.
	upgradeFrom := opts.FromVersion
	pathEntryOwned := oldState != nil && oldState.PathEntryOwned
	pathSeparatorReused := oldState != nil && oldState.PathSeparatorReused
	pathValueCreated := oldState != nil && oldState.PathValueCreated

	payload, err := loadPayload(payloadTempRoot)
	if err != nil {
		return 1, err
	}
	defer func() {
		_ = removeAllSafe(payload.TempRoot, payloadTempRoot)
		_ = os.Remove(payloadTempRoot)
	}()

	if !opts.Quiet {
		status := "Installing"
		if opts.Action == "repair" {
			status = "Repairing"
		} else if opts.Action == "upgrade" {
			status = "Upgrading"
		}
		fmt.Printf("%s DefenseClaw %s to %s\n", status, payload.Manifest.Version, installRoot)
		if payload.Manifest.Unsigned {
			fmt.Println("Local artifact is unsigned; production releases must be Authenticode signed.")
		}
	}
	if oldState != nil && compareVersions(payload.Manifest.Version, oldState.Version) < 0 {
		return 1, fmt.Errorf(
			"downgrade rejected: installed version %s is newer than packaged version %s",
			oldState.Version,
			payload.Manifest.Version,
		)
	}
	upgradeFrom = migrationSource(oldState, payload.Manifest.Version, upgradeFrom)
	if err := validateInstalledAppMutation(installRoot, oldState); err != nil {
		return 1, err
	}
	transaction, err := newSetupTransaction(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		upgradeFrom,
		payload.Manifest.Version,
		oldState,
		opts,
	)
	if err != nil {
		return 1, err
	}
	// Persist the effective connector homes chosen at intent time. Recovery
	// must never depend on a later process inheriting the same environment.
	opts.CodexHome = transaction.CodexHome
	opts.ClaudeConfigDir = transaction.ClaudeConfigDir
	if err := beginSetupTransaction(transaction); err != nil {
		return retryRequiredCode, err
	}
	tryRestore := func(cause error) (int, error) {
		rollbackErr := rollbackSetupTransaction(transaction)
		if rollbackErr == nil {
			rollbackErr = markSetupTransactionComplete(transaction, setupPhaseIntent)
		}
		if rollbackErr != nil {
			return retryRequiredCode, errors.Join(cause, fmt.Errorf("transaction rollback remains pending: %w", rollbackErr))
		}
		if errors.Is(cause, errInstalledProcessRunning) || isSharingViolation(cause) {
			return retryRequiredCode, fmt.Errorf("%w; close running DefenseClaw terminals and retry", cause)
		}
		return 1, cause
	}

	if err := stageInstallTree(
		payload,
		transaction.StagingPath,
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		pathEntryOwned,
		pathSeparatorReused,
		pathValueCreated,
		opts,
	); err != nil {
		return tryRestore(err)
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	_, err = stopOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return tryRestore(err)
	}
	if transaction.HadInstall {
		currentState, err := loadExistingInstallState(installRoot)
		if err != nil {
			return tryRestore(err)
		}
		if !installStateMatchesSnapshot(currentState, transaction.PreviousState) {
			return tryRestore(errors.New("installed state changed after the setup transaction began"))
		}
		pid, imagePath, err := liveProcessWithinInstallRoot(installRoot)
		if err != nil {
			return tryRestore(fmt.Errorf("inspect running DefenseClaw processes: %w", err))
		}
		if pid != 0 {
			return tryRestore(fmt.Errorf("%w (PID %d, %s)", errInstalledProcessRunning, pid, imagePath))
		}
		if err := renameInstallTree(installRoot, transaction.BackupPath); err != nil {
			if isTransientInstallTreeRenameError(err) {
				return tryRestore(fmt.Errorf("existing install files are locked; close running DefenseClaw terminals and retry"))
			}
			return tryRestore(fmt.Errorf("move existing install aside: %w", err))
		}
	} else if _, err := os.Lstat(installRoot); err == nil {
		return tryRestore(errors.New("install path appeared after the setup transaction began"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return tryRestore(err)
	}
	if err := renameInstallTree(transaction.StagingPath, installRoot); err != nil {
		return tryRestore(fmt.Errorf("publish staged install: %w", err))
	}

	if err := validateInstall(installRoot, payload.Manifest.Version); err != nil {
		return tryRestore(err)
	}
	if err := publishMaintenanceCopyForTransaction(transaction); err != nil {
		return tryRestore(err)
	}
	if err := markSetupTransactionCommitted(transaction); err != nil {
		if errors.Is(err, errSetupJournalDurabilityAmbiguous) {
			return retryRequiredCode, fmt.Errorf("commit setup transaction; recovery is required before retrying: %w", err)
		}
		return tryRestore(fmt.Errorf("commit setup transaction: %w", err))
	}
	if _, err := finishCommittedSetupTransaction(transaction); err != nil {
		return retryRequiredCode, fmt.Errorf("installation committed but convergence is pending: %w", err)
	}
	if err := connectorReconciliationPendingError("installation"); err != nil {
		return retryRequiredCode, err
	}
	if !opts.Quiet {
		fmt.Println("DefenseClaw installed successfully.")
		fmt.Println("Open a new terminal and run: defenseclaw")
	}
	return 0, nil
}

func preflightInstalledClients(installRoot string) error {
	if !pathExists(installRoot) {
		return nil
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	pid, imagePath, err := liveProcessWithinInstallRoot(installRoot, gatewayPath)
	if err != nil {
		return fmt.Errorf("inspect running DefenseClaw processes: %w", err)
	}
	if pid == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w (PID %d, %s); close running DefenseClaw terminals and retry",
		errInstalledProcessRunning,
		pid,
		imagePath,
	)
}

func runUninstall(opts options, installRoot, dataRoot string) (int, error) {
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return 1, err
	}
	transaction, err := preparePendingSetupTransactionForUninstall(opts, installRoot, dataRoot)
	if err != nil {
		return retryRequiredCode, err
	}
	if !opts.Quiet {
		fmt.Printf("Uninstalling DefenseClaw from %s\n", installRoot)
	}
	if transaction == nil {
		oldState, loadErr := loadExistingInstallState(installRoot)
		if loadErr != nil {
			return 1, loadErr
		}
		if pathExists(installRoot) && oldState == nil {
			return 1, fmt.Errorf("refusing to remove an existing directory without valid DefenseClaw installer state: %s", installRoot)
		}
		prepared, transactionErr := newSetupTransaction("uninstall", installRoot, dataRoot, maintenancePath, "", "", oldState, opts)
		if transactionErr != nil {
			return 1, transactionErr
		}
		if err := beginSetupTransaction(prepared); err != nil {
			return retryRequiredCode, err
		}
		transaction = &prepared
	}
	rollbackUninstall := func(cause error) (int, error) {
		rollbackErr := rollbackSetupTransaction(*transaction)
		if rollbackErr == nil {
			rollbackErr = markSetupTransactionComplete(*transaction, setupPhaseIntent)
		}
		if rollbackErr != nil {
			return retryRequiredCode, errors.Join(cause, fmt.Errorf("transaction rollback remains pending: %w", rollbackErr))
		}
		if errors.Is(cause, errInstalledProcessRunning) || isSharingViolation(cause) {
			return retryRequiredCode, fmt.Errorf("%w; close running DefenseClaw terminals and retry", cause)
		}
		return 1, cause
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	_, err = stopOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return rollbackUninstall(err)
	}
	if pathExists(installRoot) {
		currentState, stateErr := loadExistingInstallState(installRoot)
		if stateErr != nil {
			return rollbackUninstall(stateErr)
		}
		if !installStateMatchesSnapshot(currentState, transaction.PreviousState) {
			return rollbackUninstall(errors.New("installed state changed after the uninstall transaction began"))
		}
		pid, imagePath, processErr := liveProcessWithinInstallRoot(installRoot)
		if processErr != nil {
			return rollbackUninstall(fmt.Errorf("inspect running DefenseClaw processes: %w", processErr))
		}
		if pid != 0 {
			return rollbackUninstall(fmt.Errorf("%w (PID %d, %s)", errInstalledProcessRunning, pid, imagePath))
		}
		if err := renameInstallTree(installRoot, transaction.TrashPath); err != nil {
			if isTransientInstallTreeRenameError(err) {
				return rollbackUninstall(fmt.Errorf("product files are locked; close running DefenseClaw terminals and retry"))
			}
			return rollbackUninstall(err)
		}
	}
	if err := markSetupTransactionCommitted(*transaction); err != nil {
		if errors.Is(err, errSetupJournalDurabilityAmbiguous) {
			return retryRequiredCode, fmt.Errorf("commit uninstall transaction; recovery is required before retrying: %w", err)
		}
		return rollbackUninstall(fmt.Errorf("commit uninstall transaction: %w", err))
	}
	deferred, err := finishCommittedSetupTransaction(*transaction)
	if err != nil {
		return retryRequiredCode, fmt.Errorf("uninstall committed but convergence is pending: %w", err)
	}
	if err := connectorReconciliationPendingError("uninstall"); err != nil {
		return retryRequiredCode, err
	}
	if deferred && !opts.Quiet {
		fmt.Println("DefenseClaw cleanup will finish after this installer exits.")
	}
	if !opts.Quiet {
		if opts.DeleteUserData {
			fmt.Println("DefenseClaw application files and user data removed.")
		} else {
			fmt.Printf("DefenseClaw application files removed. User data preserved at %s\n", dataRoot)
		}
	}
	return 0, nil
}

type serviceState struct {
	Gateway  bool `json:"gateway"`
	Watchdog bool `json:"watchdog"`
}

func (state serviceState) any() bool {
	return state.Gateway || state.Watchdog
}

func requestedServices(opts options, previous serviceState) serviceState {
	return serviceState{
		// A configured hook connector requires the local gateway after every
		// logon. "none" remains the explicit opt-out for a CLI-only install.
		Gateway:  opts.StartGateway || previous.Gateway || opts.Connector != "none",
		Watchdog: previous.Watchdog,
	}
}

func connectorsForNativeUninstall(state *installState, dataRoot string) []string {
	seen := map[string]bool{}
	connectors := make([]string, 0, 2)
	add := func(name string) {
		if (name == "codex" || name == "claudecode") && !seen[name] {
			seen[name] = true
			connectors = append(connectors, name)
		}
	}
	if state != nil {
		add(state.Connector)
	}
	if pathExists(filepath.Join(dataRoot, "codex_config_backup.json")) {
		add("codex")
	}
	if pathExists(filepath.Join(dataRoot, "claudecode_backup.json")) {
		add("claudecode")
	}
	return connectors
}

func runConnectorLifecycle(gatewayPath, dataRoot, connectorName, action string) error {
	return runConnectorLifecycleWithEnv(gatewayPath, dataRoot, connectorName, action, managedChildEnv(dataRoot))
}

func runConnectorLifecycleWithEnv(gatewayPath, dataRoot, connectorName, action string, env []string) error {
	if !pathExists(gatewayPath) {
		return fmt.Errorf("connector %s %s requires the installed gateway binary", connectorName, action)
	}
	args := []string{
		"connector", action,
		"--connector", connectorName,
		"--data-dir", dataRoot,
		"--json",
	}
	output, err := runCapturedSetupCommand(setupControlCommandTimeout, env, gatewayPath, args...)
	if err != nil {
		return fmt.Errorf("connector %s %s failed: %w: %s", connectorName, action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type gatewayAutoStartSnapshot struct {
	Existed bool   `json:"existed"`
	Value   string `json:"value,omitempty"`
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func samePath(a, b string) bool {
	return pathidentity.Same(a, b)
}

func validConnector(value string) bool {
	return value == "none" || value == "codex" || value == "claudecode"
}

func validMode(value string) bool {
	return value == "observe" || value == "action"
}

func compareVersions(a, b string) int {
	// All production callers receive versions from a validated payload,
	// installer state, or FROMVERSION property. x/mod implements complete
	// SemVer precedence, including prerelease identifiers and the rule that
	// build metadata does not affect ordering.
	return semver.Compare("v"+a, "v"+b)
}

func migrationSource(state *installState, packagedVersion, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if state != nil && compareVersions(state.Version, packagedVersion) <= 0 {
		return state.Version
	}
	return ""
}

func shouldRunPackagedMigrations(fromVersion, toVersion string) bool {
	return fromVersion != "" && compareVersions(fromVersion, toVersion) <= 0
}

func loadExistingInstallState(installRoot string) (*installState, error) {
	return loadInstallStateFromTree(installRoot, installRoot)
}

func loadInstallStateFromTree(treeRoot, installRoot string) (*installState, error) {
	dataRoot, err := defaultDataRoot()
	if err != nil {
		return nil, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return nil, err
	}
	return loadInstallStateFromTreeForRoots(treeRoot, installRoot, dataRoot, maintenancePath)
}

func loadInstallStateFromTreeForRoots(treeRoot, installRoot, dataRoot, maintenancePath string) (*installState, error) {
	path := filepath.Join(treeRoot, "installer", "install-state.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var state installState
	if err := readJSON(path, &state); err != nil {
		return nil, fmt.Errorf("read existing installer state: %w", err)
	}
	if err := validateInstallStateForRoots(&state, installRoot, dataRoot, maintenancePath); err != nil {
		return nil, fmt.Errorf("existing installer state: %w", err)
	}
	return &state, nil
}

func updateInstalledPathOwnership(installRoot string, owned, reusedSeparator, valueCreated bool) error {
	path := filepath.Join(installRoot, "installer", "install-state.json")
	var state installState
	if err := readJSON(path, &state); err != nil {
		return err
	}
	state.PathEntryOwned = owned
	state.PathSeparatorReused = reusedSeparator
	state.PathValueCreated = valueCreated
	return writeJSON(path, state)
}

func publishMaintenanceCopyForTransaction(transaction setupTransaction) error {
	target := transaction.MaintenancePath
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if samePath(self, target) {
		if err := validateMaintenanceSnapshot(
			target,
			transaction.MaintenanceExisted,
			transaction.PreviousMaintenanceSHA256,
		); err != nil {
			return fmt.Errorf("maintenance executable changed after transaction intent: %w", err)
		}
		digest, err := fileSHA256(target)
		if err != nil {
			return err
		}
		if !strings.EqualFold(digest, transaction.MaintenanceSHA256) {
			return errors.New("running maintenance executable does not match the transaction digest")
		}
		return nil
	}
	root := filepath.Dir(target)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if err := rejectReparseAncestors(root); err != nil {
		return err
	}
	backup := transaction.MaintenanceBackup
	staged := transaction.MaintenanceNew
	for _, artifact := range []string{staged, backup} {
		if _, err := os.Lstat(artifact); err == nil {
			return fmt.Errorf("refusing pre-existing maintenance transaction artifact: %s", artifact)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := copyFile(self, staged); err != nil {
		return err
	}
	if err := validateMaintenanceSnapshot(
		target,
		transaction.MaintenanceExisted,
		transaction.PreviousMaintenanceSHA256,
	); err != nil {
		_ = removeAllSafe(staged, root)
		return fmt.Errorf("maintenance executable changed after transaction intent: %w", err)
	}
	if transaction.MaintenanceExisted {
		if err := renameInstallTree(target, backup); err != nil {
			_ = removeAllSafe(staged, root)
			return err
		}
		backupDigest, digestErr := fileSHA256(backup)
		if digestErr != nil || !strings.EqualFold(backupDigest, transaction.PreviousMaintenanceSHA256) {
			restoreErr := renameInstallTree(backup, target)
			_ = removeAllSafe(staged, root)
			if digestErr != nil {
				return errors.Join(fmt.Errorf("validate maintenance backup: %w", digestErr), restoreErr)
			}
			return errors.Join(errors.New("maintenance executable changed while it was being published"), restoreErr)
		}
	}
	if err := renameInstallTree(staged, target); err != nil {
		if transaction.MaintenanceExisted {
			_ = renameInstallTree(backup, target)
		}
		return err
	}
	return nil
}

func stageInstallTree(payload loadedPayload, staging, installRoot, dataRoot, maintenancePath, transactionID string, pathEntryOwned, pathSeparatorReused, pathValueCreated bool, opts options) error {
	if err := createExclusiveStagingRoot(staging); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(staging, "bin"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(staging, "runtime", "python"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(staging, "installer"), 0o755); err != nil {
		return err
	}
	if err := extractZipFile(filepath.Join(payload.Root, payload.Manifest.PythonEmbed), filepath.Join(staging, "runtime", "python")); err != nil {
		return fmt.Errorf("extract embedded Python: %w", err)
	}
	if err := configurePythonPTH(filepath.Join(staging, "runtime", "python")); err != nil {
		return err
	}
	sitePackages := filepath.Join(staging, "runtime", "python", "Lib", "site-packages")
	if err := os.MkdirAll(sitePackages, 0o755); err != nil {
		return err
	}
	if err := extractZipFile(filepath.Join(payload.Root, payload.Manifest.SitePackages), sitePackages); err != nil {
		return fmt.Errorf("extract managed Python packages: %w", err)
	}
	if err := extractGateway(payload, filepath.Join(staging, "bin")); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(payload.Root, payload.Manifest.Launcher), filepath.Join(staging, "bin", "defenseclaw.exe")); err != nil {
		return fmt.Errorf("install CLI launcher: %w", err)
	}
	if err := copyFile(
		filepath.Join(payload.Root, payload.Manifest.StartupLauncher),
		filepath.Join(staging, "bin", "defenseclaw-startup.exe"),
	); err != nil {
		return fmt.Errorf("install startup launcher: %w", err)
	}
	if err := copyFile(
		filepath.Join(payload.Root, payload.Manifest.CosignVerifier),
		filepath.Join(staging, "runtime", "tools", "cosign.exe"),
	); err != nil {
		return fmt.Errorf("install managed Sigstore verifier: %w", err)
	}
	if err := publishNativeLaunchers(staging); err != nil {
		return err
	}
	if err := copyFile(
		filepath.Join(payload.Root, payload.Manifest.UpgradeManifest),
		filepath.Join(staging, "installer", "upgrade-manifest.json"),
	); err != nil {
		return fmt.Errorf("install upgrade manifest: %w", err)
	}
	if err := writeJSON(filepath.Join(staging, "installer", "payload-manifest.json"), payload.Manifest); err != nil {
		return err
	}
	state := installState{
		SchemaVersion:          1,
		Version:                payload.Manifest.Version,
		SourceCommit:           payload.Manifest.SourceCommit,
		DistributionFlavor:     payload.Manifest.DistributionFlavor,
		InstallKind:            "native-windows-exe",
		InstallScope:           "user",
		InstallRoot:            installRoot,
		CommandDir:             filepath.Join(installRoot, "bin"),
		DataRoot:               dataRoot,
		Runtime:                filepath.Join(installRoot, "runtime", "python"),
		MaintenancePath:        maintenancePath,
		PathEntryOwned:         pathEntryOwned,
		PathSeparatorReused:    pathSeparatorReused,
		PathValueCreated:       pathValueCreated,
		Connector:              opts.Connector,
		Mode:                   opts.Mode,
		CodexHome:              opts.CodexHome,
		ClaudeConfigDir:        opts.ClaudeConfigDir,
		UnsignedLocalArtifact:  payload.Manifest.Unsigned,
		ReleaseSigningRequired: true,
		Toolchain:              payload.Manifest.Toolchain,
		InstalledAtUTC:         time.Now().UTC().Format(time.RFC3339),
		TransactionID:          transactionID,
	}
	if err := writeJSON(filepath.Join(staging, "installer", "install-state.json"), state); err != nil {
		return err
	}
	return nil
}

func createExclusiveStagingRoot(staging string) error {
	parent := filepath.Dir(staging)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create installer staging parent: %w", err)
	}
	if err := rejectReparseAncestors(parent); err != nil {
		return fmt.Errorf("validate installer staging parent: %w", err)
	}
	if err := os.Mkdir(staging, 0o755); err != nil {
		return fmt.Errorf("create exclusive installer staging root: %w", err)
	}
	return nil
}

func extractGateway(payload loadedPayload, binDir string) error {
	gatewayArchive := filepath.Join(payload.Root, payload.Manifest.GatewayArchive)
	tmp := filepath.Join(payload.Root, "gateway-extract")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	if err := extractZipFile(gatewayArchive, tmp); err != nil {
		return fmt.Errorf("extract gateway archive: %w", err)
	}
	if err := copyFile(filepath.Join(tmp, "defenseclaw.exe"), filepath.Join(binDir, "defenseclaw-gateway.exe")); err != nil {
		return fmt.Errorf("install gateway: %w", err)
	}
	if err := copyFile(filepath.Join(tmp, "defenseclaw-hook.exe"), filepath.Join(binDir, "defenseclaw-hook.exe")); err != nil {
		return fmt.Errorf("install hook launcher: %w", err)
	}
	return nil
}

func publishNativeLaunchers(staging string) error {
	binDir := filepath.Join(staging, "bin")
	launcher := filepath.Join(binDir, "defenseclaw.exe")
	for _, fileName := range []string{
		"skill-scanner.exe",
		"mcp-scanner.exe",
		"defenseclaw-observability.exe",
	} {
		if err := copyFile(launcher, filepath.Join(binDir, fileName)); err != nil {
			return err
		}
	}
	return nil
}

func validateInstall(root, version string) error {
	cosign := filepath.Join(root, "runtime", "tools", "cosign.exe")
	if info, err := os.Stat(cosign); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("managed Sigstore verifier is missing or invalid: %s", cosign)
	}
	launcher := filepath.Join(root, "bin", "defenseclaw.exe")
	childEnv := sanitizePythonEnv(os.Environ())
	output, err := runCapturedSetupCommand(setupValidationTimeout, childEnv, launcher, "--version-json")
	if err != nil {
		return fmt.Errorf("managed CLI version check failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := validateMachineVersion(output, "defenseclaw-cli", version); err != nil {
		return fmt.Errorf("managed CLI version check: %w", err)
	}
	gateway := filepath.Join(root, "bin", "defenseclaw-gateway.exe")
	output, err = runCapturedSetupCommand(setupValidationTimeout, childEnv, gateway, "--version-json")
	if err != nil {
		return fmt.Errorf("gateway version check failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := validateMachineVersion(output, "defenseclaw-gateway", version); err != nil {
		return fmt.Errorf("gateway version check: %w", err)
	}
	return nil
}

type machineVersionReport struct {
	SchemaVersion int    `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit,omitempty"`
	Built         string `json:"built,omitempty"`
}

func validateMachineVersion(output []byte, expectedName, expectedVersion string) error {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var report machineVersionReport
	if err := decoder.Decode(&report); err != nil {
		return fmt.Errorf("decode machine-readable version %q: %w", strings.TrimSpace(string(output)), err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("machine-readable version contains trailing content")
	}
	if report.SchemaVersion != 1 || report.Name != expectedName {
		return fmt.Errorf("unexpected version identity schema=%d name=%q", report.SchemaVersion, report.Name)
	}
	if !validPayloadVersion(report.Version) || report.Version != expectedVersion {
		return fmt.Errorf("reported version %q does not exactly match packaged version %q", report.Version, expectedVersion)
	}
	return nil
}

func runInitialConfigurationWithEnv(root, dataRoot string, opts options, env []string) error {
	if opts.Connector == "none" {
		return nil
	}
	args := []string{
		"init", "--skip-install", "--non-interactive", "--yes",
		"--connector", opts.Connector,
		"--profile", opts.Mode,
		"--no-start-gateway", "--no-verify",
	}
	output, err := runCapturedSetupCommand(setupConfigurationTimeout, env, filepath.Join(root, "bin", "defenseclaw.exe"), args...)
	if err != nil {
		return fmt.Errorf("connector configuration failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

const packagedMigrationScript = `import json, sys
from defenseclaw import migration_state
from defenseclaw.migrations import run_migrations
from_version, to_version, openclaw_home, data_root, manifest_path = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as stream:
    manifest = json.load(stream)
if manifest.get("release_version") != to_version:
    raise SystemExit("upgrade manifest version mismatch")
count = run_migrations(from_version, to_version, openclaw_home, data_root)
state = migration_state.load(data_root)
applied = set(state.applied if state else ())
missing = [value for value in manifest.get("required_cli_migrations", ()) if value not in applied]
if missing:
    raise SystemExit("required migrations are missing: " + ", ".join(missing))
print(count)`

func runPackagedMigrations(root, dataRoot, fromVersion, toVersion string) error {
	return runPackagedMigrationsWithEnv(root, dataRoot, fromVersion, toVersion, managedChildEnv(dataRoot))
}

func runPackagedMigrationsWithEnv(root, dataRoot, fromVersion, toVersion string, env []string) error {
	openClawRoot, err := defaultOpenClawRoot()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), setupMigrationTimeout)
	defer cancel()
	cmd := newPackagedMigrationCommand(ctx, root, dataRoot, openClawRoot, fromVersion, toVersion)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("run packaged migrations timed out after %s: %w: %s", setupMigrationTimeout, ctxErr, strings.TrimSpace(string(output)))
	}
	if err != nil {
		return fmt.Errorf("run packaged migrations: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func newPackagedMigrationCommand(ctx context.Context, root, dataRoot, openClawRoot, fromVersion, toVersion string) *exec.Cmd {
	python := filepath.Join(root, "runtime", "python", "python.exe")
	manifest := filepath.Join(root, "installer", "upgrade-manifest.json")
	cmd := newCapturedSetupCommand(
		ctx,
		python,
		"-I",
		// Isolated mode implies -E, so Python intentionally ignores the
		// PYTHONUTF8/PYTHONIOENCODING values in the managed environment. Keep
		// isolation and force UTF-8 on the interpreter command line instead.
		"-X",
		"utf8",
		"-c",
		packagedMigrationScript,
		fromVersion,
		toVersion,
		openClawRoot,
		dataRoot,
		manifest,
	)
	cmd.Env = managedChildEnv(dataRoot)
	return cmd
}

func startGateway(gatewayPath, dataRoot string) error {
	output, err := runCapturedSetupCommand(setupControlCommandTimeout, managedChildEnv(dataRoot), gatewayPath, "start")
	if err != nil {
		return fmt.Errorf("start gateway: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func startWatchdog(gatewayPath, dataRoot string) error {
	output, err := runCapturedSetupCommand(setupControlCommandTimeout, managedChildEnv(dataRoot), gatewayPath, "watchdog", "start")
	if err != nil {
		return fmt.Errorf("start watchdog: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stopOwnedServices(gatewayPath, dataRoot string) (serviceState, error) {
	if !pathExists(gatewayPath) {
		return serviceState{}, nil
	}
	watchdogOwned, err := managedProcessOwnedBy(gatewayPath, dataRoot, "watchdog.pid")
	if err != nil {
		return serviceState{}, err
	}
	gatewayOwned, err := managedProcessOwnedBy(gatewayPath, dataRoot, "gateway.pid")
	if err != nil {
		return serviceState{}, err
	}
	stopped := serviceState{}
	if watchdogOwned {
		output, stopErr := runCapturedSetupCommand(setupControlCommandTimeout, managedChildEnv(dataRoot), gatewayPath, "watchdog", "stop")
		if stopErr != nil {
			return serviceState{}, fmt.Errorf("stop managed watchdog: %w: %s", stopErr, strings.TrimSpace(string(output)))
		}
		stopped.Watchdog = true
	}
	if gatewayOwned {
		output, stopErr := runCapturedSetupCommand(setupControlCommandTimeout, managedChildEnv(dataRoot), gatewayPath, "stop")
		if stopErr != nil {
			if stopped.Watchdog {
				_ = startWatchdog(gatewayPath, dataRoot)
			}
			return serviceState{}, fmt.Errorf("stop managed gateway: %w: %s", stopErr, strings.TrimSpace(string(output)))
		}
		stopped.Gateway = true
	}
	return stopped, nil
}

func startSelectedServices(gatewayPath, dataRoot string, wanted serviceState) (serviceState, error) {
	started := serviceState{}
	if wanted.Gateway {
		if err := startGateway(gatewayPath, dataRoot); err != nil {
			return started, err
		}
		started.Gateway = true
	}
	if wanted.Watchdog {
		if err := startWatchdog(gatewayPath, dataRoot); err != nil {
			if started.Gateway {
				_, _ = stopOwnedServices(gatewayPath, dataRoot)
			}
			return serviceState{}, err
		}
		started.Watchdog = true
	}
	return started, nil
}

func verifySelectedServices(gatewayPath, dataRoot string, wanted serviceState) error {
	commands := make([][]string, 0, 2)
	if wanted.Gateway {
		commands = append(commands, []string{"status"})
	}
	if wanted.Watchdog {
		commands = append(commands, []string{"watchdog", "status"})
	}
	for _, args := range commands {
		output, err := runCapturedSetupCommand(setupControlCommandTimeout, managedChildEnv(dataRoot), gatewayPath, args...)
		if err != nil {
			return fmt.Errorf("verify %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	// The status commands intentionally return success for a stopped service so
	// they remain useful to operators. Setup needs the stronger postcondition:
	// every requested process must own its exact PID/start/image identity before
	// a committed repair or upgrade is reported complete.
	actual, err := inspectOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return fmt.Errorf("inspect selected services after startup: %w", err)
	}
	if wanted.Gateway && !actual.Gateway {
		return errors.New("managed gateway did not remain running after startup")
	}
	if wanted.Watchdog && !actual.Watchdog {
		return errors.New("managed watchdog did not remain running after startup")
	}
	return nil
}

type loadedPayload struct {
	Root     string
	TempRoot string
	Manifest payloadManifest
}

func loadPayload(tempParent string) (loadedPayload, error) {
	archive, err := embeddedPayload.Open("payload/installer-payload.zip")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return loadedPayload{}, errors.New("installer payload missing; build with scripts/build-windows-installer.ps1")
		}
		return loadedPayload{}, err
	}
	defer archive.Close()
	reader, err := zipReaderAtFile(archive)
	if err != nil {
		return loadedPayload{}, fmt.Errorf("open embedded payload: %w", err)
	}
	if err := os.MkdirAll(tempParent, 0o755); err != nil {
		return loadedPayload{}, err
	}
	if err := rejectReparseAncestors(tempParent); err != nil {
		return loadedPayload{}, err
	}
	tempRoot, err := os.MkdirTemp(tempParent, ".DefenseClawSetup.")
	if err != nil {
		return loadedPayload{}, err
	}
	if err := extractZipReader(reader, tempRoot); err != nil {
		_ = os.RemoveAll(tempRoot)
		return loadedPayload{}, err
	}
	var manifest payloadManifest
	if err := readJSON(filepath.Join(tempRoot, "payload", "manifest.json"), &manifest); err != nil {
		_ = os.RemoveAll(tempRoot)
		return loadedPayload{}, err
	}
	if err := verifyPayloadManifest(tempRoot, manifest); err != nil {
		_ = os.RemoveAll(tempRoot)
		return loadedPayload{}, err
	}
	return loadedPayload{Root: filepath.Join(tempRoot, "payload"), TempRoot: tempRoot, Manifest: manifest}, nil
}

func zipReaderAtFile(file fs.File) (*zip.Reader, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	readerAt, ok := file.(io.ReaderAt)
	if !ok {
		return nil, errors.New("embedded payload does not support random access")
	}
	return zip.NewReader(readerAt, info.Size())
}

func verifyPayloadManifest(root string, manifest payloadManifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported payload schema version %d", manifest.SchemaVersion)
	}
	if !validPayloadVersion(manifest.Version) {
		return fmt.Errorf("invalid payload version %q", manifest.Version)
	}
	if !validSourceCommit(manifest.SourceCommit) {
		return fmt.Errorf("invalid payload source commit %q", manifest.SourceCommit)
	}
	if manifest.DistributionFlavor != "oss" {
		return fmt.Errorf(
			"unsupported payload distribution flavor %q; managed-enterprise requires the private Windows CMID release overlay",
			manifest.DistributionFlavor,
		)
	}
	required := []string{
		manifest.GatewayArchive,
		manifest.Wheel,
		manifest.PythonEmbed,
		manifest.YaraCompatWheel,
		manifest.SitePackages,
		manifest.Launcher,
		manifest.StartupLauncher,
		manifest.CosignVerifier,
		manifest.UpgradeManifest,
	}
	for _, name := range required {
		if strings.TrimSpace(name) == "" {
			return errors.New("payload manifest is missing a required file name")
		}
		if _, ok := manifest.Files[name]; !ok {
			return fmt.Errorf("payload manifest has no hash for required file %s", name)
		}
	}
	for rel, expected := range manifest.Files {
		if len(expected) != sha256.Size*2 {
			return fmt.Errorf("payload manifest has an invalid SHA-256 for %s", rel)
		}
		if _, err := hex.DecodeString(expected); err != nil {
			return fmt.Errorf("payload manifest has an invalid SHA-256 for %s", rel)
		}
		full, err := safeJoin(filepath.Join(root, "payload"), rel)
		if err != nil {
			return err
		}
		sum, err := fileSHA256(full)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sum, expected) {
			return fmt.Errorf("payload hash mismatch for %s", rel)
		}
	}
	return nil
}

func validSourceCommit(value string) bool {
	// Get-GitSourceCommit records this repository's exact SHA-1 object ID.
	// Payload file digests are SHA-256, but the Git provenance field is the
	// 40-character commit returned by `git rev-parse HEAD`.
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func extractZipFile(path, dest string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	return extractZipReader(&reader.Reader, dest)
}

func extractZipReader(reader *zip.Reader, dest string) error {
	if len(reader.File) > maxZipFiles {
		return fmt.Errorf("zip payload contains too many entries: %d", len(reader.File))
	}
	var expanded int64
	for _, file := range reader.File {
		if file.UncompressedSize64 > uint64(maxZipExpandedBytes) ||
			file.UncompressedSize64 > uint64(maxZipExpandedBytes-expanded) {
			return fmt.Errorf("zip payload exceeds the expanded size limit")
		}
		expanded += int64(file.UncompressedSize64)
		target, err := safeJoin(dest, file.Name)
		if err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if file.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in zip payload: %s", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := rejectReparseExisting(target); err != nil {
			return err
		}
		src, err := file.Open()
		if err != nil {
			return err
		}
		err = writeExtractedFile(target, src, file.Mode())
		closeErr := src.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func validPayloadVersion(value string) bool {
	if value == "" || len(value) > 192 || strings.HasPrefix(value, "v") {
		return false
	}
	core := value
	if index := strings.IndexAny(core, "-+"); index >= 0 {
		core = core[:index]
	}
	coreParts := strings.Split(core, ".")
	if len(coreParts) != 3 {
		return false
	}
	for _, part := range coreParts {
		if len(part) == 0 || len(part) > 10 {
			return false
		}
	}
	return semver.IsValid("v" + value)
}

// writeExtractedFile writes one entry directly into a random, unpublished
// extraction tree. The outer payload is hash-verified before staging and ZIP
// readers verify each entry's CRC before returning EOF. A partial extraction
// is therefore disposable and setup recovery removes it before any retry.
//
// Do not use the durable write-and-rename path here. The managed runtime has
// thousands of small files; flushing each file and then issuing a
// MOVEFILE_WRITE_THROUGH rename serializes thousands of storage barriers and
// can leave a healthy Windows installer on its Working page for many minutes.
// CREATE_NEW retains the important security property that a concurrently
// planted target is rejected rather than followed or overwritten. On Windows
// the new handle also denies sharing until the entry is complete.
func writeExtractedFile(path string, src io.Reader, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	dst, err := createExclusiveUnpublishedFile(path)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = dst.Close()
		_ = os.Remove(path)
	}
	if err := dst.Chmod(mode.Perm()); err != nil {
		cleanup()
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		cleanup()
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeNewFile(path string, src io.Reader, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	dst, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := dst.Name()
	if err := dst.Chmod(mode.Perm()); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	_, copyErr := io.Copy(dst, src)
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmp)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := renameDurableFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func configurePythonPTH(pythonDir string) error {
	matches, err := filepath.Glob(filepath.Join(pythonDir, "python*._pth"))
	if err != nil {
		return err
	}
	if len(matches) != 1 {
		return fmt.Errorf("expected exactly one Python _pth file, found %d", len(matches))
	}
	name := filepath.Base(strings.TrimSuffix(matches[0], "._pth")) + ".zip"
	body := name + "\r\n.\r\nLib\\site-packages\r\nimport site\r\n"
	return writeFileDurable(matches[0], []byte(body), 0o644)
}

func parseArgs(args []string) (options, error) {
	opts := options{
		Action:       "install",
		InstallScope: "user",
		Connector:    "none",
		Mode:         "observe",
	}
	for _, raw := range args {
		arg := strings.TrimSpace(raw)
		if arg == "" {
			continue
		}
		lower := strings.ToLower(arg)
		switch lower {
		case "/?", "-?", "/help", "--help":
			opts.Action = "help"
		case "/quiet", "-quiet", "--quiet", "/qn":
			opts.Quiet = true
		case "/norestart":
			opts.NoRestart = true
		case "/repair", "-repair", "--repair":
			opts.Action = "repair"
		case "/uninstall", "-uninstall", "--uninstall":
			opts.Action = "uninstall"
		case "/upgrade", "-upgrade", "--upgrade":
			opts.Action = "upgrade"
		default:
			key, value, ok := strings.Cut(arg, "=")
			if !ok {
				return opts, fmt.Errorf("unrecognized setup argument %q", raw)
			}
			key = strings.ToUpper(strings.TrimLeft(strings.TrimSpace(key), "/-"))
			value = strings.Trim(strings.TrimSpace(value), "\"")
			switch key {
			case "INSTALLSCOPE":
				opts.InstallScope = strings.ToLower(value)
			case "CONNECTOR":
				opts.Connector = normalizeConnector(value)
				opts.ConnectorSet = true
			case "MODE":
				opts.Mode = strings.ToLower(value)
				opts.ModeSet = true
			case "STARTGATEWAY":
				parsed, err := parseBooleanProperty(value)
				if err != nil {
					return opts, fmt.Errorf("invalid STARTGATEWAY value: %w", err)
				}
				opts.StartGateway = parsed
				opts.StartGatewaySet = true
			case "DELETEUSERDATA":
				parsed, err := parseBooleanProperty(value)
				if err != nil {
					return opts, fmt.Errorf("invalid DELETEUSERDATA value: %w", err)
				}
				opts.DeleteUserData = parsed
			case "WAITPID":
				parsed, err := strconv.ParseUint(value, 10, 32)
				if err != nil || parsed == 0 {
					return opts, fmt.Errorf("invalid WAITPID %q", value)
				}
				opts.WaitPID = uint32(parsed)
			case "FROMVERSION":
				if !validPayloadVersion(value) {
					return opts, fmt.Errorf("invalid FROMVERSION %q", value)
				}
				opts.FromVersion = value
			default:
				return opts, fmt.Errorf("unrecognized setup property %q", key)
			}
		}
	}
	if opts.InstallScope != "user" {
		return opts, errors.New("only per-user INSTALLSCOPE=user is supported by this installer")
	}
	if opts.Connector != "none" && opts.Connector != "codex" && opts.Connector != "claudecode" {
		return opts, fmt.Errorf("invalid CONNECTOR %q; expected codex, claudecode, or none", opts.Connector)
	}
	if opts.Mode != "observe" && opts.Mode != "action" {
		return opts, fmt.Errorf("invalid MODE %q; expected observe or action", opts.Mode)
	}
	return opts, nil
}

func parseBooleanProperty(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("expected 1/0, true/false, or yes/no, got %q", value)
	}
}

func normalizeConnector(value string) string {
	switch strings.ToLower(strings.ReplaceAll(value, " ", "")) {
	case "", "none", "later", "configurelater":
		return "none"
	case "codex":
		return "codex"
	case "claude", "claudecode", "claude-code":
		return "claudecode"
	default:
		return strings.ToLower(value)
	}
}

func printUsage() {
	fmt.Println("DefenseClawSetup-x64.exe [/quiet] [/norestart] [INSTALLSCOPE=user] [CONNECTOR=codex|claudecode|none] [MODE=observe|action] [STARTGATEWAY=1]")
	fmt.Println("Maintenance: DefenseClawSetup-x64.exe /repair | /upgrade | /uninstall [DELETEUSERDATA=1]")
}

func validateManagedRoot(path string) error {
	full, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(full) == "" || full == filepath.VolumeName(full)+`\` {
		return fmt.Errorf("refusing unsafe install root: %s", path)
	}
	return rejectReparseAncestors(full)
}

func safeJoin(root, rel string) (string, error) {
	if rel == "" || strings.Contains(rel, "\x00") {
		return "", fmt.Errorf("unsafe payload path: %q", rel)
	}

	// ZIP entry names use forward slashes, but untrusted archives can contain
	// backslashes too. Normalize both forms before validating so Windows drive,
	// UNC, rooted, traversal, and alternate-data-stream paths are rejected on
	// every build host rather than only when tests execute on Windows.
	normalized := strings.ReplaceAll(rel, `\`, "/")
	cleanSlash := path.Clean(normalized)
	if path.IsAbs(normalized) || strings.Contains(normalized, ":") ||
		cleanSlash == "." || cleanSlash == ".." || strings.HasPrefix(cleanSlash, "../") {
		return "", fmt.Errorf("payload path escapes destination: %q", rel)
	}
	clean := filepath.FromSlash(cleanSlash)
	full := filepath.Join(root, clean)
	rootFull, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rootFull = strings.TrimRight(rootFull, `\/`)
	if !strings.EqualFold(fullAbs, rootFull) &&
		!strings.HasPrefix(strings.ToLower(fullAbs), strings.ToLower(rootFull)+string(os.PathSeparator)) {
		return "", fmt.Errorf("payload path escapes destination: %q", rel)
	}
	return fullAbs, nil
}

func sanitizePythonEnv(input []string) []string {
	output := make([]string, 0, len(input))
	for _, entry := range input {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "PYTHONHOME", "PYTHONPATH":
			continue
		default:
			output = append(output, entry)
		}
	}
	return output
}

func managedChildEnv(dataRoot string) []string {
	env := sanitizePythonEnv(os.Environ())
	filtered := make([]string, 0, len(env)+3)
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if ok {
			switch strings.ToUpper(name) {
			case "DEFENSECLAW_HOME", "PYTHONIOENCODING", "PYTHONUTF8":
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	return append(
		filtered,
		"DEFENSECLAW_HOME="+dataRoot,
		"PYTHONUTF8=1",
		"PYTHONIOENCODING=utf-8",
	)
}

func copyFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return writeNewFile(target, in, 0o755)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileDurable(path, data, 0o644)
}

func writeFileDurable(path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode.Perm()); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := rejectReparseExisting(path); err != nil {
			return err
		}
		return replaceDurableFile(temporaryPath, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return renameDurableFile(temporaryPath, path)
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing content")
		}
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func removeAllSafe(path, allowedRoot string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("refusing empty remove path")
	}
	full, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(allowedRoot)
	if err != nil {
		return err
	}
	root = strings.TrimRight(root, `\/`)
	if !strings.EqualFold(full, root) && !strings.HasPrefix(strings.ToLower(full), strings.ToLower(root)+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to remove path outside managed root: %s", path)
	}
	if err := rejectReparseAncestors(full); err != nil {
		return err
	}
	return os.RemoveAll(full)
}

func isSharingViolation(err error) bool {
	for err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return errno == 32 || errno == 33
		}
		err = errors.Unwrap(err)
	}
	return false
}

func renameInstallTree(source, destination string) error {
	return renameInstallTreeWith(source, destination, renameDurableFile, time.Sleep)
}

func renameInstallTreeWith(source, destination string, rename func(string, string) error, sleep func(time.Duration)) error {
	var err error
	for attempt := 0; attempt < installTreeRenameMaxAttempts; attempt++ {
		err = rename(source, destination)
		if err == nil {
			return nil
		}
		if !isTransientInstallTreeRenameError(err) || attempt+1 == installTreeRenameMaxAttempts {
			return err
		}
		sleep(installTreeRenameRetryDelay)
	}
	return err
}

func isTransientInstallTreeRenameError(err error) bool {
	return errors.Is(err, syscall.Errno(5)) ||
		errors.Is(err, syscall.Errno(32)) ||
		errors.Is(err, syscall.Errno(33))
}
