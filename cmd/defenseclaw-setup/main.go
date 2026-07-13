// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
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
)

//go:embed payload/*
var embeddedPayload embed.FS

const (
	productName                  = "DefenseClaw"
	setupArtifactName            = "DefenseClawSetup-x64.exe"
	defaultPublisher             = "Cisco Systems, Inc."
	userExitCode                 = 1602
	installTreeRenameMaxAttempts = 40
	installTreeRenameRetryDelay  = 100 * time.Millisecond
	restartRequiredCode          = 3010
	maxZipFiles                  = 100000
	maxZipExpandedBytes          = int64(2 << 30)
)

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
	UpgradeManifest    string            `json:"upgrade_manifest"`
	SitePackages       string            `json:"site_packages"`
	Launcher           string            `json:"launcher"`
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
	Connector              string            `json:"connector"`
	Mode                   string            `json:"mode"`
	UnsignedLocalArtifact  bool              `json:"unsigned_local_artifact"`
	ReleaseSigningRequired bool              `json:"release_signing_required"`
	Toolchain              map[string]string `json:"toolchain"`
	InstalledAtUTC         string            `json:"installed_at_utc"`
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
	if opts.Action == "help" {
		printUsage()
		return
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
		if code != 0 {
			os.Exit(code)
		}
		os.Exit(1)
	}
	os.Exit(code)
}

func run(opts options) (int, error) {
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
	if err := waitForProcessExit(opts.WaitPID, 2*time.Minute); err != nil {
		return restartRequiredCode, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return 1, err
	}
	if err := validateManagedRoot(filepath.Dir(maintenancePath)); err != nil {
		return 1, err
	}
	oldState, err := loadExistingInstallState(installRoot)
	if err != nil {
		return 1, err
	}
	hadInstall := pathExists(installRoot)
	if hadInstall && oldState == nil {
		return 1, fmt.Errorf("refusing to replace an existing directory without valid DefenseClaw installer state: %s", installRoot)
	}
	if oldState != nil {
		if !opts.ConnectorSet && validConnector(oldState.Connector) {
			opts.Connector = oldState.Connector
		}
		if !opts.ModeSet && validMode(oldState.Mode) {
			opts.Mode = oldState.Mode
		}
		if opts.Action == "upgrade" && opts.FromVersion == "" {
			opts.FromVersion = oldState.Version
		}
	}
	// Every install/repair/upgrade refreshes the selected connector. Existing
	// data is not evidence that hooks are configured: it also covers legacy
	// installs and data-preserving uninstalls.
	configureConnector := opts.Connector != "none"
	upgradeFrom := opts.FromVersion
	pathEntryOwned := oldState != nil && oldState.PathEntryOwned
	pathSeparatorReused := oldState != nil && oldState.PathSeparatorReused

	staging := installRoot + ".staging." + strconv.Itoa(os.Getpid())
	backup := installRoot + ".backup." + strconv.Itoa(os.Getpid())
	_ = removeAllSafe(staging, filepath.Dir(installRoot))
	_ = removeAllSafe(backup, filepath.Dir(installRoot))

	payload, err := loadPayload(filepath.Dir(installRoot))
	if err != nil {
		return 1, err
	}
	defer func() {
		_ = removeAllSafe(payload.TempRoot, filepath.Dir(installRoot))
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

	if err := stageInstallTree(payload, staging, installRoot, dataRoot, maintenancePath, pathEntryOwned, pathSeparatorReused, opts); err != nil {
		return 1, err
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	restartOld, err := stopOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		_ = removeAllSafe(staging, filepath.Dir(installRoot))
		return 1, err
	}
	if hadInstall {
		if err := ensureTreeReplaceable(installRoot); err != nil {
			_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
			_ = removeAllSafe(staging, filepath.Dir(installRoot))
			return restartRequiredCode, fmt.Errorf("installed files are in use; close running DefenseClaw terminals and retry: %w", err)
		}
	}

	published := false
	pathAdded := false
	pathAddedReusedSeparator := false
	registrationChanged := false
	maintenance := maintenancePublication{}
	startedNew := serviceState{}
	autoStartSnapshot := gatewayAutoStartSnapshot{}
	autoStartChanged := false
	previousConnectors := connectorsForNativeUninstall(oldState, dataRoot)
	connectorConfigurationAttempted := false
	tryRestore := func(cause error) (int, error) {
		if startedNew.any() {
			_, _ = stopOwnedServices(gatewayPath, dataRoot)
		}
		if autoStartChanged {
			_ = restoreGatewayAutoStart(autoStartSnapshot)
		}
		if connectorConfigurationAttempted {
			_ = runConnectorLifecycle(gatewayPath, dataRoot, opts.Connector, "teardown")
		}
		if registrationChanged {
			if oldState != nil {
				oldMaintenance := oldState.MaintenancePath
				if oldMaintenance == "" {
					oldMaintenance = maintenancePath
				}
				_ = registerInstalledApp(oldMaintenance, installRoot, oldState.Version, oldState.UnsignedLocalArtifact)
			} else {
				_ = unregisterInstalledApp()
			}
		}
		if pathAdded {
			_ = removeUserPath(filepath.Join(installRoot, "bin"), pathAddedReusedSeparator)
		}
		_ = maintenance.rollback()
		if published {
			_ = removeAllSafe(installRoot, filepath.Dir(installRoot))
		}
		if _, err := os.Stat(backup); err == nil {
			_ = renameInstallTree(backup, installRoot)
		}
		for _, connectorName := range previousConnectors {
			_ = runConnectorLifecycle(gatewayPath, dataRoot, connectorName, "reconcile")
		}
		_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
		if isSharingViolation(cause) {
			return restartRequiredCode, fmt.Errorf("%w; close running DefenseClaw terminals and retry", cause)
		}
		return 1, cause
	}

	if _, err := os.Stat(installRoot); err == nil {
		if err := renameInstallTree(installRoot, backup); err != nil {
			_ = removeAllSafe(staging, filepath.Dir(installRoot))
			if isTransientInstallTreeRenameError(err) {
				return restartRequiredCode, fmt.Errorf("existing install files are locked; close running DefenseClaw terminals and retry")
			}
			return 1, fmt.Errorf("move existing install aside: %w", err)
		}
	}
	if err := renameInstallTree(staging, installRoot); err != nil {
		return tryRestore(fmt.Errorf("publish staged install: %w", err))
	}
	published = true

	if err := validateInstall(installRoot, payload.Manifest.Version); err != nil {
		return tryRestore(err)
	}
	if upgradeFrom != "" && compareVersions(upgradeFrom, payload.Manifest.Version) < 0 {
		if err := runPackagedMigrations(installRoot, dataRoot, upgradeFrom, payload.Manifest.Version); err != nil {
			return tryRestore(err)
		}
	}
	if configureConnector {
		connectorConfigurationAttempted = true
		if err := runInitialConfiguration(installRoot, dataRoot, opts); err != nil {
			return tryRestore(err)
		}
	}
	maintenance, err = publishMaintenanceCopy(maintenancePath)
	if err != nil {
		return tryRestore(err)
	}
	pathAdded, pathAddedReusedSeparator, err = addUserPath(filepath.Join(installRoot, "bin"))
	if err != nil {
		return tryRestore(err)
	}
	if pathAdded {
		pathSeparatorReused = pathAddedReusedSeparator
	}
	if err := updateInstalledPathOwnership(installRoot, pathEntryOwned || pathAdded, pathSeparatorReused); err != nil {
		return tryRestore(err)
	}
	registrationChanged = true
	if err := registerInstalledApp(maintenancePath, installRoot, payload.Manifest.Version, payload.Manifest.Unsigned); err != nil {
		return tryRestore(err)
	}
	wanted := requestedServices(opts, restartOld)
	autoStartSnapshot, autoStartChanged, err = configureGatewayAutoStart(gatewayPath, wanted.Gateway)
	if err != nil {
		return tryRestore(err)
	}
	startedNew, err = startSelectedServices(gatewayPath, dataRoot, wanted)
	if err != nil {
		return tryRestore(err)
	}
	if err := verifySelectedServices(gatewayPath, dataRoot, wanted); err != nil {
		return tryRestore(err)
	}
	if err := removeAllSafe(backup, filepath.Dir(installRoot)); err != nil && !errors.Is(err, os.ErrNotExist) && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "DefenseClaw setup warning: old-version cleanup is pending: %v\n", err)
	}
	if err := maintenance.commit(); err != nil && !opts.Quiet {
		fmt.Fprintf(os.Stderr, "DefenseClaw setup warning: installer-cache cleanup is pending: %v\n", err)
	}
	if !opts.Quiet {
		fmt.Println("DefenseClaw installed successfully.")
		fmt.Println("Open a new terminal and run: defenseclaw")
	}
	return 0, nil
}

func runUninstall(opts options, installRoot, dataRoot string) (int, error) {
	if err := waitForProcessExit(opts.WaitPID, 2*time.Minute); err != nil {
		return restartRequiredCode, err
	}
	if !opts.Quiet {
		fmt.Printf("Uninstalling DefenseClaw from %s\n", installRoot)
	}
	oldState, err := loadExistingInstallState(installRoot)
	if err != nil {
		return 1, err
	}
	if pathExists(installRoot) && oldState == nil {
		return 1, fmt.Errorf("refusing to remove an existing directory without valid DefenseClaw installer state: %s", installRoot)
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	restartOld, err := stopOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return 1, err
	}
	connectors := connectorsForNativeUninstall(oldState, dataRoot)
	tornDown := make([]string, 0, len(connectors))
	reconcileTornDown := func() {
		for _, connectorName := range tornDown {
			_ = runConnectorLifecycle(gatewayPath, dataRoot, connectorName, "reconcile")
		}
	}
	for _, connectorName := range connectors {
		if err := runConnectorLifecycle(gatewayPath, dataRoot, connectorName, "teardown"); err != nil {
			reconcileTornDown()
			_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
			return 1, err
		}
		tornDown = append(tornDown, connectorName)
		if err := runConnectorLifecycle(gatewayPath, dataRoot, connectorName, "verify"); err != nil {
			reconcileTornDown()
			_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
			return 1, err
		}
	}
	autoStartSnapshot, autoStartChanged, err := configureGatewayAutoStart(gatewayPath, false)
	if err != nil {
		reconcileTornDown()
		_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
		return 1, err
	}
	rollbackUninstall := func() {
		if autoStartChanged {
			_ = restoreGatewayAutoStart(autoStartSnapshot)
		}
		reconcileTornDown()
		_, _ = startSelectedServices(gatewayPath, dataRoot, restartOld)
	}
	if pathExists(installRoot) {
		if err := ensureTreeReplaceable(installRoot); err != nil {
			rollbackUninstall()
			return restartRequiredCode, fmt.Errorf("product files are locked; close running DefenseClaw terminals and retry: %w", err)
		}
		trash := installRoot + ".uninstall." + strconv.Itoa(os.Getpid())
		_ = removeAllSafe(trash, filepath.Dir(installRoot))
		if err := renameInstallTree(installRoot, trash); err != nil {
			rollbackUninstall()
			if isTransientInstallTreeRenameError(err) {
				return restartRequiredCode, fmt.Errorf("product files are locked; close running DefenseClaw terminals and retry")
			}
			return 1, err
		}
		if err := removeAllSafe(trash, filepath.Dir(installRoot)); err != nil {
			_ = renameInstallTree(trash, installRoot)
			rollbackUninstall()
			if isSharingViolation(err) {
				return restartRequiredCode, fmt.Errorf("product files are locked; close running DefenseClaw terminals and retry")
			}
			return 1, err
		}
	}
	if oldState == nil || oldState.PathEntryOwned {
		reusedSeparator := oldState != nil && oldState.PathSeparatorReused
		if err := removeUserPath(filepath.Join(installRoot, "bin"), reusedSeparator); err != nil {
			return 1, err
		}
	}
	if err := unregisterInstalledApp(); err != nil {
		return 1, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return 1, err
	}
	maintenanceRoot := filepath.Dir(maintenancePath)
	self, selfErr := os.Executable()
	if selfErr != nil {
		return 1, selfErr
	}
	if samePath(self, maintenancePath) {
		if err := removeDirectoryAfterExit(maintenanceRoot, os.Getpid()); err != nil {
			return 1, fmt.Errorf("schedule installer-cache cleanup: %w", err)
		}
	} else if err := removeAllSafe(maintenanceRoot, filepath.Dir(maintenanceRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 1, err
	}
	if opts.DeleteUserData {
		if err := removeAllSafe(dataRoot, filepath.Dir(dataRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 1, err
		}
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
	Gateway  bool
	Watchdog bool
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
	if !pathExists(gatewayPath) {
		return fmt.Errorf("connector %s %s requires the installed gateway binary", connectorName, action)
	}
	args := []string{
		"connector", action,
		"--connector", connectorName,
		"--data-dir", dataRoot,
		"--json",
	}
	cmd := exec.Command(gatewayPath, args...)
	cmd.Env = managedChildEnv(dataRoot)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("connector %s %s failed: %w: %s", connectorName, action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

type gatewayAutoStartSnapshot struct {
	Existed bool
	Value   string
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func samePath(a, b string) bool {
	aFull, aErr := filepath.Abs(a)
	bFull, bErr := filepath.Abs(b)
	return aErr == nil && bErr == nil && strings.EqualFold(aFull, bFull)
}

func validConnector(value string) bool {
	return value == "none" || value == "codex" || value == "claudecode"
}

func validMode(value string) bool {
	return value == "observe" || value == "action"
}

func compareVersions(a, b string) int {
	parse := func(value string) [3]int {
		var result [3]int
		core := strings.SplitN(value, "-", 2)[0]
		for index, part := range strings.Split(core, ".") {
			if index >= len(result) {
				break
			}
			result[index], _ = strconv.Atoi(part)
		}
		return result
	}
	aVersion := parse(a)
	bVersion := parse(b)
	for index := range aVersion {
		if aVersion[index] < bVersion[index] {
			return -1
		}
		if aVersion[index] > bVersion[index] {
			return 1
		}
	}
	return 0
}

func migrationSource(state *installState, packagedVersion, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if state != nil && compareVersions(state.Version, packagedVersion) < 0 {
		return state.Version
	}
	return ""
}

func loadExistingInstallState(installRoot string) (*installState, error) {
	path := filepath.Join(installRoot, "installer", "install-state.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var state installState
	if err := readJSON(path, &state); err != nil {
		return nil, fmt.Errorf("read existing installer state: %w", err)
	}
	if state.SchemaVersion != 1 || state.InstallKind != "native-windows-exe" ||
		state.InstallScope != "user" || !validPayloadVersion(state.Version) ||
		!validConnector(state.Connector) || !validMode(state.Mode) {
		return nil, errors.New("existing installer state is not a supported native Windows install")
	}
	dataRoot, err := defaultDataRoot()
	if err != nil {
		return nil, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return nil, err
	}
	expected := map[string][2]string{
		"install root":      {state.InstallRoot, installRoot},
		"command directory": {state.CommandDir, filepath.Join(installRoot, "bin")},
		"data root":         {state.DataRoot, dataRoot},
		"runtime":           {state.Runtime, filepath.Join(installRoot, "runtime", "python")},
		"maintenance path":  {state.MaintenancePath, maintenancePath},
	}
	for label, paths := range expected {
		if !samePath(paths[0], paths[1]) {
			return nil, fmt.Errorf("existing installer state has an unexpected %s", label)
		}
	}
	return &state, nil
}

func updateInstalledPathOwnership(installRoot string, owned, reusedSeparator bool) error {
	path := filepath.Join(installRoot, "installer", "install-state.json")
	var state installState
	if err := readJSON(path, &state); err != nil {
		return err
	}
	state.PathEntryOwned = owned
	state.PathSeparatorReused = reusedSeparator
	return writeJSON(path, state)
}

type maintenancePublication struct {
	path    string
	backup  string
	changed bool
	hadOld  bool
}

func publishMaintenanceCopy(target string) (maintenancePublication, error) {
	self, err := os.Executable()
	if err != nil {
		return maintenancePublication{}, err
	}
	if samePath(self, target) {
		return maintenancePublication{path: target}, nil
	}
	root := filepath.Dir(target)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return maintenancePublication{}, err
	}
	if err := rejectReparseAncestors(root); err != nil {
		return maintenancePublication{}, err
	}
	publication := maintenancePublication{
		path:    target,
		backup:  target + ".backup." + strconv.Itoa(os.Getpid()),
		changed: true,
		hadOld:  pathExists(target),
	}
	staged := target + ".new." + strconv.Itoa(os.Getpid())
	_ = removeAllSafe(staged, root)
	_ = removeAllSafe(publication.backup, root)
	if err := copyFile(self, staged); err != nil {
		return maintenancePublication{}, err
	}
	if publication.hadOld {
		if err := os.Rename(target, publication.backup); err != nil {
			_ = removeAllSafe(staged, root)
			return maintenancePublication{}, err
		}
	}
	if err := os.Rename(staged, target); err != nil {
		if publication.hadOld {
			_ = os.Rename(publication.backup, target)
		}
		return maintenancePublication{}, err
	}
	return publication, nil
}

func (publication maintenancePublication) rollback() error {
	if !publication.changed {
		return nil
	}
	root := filepath.Dir(publication.path)
	_ = removeAllSafe(publication.path, root)
	if publication.hadOld && pathExists(publication.backup) {
		return os.Rename(publication.backup, publication.path)
	}
	return nil
}

func (publication maintenancePublication) commit() error {
	if !publication.changed || !publication.hadOld {
		return nil
	}
	return removeAllSafe(publication.backup, filepath.Dir(publication.path))
}

func ensureTreeReplaceable(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if reparse, err := isReparsePoint(path); err != nil {
			return err
		} else if reparse {
			return fmt.Errorf("installed tree contains a reparse point: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".exe", ".dll", ".pyd":
			return renameProbe(path)
		default:
			return nil
		}
	})
}

func stageInstallTree(payload loadedPayload, staging, installRoot, dataRoot, maintenancePath string, pathEntryOwned, pathSeparatorReused bool, opts options) error {
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
		Connector:              opts.Connector,
		Mode:                   opts.Mode,
		UnsignedLocalArtifact:  payload.Manifest.Unsigned,
		ReleaseSigningRequired: true,
		Toolchain:              payload.Manifest.Toolchain,
		InstalledAtUTC:         time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSON(filepath.Join(staging, "installer", "install-state.json"), state); err != nil {
		return err
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
	cmd := exec.Command(launcher, "--version")
	cmd.Env = sanitizePythonEnv(os.Environ())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("managed CLI version check failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), version) {
		return fmt.Errorf("managed CLI version %q does not report packaged version %s", strings.TrimSpace(string(output)), version)
	}
	gateway := filepath.Join(root, "bin", "defenseclaw-gateway.exe")
	cmd = exec.Command(gateway, "--version")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gateway version check failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), version) {
		return fmt.Errorf("gateway version %q does not report packaged version %s", strings.TrimSpace(string(output)), version)
	}
	return nil
}

func runInitialConfiguration(root, dataRoot string, opts options) error {
	if opts.Connector == "none" {
		return nil
	}
	args := []string{
		"init", "--skip-install", "--non-interactive", "--yes",
		"--connector", opts.Connector,
		"--profile", opts.Mode,
		"--no-start-gateway", "--no-verify",
	}
	cmd := exec.Command(filepath.Join(root, "bin", "defenseclaw.exe"), args...)
	cmd.Env = managedChildEnv(dataRoot)
	output, err := cmd.CombinedOutput()
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
	openClawRoot, err := defaultOpenClawRoot()
	if err != nil {
		return err
	}
	cmd := newPackagedMigrationCommand(root, dataRoot, openClawRoot, fromVersion, toVersion)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run packaged migrations: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func newPackagedMigrationCommand(root, dataRoot, openClawRoot, fromVersion, toVersion string) *exec.Cmd {
	python := filepath.Join(root, "runtime", "python", "python.exe")
	manifest := filepath.Join(root, "installer", "upgrade-manifest.json")
	cmd := exec.Command(
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
	cmd := exec.Command(gatewayPath, "start")
	cmd.Env = managedChildEnv(dataRoot)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start gateway: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func startWatchdog(gatewayPath, dataRoot string) error {
	cmd := exec.Command(gatewayPath, "watchdog", "start")
	cmd.Env = managedChildEnv(dataRoot)
	output, err := cmd.CombinedOutput()
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
		cmd := exec.Command(gatewayPath, "watchdog", "stop")
		cmd.Env = managedChildEnv(dataRoot)
		output, stopErr := cmd.CombinedOutput()
		if stopErr != nil {
			return serviceState{}, fmt.Errorf("stop managed watchdog: %w: %s", stopErr, strings.TrimSpace(string(output)))
		}
		stopped.Watchdog = true
	}
	if gatewayOwned {
		cmd := exec.Command(gatewayPath, "stop")
		cmd.Env = managedChildEnv(dataRoot)
		output, stopErr := cmd.CombinedOutput()
		if stopErr != nil {
			if stopped.Watchdog {
				_ = startWatchdog(gatewayPath, dataRoot)
			}
			return serviceState{}, fmt.Errorf("stop managed gateway: %w: %s", stopErr, strings.TrimSpace(string(output)))
		}
		stopped.Gateway = true
	}
	if stopped.any() {
		if err := waitFileReplaceable(gatewayPath, 40, 250*time.Millisecond); err != nil {
			_, _ = startSelectedServices(gatewayPath, dataRoot, stopped)
			return serviceState{}, err
		}
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
		cmd := exec.Command(gatewayPath, args...)
		cmd.Env = managedChildEnv(dataRoot)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("verify %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func waitFileReplaceable(path string, attempts int, delay time.Duration) error {
	for i := 0; i < attempts; i++ {
		if err := renameProbe(path); err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return fmt.Errorf("managed gateway did not release %s", path)
}

func renameProbe(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	probe := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+strconv.Itoa(os.Getpid())+".probe")
	if err := os.Rename(path, probe); err != nil {
		return err
	}
	return os.Rename(probe, path)
}

type loadedPayload struct {
	Root     string
	TempRoot string
	Manifest payloadManifest
}

func loadPayload(tempParent string) (loadedPayload, error) {
	data, err := embeddedPayload.ReadFile("payload/installer-payload.zip")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return loadedPayload{}, errors.New("installer payload missing; build with scripts/build-windows-installer.ps1")
		}
		return loadedPayload{}, err
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
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		_ = os.RemoveAll(tempRoot)
		return loadedPayload{}, fmt.Errorf("open embedded payload: %w", err)
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
		manifest.SitePackages,
		manifest.Launcher,
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
		err = writeNewFile(target, src, file.Mode())
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
	parts := strings.SplitN(value, "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) != 3 {
		return false
	}
	for _, part := range core {
		if part == "" || len(part) > 10 {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 31); err != nil {
			return false
		}
	}
	if len(parts) == 1 {
		return true
	}
	if parts[1] == "" || len(parts[1]) > 128 {
		return false
	}
	for _, char := range parts[1] {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func writeNewFile(path string, src io.Reader, mode fs.FileMode) error {
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
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
	return os.WriteFile(matches[0], []byte(body), 0o644)
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
	return os.WriteFile(path, data, 0o644)
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
	return renameInstallTreeWith(source, destination, os.Rename, time.Sleep)
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
