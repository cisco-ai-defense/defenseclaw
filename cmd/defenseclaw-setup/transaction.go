// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const setupTransactionSchemaVersion = 1

const (
	setupJournalSchemaVersion = 1
	setupPhaseIntent          = "intent"
	setupPhasePublished       = "published"
	setupPhaseCommitted       = "committed"
	setupPhaseConverged       = "converged"
	setupPhaseComplete        = "complete"
)

var (
	errTransactionCleanupDeferred      = errors.New("transaction cleanup is deferred until the setup process exits")
	errSetupJournalDurabilityAmbiguous = errors.New("setup transaction journal durability is ambiguous")
)

type durableValueWriter func(string, any, bool) error
type durableRenameFunc func(string, string) error
type connectorLifecycleRunner func(string, string, string, string, []string) error

type userPathSnapshot struct {
	Existed   bool   `json:"existed"`
	Value     string `json:"value,omitempty"`
	ValueType uint32 `json:"value_type,omitempty"`
}

type setupTransaction struct {
	SchemaVersion                  int                      `json:"schema_version"`
	ID                             string                   `json:"id"`
	Action                         string                   `json:"action"`
	InstallRoot                    string                   `json:"install_root"`
	DataRoot                       string                   `json:"data_root"`
	MaintenancePath                string                   `json:"maintenance_path"`
	StagingPath                    string                   `json:"staging_path"`
	BackupPath                     string                   `json:"backup_path"`
	TrashPath                      string                   `json:"trash_path"`
	MaintenanceNew                 string                   `json:"maintenance_new"`
	MaintenanceBackup              string                   `json:"maintenance_backup"`
	HadInstall                     bool                     `json:"had_install"`
	MaintenanceExisted             bool                     `json:"maintenance_existed"`
	PreviousMaintenanceSHA256      string                   `json:"previous_maintenance_sha256,omitempty"`
	PreviousState                  *installState            `json:"previous_state,omitempty"`
	PreviousPath                   userPathSnapshot         `json:"previous_path"`
	PreviousAutoStart              gatewayAutoStartSnapshot `json:"previous_auto_start"`
	PreviousServices               serviceState             `json:"previous_services"`
	PreviousConnectors             []string                 `json:"previous_connectors,omitempty"`
	PreserveConnectorConfiguration bool                     `json:"preserve_connector_configuration,omitempty"`
	TargetConnector                string                   `json:"target_connector"`
	TargetMode                     string                   `json:"target_mode"`
	TargetServices                 serviceState             `json:"target_services"`
	FromVersion                    string                   `json:"from_version,omitempty"`
	TargetVersion                  string                   `json:"target_version,omitempty"`
	PreviousCodexHome              string                   `json:"previous_codex_home,omitempty"`
	PreviousClaudeConfigDir        string                   `json:"previous_claude_config_dir,omitempty"`
	CodexHome                      string                   `json:"codex_home,omitempty"`
	ClaudeConfigDir                string                   `json:"claude_config_dir,omitempty"`
	MaintenanceSHA256              string                   `json:"maintenance_sha256,omitempty"`
	DeleteUserData                 bool                     `json:"delete_user_data,omitempty"`
	UninstallPathEntryOwned        bool                     `json:"uninstall_path_entry_owned,omitempty"`
	UninstallPathSeparatorReused   bool                     `json:"uninstall_path_separator_reused,omitempty"`
	UninstallPathValueCreated      bool                     `json:"uninstall_path_value_created,omitempty"`
	HandoffFromInstall             string                   `json:"handoff_from_install,omitempty"`
	HandoffPreviousState           *installState            `json:"handoff_previous_state,omitempty"`
}

type setupTransactionPaths struct {
	Root    string
	Journal string
}

type setupJournal struct {
	SchemaVersion int              `json:"schema_version"`
	Phase         string           `json:"phase"`
	Transaction   setupTransaction `json:"transaction"`
}

type setupRecoveryOps struct {
	Rollback   func(setupTransaction) error
	Activate   func(setupTransaction) error
	Converge   func(setupTransaction) error
	Cleanup    func(setupTransaction) error
	Transition func(setupTransaction, string, string) error
}

var errPublishedActivationStateChanged = errors.New("published migration state changed")

type migrationFileSnapshot struct {
	Exists bool
	SHA256 string
}

type publishedMigrationSnapshot struct {
	Config migrationFileSnapshot
	Env    migrationFileSnapshot
	Cursor migrationFileSnapshot
}

type installRuntimeConvergenceOps struct {
	disableStableHook  func(string) error
	configureAutoStart func(string, bool) (gatewayAutoStartSnapshot, bool, error)
	startServices      func(string, string, serviceState) (serviceState, error)
	verifyServices     func(string, string, serviceState) error
	stopServices       func(string, string) (serviceState, error)
	verifyStopped      func(string, string) error
}

type uninstallRecoveryOps struct {
	rollbackInstall         func(setupTransaction) error
	prepareCommittedInstall func(setupTransaction) error
	buildHandoff            func(setupTransaction) (setupTransaction, error)
	resumeUninstall         func(setupTransaction) error
	recoverUninstall        func(setupJournal) error
	replaceWithHandoff      func(setupJournal, setupTransaction) error
	afterHandoff            func() error
}

type setupTransactionExpectations struct {
	InstallRoot     string
	DataRoot        string
	MaintenancePath string
}

func newSetupTransactionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate setup transaction identity: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func validSetupTransactionID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func transactionArtifactPaths(installRoot, maintenancePath, id string) (staging, backup, trash, maintenanceNew, maintenanceBackup string) {
	return installRoot + ".staging." + id,
		installRoot + ".backup." + id,
		installRoot + ".uninstall." + id,
		maintenancePath + ".new." + id,
		maintenancePath + ".backup." + id
}

func journalPaths(root string) setupTransactionPaths {
	return setupTransactionPaths{
		Root:    root,
		Journal: filepath.Join(root, "setup-transaction.json"),
	}
}

func newSetupTransaction(action, installRoot, dataRoot, maintenancePath, fromVersion, targetVersion string, oldState *installState, opts options) (setupTransaction, error) {
	id, err := newSetupTransactionID()
	if err != nil {
		return setupTransaction{}, err
	}
	pathSnapshot, err := captureUserPath()
	if err != nil {
		return setupTransaction{}, fmt.Errorf("snapshot user PATH: %w", err)
	}
	gatewayPath := filepath.Join(installRoot, "bin", "defenseclaw-gateway.exe")
	autoStartSnapshot, err := captureGatewayAutoStart()
	if err != nil {
		return setupTransaction{}, fmt.Errorf("snapshot gateway auto-start: %w", err)
	}
	previousServices, err := inspectOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return setupTransaction{}, fmt.Errorf("snapshot managed services: %w", err)
	}
	staging, backup, trash, maintenanceNew, maintenanceBackup := transactionArtifactPaths(installRoot, maintenancePath, id)
	var previousState *installState
	if oldState != nil {
		copyState := *oldState
		previousState = &copyState
	}
	previousConnectors := normalizeStringSlice(connectorsForNativeUninstall(oldState, dataRoot))
	preserveConnectorConfiguration := action == "install" && opts.PreserveConnectorConfiguration
	targetConnector := opts.Connector
	targetServices := requestedServices(opts, previousServices)
	if preserveConnectorConfiguration && len(previousConnectors) != 0 {
		// CLI configuration can add connectors after an installer-first "none"
		// choice. Once registrations exist, servicing must restore the gateway
		// even when it was stopped before repair.
		targetServices.Gateway = true
	}
	if action == "uninstall" {
		targetConnector = "none"
		targetServices = serviceState{}
	}
	if action == "install" && targetServices.Gateway && autoStartSnapshot.Existed {
		owned, ownedErr := gatewayAutoStartValueOwned(gatewayPath, autoStartSnapshot.Value)
		if ownedErr != nil {
			return setupTransaction{}, ownedErr
		}
		if !owned {
			return setupTransaction{}, errors.New("refusing an unrelated DefenseClawGateway startup registration")
		}
	}
	defaultCodexHome, err := defaultConnectorConfigHome(".codex")
	if err != nil {
		return setupTransaction{}, err
	}
	defaultClaudeConfigDir, err := defaultConnectorConfigHome(".claude")
	if err != nil {
		return setupTransaction{}, err
	}
	codexHome, err := transactionConfigHome("CODEX_HOME", defaultCodexHome)
	if err != nil {
		return setupTransaction{}, err
	}
	claudeConfigDir, err := transactionConfigHome("CLAUDE_CONFIG_DIR", defaultClaudeConfigDir)
	if err != nil {
		return setupTransaction{}, err
	}
	previousCodexState, previousClaudeState := "", ""
	if oldState != nil {
		previousCodexState = oldState.CodexHome
		previousClaudeState = oldState.ClaudeConfigDir
	}
	previousCodexHome, err := resolvePreviousConnectorHome(
		previousCodexState, previousConnectors, dataRoot, "codex", "config.toml", defaultCodexHome,
	)
	if err != nil {
		return setupTransaction{}, err
	}
	previousClaudeConfigDir, err := resolvePreviousConnectorHome(
		previousClaudeState, previousConnectors, dataRoot, "claudecode", "settings.json", defaultClaudeConfigDir,
	)
	if err != nil {
		return setupTransaction{}, err
	}
	if preserveConnectorConfiguration {
		// A quiet repair/upgrade without a connector choice services the exact
		// homes already owned by the installation. Environment drift must not
		// silently move or collapse connector configuration.
		codexHome = previousCodexHome
		claudeConfigDir = previousClaudeConfigDir
	}
	maintenanceSHA256 := ""
	maintenanceExisted, previousMaintenanceSHA256, err := snapshotMaintenanceFile(maintenancePath)
	if err != nil {
		return setupTransaction{}, fmt.Errorf("snapshot maintenance executable: %w", err)
	}
	if action == "install" {
		self, executableErr := os.Executable()
		if executableErr != nil {
			return setupTransaction{}, executableErr
		}
		maintenanceSHA256, err = fileSHA256(self)
		if err != nil {
			return setupTransaction{}, fmt.Errorf("hash setup executable: %w", err)
		}
	}
	uninstallPathOwned := action == "uninstall" && previousState != nil && previousState.PathEntryOwned
	uninstallPathSeparatorReused := uninstallPathOwned && previousState.PathSeparatorReused
	uninstallPathValueCreated := uninstallPathOwned && previousState.PathValueCreated
	return setupTransaction{
		SchemaVersion:                  setupTransactionSchemaVersion,
		ID:                             id,
		Action:                         action,
		InstallRoot:                    installRoot,
		DataRoot:                       dataRoot,
		MaintenancePath:                maintenancePath,
		StagingPath:                    staging,
		BackupPath:                     backup,
		TrashPath:                      trash,
		MaintenanceNew:                 maintenanceNew,
		MaintenanceBackup:              maintenanceBackup,
		HadInstall:                     oldState != nil,
		MaintenanceExisted:             maintenanceExisted,
		PreviousMaintenanceSHA256:      previousMaintenanceSHA256,
		PreviousState:                  previousState,
		PreviousPath:                   pathSnapshot,
		PreviousAutoStart:              autoStartSnapshot,
		PreviousServices:               previousServices,
		PreviousConnectors:             previousConnectors,
		PreserveConnectorConfiguration: preserveConnectorConfiguration,
		TargetConnector:                targetConnector,
		TargetMode:                     opts.Mode,
		TargetServices:                 targetServices,
		FromVersion:                    fromVersion,
		TargetVersion:                  targetVersion,
		PreviousCodexHome:              previousCodexHome,
		PreviousClaudeConfigDir:        previousClaudeConfigDir,
		CodexHome:                      codexHome,
		ClaudeConfigDir:                claudeConfigDir,
		MaintenanceSHA256:              maintenanceSHA256,
		DeleteUserData:                 opts.DeleteUserData,
		UninstallPathEntryOwned:        uninstallPathOwned,
		UninstallPathSeparatorReused:   uninstallPathSeparatorReused,
		UninstallPathValueCreated:      uninstallPathValueCreated,
	}, nil
}

func newUninstallHandoffTransaction(source setupTransaction, oldState *installState, opts options) (setupTransaction, error) {
	if source.Action != "install" {
		return setupTransaction{}, errors.New("uninstall handoff source is not an install transaction")
	}
	id, err := newSetupTransactionID()
	if err != nil {
		return setupTransaction{}, err
	}
	staging, backup, trash, maintenanceNew, maintenanceBackup := transactionArtifactPaths(
		source.InstallRoot,
		source.MaintenancePath,
		id,
	)
	maintenanceExisted, previousMaintenanceSHA256, err := snapshotMaintenanceFile(source.MaintenancePath)
	if err != nil {
		return setupTransaction{}, fmt.Errorf("snapshot maintenance executable for uninstall handoff: %w", err)
	}
	previousConnectors := normalizeStringSlice(connectorsForNativeUninstall(oldState, source.DataRoot))
	defaultCodexHome, err := defaultConnectorConfigHome(".codex")
	if err != nil {
		return setupTransaction{}, err
	}
	defaultClaudeConfigDir, err := defaultConnectorConfigHome(".claude")
	if err != nil {
		return setupTransaction{}, err
	}
	configuredCodexHome, configuredClaudeHome := "", ""
	if oldState != nil {
		configuredCodexHome = oldState.CodexHome
		configuredClaudeHome = oldState.ClaudeConfigDir
	}
	previousCodexHome, err := resolvePreviousConnectorHome(
		configuredCodexHome,
		previousConnectors,
		source.DataRoot,
		"codex",
		"config.toml",
		defaultCodexHome,
	)
	if err != nil {
		return setupTransaction{}, err
	}
	previousClaudeConfigDir, err := resolvePreviousConnectorHome(
		configuredClaudeHome,
		previousConnectors,
		source.DataRoot,
		"claudecode",
		"settings.json",
		defaultClaudeConfigDir,
	)
	if err != nil {
		return setupTransaction{}, err
	}
	var previousState *installState
	if oldState != nil {
		copyState := *oldState
		previousState = &copyState
	}
	pathOwned, pathSeparatorReused, pathValueCreated := false, false, false
	if oldState != nil && oldState.PathEntryOwned {
		pathOwned = true
		pathSeparatorReused = oldState.PathSeparatorReused
		pathValueCreated = oldState.PathValueCreated
	}
	handoffFromInstall := ""
	var handoffPreviousState *installState
	if oldState != nil && oldState.TransactionID == source.ID {
		handoffFromInstall = source.ID
		if source.PreviousState != nil {
			copyState := *source.PreviousState
			handoffPreviousState = &copyState
		}
		if !pathOwned {
			// A registry read failure must not replay forward PATH publication or
			// block explicit uninstall. Claim only the exact mutation proven by
			// the source transaction's durable pre-install snapshot.
			if currentPath, captureErr := captureUserPath(); captureErr == nil {
				pathOwned, pathSeparatorReused, pathValueCreated = replayedTransactionPathOwnership(
					source.PreviousPath,
					currentPath,
					filepath.Join(source.InstallRoot, "bin"),
				)
			}
		}
	}
	return setupTransaction{
		SchemaVersion:                setupTransactionSchemaVersion,
		ID:                           id,
		Action:                       "uninstall",
		InstallRoot:                  source.InstallRoot,
		DataRoot:                     source.DataRoot,
		MaintenancePath:              source.MaintenancePath,
		StagingPath:                  staging,
		BackupPath:                   backup,
		TrashPath:                    trash,
		MaintenanceNew:               maintenanceNew,
		MaintenanceBackup:            maintenanceBackup,
		HadInstall:                   previousState != nil,
		MaintenanceExisted:           maintenanceExisted,
		PreviousMaintenanceSHA256:    previousMaintenanceSHA256,
		PreviousState:                previousState,
		PreviousConnectors:           previousConnectors,
		TargetConnector:              "none",
		TargetMode:                   opts.Mode,
		PreviousCodexHome:            previousCodexHome,
		PreviousClaudeConfigDir:      previousClaudeConfigDir,
		CodexHome:                    previousCodexHome,
		ClaudeConfigDir:              previousClaudeConfigDir,
		DeleteUserData:               opts.DeleteUserData,
		UninstallPathEntryOwned:      pathOwned,
		UninstallPathSeparatorReused: pathSeparatorReused,
		UninstallPathValueCreated:    pathValueCreated,
		HandoffFromInstall:           handoffFromInstall,
		HandoffPreviousState:         handoffPreviousState,
	}, nil
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return values
}

func snapshotMaintenanceFile(path string) (bool, string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, "", fmt.Errorf("maintenance path is not a regular file: %s", path)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return false, "", err
	}
	return true, digest, nil
}

func setupTransactionsEqual(left, right setupTransaction) bool {
	left.PreviousConnectors = normalizeStringSlice(left.PreviousConnectors)
	right.PreviousConnectors = normalizeStringSlice(right.PreviousConnectors)
	return reflect.DeepEqual(left, right)
}

func transactionConfigOverride(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", nil
	}
	full, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", name, err)
	}
	full = filepath.Clean(full)
	if err := rejectReparseAncestors(full); err != nil {
		return "", fmt.Errorf("validate %s: %w", name, err)
	}
	return full, nil
}

func defaultConnectorConfigHome(directory string) (string, error) {
	profile, err := defaultProfileRoot()
	if err != nil {
		return "", fmt.Errorf("resolve user profile: %w", err)
	}
	full, err := filepath.Abs(filepath.Join(profile, directory))
	if err != nil {
		return "", err
	}
	return filepath.Clean(full), nil
}

func transactionConfigHome(name, fallback string) (string, error) {
	override, err := transactionConfigOverride(name)
	if err != nil {
		return "", err
	}
	if override != "" {
		return override, nil
	}
	return fallback, nil
}

func inferManagedConnectorHome(dataRoot, connectorName, logicalName, fallback string) (string, error) {
	backupName := strings.NewReplacer("/", "_", `\`, "_", ":", "_", " ", "_").Replace(logicalName)
	path := filepath.Join(dataRoot, "connector_backups", connectorName, backupName+".json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fallback, nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s managed backup binding: %w", connectorName, err)
	}
	var binding struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &binding); err != nil {
		return "", fmt.Errorf("parse %s managed backup binding: %w", connectorName, err)
	}
	if strings.TrimSpace(binding.Path) == "" || !filepath.IsAbs(binding.Path) {
		return "", fmt.Errorf("%s managed backup has an invalid target path", connectorName)
	}
	return filepath.Dir(filepath.Clean(binding.Path)), nil
}

func resolvePreviousConnectorHome(
	configured string,
	previousConnectors []string,
	dataRoot, connectorName, logicalName, fallback string,
) (string, error) {
	managed := false
	for _, previous := range previousConnectors {
		if previous == connectorName {
			managed = true
			break
		}
	}
	fallbackHome := configured
	if fallbackHome == "" {
		fallbackHome = fallback
	}
	if !managed {
		return fallbackHome, nil
	}
	// The managed backup names the configuration file DefenseClaw actually
	// owns. It is newer and more specific than installer state when a connector
	// was added later through the CLI under an override home.
	return inferManagedConnectorHome(dataRoot, connectorName, logicalName, fallbackHome)
}

func transactionChildEnv(transaction setupTransaction) []string {
	return transactionChildEnvForHomes(transaction, transaction.CodexHome, transaction.ClaudeConfigDir)
}

func transactionPreviousChildEnv(transaction setupTransaction) []string {
	return transactionChildEnvForHomes(
		transaction,
		transaction.PreviousCodexHome,
		transaction.PreviousClaudeConfigDir,
	)
}

func transactionChildEnvForHomes(transaction setupTransaction, codexHome, claudeConfigDir string) []string {
	base := managedChildEnv(transaction.DataRoot)
	filtered := make([]string, 0, len(base)+2)
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if ok && (strings.EqualFold(name, "CODEX_HOME") || strings.EqualFold(name, "CLAUDE_CONFIG_DIR")) {
			continue
		}
		filtered = append(filtered, entry)
	}
	if codexHome != "" {
		filtered = append(filtered, "CODEX_HOME="+codexHome)
	}
	if claudeConfigDir != "" {
		filtered = append(filtered, "CLAUDE_CONFIG_DIR="+claudeConfigDir)
	}
	return filtered
}

func cleanupStalePayloadTemps(root string) error {
	if err := safefile.ProtectDirectory(root); err != nil {
		return err
	}
	if err := validatePrivateTransactionPath(root, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".DefenseClawSetup.") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unexpected installer payload artifact: %s", path)
		}
		if err := removeTransactionTree(path, root); err != nil {
			return err
		}
	}
	return nil
}

func inspectOwnedServices(gatewayPath, dataRoot string) (serviceState, error) {
	if !pathExists(gatewayPath) {
		return serviceState{}, nil
	}
	watchdog, err := managedProcessOwnedBy(gatewayPath, dataRoot, "watchdog.pid")
	if err != nil {
		return serviceState{}, err
	}
	gateway, err := managedProcessOwnedBy(gatewayPath, dataRoot, "gateway.pid")
	if err != nil {
		return serviceState{}, err
	}
	return serviceState{Gateway: gateway, Watchdog: watchdog}, nil
}

func validateSetupTransaction(transaction setupTransaction, expected setupTransactionExpectations) error {
	if transaction.SchemaVersion != setupTransactionSchemaVersion {
		return fmt.Errorf("unsupported setup transaction schema %d", transaction.SchemaVersion)
	}
	if !validSetupTransactionID(transaction.ID) {
		return errors.New("setup transaction has an invalid identity")
	}
	if transaction.Action != "install" && transaction.Action != "uninstall" {
		return fmt.Errorf("setup transaction has an invalid action %q", transaction.Action)
	}
	if !samePath(transaction.InstallRoot, expected.InstallRoot) ||
		!samePath(transaction.DataRoot, expected.DataRoot) ||
		!samePath(transaction.MaintenancePath, expected.MaintenancePath) {
		return errors.New("setup transaction does not match the current user's Windows Known Folders")
	}
	staging, backup, trash, maintenanceNew, maintenanceBackup := transactionArtifactPaths(
		expected.InstallRoot,
		expected.MaintenancePath,
		transaction.ID,
	)
	wantPaths := map[string][2]string{
		"staging":             {transaction.StagingPath, staging},
		"backup":              {transaction.BackupPath, backup},
		"uninstall trash":     {transaction.TrashPath, trash},
		"maintenance staging": {transaction.MaintenanceNew, maintenanceNew},
		"maintenance backup":  {transaction.MaintenanceBackup, maintenanceBackup},
	}
	for label, pair := range wantPaths {
		if !samePath(pair[0], pair[1]) {
			return fmt.Errorf("setup transaction has an unexpected %s path", label)
		}
	}
	if transaction.HadInstall != (transaction.PreviousState != nil) {
		return errors.New("setup transaction has inconsistent previous-install state")
	}
	if transaction.PreviousState != nil {
		if err := validateInstallStateForRoots(
			transaction.PreviousState,
			expected.InstallRoot,
			expected.DataRoot,
			expected.MaintenancePath,
		); err != nil {
			return fmt.Errorf("setup transaction previous state: %w", err)
		}
	}
	if !validConnector(transaction.TargetConnector) || !validMode(transaction.TargetMode) {
		return errors.New("setup transaction has an invalid target connector or mode")
	}
	if transaction.Action == "install" {
		if !validPayloadVersion(transaction.TargetVersion) {
			return errors.New("setup transaction has an invalid target version")
		}
		if transaction.FromVersion != "" && !validPayloadVersion(transaction.FromVersion) {
			return errors.New("setup transaction has an invalid migration source version")
		}
		if len(transaction.MaintenanceSHA256) != 64 {
			return errors.New("setup transaction has an invalid maintenance executable digest")
		}
		if _, err := hex.DecodeString(transaction.MaintenanceSHA256); err != nil {
			return errors.New("setup transaction has an invalid maintenance executable digest")
		}
	} else if transaction.TargetVersion != "" || transaction.FromVersion != "" || transaction.MaintenanceSHA256 != "" {
		return errors.New("uninstall transaction unexpectedly records migration versions")
	}
	if transaction.Action == "install" {
		if transaction.UninstallPathEntryOwned || transaction.UninstallPathSeparatorReused ||
			transaction.UninstallPathValueCreated || transaction.HandoffFromInstall != "" ||
			transaction.HandoffPreviousState != nil {
			return errors.New("install transaction unexpectedly records uninstall handoff state")
		}
	} else {
		if !transaction.UninstallPathEntryOwned &&
			(transaction.UninstallPathSeparatorReused || transaction.UninstallPathValueCreated) {
			return errors.New("uninstall transaction has inconsistent PATH ownership")
		}
		if transaction.UninstallPathSeparatorReused && transaction.UninstallPathValueCreated {
			return errors.New("uninstall transaction has incompatible PATH ownership metadata")
		}
		previousOwned, previousSeparator, previousCreated := false, false, false
		if transaction.PreviousState != nil && transaction.PreviousState.PathEntryOwned {
			previousOwned = true
			previousSeparator = transaction.PreviousState.PathSeparatorReused
			previousCreated = transaction.PreviousState.PathValueCreated
		}
		if transaction.HandoffFromInstall == "" {
			if transaction.HandoffPreviousState != nil {
				return errors.New("ordinary uninstall transaction has unexpected handoff ownership state")
			}
			// Schema-1 uninstall intents written by older Setup builds do not
			// contain the copied ownership fields. Accept their zero value and
			// derive ownership from PreviousState during convergence.
			if transaction.UninstallPathEntryOwned && (!previousOwned ||
				transaction.UninstallPathSeparatorReused != previousSeparator ||
				transaction.UninstallPathValueCreated != previousCreated) {
				return errors.New("ordinary uninstall transaction changed recorded PATH ownership")
			}
		} else {
			if !validSetupTransactionID(transaction.HandoffFromInstall) || transaction.PreviousState == nil ||
				transaction.PreviousState.TransactionID != transaction.HandoffFromInstall {
				return errors.New("uninstall handoff is not bound to its published install transaction")
			}
			if previousOwned && (transaction.UninstallPathEntryOwned != previousOwned ||
				transaction.UninstallPathSeparatorReused != previousSeparator ||
				transaction.UninstallPathValueCreated != previousCreated) {
				return errors.New("uninstall handoff changed recorded PATH ownership")
			}
			if transaction.HandoffPreviousState != nil {
				if err := validateInstallStateForRoots(
					transaction.HandoffPreviousState,
					expected.InstallRoot,
					expected.DataRoot,
					expected.MaintenancePath,
				); err != nil {
					return fmt.Errorf("uninstall handoff previous state: %w", err)
				}
			}
		}
	}
	if transaction.PreserveConnectorConfiguration {
		if transaction.Action != "install" || !transaction.HadInstall || transaction.PreviousState == nil {
			return errors.New("connector-preserving transaction has no previous installation")
		}
		if transaction.TargetConnector != transaction.PreviousState.Connector ||
			transaction.TargetMode != transaction.PreviousState.Mode {
			return errors.New("connector-preserving transaction changed the installer selection")
		}
		if !samePath(transaction.PreviousCodexHome, transaction.CodexHome) ||
			!samePath(transaction.PreviousClaudeConfigDir, transaction.ClaudeConfigDir) {
			return errors.New("connector-preserving transaction changed a connector configuration home")
		}
		if len(transaction.PreviousConnectors) != 0 && !transaction.TargetServices.Gateway {
			return errors.New("connector-preserving transaction disabled the required gateway")
		}
	}
	if transaction.MaintenanceExisted {
		if len(transaction.PreviousMaintenanceSHA256) != 64 {
			return errors.New("setup transaction has an invalid previous maintenance executable digest")
		}
		if _, err := hex.DecodeString(transaction.PreviousMaintenanceSHA256); err != nil {
			return errors.New("setup transaction has an invalid previous maintenance executable digest")
		}
	} else if transaction.PreviousMaintenanceSHA256 != "" {
		return errors.New("setup transaction records a digest for an absent previous maintenance executable")
	}
	for label, value := range map[string]string{
		"previous Codex home":               transaction.PreviousCodexHome,
		"previous Claude configuration dir": transaction.PreviousClaudeConfigDir,
		"Codex home":                        transaction.CodexHome,
		"Claude configuration dir":          transaction.ClaudeConfigDir,
	} {
		if value == "" {
			continue
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("setup transaction has an invalid %s override", label)
		}
	}
	if !transaction.PreviousAutoStart.Existed && transaction.PreviousAutoStart.Value != "" {
		return errors.New("setup transaction has an inconsistent absent auto-start snapshot")
	}
	if transaction.Action == "uninstall" &&
		(transaction.TargetConnector != "none" || transaction.TargetServices.any()) {
		return errors.New("uninstall transaction has an invalid target runtime state")
	}
	if transaction.Action == "install" && transaction.DeleteUserData {
		return errors.New("install transaction unexpectedly requests user-data deletion")
	}
	if transaction.PreviousPath.Existed {
		if transaction.PreviousPath.ValueType != 1 && transaction.PreviousPath.ValueType != 2 {
			return errors.New("setup transaction has an invalid PATH value type")
		}
	} else if transaction.PreviousPath.Value != "" || transaction.PreviousPath.ValueType != 0 {
		return errors.New("setup transaction has an inconsistent absent PATH snapshot")
	}
	seenConnectors := map[string]bool{}
	for _, connectorName := range transaction.PreviousConnectors {
		if connectorName != "codex" && connectorName != "claudecode" {
			return fmt.Errorf("setup transaction has an invalid previous connector %q", connectorName)
		}
		if seenConnectors[connectorName] {
			return fmt.Errorf("setup transaction repeats previous connector %q", connectorName)
		}
		seenConnectors[connectorName] = true
	}
	for _, managedPath := range []string{
		transaction.InstallRoot,
		transaction.DataRoot,
		transaction.MaintenancePath,
		transaction.StagingPath,
		transaction.BackupPath,
		transaction.TrashPath,
		transaction.MaintenanceNew,
		transaction.MaintenanceBackup,
	} {
		if err := rejectReparseAncestors(managedPath); err != nil {
			return err
		}
	}
	return nil
}

func validateInstallStateForRoots(state *installState, installRoot, dataRoot, maintenancePath string) error {
	if state == nil {
		return errors.New("installer state is absent")
	}
	if state.SchemaVersion != 1 || state.InstallKind != "native-windows-exe" ||
		state.InstallScope != "user" || !validPayloadVersion(state.Version) ||
		!validConnector(state.Connector) || !validMode(state.Mode) {
		return errors.New("installer state is not a supported native Windows install")
	}
	if state.TransactionID != "" && !validSetupTransactionID(state.TransactionID) {
		return errors.New("installer state has an invalid transaction identity")
	}
	if state.PathValueCreated && !state.PathEntryOwned {
		return errors.New("installer state claims a PATH value without owning its entry")
	}
	if state.PathValueCreated && state.PathSeparatorReused {
		return errors.New("installer state claims incompatible PATH value ownership metadata")
	}
	expectedPaths := map[string][2]string{
		"install root":      {state.InstallRoot, installRoot},
		"command directory": {state.CommandDir, filepath.Join(installRoot, "bin")},
		"data root":         {state.DataRoot, dataRoot},
		"runtime":           {state.Runtime, filepath.Join(installRoot, "runtime", "python")},
		"maintenance path":  {state.MaintenancePath, maintenancePath},
	}
	for label, pair := range expectedPaths {
		if !samePath(pair[0], pair[1]) {
			return fmt.Errorf("installer state has an unexpected %s", label)
		}
	}
	for label, value := range map[string]string{
		"Codex home":               state.CodexHome,
		"Claude configuration dir": state.ClaudeConfigDir,
	} {
		if value != "" && (!filepath.IsAbs(value) || filepath.Clean(value) != value) {
			return fmt.Errorf("installer state has an invalid %s", label)
		}
	}
	return nil
}

func transactionExpectationsFromKnownFolders(installRoot, dataRoot string) (setupTransactionExpectations, error) {
	expectedInstallRoot, err := defaultInstallRoot()
	if err != nil {
		return setupTransactionExpectations{}, err
	}
	expectedDataRoot, err := defaultDataRoot()
	if err != nil {
		return setupTransactionExpectations{}, err
	}
	maintenancePath, err := defaultMaintenancePath()
	if err != nil {
		return setupTransactionExpectations{}, err
	}
	if !samePath(installRoot, expectedInstallRoot) || !samePath(dataRoot, expectedDataRoot) {
		return setupTransactionExpectations{}, errors.New("setup mutation roots do not match Windows Known Folders")
	}
	return setupTransactionExpectations{
		InstallRoot:     expectedInstallRoot,
		DataRoot:        expectedDataRoot,
		MaintenancePath: maintenancePath,
	}, nil
}

func beginSetupTransaction(transaction setupTransaction) error {
	expected, err := transactionExpectationsFromKnownFolders(transaction.InstallRoot, transaction.DataRoot)
	if err != nil {
		return err
	}
	if err := validateSetupTransaction(transaction, expected); err != nil {
		return fmt.Errorf("refusing unsafe setup transaction: %w", err)
	}
	for _, artifact := range []string{
		transaction.StagingPath,
		transaction.BackupPath,
		transaction.TrashPath,
		transaction.MaintenanceNew,
		transaction.MaintenanceBackup,
	} {
		if _, err := os.Lstat(artifact); err == nil {
			return fmt.Errorf("refusing pre-existing setup transaction artifact: %s", artifact)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	root, err := defaultTransactionRoot()
	if err != nil {
		return err
	}
	return beginSetupTransactionAt(journalPaths(root).Journal, transaction)
}

func beginSetupTransactionAt(path string, transaction setupTransaction) error {
	return beginSetupTransactionAtWithWriter(path, transaction, writeDurableValue)
}

func beginSetupTransactionAtWithWriter(path string, transaction setupTransaction, write durableValueWriter) error {
	journal, err := readSetupJournal(path)
	if err != nil {
		return err
	}
	replace := false
	if journal != nil {
		if journal.Phase != setupPhaseComplete {
			return errors.New("a pending setup transaction must be recovered before a new mutation starts")
		}
		replace = true
	}
	return write(path, setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   transaction,
	}, replace)
}

func markSetupTransactionCommitted(transaction setupTransaction) error {
	fromPhase, err := setupTransactionCommitSourcePhase(transaction.Action)
	if err != nil {
		return err
	}
	return transitionSetupJournal(transaction, fromPhase, setupPhaseCommitted)
}

func setupTransactionCommitSourcePhase(action string) (string, error) {
	switch action {
	case "install":
		return setupPhasePublished, nil
	case "uninstall":
		return setupPhaseIntent, nil
	default:
		return "", fmt.Errorf("unsupported setup transaction action %q", action)
	}
}

func markSetupTransactionPublished(transaction setupTransaction) error {
	return transitionSetupJournal(transaction, setupPhaseIntent, setupPhasePublished)
}

func markSetupTransactionConverged(transaction setupTransaction) error {
	return transitionSetupJournal(transaction, setupPhaseCommitted, setupPhaseConverged)
}

func markSetupTransactionComplete(transaction setupTransaction, fromPhase string) error {
	return transitionSetupJournal(transaction, fromPhase, setupPhaseComplete)
}

func transitionSetupJournal(transaction setupTransaction, fromPhase, toPhase string) error {
	root, err := defaultTransactionRoot()
	if err != nil {
		return err
	}
	path := journalPaths(root).Journal
	return transitionSetupJournalAt(path, transaction, fromPhase, toPhase)
}

func transitionSetupJournalAt(path string, transaction setupTransaction, fromPhase, toPhase string) error {
	return transitionSetupJournalAtWithWriter(path, transaction, fromPhase, toPhase, writeDurableValue)
}

func transitionSetupJournalAtWithWriter(
	path string,
	transaction setupTransaction,
	fromPhase, toPhase string,
	write durableValueWriter,
) error {
	journal, err := readSetupJournal(path)
	if err != nil {
		return err
	}
	if journal == nil {
		return errors.New("setup transaction journal is missing")
	}
	if journal.Phase != fromPhase || !setupTransactionsEqual(journal.Transaction, transaction) {
		return fmt.Errorf("setup transaction journal is not in the expected %s phase", fromPhase)
	}
	journal.Phase = toPhase
	return write(path, *journal, true)
}

func writeDurableTransaction(path string, transaction setupTransaction) error {
	return writeDurableValue(path, transaction, false)
}

func writeDurableJournal(path string, journal setupJournal, replace bool) error {
	return writeDurableValue(path, journal, replace)
}

func writeDurableValue(path string, value any, replace bool) error {
	rename := durableRenameFunc(renameDurableFile)
	if replace {
		rename = replaceDurableFile
	}
	return writeDurableValueWithRename(path, value, replace, rename)
}

func writeDurableValueWithRename(path string, value any, replace bool, rename durableRenameFunc) error {
	root := filepath.Dir(path)
	if err := safefile.ProtectDirectory(root); err != nil {
		return err
	}
	if err := validatePrivateTransactionPath(root, true); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !replace {
			return fmt.Errorf("refusing to overwrite existing setup transaction marker: %s", path)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("setup transaction marker is not a regular file: %s", path)
		}
		if err := validatePrivateTransactionPath(path, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if replace {
		return fmt.Errorf("setup transaction marker disappeared before replacement: %s", path)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	id, err := newSetupTransactionID()
	if err != nil {
		return err
	}
	temporary := path + ".new." + id
	file, err := safefile.CreateExclusive(temporary)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// The phase change becomes authoritative at the rename. Apply and validate
	// the private DACL while the file is still transaction-owned so there is no
	// fallible post-publication work that could make a committed transition look
	// like an intent failure to its caller.
	if err := safefile.ProtectFile(temporary); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := validatePrivateTransactionPath(temporary, false); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		// MoveFileEx can report a late write-through error after the directory
		// entry became visible. Equality proves only visibility, not that the
		// directory update reached stable storage. Report this separately so the
		// caller neither rolls back beneath a possibly published commit nor runs
		// effects that require the new phase. Recovery on the next invocation
		// follows whichever phase actually survived.
		if published, readErr := os.ReadFile(path); readErr == nil && string(published) == string(data) {
			return fmt.Errorf("%w: %s may contain the new phase after rename failed: %v", errSetupJournalDurabilityAmbiguous, path, err)
		}
		return err
	}
	return nil
}

func readSetupTransaction(path string) (*setupTransaction, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("setup transaction marker is not a regular file: %s", path)
	}
	if err := rejectReparseAncestors(path); err != nil {
		return nil, err
	}
	var transaction setupTransaction
	if err := readJSON(path, &transaction); err != nil {
		return nil, fmt.Errorf("read setup transaction %s: %w", path, err)
	}
	return &transaction, nil
}

func readSetupJournal(path string) (*setupJournal, error) {
	root := filepath.Dir(path)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := rejectReparseAncestors(root); err != nil {
		return nil, err
	}
	if err := validatePrivateTransactionPath(root, true); err != nil {
		return nil, err
	}
	if err := cleanupSetupJournalTemps(root, filepath.Base(path)+".new."); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("setup transaction journal is not a regular file: %s", path)
	}
	if err := validatePrivateTransactionPath(path, false); err != nil {
		return nil, err
	}
	var journal setupJournal
	if err := readJSON(path, &journal); err != nil {
		return nil, fmt.Errorf("read setup transaction journal %s: %w", path, err)
	}
	if journal.SchemaVersion != setupJournalSchemaVersion {
		return nil, fmt.Errorf("unsupported setup transaction journal schema %d", journal.SchemaVersion)
	}
	switch journal.Phase {
	case setupPhaseIntent, setupPhasePublished, setupPhaseCommitted, setupPhaseConverged, setupPhaseComplete:
	default:
		return nil, fmt.Errorf("invalid setup transaction journal phase %q", journal.Phase)
	}
	return &journal, nil
}

func cleanupSetupJournalTemps(root, prefix string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if !entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unexpected setup journal temporary path: %s", path)
		}
		if err := validatePrivateTransactionPath(path, false); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func removeRegularMarkerIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing non-regular setup transaction marker: %s", path)
	}
	if err := rejectReparseAncestors(path); err != nil {
		return err
	}
	return os.Remove(path)
}

func recoverPendingSetupTransaction(installRoot, dataRoot string) error {
	expected, err := transactionExpectationsFromKnownFolders(installRoot, dataRoot)
	if err != nil {
		return err
	}
	root, err := defaultTransactionRoot()
	if err != nil {
		return err
	}
	paths := journalPaths(root)
	return recoverSetupTransactionAt(paths.Journal, expected, setupRecoveryOps{
		Rollback: rollbackSetupTransaction,
		Activate: activatePublishedSetupTransaction,
		Converge: convergeCommittedSetupTransaction,
		Cleanup:  cleanupCommittedSetupTransaction,
		Transition: func(transaction setupTransaction, fromPhase, toPhase string) error {
			return transitionSetupJournal(transaction, fromPhase, toPhase)
		},
	})
}

func preparePendingSetupTransactionForUninstall(opts options, installRoot, dataRoot string) (*setupTransaction, error) {
	expected, err := transactionExpectationsFromKnownFolders(installRoot, dataRoot)
	if err != nil {
		return nil, err
	}
	root, err := defaultTransactionRoot()
	if err != nil {
		return nil, err
	}
	path := journalPaths(root).Journal
	return preparePendingSetupTransactionForUninstallAt(path, expected, uninstallRecoveryOps{
		rollbackInstall:         rollbackInstallForUninstallHandoff,
		prepareCommittedInstall: prepareCommittedInstallForUninstallHandoff,
		buildHandoff: func(source setupTransaction) (setupTransaction, error) {
			state, loadErr := loadExistingInstallState(installRoot)
			if loadErr != nil {
				return setupTransaction{}, loadErr
			}
			return newUninstallHandoffTransaction(source, state, opts)
		},
		resumeUninstall: resumeUninstallIntentWithoutActivation,
		recoverUninstall: func(journal setupJournal) error {
			return recoverSetupJournalPhase(journal, setupRecoveryOps{
				Rollback: rollbackSetupTransaction,
				Activate: activatePublishedSetupTransaction,
				Converge: convergeCommittedSetupTransaction,
				Cleanup:  cleanupCommittedSetupTransaction,
				Transition: func(transaction setupTransaction, fromPhase, toPhase string) error {
					return transitionSetupJournal(transaction, fromPhase, toPhase)
				},
			})
		},
		replaceWithHandoff: func(source setupJournal, next setupTransaction) error {
			return replaceSetupJournalWithUninstallIntentAt(path, expected, source, next)
		},
	})
}

func preparePendingSetupTransactionForUninstallAt(
	path string,
	expected setupTransactionExpectations,
	ops uninstallRecoveryOps,
) (*setupTransaction, error) {
	journal, err := readSetupJournal(path)
	if err != nil || journal == nil || journal.Phase == setupPhaseComplete {
		return nil, err
	}
	if err := validateSetupTransaction(journal.Transaction, expected); err != nil {
		return nil, fmt.Errorf("refusing unsafe setup transaction recovery: %w", err)
	}
	if journal.Transaction.Action == "uninstall" {
		if journal.Phase == setupPhaseIntent {
			if err := ops.resumeUninstall(journal.Transaction); err != nil {
				return nil, fmt.Errorf("resume interrupted uninstall intent: %w", err)
			}
			transaction := journal.Transaction
			return &transaction, nil
		}
		if err := ops.recoverUninstall(*journal); err != nil {
			return nil, err
		}
		return nil, nil
	}

	switch journal.Phase {
	case setupPhaseIntent:
		if err := ops.rollbackInstall(journal.Transaction); err != nil {
			return nil, fmt.Errorf("prepare interrupted install for uninstall handoff: %w", err)
		}
	case setupPhasePublished:
		if err := ops.recoverUninstall(*journal); err != nil {
			return nil, err
		}
		return nil, nil
	case setupPhaseCommitted, setupPhaseConverged:
		if err := ops.prepareCommittedInstall(journal.Transaction); err != nil {
			return nil, fmt.Errorf("prepare committed install for uninstall handoff: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported install-to-uninstall handoff phase %q", journal.Phase)
	}
	next, err := ops.buildHandoff(journal.Transaction)
	if err != nil {
		return nil, fmt.Errorf("build uninstall handoff: %w", err)
	}
	if err := ops.replaceWithHandoff(*journal, next); err != nil {
		return nil, fmt.Errorf("publish uninstall handoff: %w", err)
	}
	if ops.afterHandoff != nil {
		if err := ops.afterHandoff(); err != nil {
			return nil, fmt.Errorf("after durable uninstall handoff: %w", err)
		}
	}
	return &next, nil
}

func replaceSetupJournalWithUninstallIntentAt(
	path string,
	expected setupTransactionExpectations,
	source setupJournal,
	next setupTransaction,
) error {
	return replaceSetupJournalWithUninstallIntentAtWithWriter(path, expected, source, next, writeDurableValue)
}

func replaceSetupJournalWithUninstallIntentAtWithWriter(
	path string,
	expected setupTransactionExpectations,
	source setupJournal,
	next setupTransaction,
	write durableValueWriter,
) error {
	current, err := readSetupJournal(path)
	if err != nil {
		return err
	}
	if current == nil || current.Phase != source.Phase ||
		!setupTransactionsEqual(current.Transaction, source.Transaction) {
		return errors.New("setup transaction changed before uninstall handoff")
	}
	if source.Transaction.Action != "install" || source.Phase == setupPhaseComplete {
		return errors.New("uninstall handoff source is not a pending install transaction")
	}
	if next.Action != "uninstall" {
		return errors.New("uninstall handoff target has the wrong action")
	}
	if err := validateSetupTransaction(next, expected); err != nil {
		return fmt.Errorf("refusing unsafe uninstall handoff: %w", err)
	}
	return write(path, setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseIntent,
		Transaction:   next,
	}, true)
}

func recoverSetupTransactionAt(path string, expected setupTransactionExpectations, ops setupRecoveryOps) error {
	journal, err := readSetupJournal(path)
	if err != nil {
		return err
	}
	if journal == nil || journal.Phase == setupPhaseComplete {
		return nil
	}
	if err := validateSetupTransaction(journal.Transaction, expected); err != nil {
		return fmt.Errorf("refusing unsafe setup transaction recovery: %w", err)
	}
	return recoverSetupJournalPhase(*journal, ops)
}

func recoverSetupJournalPhase(journal setupJournal, ops setupRecoveryOps) error {
	transaction := journal.Transaction
	switch journal.Phase {
	case setupPhaseComplete:
		return nil
	case setupPhaseIntent:
		if err := ops.Rollback(transaction); err != nil {
			return fmt.Errorf("roll back interrupted setup transaction: %w", err)
		}
		return ops.Transition(transaction, setupPhaseIntent, setupPhaseComplete)
	case setupPhasePublished:
		if err := ops.Activate(transaction); err != nil {
			if errors.Is(err, errPublishedActivationStateChanged) {
				return fmt.Errorf("activate interrupted published setup transaction; target runtime retained for recovery: %w", err)
			}
			rollbackErr := ops.Rollback(transaction)
			if rollbackErr == nil {
				rollbackErr = ops.Transition(transaction, setupPhasePublished, setupPhaseComplete)
			}
			return errors.Join(
				fmt.Errorf("activate interrupted published setup transaction: %w", err),
				rollbackErr,
			)
		}
		if err := ops.Transition(transaction, setupPhasePublished, setupPhaseCommitted); err != nil {
			return fmt.Errorf("commit activated setup transaction: %w", err)
		}
		fallthrough
	case setupPhaseCommitted:
		if err := ops.Converge(transaction); err != nil {
			return fmt.Errorf("complete committed setup transaction: %w", err)
		}
		if err := ops.Transition(transaction, setupPhaseCommitted, setupPhaseConverged); err != nil {
			return fmt.Errorf("record converged setup transaction: %w", err)
		}
		fallthrough
	case setupPhaseConverged:
		if err := ops.Cleanup(transaction); err != nil {
			if errors.Is(err, errTransactionCleanupDeferred) {
				return err
			}
			return fmt.Errorf("clean committed setup transaction: %w", err)
		}
		return ops.Transition(transaction, setupPhaseConverged, setupPhaseComplete)
	default:
		return fmt.Errorf("unsupported setup transaction recovery phase %q", journal.Phase)
	}
}

func finishCommittedSetupTransaction(transaction setupTransaction) (bool, error) {
	if err := convergeCommittedSetupTransaction(transaction); err != nil {
		return false, err
	}
	if err := markSetupTransactionConverged(transaction); err != nil {
		return false, err
	}
	if err := cleanupCommittedSetupTransaction(transaction); err != nil {
		if errors.Is(err, errTransactionCleanupDeferred) {
			return true, nil
		}
		return false, err
	}
	if err := markSetupTransactionComplete(transaction, setupPhaseConverged); err != nil {
		return false, err
	}
	return false, nil
}

func rollbackSetupTransaction(transaction setupTransaction) error {
	return rollbackSetupTransactionWithRuntime(
		transaction,
		stopOwnedServices,
		startMissingServices,
	)
}

func rollbackSetupTransactionWithRuntime(
	transaction setupTransaction,
	stopServices func(string, string) (serviceState, error),
	startServices func(string, string, serviceState) (serviceState, error),
) error {
	restoreServices := transaction.PreviousServices
	currentGateway := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	if pathExists(currentGateway) {
		if err := rejectReparseTree(transaction.InstallRoot); err != nil {
			return err
		}
		stopped, err := stopServices(currentGateway, transaction.DataRoot)
		if err != nil {
			return err
		}
		// A later invocation can start an exact-owned runtime while an older
		// intent remains pending (for example, after a locked-file rollback).
		// Preserve services this recovery invocation actually stopped instead of
		// losing them to the intent's now-stale pre-operation snapshot.
		restoreServices = mergeServiceStates(restoreServices, stopped)
	}
	restoreRuntime := func(restoreStoppedFreshRuntime bool) error {
		if !restoreServices.Gateway && !restoreServices.Watchdog {
			return nil
		}
		// A successful fresh-install rollback deliberately leaves no runtime to
		// restore. If file rollback failed, however, the transaction-owned
		// payload is still present and services stopped above must be restarted
		// even though there was no pre-install state snapshot.
		if transaction.PreviousState == nil && !restoreStoppedFreshRuntime {
			return nil
		}
		gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
		_, err := startServices(gatewayPath, transaction.DataRoot, restoreServices)
		return err
	}
	if err := rollbackTransactionFiles(transaction); err != nil {
		// File rollback can fail on a late sharing violation or ACL error after
		// owned services were stopped. Restore the pre-operation runtime even
		// though the durable intent must remain pending for a later retry.
		return errors.Join(err, restoreRuntime(true))
	}
	var restoreErrors []error
	if err := rollbackMaintenancePublication(transaction); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	if err := restoreRuntime(false); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	return errors.Join(restoreErrors...)
}

func mergeServiceStates(left, right serviceState) serviceState {
	return serviceState{
		Gateway:  left.Gateway || right.Gateway,
		Watchdog: left.Watchdog || right.Watchdog,
	}
}

func nativeInstallRuntimeConvergenceOps() installRuntimeConvergenceOps {
	return installRuntimeConvergenceOps{
		disableStableHook:  disableStableHookRuntime,
		configureAutoStart: configureGatewayAutoStart,
		startServices:      startMissingServices,
		verifyServices:     verifySelectedServices,
		stopServices:       stopOwnedServices,
		verifyStopped:      verifyOwnedServicesStopped,
	}
}

func validateCommittedInstallForUninstallHandoff(transaction setupTransaction) error {
	state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
	if err != nil {
		return err
	}
	if state == nil || state.TransactionID != transaction.ID || state.Version != transaction.TargetVersion ||
		state.Connector != transaction.TargetConnector || state.Mode != transaction.TargetMode {
		return errors.New("committed install transaction does not own the published install tree")
	}
	if err := validateInstall(transaction.InstallRoot, transaction.TargetVersion); err != nil {
		return err
	}
	maintenanceDigest, err := fileSHA256(transaction.MaintenancePath)
	if err != nil {
		return fmt.Errorf("validate maintenance executable: %w", err)
	}
	if !strings.EqualFold(maintenanceDigest, transaction.MaintenanceSHA256) {
		return errors.New("maintenance executable does not match the committed installer transaction")
	}
	if err := verifySetupExecutablePolicyAt(transaction.MaintenancePath, state.UnsignedLocalArtifact); err != nil {
		return fmt.Errorf("validate maintenance executable Authenticode policy: %w", err)
	}
	return nil
}

func prepareCommittedInstallForUninstallHandoff(transaction setupTransaction) error {
	if err := validateCommittedInstallForUninstallHandoff(transaction); err != nil {
		return err
	}
	if err := disableStableHookRuntime(transaction.ID); err != nil {
		return fmt.Errorf("disable stable hook runtime: %w", err)
	}
	gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	if err := quiesceOwnedInstallRuntime(gatewayPath, transaction.DataRoot, nativeInstallRuntimeConvergenceOps()); err != nil {
		return err
	}
	if err := retireInstalledAppPendingOwned(transaction.InstallRoot, transaction.ID); err != nil {
		return fmt.Errorf("retire transaction-owned Apps & Features staging: %w", err)
	}
	return cleanupCommittedSetupTransaction(transaction)
}

func rollbackInstallForUninstallHandoff(transaction setupTransaction) error {
	if transaction.Action != "install" {
		return errors.New("uninstall handoff rollback source is not an install transaction")
	}
	if err := disableStableHookRuntime(transaction.ID); err != nil {
		return fmt.Errorf("disable stable hook runtime: %w", err)
	}
	gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	if err := quiesceOwnedInstallRuntime(gatewayPath, transaction.DataRoot, nativeInstallRuntimeConvergenceOps()); err != nil {
		return err
	}
	if err := rollbackTransactionFiles(transaction); err != nil {
		return err
	}
	if err := rollbackMaintenancePublication(transaction); err != nil {
		return err
	}
	// An interrupted upgrade may restore an older owned gateway at the same
	// fixed path. Keep it quiescent rather than replaying PreviousServices.
	return quiesceOwnedInstallRuntime(gatewayPath, transaction.DataRoot, nativeInstallRuntimeConvergenceOps())
}

func resumeUninstallIntentWithoutActivation(transaction setupTransaction) error {
	if transaction.Action != "uninstall" {
		return errors.New("resume target is not an uninstall transaction")
	}
	if err := disableStableHookRuntime(transaction.ID); err != nil {
		return fmt.Errorf("disable stable hook runtime: %w", err)
	}
	trashGateway := filepath.Join(transaction.TrashPath, "bin", "defenseclaw-gateway.exe")
	if pathExists(trashGateway) {
		if _, err := stopOwnedServices(trashGateway, transaction.DataRoot); err != nil {
			return err
		}
		if err := verifyOwnedServicesStopped(trashGateway, transaction.DataRoot); err != nil {
			return err
		}
	}
	if err := rollbackUninstallFiles(transaction); err != nil {
		return err
	}
	if err := rollbackMaintenancePublication(transaction); err != nil {
		return err
	}
	gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	return quiesceOwnedInstallRuntime(gatewayPath, transaction.DataRoot, nativeInstallRuntimeConvergenceOps())
}

func startMissingServices(gatewayPath, dataRoot string, wanted serviceState) (serviceState, error) {
	current, err := inspectOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return serviceState{}, err
	}
	missing := serviceState{
		Gateway:  wanted.Gateway && !current.Gateway,
		Watchdog: wanted.Watchdog && !current.Watchdog,
	}
	return startSelectedServices(gatewayPath, dataRoot, missing)
}

func activatePublishedSetupTransaction(transaction setupTransaction) error {
	if transaction.Action != "install" {
		return errors.New("only an install transaction can enter the published phase")
	}
	state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
	if err != nil {
		return err
	}
	if state == nil || state.TransactionID != transaction.ID || state.Version != transaction.TargetVersion ||
		state.Connector != transaction.TargetConnector || state.Mode != transaction.TargetMode {
		return errors.New("published install transaction does not own the target install tree")
	}
	if err := validateInstall(transaction.InstallRoot, transaction.TargetVersion); err != nil {
		return err
	}
	maintenanceDigest, err := fileSHA256(transaction.MaintenancePath)
	if err != nil {
		return fmt.Errorf("validate published maintenance executable: %w", err)
	}
	if !strings.EqualFold(maintenanceDigest, transaction.MaintenanceSHA256) {
		return errors.New("published maintenance executable does not match the setup transaction")
	}
	if err := verifySetupExecutablePolicyAt(transaction.MaintenancePath, state.UnsignedLocalArtifact); err != nil {
		return fmt.Errorf("validate published maintenance executable Authenticode policy: %w", err)
	}
	if !shouldRunPackagedMigrations(transaction.FromVersion, transaction.TargetVersion) {
		return nil
	}
	before, err := snapshotPublishedMigrationState(transaction.DataRoot)
	if err != nil {
		return fmt.Errorf("snapshot live migration state before activation: %w", err)
	}
	err = runPackagedMigrationsWithEnv(
		transaction.InstallRoot,
		transaction.DataRoot,
		transaction.FromVersion,
		transaction.TargetVersion,
		transactionChildEnv(transaction),
	)
	if err == nil {
		return nil
	}
	after, snapshotErr := snapshotPublishedMigrationState(transaction.DataRoot)
	if snapshotErr != nil {
		return errors.Join(
			errPublishedActivationStateChanged,
			fmt.Errorf("packaged migration failed: %w", err),
			fmt.Errorf("verify live migration state after failure: %w", snapshotErr),
		)
	}
	if before != after {
		return errors.Join(
			errPublishedActivationStateChanged,
			fmt.Errorf("packaged migration failed after changing live migration state: %w", err),
		)
	}
	return err
}

func snapshotPublishedMigrationState(dataRoot string) (publishedMigrationSnapshot, error) {
	config, err := snapshotMigrationFile(filepath.Join(dataRoot, "config.yaml"))
	if err != nil {
		return publishedMigrationSnapshot{}, fmt.Errorf("snapshot config: %w", err)
	}
	env, err := snapshotMigrationFile(filepath.Join(dataRoot, ".env"))
	if err != nil {
		return publishedMigrationSnapshot{}, fmt.Errorf("snapshot environment: %w", err)
	}
	cursor, err := snapshotMigrationFile(filepath.Join(dataRoot, ".migration_state.json"))
	if err != nil {
		return publishedMigrationSnapshot{}, fmt.Errorf("snapshot migration cursor: %w", err)
	}
	return publishedMigrationSnapshot{Config: config, Env: env, Cursor: cursor}, nil
}

func snapshotMigrationFile(path string) (migrationFileSnapshot, error) {
	if err := rejectReparseAncestors(path); err != nil {
		return migrationFileSnapshot{}, err
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return migrationFileSnapshot{}, nil
	}
	if err != nil {
		return migrationFileSnapshot{}, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return migrationFileSnapshot{}, fmt.Errorf("migration state path is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return migrationFileSnapshot{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return migrationFileSnapshot{}, err
	}
	if !os.SameFile(before, opened) {
		return migrationFileSnapshot{}, fmt.Errorf("migration state path changed while opening: %s", path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return migrationFileSnapshot{}, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return migrationFileSnapshot{}, err
	}
	if !os.SameFile(opened, after) {
		return migrationFileSnapshot{}, fmt.Errorf("migration state path changed while reading: %s", path)
	}
	if err := rejectReparseAncestors(path); err != nil {
		return migrationFileSnapshot{}, err
	}
	return migrationFileSnapshot{Exists: true, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func convergeCommittedSetupTransaction(transaction setupTransaction) error {
	if transaction.Action == "uninstall" {
		// Agent clients cache hook commands for the lifetime of their process.
		// Disable the stable launcher before touching connector configuration or
		// user data; the launcher itself deliberately survives every uninstall
		// mode and returns success for those cached invocations.
		if err := disableStableHookRuntime(transaction.ID); err != nil {
			return fmt.Errorf("disable stable hook runtime: %w", err)
		}
		publishedGateway := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
		gatewayPath := filepath.Join(transaction.TrashPath, "bin", "defenseclaw-gateway.exe")
		if pathExists(transaction.TrashPath) {
			state, err := loadTransactionInstallState(transaction.TrashPath, transaction)
			if err != nil {
				return err
			}
			if !installStateMatchesSnapshot(state, transaction.PreviousState) {
				return errors.New("committed uninstall found an unrelated transaction trash tree")
			}
			if _, err := stopOwnedServices(gatewayPath, transaction.DataRoot); err != nil {
				return err
			}
		}
		// Connector lifecycle is always run by the manifest-verified gateway
		// embedded in the executing Setup binary. The installed/trash copy is
		// retained above only as the process-ownership identity used to stop a
		// previously running service; it is never trusted to edit agent config.
		reconciliation := reconcileRemovedConnectorsWithMaintenance(
			transaction,
			transactionPreviousChildEnv(transaction),
			prepareConnectorMaintenanceGateway,
			runConnectorLifecycleWithEnv,
		)
		if err := reconciliation.persist(); err != nil {
			return fmt.Errorf("persist connector reconciliation residue: %w", err)
		}
		if _, _, err := configureGatewayAutoStart(publishedGateway, false); err != nil {
			return err
		}
		pathOwned, reusedSeparator, valueCreated := uninstallPathOwnership(transaction)
		if pathOwned {
			if err := removeUserPath(filepath.Join(transaction.InstallRoot, "bin"), reusedSeparator, valueCreated); err != nil {
				return err
			}
		}
		if err := unregisterInstalledAppOwned(transaction.InstallRoot, transaction.PreviousState); err != nil {
			return err
		}
		if transaction.HandoffPreviousState != nil {
			if err := unregisterInstalledAppOwned(transaction.InstallRoot, transaction.HandoffPreviousState); err != nil {
				return err
			}
		}
		return nil
	}
	if err := activatePublishedSetupTransaction(transaction); err != nil {
		return err
	}
	state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
	if err != nil {
		return err
	}
	childEnv := transactionChildEnv(transaction)
	previousChildEnv := transactionPreviousChildEnv(transaction)
	gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	// Publish the signed no-console launcher outside both InstallRoot and
	// DataRoot before connector configuration writes absolute commands. The
	// publishing/active handshake makes this step idempotent under committed
	// transaction recovery and re-enables a data-preserving reinstall.
	if err := publishStableHookRuntime(
		filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-hook.exe"),
		filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe"),
		transaction.DataRoot,
		transaction.ID,
	); err != nil {
		return fmt.Errorf("publish stable hook runtime: %w", err)
	}
	reconciliation := connectorReconciliationRecorder{}
	if transaction.PreserveConnectorConfiguration {
		reconciliation = reconcilePreservedConnectors(
			transaction,
			gatewayPath,
			previousChildEnv,
			runConnectorLifecycleWithEnv,
		)
	} else {
		for _, connectorName := range transaction.PreviousConnectors {
			if connectorName == transaction.TargetConnector && !connectorHomeChanged(transaction, connectorName) {
				continue
			}
			configHome := connectorConfigHome(transaction, connectorName, true)
			if !reconciliation.run(transaction.ID, connectorName, configHome, "teardown", func() error {
				return runConnectorLifecycleWithEnv(
					gatewayPath,
					transaction.DataRoot,
					connectorName,
					"teardown",
					previousChildEnv,
				)
			}) {
				continue
			}
			reconciliation.run(transaction.ID, connectorName, configHome, "verify", func() error {
				return runConnectorLifecycleWithEnv(
					gatewayPath,
					transaction.DataRoot,
					connectorName,
					"verify",
					previousChildEnv,
				)
			})
		}
		if transaction.TargetConnector != "none" {
			opts := options{Connector: transaction.TargetConnector, Mode: transaction.TargetMode, Quiet: true}
			configHome := connectorConfigHome(transaction, transaction.TargetConnector, false)
			if reconciliation.run(transaction.ID, transaction.TargetConnector, configHome, "configure", func() error {
				return runInitialConfigurationWithEnv(transaction.InstallRoot, transaction.DataRoot, opts, childEnv)
			}) {
				reconciliation.run(transaction.ID, transaction.TargetConnector, configHome, "reconcile", func() error {
					return runConnectorLifecycleWithEnv(
						gatewayPath,
						transaction.DataRoot,
						transaction.TargetConnector,
						"reconcile",
						childEnv,
					)
				})
			}
		}
	}
	persistReconciliation := func() error {
		if err := retryPendingConnectorReconciliation(
			transaction,
			gatewayPath,
			&reconciliation,
			readConnectorReconciliation,
			runConnectorLifecycleWithEnv,
		); err != nil {
			return fmt.Errorf("retry pending connector reconciliation: %w", err)
		}
		return reconciliation.persist()
	}
	connectorReconciliationPending, err := settleInstallConnectorReconciliation(
		transaction.ID,
		gatewayPath,
		transaction.DataRoot,
		transaction.TargetServices,
		len(reconciliation.failures) != 0,
		persistReconciliation,
		connectorReconciliationSummary,
		nativeInstallRuntimeConvergenceOps(),
	)
	if err != nil {
		return err
	}
	pathAdded, reusedSeparator, valueCreated, pathMutationErr := addUserPath(
		filepath.Join(transaction.InstallRoot, "bin"),
	)
	pathOwned := pathAdded
	if !pathOwned && !state.PathEntryOwned {
		currentPath, captureErr := captureUserPath()
		if captureErr != nil {
			return errors.Join(pathMutationErr, fmt.Errorf("inspect user PATH ownership after convergence: %w", captureErr))
		}
		pathOwned, reusedSeparator, valueCreated = replayedTransactionPathOwnership(
			transaction.PreviousPath,
			currentPath,
			filepath.Join(transaction.InstallRoot, "bin"),
		)
	}
	if pathOwned {
		if err := updateInstalledPathOwnership(
			transaction.InstallRoot,
			true,
			reusedSeparator,
			valueCreated,
		); err != nil {
			return errors.Join(pathMutationErr, fmt.Errorf("record user PATH ownership: %w", err))
		}
	}
	if pathMutationErr != nil {
		return pathMutationErr
	}
	if err := registerInstalledAppOwned(
		state.MaintenancePath,
		transaction.InstallRoot,
		state.Version,
		transaction.ID,
		state.UnsignedLocalArtifact,
		transaction.PreviousState,
	); err != nil {
		return err
	}
	// PATH ownership and Apps & Features registration are durable core state.
	// Once they converge, connector residue must not leave the transaction
	// journal pending, and it must never enable or launch an unenforced gateway.
	if connectorReconciliationPending {
		return nil
	}
	return convergeInstallRuntime(
		transaction.ID,
		false,
		gatewayPath,
		transaction.DataRoot,
		transaction.TargetServices,
		nativeInstallRuntimeConvergenceOps(),
	)
}

func uninstallPathOwnership(transaction setupTransaction) (owned, reusedSeparator, valueCreated bool) {
	if transaction.UninstallPathEntryOwned {
		return true, transaction.UninstallPathSeparatorReused, transaction.UninstallPathValueCreated
	}
	// Backward compatibility for schema-1 uninstall intents written before the
	// handoff fields were introduced.
	if transaction.PreviousState != nil && transaction.PreviousState.PathEntryOwned {
		return true, transaction.PreviousState.PathSeparatorReused, transaction.PreviousState.PathValueCreated
	}
	return false, false, false
}

func settleInstallConnectorReconciliation(
	transactionID, gatewayPath, dataRoot string,
	wanted serviceState,
	inMemoryPending bool,
	persist func() error,
	summary func() (string, error),
	ops installRuntimeConvergenceOps,
) (bool, error) {
	quiesce := func(cause error) error {
		return errors.Join(cause, convergeInstallRuntime(
			transactionID,
			true,
			gatewayPath,
			dataRoot,
			wanted,
			ops,
		))
	}
	if err := persist(); err != nil {
		return true, quiesce(fmt.Errorf("persist connector reconciliation residue: %w", err))
	}
	connectorSummary, err := summary()
	if err != nil {
		return true, quiesce(fmt.Errorf("read pending connector reconciliation before runtime activation: %w", err))
	}
	pending := inMemoryPending || connectorSummary != ""
	if !pending {
		return false, nil
	}
	// An upgrade can inherit both an owned Run value and live managed
	// processes. Quiesce them before fallible PATH/ARP core convergence so a
	// later registry failure cannot leave an unenforced runtime active.
	return true, convergeInstallRuntime(transactionID, true, gatewayPath, dataRoot, wanted, ops)
}

func convergeInstallRuntime(
	transactionID string,
	connectorReconciliationPending bool,
	gatewayPath, dataRoot string,
	wanted serviceState,
	ops installRuntimeConvergenceOps,
) error {
	if connectorReconciliationPending {
		hookErr := ops.disableStableHook(transactionID)
		if hookErr != nil {
			hookErr = fmt.Errorf("disable stable hook runtime: %w", hookErr)
		}
		return errors.Join(hookErr, quiesceOwnedInstallRuntime(gatewayPath, dataRoot, ops))
	}
	if _, _, err := ops.configureAutoStart(gatewayPath, wanted.Gateway); err != nil {
		return err
	}
	if _, err := ops.startServices(gatewayPath, dataRoot, wanted); err != nil {
		return err
	}
	return ops.verifyServices(gatewayPath, dataRoot, wanted)
}

func quiesceOwnedInstallRuntime(
	gatewayPath, dataRoot string,
	ops installRuntimeConvergenceOps,
) error {
	var quiesceErrors []error
	if _, _, err := ops.configureAutoStart(gatewayPath, false); err != nil {
		quiesceErrors = append(quiesceErrors, fmt.Errorf("disable owned gateway auto-start: %w", err))
	}
	if _, err := ops.stopServices(gatewayPath, dataRoot); err != nil {
		quiesceErrors = append(quiesceErrors, fmt.Errorf("stop owned gateway runtime: %w", err))
	}
	if err := ops.verifyStopped(gatewayPath, dataRoot); err != nil {
		quiesceErrors = append(quiesceErrors, fmt.Errorf("verify owned gateway runtime stopped: %w", err))
	}
	return errors.Join(quiesceErrors...)
}

func verifyOwnedServicesStopped(gatewayPath, dataRoot string) error {
	state, err := inspectOwnedServices(gatewayPath, dataRoot)
	if err != nil {
		return err
	}
	if state.any() {
		return errors.New("owned gateway or watchdog process remains running")
	}
	return nil
}

// replayedTransactionPathOwnership recognizes the exact PATH mutation implied
// by the transaction's durable pre-mutation snapshot. This repairs ownership
// metadata after a crash between the registry write and install-state update,
// without claiming a path that already existed or was subsequently edited.
func replayedTransactionPathOwnership(
	previous, current userPathSnapshot,
	commandDir string,
) (owned, reusedSeparator, valueCreated bool) {
	if !current.Existed || pathContains(strings.Split(previous.Value, ";"), commandDir) {
		return false, false, false
	}
	want, reusedSeparator := prependUserPathEntry(previous.Value, commandDir)
	if current.Value != want {
		return false, false, false
	}
	if previous.Existed {
		if current.ValueType != previous.ValueType {
			return false, false, false
		}
		return true, reusedSeparator, false
	}
	// addUserPath creates a missing per-user PATH value as REG_SZ (1).
	if previous.Value != "" || previous.ValueType != 0 || current.ValueType != 1 {
		return false, false, false
	}
	return true, reusedSeparator, true
}

func teardownSupersededConnectors(
	transaction setupTransaction,
	gatewayPath string,
	childEnv []string,
	run connectorLifecycleRunner,
) error {
	for _, connectorName := range transaction.PreviousConnectors {
		if connectorName == transaction.TargetConnector && !connectorHomeChanged(transaction, connectorName) {
			continue
		}
		if err := run(
			gatewayPath,
			transaction.DataRoot,
			connectorName,
			"teardown",
			childEnv,
		); err != nil {
			return err
		}
		if err := run(
			gatewayPath,
			transaction.DataRoot,
			connectorName,
			"verify",
			childEnv,
		); err != nil {
			return err
		}
	}
	return nil
}

func connectorHomeChanged(transaction setupTransaction, connectorName string) bool {
	switch connectorName {
	case "codex":
		return !samePath(transaction.PreviousCodexHome, transaction.CodexHome)
	case "claudecode":
		return !samePath(transaction.PreviousClaudeConfigDir, transaction.ClaudeConfigDir)
	default:
		return false
	}
}

func rollbackTransactionFiles(transaction setupTransaction) error {
	if transaction.Action == "uninstall" {
		return rollbackUninstallFiles(transaction)
	}
	return rollbackInstallFiles(transaction)
}

func rollbackInstallFiles(transaction setupTransaction) error {
	return rollbackInstallFilesWithRename(transaction, renameInstallTree)
}

func rollbackInstallFilesWithRename(transaction setupTransaction, rename func(string, string) error) error {
	if pathExists(transaction.BackupPath) {
		state, err := loadTransactionInstallState(transaction.BackupPath, transaction)
		if err != nil {
			return fmt.Errorf("validate interrupted-install backup: %w", err)
		}
		if !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("interrupted-install backup does not match the recorded previous installation")
		}
		if pathExists(transaction.InstallRoot) {
			current, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
			if err != nil {
				return err
			}
			if current == nil || current.TransactionID != transaction.ID {
				return errors.New("refusing to replace an install tree not owned by the interrupted transaction")
			}
			if pathExists(transaction.StagingPath) {
				return errors.New("both the published transaction tree and transaction staging path exist")
			}
			if err := rename(transaction.InstallRoot, transaction.StagingPath); err != nil {
				return err
			}
		}
		if err := cleanupStagingTree(transaction); err != nil {
			return err
		}
		if err := rename(transaction.BackupPath, transaction.InstallRoot); err != nil {
			return err
		}
	} else if transaction.HadInstall {
		state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
		if err != nil {
			return err
		}
		if !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("previous installation is missing and no valid transaction backup remains")
		}
		// The prior rollback rename may have become visible while its
		// write-through failed. Round-trip through the recorded backup name so
		// this invocation obtains a confirmed durable rename before completing
		// the intent journal.
		if err := rename(transaction.InstallRoot, transaction.BackupPath); err != nil {
			return err
		}
		if err := rename(transaction.BackupPath, transaction.InstallRoot); err != nil {
			return err
		}
	} else if pathExists(transaction.InstallRoot) {
		if pathExists(transaction.StagingPath) {
			// The staged tree still being present proves publication never moved it
			// to the fixed install path. Preserve a directory that appeared there
			// concurrently and discard only the random transaction-owned staging.
			return cleanupStagingTree(transaction)
		}
		state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
		if err != nil {
			return err
		}
		if state == nil || state.TransactionID != transaction.ID {
			return errors.New("refusing to remove an install tree not owned by the interrupted transaction")
		}
		if pathExists(transaction.StagingPath) {
			return errors.New("both the published transaction tree and transaction staging path exist")
		}
		if err := rename(transaction.InstallRoot, transaction.StagingPath); err != nil {
			return err
		}
	}
	return cleanupStagingTree(transaction)
}

func rollbackUninstallFiles(transaction setupTransaction) error {
	return rollbackUninstallFilesWithRename(transaction, renameInstallTree)
}

func rollbackUninstallFilesWithRename(transaction setupTransaction, rename func(string, string) error) error {
	if pathExists(transaction.TrashPath) {
		state, err := loadTransactionInstallState(transaction.TrashPath, transaction)
		if err != nil {
			return fmt.Errorf("validate interrupted-uninstall tree: %w", err)
		}
		if !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("interrupted-uninstall tree does not match the recorded installation")
		}
		if pathExists(transaction.InstallRoot) {
			return errors.New("both the installed tree and interrupted-uninstall tree exist")
		}
		if err := rename(transaction.TrashPath, transaction.InstallRoot); err != nil {
			return err
		}
	} else if transaction.HadInstall {
		state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
		if err != nil {
			return err
		}
		if !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("recorded installation is missing and no interrupted-uninstall tree remains")
		}
		if err := rename(transaction.InstallRoot, transaction.TrashPath); err != nil {
			return err
		}
		if err := rename(transaction.TrashPath, transaction.InstallRoot); err != nil {
			return err
		}
	}
	return nil
}

func installStateMatchesSnapshot(state, snapshot *installState) bool {
	if state == nil || snapshot == nil {
		return state == nil && snapshot == nil
	}
	return reflect.DeepEqual(*state, *snapshot)
}

func loadTransactionInstallState(treeRoot string, transaction setupTransaction) (*installState, error) {
	if _, err := os.Lstat(treeRoot); err == nil {
		if err := rejectReparseTree(treeRoot); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return loadInstallStateFromTreeForRoots(
		treeRoot,
		transaction.InstallRoot,
		transaction.DataRoot,
		transaction.MaintenancePath,
	)
}

func cleanupStagingTree(transaction setupTransaction) error {
	if !pathExists(transaction.StagingPath) {
		return nil
	}
	state, err := loadTransactionInstallState(transaction.StagingPath, transaction)
	if err != nil {
		// A crash while staging can leave an incomplete tree without state. The
		// immutable intent names this exact random path, so it remains owned; the
		// full-tree reparse check below still protects the deletion boundary.
		if !errors.Is(err, os.ErrNotExist) {
			statePath := filepath.Join(transaction.StagingPath, "installer", "install-state.json")
			if pathExists(statePath) {
				return err
			}
		}
	} else if state != nil && state.TransactionID != transaction.ID {
		return errors.New("staging tree is not owned by the interrupted transaction")
	}
	return removeTransactionTree(transaction.StagingPath, filepath.Dir(transaction.InstallRoot))
}

func removeTransactionTree(path, allowedRoot string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := rejectReparseTree(path); err != nil {
		return err
	}
	return removeAllSafe(path, allowedRoot)
}

func rejectReparseTree(root string) error {
	return filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		reparse, err := isReparsePoint(path)
		if err != nil {
			return err
		}
		if reparse {
			return fmt.Errorf("transaction tree contains a reparse point: %s", path)
		}
		return nil
	})
}

func rollbackMaintenancePublication(transaction setupTransaction) error {
	root := filepath.Dir(transaction.MaintenancePath)
	if transaction.Action == "uninstall" {
		for _, artifact := range []string{transaction.MaintenanceNew, transaction.MaintenanceBackup} {
			if pathExists(artifact) {
				return fmt.Errorf("unexpected maintenance publication artifact during uninstall rollback: %s", artifact)
			}
		}
		// Uninstall does not touch the cache before commit. Preserve whatever
		// currently occupies the path, including a legitimate concurrent update.
		return nil
	}
	stagedExists := pathExists(transaction.MaintenanceNew)
	backupExists := pathExists(transaction.MaintenanceBackup)
	if stagedExists && !backupExists {
		// Publication has not moved either fixed path yet. In particular, a
		// same-digest file that appeared at MaintenancePath is concurrent, not
		// transaction-owned.
		return removeTransactionPath(transaction.MaintenanceNew, root)
	}
	if stagedExists {
		if err := removeTransactionPath(transaction.MaintenanceNew, root); err != nil {
			return err
		}
	}
	if backupExists {
		if !transaction.MaintenanceExisted {
			return errors.New("unexpected maintenance backup for a transaction without a prior cache")
		}
		backupDigest, err := maintenanceFileDigest(transaction.MaintenanceBackup)
		if err != nil {
			return fmt.Errorf("validate maintenance rollback backup: %w", err)
		}
		if !strings.EqualFold(backupDigest, transaction.PreviousMaintenanceSHA256) {
			currentDigest, exists, currentErr := maintenanceFileDigestIfPresent(transaction.MaintenancePath)
			if currentErr != nil {
				return currentErr
			}
			if exists {
				if !strings.EqualFold(currentDigest, transaction.MaintenanceSHA256) {
					return errors.New("refusing to overwrite a concurrent maintenance executable with an unexpected backup")
				}
				if err := removeTransactionPath(transaction.MaintenancePath, root); err != nil {
					return err
				}
			}
			if err := renameDurableFile(transaction.MaintenanceBackup, transaction.MaintenancePath); err != nil {
				return err
			}
			// The file that won the validate-to-rename race has been restored.
			// It is not transaction-owned, but rollback has preserved it and may
			// safely complete.
			return nil
		}
		currentDigest, exists, err := maintenanceFileDigestIfPresent(transaction.MaintenancePath)
		if err != nil {
			return err
		}
		if exists {
			switch {
			case strings.EqualFold(currentDigest, transaction.MaintenanceSHA256):
				if err := removeTransactionPath(transaction.MaintenancePath, root); err != nil {
					return err
				}
			case strings.EqualFold(currentDigest, transaction.PreviousMaintenanceSHA256):
				return removeTransactionPath(transaction.MaintenanceBackup, root)
			default:
				return errors.New("refusing to overwrite a concurrent maintenance executable during rollback")
			}
		}
		return renameDurableFile(transaction.MaintenanceBackup, transaction.MaintenancePath)
	}
	if !transaction.MaintenanceExisted {
		currentDigest, exists, err := maintenanceFileDigestIfPresent(transaction.MaintenancePath)
		if err != nil || !exists {
			return err
		}
		if !strings.EqualFold(currentDigest, transaction.MaintenanceSHA256) {
			return errors.New("refusing to remove a concurrent maintenance executable during rollback")
		}
		return removeTransactionPath(transaction.MaintenancePath, root)
	}
	currentDigest, exists, err := maintenanceFileDigestIfPresent(transaction.MaintenancePath)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("previous maintenance executable is missing during rollback")
	}
	if !strings.EqualFold(currentDigest, transaction.PreviousMaintenanceSHA256) {
		return errors.New("maintenance executable changed concurrently during rollback")
	}
	if err := renameDurableFile(transaction.MaintenancePath, transaction.MaintenanceBackup); err != nil {
		return err
	}
	return renameDurableFile(transaction.MaintenanceBackup, transaction.MaintenancePath)
}

func validateMaintenanceSnapshot(path string, existed bool, expectedDigest string) error {
	digest, present, err := maintenanceFileDigestIfPresent(path)
	if err != nil {
		return err
	}
	if present != existed {
		if existed {
			return errors.New("recorded maintenance executable disappeared")
		}
		return errors.New("an unowned maintenance executable appeared")
	}
	if present && !strings.EqualFold(digest, expectedDigest) {
		return errors.New("maintenance executable digest no longer matches the transaction snapshot")
	}
	return nil
}

func maintenanceFileDigestIfPresent(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, fmt.Errorf("maintenance path is not a regular file: %s", path)
	}
	digest, err := fileSHA256(path)
	return digest, true, err
}

func maintenanceFileDigest(path string) (string, error) {
	digest, present, err := maintenanceFileDigestIfPresent(path)
	if err != nil {
		return "", err
	}
	if !present {
		return "", os.ErrNotExist
	}
	return digest, nil
}

func removeTransactionPath(path, allowedRoot string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing transaction reparse path: %s", path)
	}
	return removeAllSafe(path, allowedRoot)
}

func cleanupCommittedSetupTransaction(transaction setupTransaction) error {
	return cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readConnectorReconciliation)
}

func cleanupCommittedSetupTransactionWithReconciliationReader(
	transaction setupTransaction,
	readReconciliation func() (*connectorReconciliationState, error),
) error {
	if transaction.Action == "install" {
		state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
		if err != nil {
			return err
		}
		if state == nil || state.TransactionID != transaction.ID {
			return errors.New("committed install tree is not owned by the transaction")
		}
		if err := cleanupStagingTree(transaction); err != nil {
			return err
		}
		if pathExists(transaction.BackupPath) {
			backupState, err := loadTransactionInstallState(transaction.BackupPath, transaction)
			if err != nil {
				return err
			}
			// Committed cleanup may already have removed install-state.json before
			// encountering a locked file. The committed marker authorizes finishing
			// deletion of this exact random backup path.
			if backupState != nil && !installStateMatchesSnapshot(backupState, transaction.PreviousState) {
				return errors.New("committed transaction backup does not match previous state")
			}
			if err := removeTransactionTree(transaction.BackupPath, filepath.Dir(transaction.InstallRoot)); err != nil {
				return err
			}
		}
		if err := removeTransactionPath(transaction.MaintenanceNew, filepath.Dir(transaction.MaintenancePath)); err != nil {
			return err
		}
		return removeTransactionPath(transaction.MaintenanceBackup, filepath.Dir(transaction.MaintenancePath))
	}
	if pathExists(transaction.InstallRoot) {
		state, err := loadTransactionInstallState(transaction.InstallRoot, transaction)
		if err != nil {
			return err
		}
		if !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("committed uninstall found an unrelated install tree")
		}
		if err := removeTransactionTree(transaction.InstallRoot, filepath.Dir(transaction.InstallRoot)); err != nil {
			return err
		}
	}
	if pathExists(transaction.TrashPath) {
		state, err := loadTransactionInstallState(transaction.TrashPath, transaction)
		if err != nil {
			return err
		}
		// As above, a missing state file represents a partially deleted, exact
		// committed trash path; a present state must still match the snapshot.
		if state != nil && !installStateMatchesSnapshot(state, transaction.PreviousState) {
			return errors.New("committed uninstall trash does not match previous state")
		}
		if err := removeTransactionTree(transaction.TrashPath, filepath.Dir(transaction.InstallRoot)); err != nil {
			return err
		}
	}
	if transaction.DeleteUserData {
		residue, err := readReconciliation()
		if err != nil {
			return err
		}
		// Connector backups and token metadata are required for a safe retry.
		// Preserve DataRoot when third-party configuration could not be cleaned;
		// setup reports the precise residue after the core transaction completes.
		if residue == nil || len(residue.Failures) == 0 {
			if err := removeAllSafe(transaction.DataRoot, filepath.Dir(transaction.DataRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	maintenanceRoot := filepath.Dir(transaction.MaintenancePath)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if samePath(self, transaction.MaintenancePath) && pathExists(maintenanceRoot) {
		transactionRoot, err := defaultTransactionRoot()
		if err != nil {
			return err
		}
		if err := removeDirectoryAfterExit(
			maintenanceRoot,
			journalPaths(transactionRoot).Journal,
			os.Getpid(),
			transaction.ID,
		); err != nil {
			return fmt.Errorf("schedule installer-cache cleanup: %w", err)
		}
		return errTransactionCleanupDeferred
	}
	if err := removeAllSafe(maintenanceRoot, filepath.Dir(maintenanceRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
