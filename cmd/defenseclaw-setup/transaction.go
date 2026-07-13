// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	SchemaVersion             int                      `json:"schema_version"`
	ID                        string                   `json:"id"`
	Action                    string                   `json:"action"`
	InstallRoot               string                   `json:"install_root"`
	DataRoot                  string                   `json:"data_root"`
	MaintenancePath           string                   `json:"maintenance_path"`
	StagingPath               string                   `json:"staging_path"`
	BackupPath                string                   `json:"backup_path"`
	TrashPath                 string                   `json:"trash_path"`
	MaintenanceNew            string                   `json:"maintenance_new"`
	MaintenanceBackup         string                   `json:"maintenance_backup"`
	HadInstall                bool                     `json:"had_install"`
	MaintenanceExisted        bool                     `json:"maintenance_existed"`
	PreviousMaintenanceSHA256 string                   `json:"previous_maintenance_sha256,omitempty"`
	PreviousState             *installState            `json:"previous_state,omitempty"`
	PreviousPath              userPathSnapshot         `json:"previous_path"`
	PreviousAutoStart         gatewayAutoStartSnapshot `json:"previous_auto_start"`
	PreviousServices          serviceState             `json:"previous_services"`
	PreviousConnectors        []string                 `json:"previous_connectors,omitempty"`
	TargetConnector           string                   `json:"target_connector"`
	TargetMode                string                   `json:"target_mode"`
	TargetServices            serviceState             `json:"target_services"`
	FromVersion               string                   `json:"from_version,omitempty"`
	TargetVersion             string                   `json:"target_version,omitempty"`
	PreviousCodexHome         string                   `json:"previous_codex_home,omitempty"`
	PreviousClaudeConfigDir   string                   `json:"previous_claude_config_dir,omitempty"`
	CodexHome                 string                   `json:"codex_home,omitempty"`
	ClaudeConfigDir           string                   `json:"claude_config_dir,omitempty"`
	MaintenanceSHA256         string                   `json:"maintenance_sha256,omitempty"`
	DeleteUserData            bool                     `json:"delete_user_data,omitempty"`
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
	Converge   func(setupTransaction) error
	Cleanup    func(setupTransaction) error
	Transition func(setupTransaction, string, string) error
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
	targetConnector := opts.Connector
	targetServices := requestedServices(opts, previousServices)
	if action == "uninstall" {
		targetConnector = "none"
		targetServices = serviceState{}
	}
	if action == "install" && targetServices.Gateway && autoStartSnapshot.Existed &&
		autoStartSnapshot.Value != gatewayAutoStartCommand(gatewayPath) &&
		autoStartSnapshot.Value != legacyGatewayAutoStartCommand(gatewayPath) {
		return setupTransaction{}, errors.New("refusing an unrelated DefenseClawGateway startup registration")
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
	previousCodexHome := defaultCodexHome
	previousClaudeConfigDir := defaultClaudeConfigDir
	if oldState != nil {
		if oldState.CodexHome != "" {
			previousCodexHome = oldState.CodexHome
		} else if inferred, inferErr := inferManagedConnectorHome(dataRoot, "codex", "config.toml", defaultCodexHome); inferErr != nil {
			return setupTransaction{}, inferErr
		} else {
			previousCodexHome = inferred
		}
		if oldState.ClaudeConfigDir != "" {
			previousClaudeConfigDir = oldState.ClaudeConfigDir
		} else if inferred, inferErr := inferManagedConnectorHome(dataRoot, "claudecode", "settings.json", defaultClaudeConfigDir); inferErr != nil {
			return setupTransaction{}, inferErr
		} else {
			previousClaudeConfigDir = inferred
		}
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
	return setupTransaction{
		SchemaVersion:             setupTransactionSchemaVersion,
		ID:                        id,
		Action:                    action,
		InstallRoot:               installRoot,
		DataRoot:                  dataRoot,
		MaintenancePath:           maintenancePath,
		StagingPath:               staging,
		BackupPath:                backup,
		TrashPath:                 trash,
		MaintenanceNew:            maintenanceNew,
		MaintenanceBackup:         maintenanceBackup,
		HadInstall:                oldState != nil,
		MaintenanceExisted:        maintenanceExisted,
		PreviousMaintenanceSHA256: previousMaintenanceSHA256,
		PreviousState:             previousState,
		PreviousPath:              pathSnapshot,
		PreviousAutoStart:         autoStartSnapshot,
		PreviousServices:          previousServices,
		PreviousConnectors:        normalizeStringSlice(connectorsForNativeUninstall(oldState, dataRoot)),
		TargetConnector:           targetConnector,
		TargetMode:                opts.Mode,
		TargetServices:            targetServices,
		FromVersion:               fromVersion,
		TargetVersion:             targetVersion,
		PreviousCodexHome:         previousCodexHome,
		PreviousClaudeConfigDir:   previousClaudeConfigDir,
		CodexHome:                 codexHome,
		ClaudeConfigDir:           claudeConfigDir,
		MaintenanceSHA256:         maintenanceSHA256,
		DeleteUserData:            opts.DeleteUserData,
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
	return transitionSetupJournal(transaction, setupPhaseIntent, setupPhaseCommitted)
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
	case setupPhaseIntent, setupPhaseCommitted, setupPhaseConverged, setupPhaseComplete:
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
		Converge: convergeCommittedSetupTransaction,
		Cleanup:  cleanupCommittedSetupTransaction,
		Transition: func(transaction setupTransaction, fromPhase, toPhase string) error {
			return transitionSetupJournal(transaction, fromPhase, toPhase)
		},
	})
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
	currentGateway := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	if pathExists(currentGateway) {
		if err := rejectReparseTree(transaction.InstallRoot); err != nil {
			return err
		}
		if _, err := stopOwnedServices(currentGateway, transaction.DataRoot); err != nil {
			return err
		}
	}
	if err := rollbackTransactionFiles(transaction); err != nil {
		return err
	}
	var restoreErrors []error
	if err := rollbackMaintenancePublication(transaction); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	if transaction.PreviousState != nil {
		gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
		if _, err := startMissingServices(gatewayPath, transaction.DataRoot, transaction.PreviousServices); err != nil {
			restoreErrors = append(restoreErrors, err)
		}
	}
	return errors.Join(restoreErrors...)
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
			previousChildEnv := transactionPreviousChildEnv(transaction)
			for _, connectorName := range transaction.PreviousConnectors {
				if err := runConnectorLifecycleWithEnv(
					gatewayPath,
					transaction.DataRoot,
					connectorName,
					"teardown",
					previousChildEnv,
				); err != nil {
					return err
				}
				if err := runConnectorLifecycleWithEnv(
					gatewayPath,
					transaction.DataRoot,
					connectorName,
					"verify",
					previousChildEnv,
				); err != nil {
					return err
				}
			}
		} else if transaction.PreviousState != nil || len(transaction.PreviousConnectors) != 0 {
			return errors.New("committed uninstall lost its transaction trash tree before connector teardown")
		}
		if _, _, err := configureGatewayAutoStart(publishedGateway, false); err != nil {
			return err
		}
		if transaction.PreviousState != nil && transaction.PreviousState.PathEntryOwned {
			reusedSeparator := transaction.PreviousState.PathSeparatorReused
			if err := removeUserPath(filepath.Join(transaction.InstallRoot, "bin"), reusedSeparator); err != nil {
				return err
			}
		}
		if err := unregisterInstalledAppOwned(transaction.InstallRoot); err != nil {
			return err
		}
		return nil
	}
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
	childEnv := transactionChildEnv(transaction)
	previousChildEnv := transactionPreviousChildEnv(transaction)
	if shouldRunPackagedMigrations(transaction.FromVersion, transaction.TargetVersion) {
		if err := runPackagedMigrationsWithEnv(
			transaction.InstallRoot,
			transaction.DataRoot,
			transaction.FromVersion,
			transaction.TargetVersion,
			childEnv,
		); err != nil {
			return err
		}
	}
	// Publish the signed no-console launcher outside both InstallRoot and
	// DataRoot before connector configuration writes absolute commands. The
	// publishing/active handshake makes this step idempotent under committed
	// transaction recovery and re-enables a data-preserving reinstall.
	if err := publishStableHookRuntime(
		filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-hook.exe"),
		transaction.DataRoot,
		transaction.ID,
	); err != nil {
		return fmt.Errorf("publish stable hook runtime: %w", err)
	}
	gatewayPath := filepath.Join(transaction.InstallRoot, "bin", "defenseclaw-gateway.exe")
	if err := teardownSupersededConnectors(
		transaction,
		gatewayPath,
		previousChildEnv,
		runConnectorLifecycleWithEnv,
	); err != nil {
		return err
	}
	if transaction.TargetConnector != "none" {
		opts := options{Connector: transaction.TargetConnector, Mode: transaction.TargetMode, Quiet: true}
		if err := runInitialConfigurationWithEnv(transaction.InstallRoot, transaction.DataRoot, opts, childEnv); err != nil {
			return err
		}
		if err := runConnectorLifecycleWithEnv(
			gatewayPath,
			transaction.DataRoot,
			transaction.TargetConnector,
			"reconcile",
			childEnv,
		); err != nil {
			return err
		}
	}
	if _, _, err := addUserPath(filepath.Join(transaction.InstallRoot, "bin")); err != nil {
		return err
	}
	if err := registerInstalledAppOwned(
		state.MaintenancePath,
		transaction.InstallRoot,
		state.Version,
		transaction.ID,
		state.UnsignedLocalArtifact,
	); err != nil {
		return err
	}
	if _, _, err := configureGatewayAutoStart(gatewayPath, transaction.TargetServices.Gateway); err != nil {
		return err
	}
	if _, err = startMissingServices(gatewayPath, transaction.DataRoot, transaction.TargetServices); err != nil {
		return err
	}
	if err := verifySelectedServices(gatewayPath, transaction.DataRoot, transaction.TargetServices); err != nil {
		return err
	}
	return nil
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
		if err := removeAllSafe(transaction.DataRoot, filepath.Dir(transaction.DataRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	maintenanceRoot := filepath.Dir(transaction.MaintenancePath)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if samePath(self, transaction.MaintenancePath) && pathExists(maintenanceRoot) {
		if err := removeDirectoryAfterExit(maintenanceRoot, os.Getpid()); err != nil {
			return fmt.Errorf("schedule installer-cache cleanup: %w", err)
		}
		return errTransactionCleanupDeferred
	}
	if err := removeAllSafe(maintenanceRoot, filepath.Dir(maintenanceRoot)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
