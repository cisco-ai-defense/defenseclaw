// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	connectorReconciliationSchemaVersion = 1
	connectorReconciliationFileName      = "connector-reconciliation.json"
	maxConnectorReconciliationFailures   = 16
	// Retain enough bounded child output for private CI diagnostics. The public
	// Setup summary remains independently bounded by the setup-log writer.
	maxConnectorReconciliationMessage = 16384
)

type connectorReconciliationAttempt struct {
	Connector  string
	ConfigHome string
}

type connectorReconciliationFailure struct {
	Connector     string `json:"connector"`
	Operation     string `json:"operation"`
	ConfigHome    string `json:"config_home"`
	Message       string `json:"message"`
	TransactionID string `json:"transaction_id"`
}

type connectorReconciliationState struct {
	SchemaVersion int                              `json:"schema_version"`
	Failures      []connectorReconciliationFailure `json:"failures"`
}

type connectorReconciliationRecorder struct {
	attempts []connectorReconciliationAttempt
	failures []connectorReconciliationFailure
}

type connectorReconciliationReader func() (*connectorReconciliationState, error)
type connectorReconciliationWriter func([]connectorReconciliationAttempt, []connectorReconciliationFailure) error

func (recorder *connectorReconciliationRecorder) run(
	transactionID, connectorName, configHome, operation string,
	operationFn func() error,
) bool {
	recorder.attempts = append(recorder.attempts, connectorReconciliationAttempt{
		Connector:  connectorName,
		ConfigHome: configHome,
	})
	if err := operationFn(); err != nil {
		recorder.failures = append(recorder.failures, connectorReconciliationFailure{
			Connector:     connectorName,
			Operation:     operation,
			ConfigHome:    filepath.Clean(configHome),
			Message:       boundedReconciliationMessage(err.Error()),
			TransactionID: transactionID,
		})
		return false
	}
	return true
}

func (recorder *connectorReconciliationRecorder) persist() error {
	if len(recorder.attempts) == 0 {
		return nil
	}
	return updateConnectorReconciliation(recorder.attempts, recorder.failures)
}

// retryPendingConnectorReconciliation revisits durable residue that the
// current install transaction did not already touch. Verification comes first:
// a clean stale marker can be retired without mutating third-party settings.
// Teardown is only safe when this connector has not been attempted at another
// home, because connector backup metadata is shared beneath DataRoot.
func retryPendingConnectorReconciliation(
	transaction setupTransaction,
	gatewayPath string,
	recorder *connectorReconciliationRecorder,
	read func() (*connectorReconciliationState, error),
	run connectorLifecycleRunner,
) error {
	state, err := read()
	if err != nil || state == nil {
		return err
	}
	attemptedIdentities := make(map[string]bool, len(recorder.attempts))
	attemptedConnectors := make(map[string]bool, len(recorder.attempts))
	for _, attempt := range recorder.attempts {
		attemptedIdentities[connectorReconciliationKey(attempt.Connector, attempt.ConfigHome)] = true
		attemptedConnectors[strings.ToLower(attempt.Connector)] = true
	}
	seen := make(map[string]bool, len(state.Failures))
	for _, failure := range state.Failures {
		identity := connectorReconciliationKey(failure.Connector, failure.ConfigHome)
		if seen[identity] || attemptedIdentities[identity] {
			continue
		}
		seen[identity] = true
		connectorName := strings.ToLower(failure.Connector)
		codexHome, claudeHome, copilotHome, cursorHome, windsurfHome, antigravityHome, openCodeHome, omnigentHome, hermesHome := "", "", "", "", "", "", "", "", ""
		if connectorName == "codex" {
			codexHome = failure.ConfigHome
		} else if connectorName == "claudecode" {
			claudeHome = failure.ConfigHome
		} else if connectorName == "copilot" {
			copilotHome = failure.ConfigHome
		} else if connectorName == "cursor" {
			cursorHome = failure.ConfigHome
		} else if connectorName == "windsurf" {
			windsurfHome = failure.ConfigHome
		} else if connectorName == "antigravity" {
			antigravityHome = failure.ConfigHome
		} else if connectorName == "opencode" {
			openCodeHome = failure.ConfigHome
		} else if connectorName == "omnigent" {
			omnigentHome = failure.ConfigHome
		} else if connectorName == "hermes" {
			hermesHome = failure.ConfigHome
		}
		env := transactionChildEnvForConnectorHomes(
			transaction, codexHome, claudeHome, copilotHome, cursorHome, windsurfHome, antigravityHome, openCodeHome, omnigentHome, hermesHome,
		)
		verify := func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "verify", env)
		}
		verifyErr := verify()
		if verifyErr == nil {
			recorder.run(transaction.ID, connectorName, failure.ConfigHome, "verify", func() error { return nil })
			attemptedIdentities[identity] = true
			continue
		}
		if attemptedConnectors[connectorName] {
			recorder.run(transaction.ID, connectorName, failure.ConfigHome, "verify", func() error { return verifyErr })
			attemptedIdentities[identity] = true
			continue
		}

		// Claim the connector before teardown so at most one stale home can
		// consume its shared backup metadata in this recovery pass.
		attemptedConnectors[connectorName] = true
		teardownErr := run(gatewayPath, transaction.DataRoot, connectorName, "teardown", env)
		finalVerifyErr := verify()
		operation := "verify"
		terminalErr := finalVerifyErr
		if teardownErr != nil {
			operation = "teardown"
			terminalErr = fmt.Errorf("teardown retry: %w", teardownErr)
			if finalVerifyErr != nil {
				terminalErr = errors.Join(
					terminalErr,
					fmt.Errorf("verification after teardown: %w", finalVerifyErr),
				)
			}
		}
		recorder.run(transaction.ID, connectorName, failure.ConfigHome, operation, func() error {
			return terminalErr
		})
		attemptedIdentities[identity] = true
	}
	return nil
}

// retryPendingConvergedUninstallConnectorReconciliation gives an explicit
// uninstall retry one bounded opportunity to finish connector cleanup recorded
// by the exact converged uninstall transaction. Ordinary install/repair
// recovery does not call this path. The manifest-verified gateway embedded in
// the executing Setup binary is the only process authorized to revisit the
// transaction-bound configuration homes.
func retryPendingConvergedUninstallConnectorReconciliation(transaction setupTransaction) error {
	if err := retryPendingConvergedUninstallConnectorReconciliationWith(
		transaction,
		prepareConnectorMaintenanceGateway,
		readConnectorReconciliation,
		updateConnectorReconciliation,
		runConnectorLifecycleWithEnv,
	); err != nil {
		return err
	}
	return connectorReconciliationPendingError("uninstall")
}

func retryPendingConvergedUninstallConnectorReconciliationWith(
	transaction setupTransaction,
	prepare connectorMaintenanceGatewayProvider,
	read connectorReconciliationReader,
	write connectorReconciliationWriter,
	run connectorLifecycleRunner,
) error {
	if transaction.Action != "uninstall" {
		return errors.New("pending uninstall connector reconciliation requires an uninstall transaction")
	}
	readBoundState := func() (*connectorReconciliationState, error) {
		state, err := read()
		if err != nil || state == nil {
			return state, err
		}
		for _, failure := range state.Failures {
			if failure.TransactionID != transaction.ID {
				return nil, errors.New("pending connector reconciliation belongs to a different transaction")
			}
			bound := false
			for _, home := range connectorCleanupHomes(transaction, failure.Connector) {
				if samePath(home, failure.ConfigHome) {
					bound = true
					break
				}
			}
			if !bound {
				return nil, fmt.Errorf(
					"pending %s connector reconciliation names a configuration home outside the uninstall transaction",
					failure.Connector,
				)
			}
		}
		return state, nil
	}

	state, err := readBoundState()
	if err != nil || state == nil || len(state.Failures) == 0 {
		return err
	}
	maintenance, err := prepare()
	if err != nil {
		return fmt.Errorf("prepare connector maintenance gateway: %w", err)
	}
	if maintenance.cleanup == nil {
		maintenance.cleanup = func() {}
	}
	defer maintenance.cleanup()

	reconciliation := connectorReconciliationRecorder{}
	if err := retryPendingConnectorReconciliation(
		transaction,
		maintenance.path,
		&reconciliation,
		readBoundState,
		run,
	); err != nil {
		return err
	}
	if len(reconciliation.attempts) == 0 {
		return errors.New("pending uninstall connector reconciliation made no bounded attempts")
	}
	return write(reconciliation.attempts, reconciliation.failures)
}

func reconcileRemovedConnectors(
	transaction setupTransaction,
	gatewayPath string,
	childEnv []string,
	run connectorLifecycleRunner,
) connectorReconciliationRecorder {
	reconciliation := connectorReconciliationRecorder{}
	for _, connectorName := range transaction.PreviousConnectors {
		homes := connectorCleanupHomes(transaction, connectorName)
		if len(homes) == 0 {
			continue
		}
		primaryHome := homes[0]
		if !reconciliation.run(transaction.ID, connectorName, primaryHome, "teardown", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "teardown", childEnv)
		}) {
			continue
		}
		if !reconciliation.run(transaction.ID, connectorName, primaryHome, "verify", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "verify", childEnv)
		}) {
			continue
		}

		// The managed backup binding is the first restore authority, but an
		// older/repeated setup can leave strict product residue at another home
		// already bound into the transaction: the persisted install-state home or
		// the validated current home. Verify these finite candidates before any
		// fallback mutation. This preserves unrelated operator configuration and
		// closes the gap where teardown and VerifyClean could agree on a stale
		// historical target after consuming its shared backup metadata.
		for _, configHome := range homes[1:] {
			env := connectorLifecycleEnvForHome(transaction, connectorName, configHome)
			verify := func() error {
				return run(gatewayPath, transaction.DataRoot, connectorName, "verify", env)
			}
			if err := verify(); err == nil {
				reconciliation.run(transaction.ID, connectorName, configHome, "verify", func() error { return nil })
				continue
			}
			if !reconciliation.run(transaction.ID, connectorName, configHome, "teardown", func() error {
				return run(gatewayPath, transaction.DataRoot, connectorName, "teardown", env)
			}) {
				continue
			}
			reconciliation.run(transaction.ID, connectorName, configHome, "verify", verify)
		}
	}
	return reconciliation
}

func connectorCleanupHomes(transaction setupTransaction, connectorName string) []string {
	candidates := []string{connectorConfigHome(transaction, connectorName, true)}
	if transaction.PreviousState != nil {
		switch connectorName {
		case "codex":
			candidates = append(candidates, transaction.PreviousState.CodexHome)
		case "claudecode":
			candidates = append(candidates, transaction.PreviousState.ClaudeConfigDir)
		case "copilot":
			candidates = append(candidates, transaction.PreviousState.CopilotHome)
		case "cursor":
			candidates = append(candidates, transaction.PreviousState.CursorHome)
		case "windsurf":
			candidates = append(candidates, transaction.PreviousState.WindsurfUserHome)
		case "antigravity":
			candidates = append(candidates, transaction.PreviousState.AntigravityConfigDir)
		case "opencode":
			candidates = append(candidates, transaction.PreviousState.OpenCodeConfigDir)
		case "omnigent":
			candidates = append(candidates, transaction.PreviousState.OmnigentConfigHome)
		case "hermes":
			candidates = append(candidates, transaction.PreviousState.HermesHome)
		}
	}
	candidates = append(candidates, connectorConfigHome(transaction, connectorName, false))
	if connectorName != "windsurf" &&
		!connectorManagedBackupExists(transaction.DataRoot, connectorName) {
		// A predecessor or concurrent reconcile can discard its exact managed
		// backup after detecting config drift while retaining the field-level
		// cleanup authority. Installer state from a pre-home-binding release can
		// then name only a stale override. The native data root is already bound
		// to %USERPROFILE%\.defenseclaw, so its finite sibling is the only safe
		// default-home fallback. Windsurf is deliberately excluded: it has no
		// vendor home override and maintenance may target only the profile root
		// captured in installer state or managed backup, never an inferred
		// ambient profile. Verification runs before any mutation, and the
		// lifecycle command still rejects reparse points and unsafe ownership.
		candidates = append(candidates, connectorDefaultHomeBesideDataRoot(
			transaction.DataRoot,
			connectorName,
		))
	}

	homes := make([]string, 0, len(candidates))
	for index, candidate := range candidates {
		// Preserve the primary candidate even when corrupt or empty. The lifecycle
		// command is the path-validation authority and must record a fail-closed
		// refusal instead of allowing Setup to silently skip connector cleanup.
		if index > 0 && candidate == "" {
			continue
		}
		duplicate := false
		for _, existing := range homes {
			if samePath(existing, candidate) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			homes = append(homes, candidate)
		}
	}
	return homes
}

func connectorManagedBackupExists(dataRoot, connectorName string) bool {
	logicalName := ""
	switch connectorName {
	case "codex":
		logicalName = "config.toml"
	case "claudecode":
		logicalName = "settings.json"
	case "amp":
		logicalName = "config"
	case "copilot", "omnigent":
		logicalName = "config"
	case "cursor":
		logicalName = "hooks.json"
	case "windsurf":
		logicalName = "config"
	case "antigravity":
		logicalName = "hooks.json"
	case "opencode":
		logicalName = "config"
	case "hermes":
		logicalName = "config.yaml"
	default:
		return false
	}
	backupName := strings.NewReplacer("/", "_", `\`, "_", ":", "_", " ", "_").Replace(logicalName)
	if pathExists(filepath.Join(dataRoot, "connector_backups", connectorName, backupName+".json")) {
		return true
	}
	return connectorName == "antigravity" &&
		pathExists(filepath.Join(dataRoot, "connector_backups", connectorName, "config.json"))
}

func connectorDefaultHomeBesideDataRoot(dataRoot, connectorName string) string {
	cleanDataRoot := filepath.Clean(dataRoot)
	if !filepath.IsAbs(cleanDataRoot) || !strings.EqualFold(filepath.Base(cleanDataRoot), ".defenseclaw") {
		return ""
	}
	directory := ""
	switch connectorName {
	case "codex":
		directory = ".codex"
	case "claudecode":
		directory = ".claude"
	case "amp":
		return filepath.Join(filepath.Dir(cleanDataRoot), ".config", "amp")
	case "copilot":
		directory = ".copilot"
	case "cursor":
		directory = ".cursor"
	case "antigravity":
		return filepath.Join(filepath.Dir(cleanDataRoot), ".gemini", "config")
	case "opencode":
		directory = filepath.Join(".config", "opencode")
	case "omnigent":
		directory = ".omnigent"
	case "hermes":
		// Native Hermes defaults to LocalAppData, which is not derivable from
		// DataRoot's profile sibling. Only transaction/install-state/backup
		// bindings may authorize cleanup.
		return ""
	default:
		return ""
	}
	return filepath.Join(filepath.Dir(cleanDataRoot), directory)
}

func connectorLifecycleEnvForHome(transaction setupTransaction, connectorName, configHome string) []string {
	codexHome := transaction.PreviousCodexHome
	claudeHome := transaction.PreviousClaudeConfigDir
	copilotHome := transaction.PreviousCopilotHome
	cursorHome := transaction.PreviousCursorHome
	windsurfHome := transaction.PreviousWindsurfUserHome
	antigravityHome := transaction.PreviousAntigravityConfigDir
	openCodeHome := transaction.PreviousOpenCodeConfigDir
	omnigentHome := transaction.PreviousOmnigentConfigHome
	hermesHome := transaction.PreviousHermesHome
	if connectorName == "codex" {
		codexHome = configHome
	} else if connectorName == "claudecode" {
		claudeHome = configHome
	} else if connectorName == "copilot" {
		copilotHome = configHome
	} else if connectorName == "cursor" {
		cursorHome = configHome
	} else if connectorName == "windsurf" {
		windsurfHome = configHome
	} else if connectorName == "antigravity" {
		antigravityHome = configHome
	} else if connectorName == "opencode" {
		openCodeHome = configHome
	} else if connectorName == "omnigent" {
		omnigentHome = configHome
	} else if connectorName == "hermes" {
		hermesHome = configHome
	}
	return transactionChildEnvForConnectorHomes(
		transaction, codexHome, claudeHome, copilotHome, cursorHome, windsurfHome, antigravityHome, openCodeHome, omnigentHome, hermesHome,
	)
}

func reconcilePreservedConnectors(
	transaction setupTransaction,
	gatewayPath string,
	previousChildEnv []string,
	currentChildEnv []string,
	run connectorLifecycleRunner,
) connectorReconciliationRecorder {
	reconciliation := connectorReconciliationRecorder{}
	for _, connectorName := range transaction.PreviousConnectors {
		previousHome := connectorConfigHome(transaction, connectorName, true)
		currentHome := connectorConfigHome(transaction, connectorName, false)
		if !samePath(previousHome, currentHome) {
			if !reconciliation.run(
				transaction.ID,
				connectorName,
				previousHome,
				"teardown",
				func() error {
					return run(
						gatewayPath,
						transaction.DataRoot,
						connectorName,
						"teardown",
						previousChildEnv,
					)
				},
			) {
				continue
			}
			if !reconciliation.run(
				transaction.ID,
				connectorName,
				previousHome,
				"verify",
				func() error {
					return run(
						gatewayPath,
						transaction.DataRoot,
						connectorName,
						"verify",
						previousChildEnv,
					)
				},
			) {
				continue
			}
		}
		reconciliation.run(transaction.ID, connectorName, currentHome, "reconcile", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "reconcile", currentChildEnv)
		})
	}
	return reconciliation
}

func boundedReconciliationMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > maxConnectorReconciliationMessage {
		message = message[:maxConnectorReconciliationMessage]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	if message == "" {
		return "connector operation failed without an error message"
	}
	return message
}

func connectorReconciliationPath() (string, error) {
	root, err := defaultTransactionRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, connectorReconciliationFileName), nil
}

func updateConnectorReconciliation(
	attempts []connectorReconciliationAttempt,
	failures []connectorReconciliationFailure,
) error {
	path, err := connectorReconciliationPath()
	if err != nil {
		return err
	}
	return updateConnectorReconciliationAt(path, attempts, failures)
}

func updateConnectorReconciliationAt(
	path string,
	attempts []connectorReconciliationAttempt,
	failures []connectorReconciliationFailure,
) error {
	state, err := readConnectorReconciliationAt(path)
	if err != nil {
		return err
	}
	replace := state != nil
	if state == nil {
		state = &connectorReconciliationState{SchemaVersion: connectorReconciliationSchemaVersion}
	}

	attempted := make(map[string]bool, len(attempts))
	for _, attempt := range attempts {
		if err := validateConnectorReconciliationIdentity(attempt.Connector, attempt.ConfigHome); err != nil {
			return err
		}
		attempted[connectorReconciliationKey(attempt.Connector, attempt.ConfigHome)] = true
	}
	retained := state.Failures[:0]
	for _, failure := range state.Failures {
		if !attempted[connectorReconciliationKey(failure.Connector, failure.ConfigHome)] {
			retained = append(retained, failure)
		}
	}
	state.Failures = append(retained, failures...)
	if err := validateConnectorReconciliationState(state); err != nil {
		return err
	}
	if len(state.Failures) == 0 {
		if !replace {
			return nil
		}
		if err := validatePrivateTransactionPath(path, false); err != nil {
			return err
		}
		return removeRegularMarkerIfPresent(path)
	}
	sort.Slice(state.Failures, func(left, right int) bool {
		leftKey := connectorReconciliationFailureKey(state.Failures[left])
		rightKey := connectorReconciliationFailureKey(state.Failures[right])
		return leftKey < rightKey
	})
	return writeDurableValue(path, *state, replace)
}

func readConnectorReconciliation() (*connectorReconciliationState, error) {
	path, err := connectorReconciliationPath()
	if err != nil {
		return nil, err
	}
	return readConnectorReconciliationAt(path)
}

func readConnectorReconciliationAt(path string) (*connectorReconciliationState, error) {
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
		return nil, fmt.Errorf("connector reconciliation state is not a regular file: %s", path)
	}
	if err := validatePrivateTransactionPath(path, false); err != nil {
		return nil, err
	}
	var state connectorReconciliationState
	if err := readJSON(path, &state); err != nil {
		return nil, fmt.Errorf("read connector reconciliation state %s: %w", path, err)
	}
	if err := validateConnectorReconciliationState(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func validateConnectorReconciliationState(state *connectorReconciliationState) error {
	if state == nil || state.SchemaVersion != connectorReconciliationSchemaVersion {
		return errors.New("unsupported connector reconciliation state schema")
	}
	if len(state.Failures) > maxConnectorReconciliationFailures {
		return errors.New("connector reconciliation state contains too many failures")
	}
	seen := make(map[string]bool, len(state.Failures))
	for _, failure := range state.Failures {
		if err := validateConnectorReconciliationIdentity(failure.Connector, failure.ConfigHome); err != nil {
			return err
		}
		switch failure.Operation {
		case "teardown", "verify", "configure", "reconcile", "payload-missing":
		default:
			return fmt.Errorf("invalid connector reconciliation operation %q", failure.Operation)
		}
		if failure.Message == "" || len(failure.Message) > maxConnectorReconciliationMessage {
			return errors.New("invalid connector reconciliation failure message")
		}
		if !validSetupTransactionID(failure.TransactionID) {
			return errors.New("invalid connector reconciliation transaction identity")
		}
		key := connectorReconciliationFailureKey(failure)
		if seen[key] {
			return errors.New("duplicate connector reconciliation failure")
		}
		seen[key] = true
	}
	return nil
}

func validateConnectorReconciliationIdentity(connectorName, configHome string) error {
	if connectorName == "none" || !validConnector(connectorName) {
		return fmt.Errorf("invalid connector reconciliation target %q", connectorName)
	}
	if configHome == "" || !filepath.IsAbs(configHome) || filepath.Clean(configHome) != configHome {
		return fmt.Errorf("invalid %s connector configuration home", connectorName)
	}
	return nil
}

func connectorReconciliationKey(connectorName, configHome string) string {
	return strings.ToLower(connectorName) + "\x00" + strings.ToLower(filepath.Clean(configHome))
}

func connectorReconciliationFailureKey(failure connectorReconciliationFailure) string {
	return connectorReconciliationKey(failure.Connector, failure.ConfigHome) +
		"\x00" + failure.Operation + "\x00" + failure.TransactionID
}

func connectorReconciliationSummary() (string, error) {
	state, err := readConnectorReconciliation()
	if err != nil || state == nil || len(state.Failures) == 0 {
		return "", err
	}
	parts := make([]string, 0, len(state.Failures))
	for _, failure := range state.Failures {
		parts = append(parts, fmt.Sprintf(
			"%s %s at %s: %s",
			failure.Connector,
			failure.Operation,
			failure.ConfigHome,
			failure.Message,
		))
	}
	return strings.Join(parts, "; "), nil
}

func connectorReconciliationPendingError(action string) error {
	summary, err := connectorReconciliationSummary()
	if err != nil {
		return fmt.Errorf("read pending connector reconciliation: %w", err)
	}
	if summary == "" {
		return nil
	}
	return fmt.Errorf(
		"DefenseClaw core %s completed, but connector reconciliation remains pending: %s; fix the reported client configuration or reinstall the missing payload, then rerun Setup",
		action,
		summary,
	)
}

func connectorConfigHome(transaction setupTransaction, connectorName string, previous bool) string {
	switch connectorName {
	case "codex":
		if previous {
			return transaction.PreviousCodexHome
		}
		return transaction.CodexHome
	case "claudecode":
		if previous {
			return transaction.PreviousClaudeConfigDir
		}
		return transaction.ClaudeConfigDir
	case "amp":
		// Amp has no home override. DataRoot is bound to the current token's
		// %USERPROFILE%\.defenseclaw, so this is the exact documented
		// %USERPROFILE%\.config\amp directory for lifecycle operations.
		return connectorDefaultHomeBesideDataRoot(transaction.DataRoot, connectorName)
	case "copilot":
		if previous {
			return transaction.PreviousCopilotHome
		}
		return transaction.CopilotHome
	case "cursor":
		if previous {
			return transaction.PreviousCursorHome
		}
		return transaction.CursorHome
	case "windsurf":
		if previous {
			return transaction.PreviousWindsurfUserHome
		}
		return transaction.WindsurfUserHome
	case "antigravity":
		if previous {
			return transaction.PreviousAntigravityConfigDir
		}
		return transaction.AntigravityConfigDir
	case "opencode":
		if previous {
			return transaction.PreviousOpenCodeConfigDir
		}
		return transaction.OpenCodeConfigDir
	case "omnigent":
		if previous {
			return transaction.PreviousOmnigentConfigHome
		}
		return transaction.OmnigentConfigHome
	case "hermes":
		if previous {
			return transaction.PreviousHermesHome
		}
		return transaction.HermesHome
	default:
		return ""
	}
}
