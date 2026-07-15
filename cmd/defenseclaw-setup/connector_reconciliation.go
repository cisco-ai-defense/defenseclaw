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
	maxConnectorReconciliationMessage    = 2048
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
		codexHome, claudeHome := "", ""
		if connectorName == "codex" {
			codexHome = failure.ConfigHome
		} else {
			claudeHome = failure.ConfigHome
		}
		env := transactionChildEnvForHomes(transaction, codexHome, claudeHome)
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

func reconcileRemovedConnectors(
	transaction setupTransaction,
	gatewayPath string,
	childEnv []string,
	run connectorLifecycleRunner,
) connectorReconciliationRecorder {
	reconciliation := connectorReconciliationRecorder{}
	for _, connectorName := range transaction.PreviousConnectors {
		configHome := connectorConfigHome(transaction, connectorName, true)
		if !reconciliation.run(transaction.ID, connectorName, configHome, "teardown", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "teardown", childEnv)
		}) {
			continue
		}
		reconciliation.run(transaction.ID, connectorName, configHome, "verify", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "verify", childEnv)
		})
	}
	return reconciliation
}

func reconcilePreservedConnectors(
	transaction setupTransaction,
	gatewayPath string,
	childEnv []string,
	run connectorLifecycleRunner,
) connectorReconciliationRecorder {
	reconciliation := connectorReconciliationRecorder{}
	for _, connectorName := range transaction.PreviousConnectors {
		configHome := connectorConfigHome(transaction, connectorName, true)
		reconciliation.run(transaction.ID, connectorName, configHome, "reconcile", func() error {
			return run(gatewayPath, transaction.DataRoot, connectorName, "reconcile", childEnv)
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
	if connectorName != "codex" && connectorName != "claudecode" {
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
	default:
		return ""
	}
}
