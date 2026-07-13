// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConnectorReconciliationRecordsAndClearsPerConfigHome(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "private", connectorReconciliationFileName)
	codexHome := filepath.Join(root, "codex")
	claudeHome := filepath.Join(root, "claude")
	codexID := strings.Repeat("a", 32)
	claudeID := strings.Repeat("b", 32)

	codexAttempt := connectorReconciliationAttempt{Connector: "codex", ConfigHome: codexHome}
	codexFailure := connectorReconciliationFailure{
		Connector:     "codex",
		Operation:     "payload-missing",
		ConfigHome:    codexHome,
		Message:       "gateway quarantined",
		TransactionID: codexID,
	}
	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{codexAttempt}, []connectorReconciliationFailure{codexFailure}); err != nil {
		t.Fatal(err)
	}

	claudeAttempt := connectorReconciliationAttempt{Connector: "claudecode", ConfigHome: claudeHome}
	claudeFailure := connectorReconciliationFailure{
		Connector:     "claudecode",
		Operation:     "teardown",
		ConfigHome:    claudeHome,
		Message:       "settings file is locked",
		TransactionID: claudeID,
	}
	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{claudeAttempt}, []connectorReconciliationFailure{claudeFailure}); err != nil {
		t.Fatal(err)
	}

	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{codexAttempt}, nil); err != nil {
		t.Fatal(err)
	}
	state, err := readConnectorReconciliationAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || len(state.Failures) != 1 || state.Failures[0].Connector != "claudecode" {
		t.Fatalf("successful Codex retry removed the wrong residue: %+v", state)
	}

	if err := updateConnectorReconciliationAt(path, []connectorReconciliationAttempt{claudeAttempt}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciliation marker survived complete cleanup: %v", err)
	}
}

func TestConnectorReconciliationRecorderCapturesMissingPayload(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "private", connectorReconciliationFileName)
	home := filepath.Join(root, "codex")
	transactionID := strings.Repeat("c", 32)
	recorder := connectorReconciliationRecorder{}
	if recorder.run(transactionID, "codex", home, "payload-missing", func() error {
		return errors.New("installed gateway payload is missing")
	}) {
		t.Fatal("missing payload was reported as a successful connector operation")
	}
	if err := updateConnectorReconciliationAt(path, recorder.attempts, recorder.failures); err != nil {
		t.Fatal(err)
	}
	state, err := readConnectorReconciliationAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || len(state.Failures) != 1 {
		t.Fatalf("missing-payload residue was not durable: %+v", state)
	}
	failure := state.Failures[0]
	if failure.Operation != "payload-missing" || failure.TransactionID != transactionID {
		t.Fatalf("unexpected missing-payload residue: %+v", failure)
	}
}

func TestReconcileRemovedConnectorsTreatsMissingPayloadAsResidue(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transaction := setupTransaction{
		ID:                 strings.Repeat("e", 32),
		DataRoot:           filepath.Join(root, "data"),
		PreviousConnectors: []string{"codex"},
		PreviousCodexHome:  filepath.Join(root, "codex"),
	}
	called := false
	recorder := reconcileRemovedConnectors(
		transaction,
		filepath.Join(root, "missing-gateway.exe"),
		nil,
		func(_, _, _, _ string, _ []string) error {
			called = true
			return nil
		},
	)
	if called {
		t.Fatal("connector command ran without an installed gateway payload")
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "payload-missing" {
		t.Fatalf("missing gateway was not reduced to durable residue: %+v", recorder.failures)
	}
}

func TestReconcileRemovedConnectorsDoesNotLetClientFailureEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	gatewayPath := filepath.Join(root, "defenseclaw-gateway.exe")
	if err := os.WriteFile(gatewayPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	transaction := setupTransaction{
		ID:                      strings.Repeat("f", 32),
		DataRoot:                filepath.Join(root, "data"),
		PreviousConnectors:      []string{"claudecode"},
		PreviousClaudeConfigDir: filepath.Join(root, "claude"),
	}
	var actions []string
	recorder := reconcileRemovedConnectors(transaction, gatewayPath, nil, func(_, _, _, action string, _ []string) error {
		actions = append(actions, action)
		return errors.New("third-party settings are read-only")
	})
	if strings.Join(actions, ",") != "teardown" {
		t.Fatalf("connector actions = %v, want teardown only after failure", actions)
	}
	if len(recorder.failures) != 1 || recorder.failures[0].Operation != "teardown" {
		t.Fatalf("third-party failure was not isolated as residue: %+v", recorder.failures)
	}
}

func TestBoundedReconciliationMessageIsSingleLineValidUTF8(t *testing.T) {
	t.Parallel()
	message := boundedReconciliationMessage("  locked\r\n" + strings.Repeat("é", maxConnectorReconciliationMessage))
	if strings.ContainsAny(message, "\r\n\t") {
		t.Fatalf("message retained control whitespace: %q", message)
	}
	if len(message) > maxConnectorReconciliationMessage {
		t.Fatalf("message length = %d, want <= %d", len(message), maxConnectorReconciliationMessage)
	}
	if !utf8.ValidString(message) {
		t.Fatal("bounded message is not valid UTF-8")
	}
}

func TestValidateConnectorReconciliationRejectsUnsafeState(t *testing.T) {
	t.Parallel()
	state := &connectorReconciliationState{
		SchemaVersion: connectorReconciliationSchemaVersion,
		Failures: []connectorReconciliationFailure{{
			Connector:     "codex",
			Operation:     "shell",
			ConfigHome:    filepath.Join(t.TempDir(), "codex"),
			Message:       "unexpected operation",
			TransactionID: strings.Repeat("d", 32),
		}},
	}
	if err := validateConnectorReconciliationState(state); err == nil {
		t.Fatal("unsupported connector operation was accepted")
	}
}
