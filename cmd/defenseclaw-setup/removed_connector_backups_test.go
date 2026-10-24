// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// until 1.1 (rel-1-0-4 GAP-0651): DELETEUSERDATA=1 keeps the removed
// connectors' connector_backups/<connector> folders, which the leftover notes
// tell the user to copy back from, beside the data folder, and the notes name
// them there. What the removal took is not listed as left for the user.
func TestCommittedUninstallKeepsTheRemovedConnectorBackupsTheNotesName(t *testing.T) {
	bypassDeferredUninstallCleanupForTest(t)
	resetRemovedConnectorNotes(t)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.DeleteUserData = true
	agentConfig := filepath.Join(filepath.Dir(dataRoot), ".omnigent", "config.yaml")
	backups := filepath.Join(dataRoot, "connector_backups")
	kept := map[string]string{
		filepath.Join("omnigent", "config.json"):                                `{"connector":"omnigent","pristine_bytes":"bW9kZWw6IGxvY2FsCg=="}`,
		filepath.Join("omnigent", "defenseclaw_omnigent_policy.py.edited-0123"): "# my edit\n",
		filepath.Join("openhands", "config.json"):                               `{"connector":"openhands"}`,
	}
	files := map[string]string{
		filepath.Join(dataRoot, "config.yaml"):                             "config_version: 9\n",
		filepath.Join(dataRoot, "hooks", "defenseclaw_omnigent_policy.py"): "# defenseclaw-managed-policy v1\n",
		filepath.Join(backups, "codex", "config.toml.json"):                "{}",
		agentConfig: "policy_modules: [defenseclaw_omnigent_policy]\n",
	}
	for rel, body := range kept {
		files[filepath.Join(backups, rel)] = body
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	leftovers := []removedConnectorLeftover{
		{Path: agentConfig, What: "OmniGent still imports DefenseClaw's policy module from here", Step: "remove it"},
		{Path: filepath.Join(dataRoot, "hooks", "defenseclaw_omnigent_policy.py"), What: "the stub that blocks every OmniGent call", Step: "delete it once nothing above runs it"},
		{Path: filepath.Join(backups, "omnigent"), What: "the copies of your files DefenseClaw saved before its setup changed them", Step: "copy back what you need, then delete this folder"},
		{Path: filepath.Join(backups, "omnigent", "defenseclaw_omnigent_policy.py.edited-0123"), What: "your edited module", Step: "copy back what you need, then delete it"},
	}
	payload, err := json.Marshal(map[string]any{"connector": "omnigent", "ok": true, "leftovers": leftovers})
	if err != nil {
		t.Fatal(err)
	}
	recordRemovedConnectorLeftovers("omnigent", payload)

	readNone := func() (*connectorReconciliationState, error) { return nil, nil }
	if err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readNone); err != nil {
		t.Fatalf("cleanupCommittedSetupTransaction: %v", err)
	}
	assertPathAbsent(t, dataRoot)
	root := removedConnectorBackupsKeptRoot(dataRoot)
	for rel, body := range kept {
		if got, err := os.ReadFile(filepath.Join(root, rel)); err != nil || string(got) != body {
			t.Fatalf("kept backup %s = %q, %v; want %q", rel, got, err, body)
		}
	}
	assertPathAbsent(t, filepath.Join(root, "codex"))

	notes := removedConnectorNotesText()
	for _, want := range []string{agentConfig, filepath.Join(root, "omnigent") + ":", filepath.Join(root, "omnigent", "defenseclaw_omnigent_policy.py.edited-0123") + ":", "data folder was removed"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes do not name %q:\n%s", want, notes)
		}
	}
	// Every path the notes tell the user about is still there.
	for _, line := range strings.Split(notes, "\r\n") {
		path, _, ok := strings.Cut(strings.TrimPrefix(line, "  - "), ": ")
		if !strings.HasPrefix(line, "  - ") || !ok {
			continue
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("notes name %s, which the uninstall removed: %v\n%s", path, err, notes)
		}
	}

	// A second data removal keeps the first copy and adds its own.
	if err := os.MkdirAll(filepath.Join(backups, "omnigent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backups, "omnigent", "config.json"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, readNone); err != nil {
		t.Fatalf("second cleanupCommittedSetupTransaction: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "omnigent-2", "config.json")); err != nil || string(got) != "second" {
		t.Fatalf("second kept backup = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "omnigent", "config.json")); err != nil || string(got) != kept[filepath.Join("omnigent", "config.json")] {
		t.Fatalf("first kept backup = %q, %v", got, err)
	}
}

// until 1.1: when a removed connector's backups cannot be moved out, the data
// folder stays whole.
func TestCommittedUninstallKeepsTheDataWhenTheBackupsCannotMove(t *testing.T) {
	bypassDeferredUninstallCleanupForTest(t)
	resetRemovedConnectorNotes(t)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	transaction := testSetupTransactionForRoots("uninstall", installRoot, dataRoot, maintenancePath, nil)
	transaction.DeleteUserData = true
	record := filepath.Join(dataRoot, "connector_backups", "openhands", "config.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file where the kept folder goes.
	if err := os.WriteFile(removedConnectorBackupsKeptRoot(dataRoot), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cleanupCommittedSetupTransactionWithReconciliationReader(transaction, func() (*connectorReconciliationState, error) { return nil, nil })
	if err == nil || !strings.Contains(err.Error(), "in the way") {
		t.Fatalf("cleanup = %v, want the kept folder refused", err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the backup went with the data: %v", err)
	}
}
