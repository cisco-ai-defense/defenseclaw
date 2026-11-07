// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeG669Files(t *testing.T, dataDir string, rels []string) {
	t.Helper()
	for _, rel := range rels {
		path := filepath.Join(dataDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-0669 review M1: the files `enterprise acp setup` and the credential
// store write below acp/ are DefenseClaw's and go with a purge, with the
// folders they leave empty.
func TestGAP0669PurgeRemovesManagedACPState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	managed := []string{
		"acp/.token",
		"acp/zed-kiro.token",
		"acp/zed-kiro.enrollment.json",
		"acp/zed-kiro.contract-lock.json",
		"acp/owned-entries.json",
		"acp/.enterprise-credentials.lock",
		"acp/.enterprise-enrollment.lock",
		"acp/enterprise-token-index/" + strings.Repeat("a", 64) + ".json",
		"acp/enterprise-credentials/" + strings.Repeat("b", 64) + ".json",
	}
	writeG669Files(t, dataDir, managed)
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Errorf("a data directory with only managed ACP state stayed: %v", err)
	}
}

// Benign twin: account files in and around acp/, including ones whose names
// resemble managed ones, stay.
func TestGAP0669PurgeKeepsAccountFilesInACP(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	keep := []string{
		"acp/account.txt",
		"acp/inventory.db",
		"acp/unknown-agent.token",
		"acp/zed-kiro.token.bak",
		"acp/notes.contract-lock.json",
		"acp/enterprise-credentials/account.json",
		"acp/enterprise-token-index/" + strings.Repeat("A", 64) + ".json",
		"acp/deeper/zed-kiro.token",
	}
	writeG669Files(t, dataDir, append(keep, "acp/zed-kiro.token", "session-facts.json"))
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range keep {
		if got, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(rel))); err != nil || string(got) != rel {
			t.Errorf("account entry %s changed: %q, %v", rel, got, err)
		}
	}
	for _, rel := range []string{"acp/zed-kiro.token", "session-facts.json"} {
		if _, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("managed entry %s stayed: %v", rel, err)
		}
	}
}

// GAP-0669 review M2: lock files left beside managed files are managed.
func TestGAP0669PurgeRemovesManagedLocks(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	managed := []string{
		".codex-lifecycle.lock",
		".hermes-lifecycle.lock",
		".hook-api-token-publish.lock",
		"hook_contract_lock.json.lock",
		"agent_selection.json.lock",
		"hooks/.otlp-codex.token.lock",
		"hooks/.hookcfg.lock",
	}
	writeG669Files(t, dataDir, managed)
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Errorf("a data directory with only managed locks stayed: %v", err)
	}
}

// Benign twin: a lock beside an account file or an unknown connector stays.
func TestGAP0669PurgeKeepsLocksOfAccountFiles(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	// session-facts.json and the other managed files that are renamed into
	// place have no lock: a file named like one is the account's, and so is a
	// lock of a lock.
	keep := []string{
		"personal.txt.lock", ".notaconnector-lifecycle.lock", "hooks/personal.lock", "lock",
		"session-facts.json.lock", "session-facts.json.lock.lock", "inventory.db.lock",
		"agent_selection.json.lock.lock", "hooks/.hookcfg.lock.lock", "hooks/.otlp-codex.token.lock.lock",
		"acp/zed-kiro.token.lock", "acp/owned-entries.json.lock", "acp/zed-kiro.contract-lock.json.lock",
	}
	writeG669Files(t, dataDir, keep)
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range keep {
		if _, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("account entry %s removed: %v", rel, err)
		}
	}
}

// A teardown that creates the data directory and its lock removes both again.
func TestGAP0669TeardownRemovesItsOwnLock(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	conn := &createdDirsConnector{stubConnector: stubConnector{name: "codex"}}
	err := WithUserHomeDir(home, func() error {
		return RemovalLeavingNoNewDirs(conn, SetupOpts{DataDir: dataDir}, func() error {
			writeG669Files(t, dataDir, []string{"hooks/fake-hook.sh", ".codex-lifecycle.lock", "hooks/.otlp-codex.token.lock"})
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Errorf("teardown-created data directory stayed: %v", err)
	}
}

// Ownership follows the path from the data directory: a name that is managed
// at the top (inventory.db) is account data inside acp/.
func TestGAP0669OwnershipReadsThePathFromTheDataDir(t *testing.T) {
	for rel, want := range map[string]bool{
		"inventory.db":               true,
		"acp/inventory.db":           false,
		"zed-kiro.token":             false,
		"acp/zed-kiro.token":         true,
		"acp/.token":                 true,
		"hooks/inventory.db":         false,
		"acp/enterprise-credentials": false,
	} {
		if got := ManagedUserStateFile(rel); got != want {
			t.Errorf("ManagedUserStateFile(%q) = %v, want %v", rel, got, want)
		}
	}
}

// GAP-0669 review 3 M3: only the connectors whose setup writes a lifecycle lock
// (codex, hermes) own that name. A lock-looking file named for any other built-in
// connector, for a removed one or for an unknown one was never written by
// DefenseClaw and stays, with the written locks removed beside it.
func TestGAP0669PurgeKeepsLifecycleLocksNoWriterCreates(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	written := []string{codexLifecycleLockName, hermesLifecycleLockName}
	var keep []string
	for name := range builtinConnectorNames() {
		lock := "." + name + "-lifecycle.lock"
		if !slices.Contains(written, lock) {
			keep = append(keep, lock)
		}
	}
	if len(keep) == 0 {
		t.Fatal("no built-in connector without a lifecycle lock writer")
	}
	keep = append(keep, ".amp-lifecycle.lock", ".cursor-lifecycle.lock", ".notaconnector-lifecycle.lock")
	writeG669Files(t, dataDir, append(slices.Clone(keep), written...))
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range keep {
		if _, err := os.Lstat(filepath.Join(dataDir, rel)); err != nil {
			t.Errorf("account entry %s removed: %v", rel, err)
		}
	}
	for _, rel := range written {
		if _, err := os.Lstat(filepath.Join(dataDir, rel)); !os.IsNotExist(err) {
			t.Errorf("written lifecycle lock %s stayed: %v", rel, err)
		}
	}
}
