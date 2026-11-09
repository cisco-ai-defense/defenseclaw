// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

func writeConnectorRuntimeFixture(t *testing.T, dataDir string, names ...string) {
	t.Helper()
	for _, rel := range names {
		path := filepath.Join(dataDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func connectorRuntimeLeft(t *testing.T, dataDir string) map[string]bool {
	t.Helper()
	left := map[string]bool{}
	_ = filepath.WalkDir(dataDir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			rel, _ := filepath.Rel(dataDir, path)
			left[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	return left
}

// GAP-0916: what one machine-scope connector's managed install wrote for an
// account goes; the other connectors' files, the scripts they share and the
// account's own files stay.
func TestRemoveWindowsConnectorUserRuntimeEntriesTakesOnlyTheConnectorsFiles(t *testing.T) {
	dataDir := t.TempDir()
	all := []string{
		"hooks/.hook-cursor.token", "hooks/.hookcfg.cursor", "hooks/.managed-runtime-cursor-0123abcd.json",
		"hooks/.hook-claudecode.token", "hooks/.hookcfg.claudecode", "hooks/claude-code-hook.sh",
		"hooks/.managed-runtime-claudecode-0123abcd.json",
		"hooks/.hook-codex.token", "hooks/.hookcfg.codex", "hooks/.managed-runtime-codex-0123abcd.json",
		"hooks/.hookcfg", "hooks/.hookcfg.lock", "hooks/_hardening.sh", "hooks/inspect-tool.sh",
		"hooks/user-notes.txt", "hooks/.managed-runtime-cursorish-0123abcd.json", "hook_contract_lock.json", "config.yaml",
	}
	writeConnectorRuntimeFixture(t, dataDir, all...)
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, tc := range []struct {
		name    string
		removed []string
	}{
		{"cursor", []string{"hooks/.hook-cursor.token", "hooks/.hookcfg.cursor", "hooks/.managed-runtime-cursor-0123abcd.json"}},
		{"claudecode", []string{"hooks/.hook-claudecode.token", "hooks/.hookcfg.claudecode", "hooks/claude-code-hook.sh", "hooks/.managed-runtime-claudecode-0123abcd.json"}},
		{"codex", []string{"hooks/.hook-codex.token", "hooks/.hookcfg.codex", "hooks/.managed-runtime-codex-0123abcd.json"}},
	} {
		leaves, err := windowsConnectorUserRuntimeLeaves(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		left := connectorRuntimeLeft(t, dataDir)
		for _, rel := range tc.removed {
			if left[rel] {
				t.Errorf("%s: %s is still there", tc.name, rel)
			}
			delete(left, rel)
		}
		// A second run finds nothing to do.
		if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
			t.Fatalf("%s again: %v", tc.name, err)
		}
	}
	left := connectorRuntimeLeft(t, dataDir)
	want := []string{"hooks/.hookcfg", "hooks/.hookcfg.lock", "hooks/_hardening.sh", "hooks/inspect-tool.sh",
		"hooks/user-notes.txt", "hooks/.managed-runtime-cursorish-0123abcd.json", "hook_contract_lock.json", "config.yaml"}
	if len(left) != len(want) {
		t.Fatalf("left = %v, want exactly %v", left, want)
	}
	for _, rel := range want {
		if !left[rel] {
			t.Errorf("%s was removed", rel)
		}
	}
}

func TestWindowsConnectorUserRuntimeLeavesAreBounded(t *testing.T) {
	for _, name := range []string{"copilot", "opencode", "hermes", "", "unknown"} {
		if WindowsMachineScopeUserRuntimeConnector(name) {
			t.Errorf("%q is not a machine-scope connector", name)
		}
		if _, err := windowsConnectorUserRuntimeLeaves(name); err == nil {
			t.Errorf("%q has no machine-scope user runtime to remove, but its leaves were returned", name)
		}
	}
	leaves, err := windowsConnectorUserRuntimeLeaves("cursor")
	if err != nil || len(leaves) != 2 {
		t.Fatalf("cursor leaves = %v, %v; want the hook config and the scoped token", leaves, err)
	}
}

func TestRemoveWindowsConnectorUserRuntimeLeavesALinkedHooksFolderAsFound(t *testing.T) {
	dataDir, target := t.TempDir(), t.TempDir()
	writeConnectorRuntimeFixture(t, target, ".hook-cursor.token")
	if err := os.Symlink(target, filepath.Join(dataDir, "hooks")); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	leaves, _ := windowsConnectorUserRuntimeLeaves("cursor")
	if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), "cursor", leaves); err == nil {
		t.Fatal("a linked hooks folder was not refused")
	}
	if _, err := os.Stat(filepath.Join(target, ".hook-cursor.token")); err != nil {
		t.Fatalf("a file behind the link was removed: %v", err)
	}
}

// ---- RemoveWindowsConnectorUserRuntime (GAP-0916) ----

const connectorRuntimeGateway = "DefenseClawGateway"

// connectorRuntimeFixture builds an account folder as the managed install
// leaves it: a scoped token and hook config for each of Claude Code and Cursor
// (ReconcileManagedNativeHookRuntime), and a hook contract lock with an entry
// for each, bound to the gateway service of this deployment.
func connectorRuntimeFixture(t *testing.T, gateway string) (home, dataDir string, sid *windows.SID) {
	t.Helper()
	gap45AllowMutation(t)
	sid = currentWindowsTestSID(t)
	home = filepath.Join(t.TempDir(), "home")
	dataDir = filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gap45Own(t, sid, home, dataDir)
	for _, name := range []string{"claudecode", "cursor"} {
		if err := connector.ReconcileManagedNativeHookRuntime(dataDir, "127.0.0.1:18970", name, "scoped-"+name+"-token", "closed"); err != nil {
			t.Fatalf("%s runtime: %v", name, err)
		}
		if err := connector.SaveHookContractLockEntryForMode(dataDir, connector.HookContractLockEntry{
			Connector: name, RawAgentVersion: "1", ContractID: name + "-hooks-v1", HookFailMode: "closed",
			ManagedGatewayServiceName: gateway,
		}, true); err != nil {
			t.Fatalf("%s contract: %v", name, err)
		}
	}
	// The runtime generation record a managed install publishes.
	gap45WriteFile(t, filepath.Join(dataDir, "hooks", ".managed-runtime-cursor-0123456789abcdef0123456789abcdef.json"), "{}")
	gap45WriteFile(t, filepath.Join(dataDir, "hooks", ".managed-runtime-claudecode-0123456789abcdef0123456789abcdef.json"), "{}")
	return home, dataDir, sid
}

func connectorRuntimeLockEntries(t *testing.T, dataDir string, sid *windows.SID) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Connectors map[string]json.RawMessage `json:"connectors"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		t.Fatal(err)
	}
	entries := map[string]bool{}
	for name := range lock.Connectors {
		entries[name] = true
	}
	return entries
}

func connectorRuntimeExists(t *testing.T, dataDir string, rels ...string) []bool {
	t.Helper()
	var present []bool
	for _, rel := range rels {
		_, err := os.Lstat(filepath.Join(dataDir, rel))
		present = append(present, err == nil)
	}
	return present
}

func TestRemoveWindowsConnectorUserRuntimeTakesOnlyTheConnectorAndItsLockEntry(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatal(err)
	}
	got := connectorRuntimeExists(t, dataDir,
		`hooks\.hook-cursor.token`, `hooks\.hookcfg.cursor`, `hooks\.managed-runtime-cursor-0123456789abcdef0123456789abcdef.json`,
		`hooks\.hook-claudecode.token`, `hooks\.hookcfg.claudecode`, `hooks\.managed-runtime-claudecode-0123456789abcdef0123456789abcdef.json`,
		"hook_contract_lock.json")
	want := []bool{false, false, false, true, true, true, true}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("files present after the removal = %v, want %v", got, want)
		}
	}
	if entries := connectorRuntimeLockEntries(t, dataDir, sid); entries["cursor"] || !entries["claudecode"] {
		t.Fatalf("lock entries = %v, want claudecode only", entries)
	}
	// Idempotent.
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatalf("second removal: %v", err)
	}
}

// A lock entry bound to another gateway service is superseded: the files of
// the removed connector go, the entry is left.
func TestRemoveWindowsConnectorUserRuntimeLeavesASupersededLockEntry(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, "DefenseClawGateway-OtherScope")
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatal(err)
	}
	if entries := connectorRuntimeLockEntries(t, dataDir, sid); !entries["cursor"] || !entries["claudecode"] {
		t.Fatalf("a lock entry another gateway owns was removed: %v", entries)
	}
	if present := connectorRuntimeExists(t, dataDir, `hooks\.hook-cursor.token`); present[0] {
		t.Fatal("the cursor token stays")
	}
}

func TestRemoveWindowsConnectorUserRuntimeRefusesAWrongSIDAndANonLocalSystemCaller(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	// Another account's SID against this profile.
	if err := RemoveWindowsConnectorUserRuntime(home, "S-1-5-21-1-2-3-1999", "", "cursor"); err == nil {
		t.Fatal("a SID that does not own the profile was accepted")
	}
	// A connector this removal does not cover.
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "copilot"); err == nil {
		t.Fatal("a per-user connector was accepted")
	}
	previous := windowsEnterpriseMutationIdentityCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return errors.New("not LocalSystem") }
	err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor")
	windowsEnterpriseMutationIdentityCheck = previous
	if err == nil {
		t.Fatal("removal ran without LocalSystem")
	}
	if present := connectorRuntimeExists(t, dataDir, `hooks\.hook-cursor.token`, "hook_contract_lock.json"); !present[0] || !present[1] {
		t.Fatalf("a refused removal changed the folder: %v", present)
	}
}

func TestRemoveWindowsConnectorUserRuntimeLeavesLinksAsFound(t *testing.T) {
	// A junction at the DefenseClaw folder.
	gap45AllowMutation(t)
	sid := currentWindowsTestSID(t)
	linkHome := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(linkHome, 0o700); err != nil {
		t.Fatal(err)
	}
	gap45Own(t, sid, linkHome)
	outside, canary := outsideDataDirTree(t, linkHome)
	plantWindowsAccountJunction(t, filepath.Join(linkHome, ".defenseclaw"), outside, sid)
	if err := RemoveWindowsConnectorUserRuntime(linkHome, sid.String(), "", "cursor"); err == nil || !strings.Contains(err.Error(), "left as found") {
		t.Fatalf("junction at the folder = %v", err)
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)

	// A junction at hooks: nothing behind it is touched, and the removal does not claim success.
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	outside, canary = outsideDataDirTree(t, home)
	if err := os.RemoveAll(filepath.Join(dataDir, "hooks")); err != nil {
		t.Fatal(err)
	}
	plantWindowsAccountJunction(t, filepath.Join(dataDir, "hooks"), outside, sid)
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err == nil {
		t.Fatal("a junction at hooks was followed or accepted")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
}

// A junction swapped in for the DefenseClaw folder right before the privileged
// lock write cannot happen: the folder is pinned without delete sharing.
func TestRemoveWindowsConnectorUserRuntimeCannotSwapTheFolderBeforeTheLockWrite(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	outside, canary := outsideDataDirTree(t, home)
	var renameErr error
	previous := windowsConnectorUserRuntimeBeforeLockClear
	windowsConnectorUserRuntimeBeforeLockClear = func() {
		renameErr = os.Rename(dataDir, dataDir+".moved")
	}
	t.Cleanup(func() { windowsConnectorUserRuntimeBeforeLockClear = previous })
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatal(err)
	}
	if renameErr == nil {
		t.Fatal("the pinned folder was renamed away between the link check and the lock write")
	}
	requireOutsideDataDirTreeUnchanged(t, outside, canary)
	if entries := connectorRuntimeLockEntries(t, dataDir, sid); entries["cursor"] {
		t.Fatalf("the lock entry stays: %v", entries)
	}
}

// A folder that holds a per-user DefenseClaw install is left as found.
func TestRemoveWindowsConnectorUserRuntimeLeavesAPerUserInstall(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	gap45WriteFile(t, filepath.Join(dataDir, "config.yaml"), "config_version: 8\n")
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); !errors.Is(err, ErrWindowsConnectorUserRuntimeKept) || !strings.Contains(err.Error(), "config.yaml") {
		t.Fatalf("a per-user install folder was reported as done: %v", err)
	}
	if present := connectorRuntimeExists(t, dataDir, `hooks\.hook-cursor.token`, "hook_contract_lock.json"); !present[0] || !present[1] {
		t.Fatalf("a per-user install's files were removed: %v", present)
	}
}

// The account's runtime transaction lock is held around the removal, so an
// install (or managed-policy removal) of the same account cannot interleave.
func TestRemoveWindowsConnectorUserRuntimeWaitsForTheRuntimeTransactionLock(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	release, err := lockWindowsUserRuntimeTransaction(sid.String())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor") }()
	select {
	case err := <-done:
		release()
		t.Fatalf("the removal ran while the account's runtime lock was held: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if present := connectorRuntimeExists(t, dataDir, `hooks\.hook-cursor.token`); !present[0] {
		release()
		t.Fatal("the file was removed while the lock was held")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the removal did not run after the lock was released")
	}
	if present := connectorRuntimeExists(t, dataDir, `hooks\.hook-cursor.token`); present[0] {
		t.Fatal("the file stays after the lock was released")
	}
}

// GAP-0964: the guardian asks, for every account on every pass, whether a
// removed connector left any of its own files, and queues the removal only
// where it did. Another connector's files, the shared scripts and the
// account's own files do not count.
func TestWindowsConnectorUserRuntimeLeftoverSeesOnlyTheConnectorsOwnFiles(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if WindowsConnectorUserRuntimeLeftover(home, "", "cursor") {
		t.Fatal("a profile with no DefenseClaw folder reported a leftover")
	}
	writeConnectorRuntimeFixture(t, dataDir,
		"hooks/.hook-claudecode.token", "hooks/claude-code-hook.sh", "hooks/_hardening.sh", "hooks/inspect-tool.sh",
		"hooks/.hookcfg", "hooks/.hookcfg.lock", "hooks/.managed-runtime-cursorish-0123abcd.json", "hook_contract_lock.json", "config.yaml")
	if WindowsConnectorUserRuntimeLeftover(home, "", "cursor") || WindowsConnectorUserRuntimeLeftover(home, "", "codex") {
		t.Fatal("another connector's files, the shared scripts or the account's own files counted as a leftover")
	}
	if !WindowsConnectorUserRuntimeLeftover(home, "", "Claudecode") {
		t.Fatal("Claude Code's own token and script were not seen")
	}
	for _, rel := range []string{"hooks/.hook-cursor.token", "hooks/.hookcfg.cursor", "hooks/.managed-runtime-cursor-0123abcd.json"} {
		writeConnectorRuntimeFixture(t, dataDir, rel)
		if !WindowsConnectorUserRuntimeLeftover(home, dataDir, "cursor") {
			t.Fatalf("%s was not seen", rel)
		}
		if err := os.Remove(filepath.Join(dataDir, rel)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"hermes", "opencode", "", "../cursor"} {
		if WindowsConnectorUserRuntimeLeftover(home, "", name) {
			t.Fatalf("%q is not a machine-scope connector and reported a leftover", name)
		}
	}
	if WindowsConnectorUserRuntimeLeftover("relative", "", "cursor") || WindowsConnectorUserRuntimeLeftover(home, filepath.Join(t.TempDir(), "elsewhere"), "cursor") {
		t.Fatal("a relative home or a data folder outside the profile reported a leftover")
	}
}
