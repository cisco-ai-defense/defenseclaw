// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"crypto/sha256"
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
		if _, err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
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
		if _, err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), tc.name, leaves); err != nil {
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
	if _, err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(0), "cursor", leaves); err == nil {
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

// GAP-0964: the guardian asks, for every account, whether a removed connector
// left any of its own files, and queues the removal only where it did. Another
// connector's files, the shared scripts and the account's own files do not
// count, and a folder that holds a per-user install is not offered (the removal
// leaves it as found).
func TestWindowsConnectorUserRuntimeLeftoversSeesOnlyTheConnectorsOwnFiles(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	writeConnectorRuntimeFixture(t, dataDir, "hooks/_hardening.sh", "hooks/inspect-tool.sh", "hooks/.hookcfg", "hooks/.hookcfg.lock",
		"hooks/.managed-runtime-cursorish-0123abcd.json", "notes.txt")
	all := []string{"claudecode", "codex", "cursor"}
	if got := strings.Join(WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", all), ","); got != "claudecode,cursor" {
		t.Fatalf("leftovers = %q, want claudecode,cursor (codex has no file)", got)
	}
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", []string{"Cursor", "hermes", "", "../cursor"}); strings.Join(got, ",") != "cursor" {
		t.Fatalf("only a machine-scope connector counts: %v", got)
	}
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), filepath.Join(t.TempDir(), "elsewhere"), all); got != nil {
		t.Fatalf("a data folder outside the profile reported %v", got)
	}
	if got := WindowsConnectorUserRuntimeLeftovers("relative", sid.String(), "", all); got != nil {
		t.Fatalf("a relative home reported %v", got)
	}
	// A per-user DefenseClaw install in the folder is left as found by the
	// removal, so it is not offered for it.
	writeConnectorRuntimeFixture(t, dataDir, "config.yaml")
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", all); got != nil {
		t.Fatalf("a folder that holds a per-user install was offered: %v", got)
	}
	if err := os.Remove(filepath.Join(dataDir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", all), ","); got != "claudecode" {
		t.Fatalf("after the Cursor removal leftovers = %q, want claudecode", got)
	}
}

// decoyTree is a folder outside any profile that holds files named like the
// connector's: nothing the guardian does may read through a link to it or
// change it.
type decoyTree struct {
	root   string
	hashes map[string][32]byte
}

func newDecoyTree(t *testing.T, parent, name string) decoyTree {
	t.Helper()
	tree := decoyTree{root: filepath.Join(parent, name), hashes: map[string][32]byte{}}
	for rel, body := range map[string]string{
		`hooks\.hook-cursor.token`: "decoy token",
		`hooks\.hookcfg.cursor`:    "decoy hook config",
		`.hook-cursor.token`:       "decoy token at the root",
		`.hookcfg.cursor`:          "decoy hook config at the root",
	} {
		path := filepath.Join(tree.root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		tree.hashes[path] = sha256.Sum256([]byte(body))
	}
	return tree
}

func (d decoyTree) requireUnchanged(t *testing.T) {
	t.Helper()
	for path, want := range d.hashes {
		got, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(got) != want {
			t.Fatalf("decoy %s changed: %v", path, err)
		}
	}
}

// GAP-0964, lead ruling: the scan never follows a link or junction out of a
// profile, and the removal never reads or changes what a link names.
func TestWindowsConnectorUserRuntimeLeftoversNeverFollowAJunction(t *testing.T) {
	all := []string{"claudecode", "codex", "cursor"}

	// A junction at the profile folder itself.
	realHome, _, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	linkHome := filepath.Join(t.TempDir(), "link-home")
	plantWindowsAccountJunction(t, linkHome, realHome, sid)
	if got := WindowsConnectorUserRuntimeLeftovers(linkHome, sid.String(), "", all); got != nil {
		t.Fatalf("a junction at the profile folder was followed: %v", got)
	}
	if err := RemoveWindowsConnectorUserRuntime(linkHome, sid.String(), "", "cursor"); err == nil {
		t.Fatal("the removal accepted a junction at the profile folder")
	}
	if present := connectorRuntimeExists(t, filepath.Join(realHome, ".defenseclaw"), `hooks\.hook-cursor.token`, `hooks\.hookcfg.cursor`); !present[0] || !present[1] {
		t.Fatal("the files behind the profile junction were touched")
	}

	// A junction at the DefenseClaw folder.
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	gap45Own(t, sid, home)
	decoys := newDecoyTree(t, filepath.Dir(home), "outside-defenseclaw")
	plantWindowsAccountJunction(t, filepath.Join(home, ".defenseclaw"), decoys.root, sid)
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", all); got != nil {
		t.Fatalf("a junction at .defenseclaw was followed: %v", got)
	}
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err == nil || !strings.Contains(err.Error(), "left as found") {
		t.Fatalf("junction at .defenseclaw removal = %v", err)
	}
	decoys.requireUnchanged(t)

	// A junction at hooks.
	home2, dataDir2, sid2 := connectorRuntimeFixture(t, connectorRuntimeGateway)
	decoys2 := newDecoyTree(t, filepath.Dir(home2), "outside-hooks")
	if err := os.RemoveAll(filepath.Join(dataDir2, "hooks")); err != nil {
		t.Fatal(err)
	}
	plantWindowsAccountJunction(t, filepath.Join(dataDir2, "hooks"), filepath.Join(decoys2.root, "hooks"), sid2)
	if got := WindowsConnectorUserRuntimeLeftovers(home2, sid2.String(), "", all); got != nil {
		t.Fatalf("a junction at hooks was followed: %v", got)
	}
	if err := RemoveWindowsConnectorUserRuntime(home2, sid2.String(), "", "cursor"); err == nil {
		t.Fatal("the removal accepted a junction at hooks")
	}
	decoys2.requireUnchanged(t)
}

// A symlink where the token should be is not a file the connector owns: it is
// not counted, not followed, and left in place; a hard link is the connector's
// own name, which is unlinked without touching the file it shares.
func TestWindowsConnectorUserRuntimeLinkLeaves(t *testing.T) {
	home, dataDir, sid := connectorRuntimeFixture(t, connectorRuntimeGateway)
	decoys := newDecoyTree(t, filepath.Dir(home), "outside-leaf")
	token := filepath.Join(dataDir, "hooks", ".hook-cursor.token")
	for _, rel := range []string{`hooks\.hook-cursor.token`, `hooks\.hookcfg.cursor`} {
		if err := os.Remove(filepath.Join(dataDir, rel)); err != nil {
			t.Fatal(err)
		}
	}
	record, err := filepath.Glob(filepath.Join(dataDir, "hooks", ".managed-runtime-cursor-*.json"))
	if err != nil || len(record) != 1 {
		t.Fatalf("runtime record: %v %v", record, err)
	}
	if err := os.Remove(record[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(decoys.root, ".hook-cursor.token"), token); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", []string{"cursor"}); got != nil {
		t.Fatalf("a symlink leaf was counted as a leftover: %v", got)
	}
	err = RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor")
	var left *WindowsConnectorUserRuntimeLinksLeft
	if !errors.As(err, &left) || len(left.Links) != 1 {
		t.Fatalf("symlink leaf removal = %v, want the link named and left", err)
	}
	if info, lerr := os.Lstat(token); lerr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was not left in place: %v", lerr)
	}
	decoys.requireUnchanged(t)

	// A hard link to an outside file at a leaf.
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(decoys.root, ".hook-cursor.token"), token); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}
	if got := WindowsConnectorUserRuntimeLeftovers(home, sid.String(), "", []string{"cursor"}); strings.Join(got, ",") != "cursor" {
		t.Fatalf("a hard-linked token name was not seen: %v", got)
	}
	if err := RemoveWindowsConnectorUserRuntime(home, sid.String(), "", "cursor"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(token); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the hard-linked name stayed: %v", err)
	}
	decoys.requireUnchanged(t)
}
