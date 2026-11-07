// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rootOwnedByName stands in for root-owned files: the paths in rootOwned are
// owned by uid 0, everything else by the caller.
func rootOwnedByName(t *testing.T, rootOwned ...string) {
	t.Helper()
	if os.Geteuid() <= 0 {
		t.Skip("a root caller never sees root-owned leftovers")
	}
	var infos []fs.FileInfo
	for _, path := range rootOwned {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, info)
	}
	old := ownerOfFile
	t.Cleanup(func() { ownerOfFile = old })
	ownerOfFile = func(info fs.FileInfo) (uint32, bool) {
		for _, root := range infos {
			if os.SameFile(info, root) {
				return 0, true
			}
		}
		return uint32(os.Geteuid()), true
	}
}

func writeRuntimeFile(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// GAP-0788: the files a stopped root-run gateway leaves are named, and only
// the private root-owned ones: a file the account owns, or a root-owned file
// the account can read, is not a start blocker.
func TestRootOwnedRuntimeLeftoversNamesOnlyPrivateRootFiles(t *testing.T) {
	dir := t.TempDir()
	lock := writeRuntimeFile(t, dir, "hook_contract_lock.json", 0o600)
	active := writeRuntimeFile(t, dir, "active_connector.json", 0o600)
	writeRuntimeFile(t, dir, "application_protection_state.json", 0o600) // the account's own
	shared := writeRuntimeFile(t, dir, "device.key.provenance", 0o644)   // root-owned but world-readable
	token := writeRuntimeFile(t, dir, "hooks/.hook-abc.token", 0o600)
	writeRuntimeFile(t, dir, "hooks/not-a-token.txt", 0o600)
	rootOwnedByName(t, lock, active, shared, token)

	got := strings.Join(RootOwnedRuntimeLeftovers(dir), ",")
	want := "hook_contract_lock.json,active_connector.json,hooks/.hook-abc.token"
	if got != want {
		t.Fatalf("leftovers = %q, want %q", got, want)
	}
}

// The benign twin: a data directory of the account's own files has none.
func TestRootOwnedRuntimeLeftoversIgnoresTheAccountsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range rootRuntimeLeftoverNames {
		writeRuntimeFile(t, dir, name, 0o600)
	}
	writeRuntimeFile(t, dir, "hooks/.hook-abc.token", 0o600)
	if os.Geteuid() <= 0 {
		t.Skip("a root caller never sees root-owned leftovers")
	}
	if got := RootOwnedRuntimeLeftovers(dir); len(got) != 0 {
		t.Fatalf("own files named as leftovers: %v", got)
	}
	if got := RootOwnedRuntimeLeftovers(filepath.Join(dir, "missing")); len(got) != 0 {
		t.Fatalf("missing directory named leftovers: %v", got)
	}
}

// The Go list and Doctor's list name the same files.
func TestRootRuntimeLeftoverNamesMatchDoctor(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "cli", "defenseclaw", "file_permissions.py"))
	if err != nil {
		t.Skipf("Python sources not in this checkout: %v", err)
	}
	block := regexp.MustCompile(`(?s)SUDO_RUNTIME_LEFTOVER_NAMES[^=]*=\s*\((.*?)\n\)`).FindSubmatch(source)
	if block == nil {
		t.Fatal("SUDO_RUNTIME_LEFTOVER_NAMES not found in file_permissions.py")
	}
	var python []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(block[1], -1) {
		python = append(python, string(m[1]))
	}
	if strings.Join(python, ",") != strings.Join(rootRuntimeLeftoverNames, ",") {
		t.Fatalf("Doctor names %v, Go names %v", python, rootRuntimeLeftoverNames)
	}
}

// The remedy is the Doctor chain: stop, return the home and the moved store,
// start, in that order, and it ends with the command alone.
func TestRootLeftoversRemedyReturnsHomeAndMovedStore(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "moved store")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("data_dir: \""+store+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", "")
	remedy := RootLeftoversRemedy(home)
	if !strings.HasPrefix(remedy, "stop the gateway if it runs as root, give its files back to this account and start it as yourself: sudo env DEFENSECLAW_HOME=") {
		t.Fatalf("remedy = %q", remedy)
	}
	if !strings.Contains(remedy, ` stop && sudo chown -R "$(id -un)" `) || !strings.HasSuffix(remedy, " && defenseclaw-gateway start") {
		t.Fatalf("remedy is not stop, return, start: %q", remedy)
	}
	for _, dir := range []string{home, store} {
		if !strings.Contains(remedy, "'"+dir+"'") {
			t.Errorf("remedy does not return %q: %q", dir, remedy)
		}
	}
}
