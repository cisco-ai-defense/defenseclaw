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

func usableDirs(t *testing.T, usable bool) {
	t.Helper()
	old := dirUsable
	t.Cleanup(func() { dirUsable = old })
	dirUsable = func(string) bool { return usable }
}

// GAP-0788: the files a stopped root-run gateway leaves are named in any mode,
// and the ones that grant group or others access are flagged so the repair
// takes that access away: the gateway refuses them even once the owner is
// back. A file the account owns is not a start blocker.
func TestRootOwnedStartBlockersNamesRootFilesOfAnyMode(t *testing.T) {
	dir := t.TempDir()
	lock := writeRuntimeFile(t, dir, "hook_contract_lock.json", 0o600)
	active := writeRuntimeFile(t, dir, "active_connector.json", 0o644)
	writeRuntimeFile(t, dir, "application_protection_state.json", 0o600) // the account's own
	shared := writeRuntimeFile(t, dir, "device.key.provenance", 0o640)
	token := writeRuntimeFile(t, dir, "hooks/.hook-abc.token", 0o600)
	writeRuntimeFile(t, dir, "hooks/not-a-token.txt", 0o600)
	rootOwnedByName(t, lock, active, shared, token)
	usableDirs(t, true)

	blockers, loose := RootOwnedStartBlockers(dir, "", true)
	if got, want := strings.Join(blockers, ","), "hook_contract_lock.json,active_connector.json,device.key.provenance,hooks/.hook-abc.token"; got != want {
		t.Fatalf("blockers = %q, want %q", got, want)
	}
	want := []string{filepath.Join(dir, "active_connector.json"), filepath.Join(dir, "device.key.provenance")}
	if strings.Join(loose, ",") != strings.Join(want, ",") {
		t.Fatalf("loose = %v, want %v", loose, want)
	}
}

// The start validates the PID records in the install home, so a root-owned
// record there is a blocker; the same name in a moved store is not read by the
// start and does not stop it (GAP-0788 review 2).
func TestRootOwnedStartBlockersNamesRootPIDRecordsOfTheInstallHomeOnly(t *testing.T) {
	store, home := t.TempDir(), t.TempDir()
	stale := writeRuntimeFile(t, store, "gateway.pid", 0o600)
	watchdog := writeRuntimeFile(t, home, "watchdog.pid", 0o600)
	writeRuntimeFile(t, home, "device.key", 0o600) // root-owned in a home the store left: not read
	rootOwnedByName(t, stale, watchdog, filepath.Join(home, "device.key"))
	usableDirs(t, true)

	blockers, loose := RootOwnedStartBlockers(store, home, true)
	if got, want := strings.Join(blockers, ","), filepath.Join(home, "watchdog.pid"); got != want {
		t.Fatalf("blockers = %q, want %q", got, want)
	}
	if len(loose) != 0 {
		t.Fatalf("loose = %v", loose)
	}
	// With the store and the home one folder, the record is read from it.
	blockers, _ = RootOwnedStartBlockers(store, store, true)
	if got, want := strings.Join(blockers, ","), "gateway.pid"; got != want {
		t.Fatalf("same folder: blockers = %q, want %q", got, want)
	}
}

// The hook files are read from the store (cfg.DataDir/hooks), so a root-owned
// hooks folder of the install home the store left is not a start blocker, and
// the store own hooks folder is.
func TestRootOwnedStartBlockersReadsTheHookFilesOfTheStoreNotTheInstallHome(t *testing.T) {
	store, home := t.TempDir(), t.TempDir()
	oldToken := writeRuntimeFile(t, home, "hooks/.hook-old.token", 0o600)
	newToken := writeRuntimeFile(t, store, "hooks/.hook-new.token", 0o600)
	rootOwnedByName(t, oldToken, filepath.Join(home, "hooks"), newToken)
	usableDirs(t, true)

	blockers, _ := RootOwnedStartBlockers(store, home, true)
	if got, want := strings.Join(blockers, ","), "hooks/.hook-new.token"; got != want {
		t.Fatalf("blockers = %q, want %q", got, want)
	}
	if blockers, _ = RootOwnedStartBlockers(store, store, true); strings.Join(blockers, ",") != "hooks/.hook-new.token" {
		t.Fatalf("same folder blockers = %v", blockers)
	}
}

// NamesGatewayPIDRecord recognises the records in either folder.
func TestNamesGatewayPIDRecord(t *testing.T) {
	for name, want := range map[string]bool{
		"gateway.pid": true, "/home/u/.defenseclaw/watchdog.pid": true,
		"active_connector.json": false, StoreDirEntry: false, "hooks/": false,
	} {
		if got := NamesGatewayPIDRecord(name); got != want {
			t.Errorf("NamesGatewayPIDRecord(%q) = %v, want %v", name, got, want)
		}
	}
}

// A root-owned store the account cannot enter hides its files, so the
// directory itself is the blocker. The same directory the account can write
// to is not one.
func TestRootOwnedStartBlockersNamesAStoreTheAccountCannotUse(t *testing.T) {
	dir := t.TempDir()
	rootOwnedByName(t, dir)
	usableDirs(t, false)
	blockers, loose := RootOwnedStartBlockers(dir, "", true)
	if strings.Join(blockers, ",") != StoreDirEntry {
		t.Fatalf("blockers = %v, want the store itself", blockers)
	}
	if want := dir + string(filepath.Separator); strings.Join(loose, ",") != want {
		t.Fatalf("loose = %v, want the store as a folder to sweep (%q)", loose, want)
	}
	usableDirs(t, true)
	if blockers, _ := RootOwnedStartBlockers(dir, "", true); len(blockers) != 0 {
		t.Fatalf("a root-owned store the account can write was named: %v", blockers)
	}
}

// The AI discovery state is read only when discovery is on, so a root-owned
// copy of it does not stop an ordinary start of a store that has it off.
func TestRootOwnedStartBlockersIgnoresDiscoveryStateWhileDiscoveryIsOff(t *testing.T) {
	dir := t.TempDir()
	state := writeRuntimeFile(t, dir, "ai_discovery_state.json", 0o600)
	rootOwnedByName(t, state)
	usableDirs(t, true)
	if blockers, _ := RootOwnedStartBlockers(dir, "", false); len(blockers) != 0 {
		t.Fatalf("disabled discovery state blocks a start: %v", blockers)
	}
	if blockers, _ := RootOwnedStartBlockers(dir, "", true); strings.Join(blockers, ",") != "ai_discovery_state.json" {
		t.Fatalf("enabled discovery state not named: %v", blockers)
	}
}

// The benign twin: a data directory of the account's own files has none.
func TestRootOwnedStartBlockersIgnoresTheAccountsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range rootRuntimeLeftoverNames {
		writeRuntimeFile(t, dir, name, 0o600)
	}
	writeRuntimeFile(t, dir, "hooks/.hook-abc.token", 0o600)
	if os.Geteuid() <= 0 {
		t.Skip("a root caller never sees root-owned leftovers")
	}
	if blockers, loose := RootOwnedStartBlockers(dir, dir, true); len(blockers) != 0 || len(loose) != 0 {
		t.Fatalf("own files named as blockers: %v %v", blockers, loose)
	}
	if blockers, _ := RootOwnedStartBlockers(filepath.Join(dir, "missing"), "", true); len(blockers) != 0 {
		t.Fatalf("missing directory named blockers: %v", blockers)
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
	remedy := RootLeftoversRemedy(home, nil)
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

// A root-owned file the gateway also refuses for its mode needs a chmod between
// the return and the start; without one the chain is unchanged.
func TestRootLeftoversRemedyTakesAwayGroupAndOtherAccessBeforeTheStart(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_CONFIG", "")
	loose := filepath.Join(home, "active connector.json")
	remedy := RootLeftoversRemedy(home, []string{loose})
	want := " && chmod go-rwx " + shellQuote(loose) + " && defenseclaw-gateway start"
	if !strings.HasSuffix(remedy, want) || !strings.Contains(remedy, ` chown -R "$(id -un)" `) {
		t.Fatalf("remedy = %q", remedy)
	}
	if strings.Contains(RootLeftoversRemedy(home, nil), "chmod") {
		t.Fatal("a chain with nothing loose runs chmod")
	}
}

// A store root owns and the account cannot enter hides its files, so the chain
// sweeps the runtime files in it after the owner is returned, and a visible
// file gets the plain chmod. Without a hidden store there is no find.
func TestRootLeftoversRemedySweepsAHiddenStoreAfterTheReturn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_CONFIG", "")
	store := filepath.Join(t.TempDir(), "moved store") + string(filepath.Separator)
	remedy := RootLeftoversRemedy(home, []string{store})
	sweep := " && find " + shellQuote(store) + " -maxdepth 2 -type f \\( -name gateway.pid -o "
	if !strings.Contains(remedy, sweep) || !strings.HasSuffix(remedy, " -path '*/hooks/.hook-*.token' \\) -exec chmod go-rwx {} + && defenseclaw-gateway start") {
		t.Fatalf("remedy has no sweep of the hidden store before the start: %q", remedy)
	}
	for _, name := range rootRuntimeLeftoverNames {
		if !strings.Contains(remedy, "-name "+name) {
			t.Errorf("sweep does not cover %s: %q", name, remedy)
		}
	}
	if strings.Index(remedy, "chown -R") > strings.Index(remedy, "find ") {
		t.Fatalf("the sweep runs before the owner is returned: %q", remedy)
	}
	if strings.Contains(RootLeftoversRemedy(home, []string{filepath.Join(home, "x.json")}), "find ") {
		t.Fatal("a visible file is repaired with a sweep")
	}
}
