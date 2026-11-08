// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

// yamlSingleQuoted writes a path as a single-quoted YAML scalar, in which a
// backslash is literal, so a Windows temp path reads back unchanged.
func yamlSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// The remedy is the Doctor chain: stop, return the home and the moved store,
// start, in that order, and it ends with the command alone.
func TestRootLeftoversRemedyReturnsHomeAndMovedStore(t *testing.T) {
	home := t.TempDir()
	// The store name carries an apostrophe: the YAML scalar doubles it and the
	// printed command escapes it, and both must give back the same path.
	store := filepath.Join(t.TempDir(), "O'Connor moved store")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("data_dir: "+yamlSingleQuoted(store)+"\n"), 0o600); err != nil {
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
		if !strings.Contains(remedy, shellQuote(dir)) {
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
	if strings.Contains(RootLeftoversRemedy(home, nil), "chmod go-rwx") {
		t.Fatal("a chain with nothing loose takes group and other access away")
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

// FailedPIDRecord names the record the identity check refused, with the error
// text unchanged, and nothing for an error from elsewhere.
func TestFailedPIDRecordNamesTheRefusedRecord(t *testing.T) {
	for _, record := range []string{PIDFileName, WatchdogPIDFileName} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, record), []byte("invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := New(dir).ValidateStartIdentityFiles()
		if failed, unreadable := FailedPIDRecord(err); err == nil || failed != record || unreadable {
			t.Fatalf("%s: err=%v record=%q unreadable=%v", record, err, failed, unreadable)
		}
		if !errors.Is(err, ErrUnsafeProcessIdentity) || !strings.Contains(err.Error(), record) {
			t.Fatalf("%s: the identity text changed: %v", record, err)
		}
	}
	if got, unreadable := FailedPIDRecord(errors.New("other")); got != "" || unreadable {
		t.Fatalf("FailedPIDRecord(other) = %q, %v", got, unreadable)
	}
}

// Only a permission refusal that root causes is flagged: the record or the
// folder hiding it is root-owned. The same refusal on a file the account owns
// (a mode it set itself), or a record it can read whatever its content, is an
// independent failure that returning the ownership does not clear (GAP-0788
// reviews 4 and 5). Root ownership is stood in for through ownerOfFile.
func TestFailedPIDRecordFlagsOnlyARootDeniedRecord(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a mode cannot make a file unreadable here")
	}
	rootOwns := func(t *testing.T, name string) {
		t.Helper()
		old := ownerOfFile
		t.Cleanup(func() { ownerOfFile = old })
		ownerOfFile = func(info fs.FileInfo) (uint32, bool) {
			if info.Name() == name {
				return 0, true
			}
			return old(info)
		}
	}
	for _, record := range []string{PIDFileName, WatchdogPIDFileName} {
		write := func(t *testing.T, content string, mode os.FileMode) *Daemon {
			t.Helper()
			dir := t.TempDir()
			path := filepath.Join(dir, record)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			return New(dir)
		}
		hiddenFolder := false
		check := func(t *testing.T, d *Daemon, want bool) {
			t.Helper()
			failedWant := record
			if hiddenFolder {
				failedWant = PIDFileName // a hidden folder fails the gateway record first
			}
			err := d.ValidateStartIdentityFiles()
			if failed, rootDenied := FailedPIDRecord(err); err == nil || failed != failedWant || rootDenied != want {
				t.Fatalf("%s: err=%v record=%q root-denied=%v, want %q %v", record, err, failed, rootDenied, failedWant, want)
			}
		}
		t.Run(record+"_account_owned_mode_000", func(t *testing.T) {
			check(t, write(t, "1\n", 0), false)
		})
		t.Run(record+"_root_owned_mode_000", func(t *testing.T) {
			rootOwns(t, record)
			check(t, write(t, "1\n", 0), true)
		})
		t.Run(record+"_root_owned_but_readable_and_malformed", func(t *testing.T) {
			rootOwns(t, record)
			check(t, write(t, "invalid\n", 0o600), false)
		})
		t.Run(record+"_hidden_by_a_root_owned_folder", func(t *testing.T) {
			d := write(t, "1\n", 0o600)
			if err := os.Chmod(d.dataDir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(d.dataDir, 0o700) })
			hiddenFolder = true
			check(t, d, false)
			rootOwns(t, filepath.Base(d.dataDir))
			check(t, d, true)
		})
	}
}

// The printed chain has to leave the files usable. After the owner is returned,
// a file whose owner bits lack read access (mode 000, or 044 once the group and
// other access is taken away) is still refused to its new owner, so the chain
// restores the owner bits between the return and the start. The steps that need
// root (stop, chown) and the start are left out; the rest runs for real on files
// of this account, in the order the chain prints it (GAP-0788 review 5).
func TestRootLeftoversRemedyLeavesRootOwnedFilesUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_CONFIG", "")
	files := map[string]os.FileMode{
		"active_connector.json":   0o000,
		"hook_contract_lock.json": 0o044,
		"hooks/.hook-a.token":     0o000,
	}
	if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	var loose []string
	for rel, mode := range files {
		path := filepath.Join(home, rel)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if mode&0o077 != 0 {
			loose = append(loose, path)
		}
	}
	if err := os.Chmod(filepath.Join(home, "hooks"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(home, "hooks"), 0o700) })

	_, chain, ok := strings.Cut(RootLeftoversRemedy(home, loose), ": ")
	if !ok {
		t.Fatal("the remedy has no command")
	}
	var local []string
	for _, step := range strings.Split(chain, " && ") {
		if !strings.HasPrefix(step, "sudo ") && !strings.Contains(step, "defenseclaw-gateway start") {
			local = append(local, step)
		}
	}
	if len(local) < 2 || !strings.HasPrefix(local[0], "chmod -R u+rwX ") || !strings.HasPrefix(local[1], "chmod go-rwx ") {
		t.Fatalf("the steps between the return and the start are %q", local)
	}
	if out, err := exec.Command("sh", "-c", strings.Join(local, " && ")).CombinedOutput(); err != nil {
		t.Fatalf("chain steps failed: %v\n%s", err, out)
	}
	for rel := range files {
		info, err := os.Stat(filepath.Join(home, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s is %04o after the chain, want 0600", rel, got)
		}
		if _, err := os.ReadFile(filepath.Join(home, rel)); err != nil {
			t.Errorf("%s is still unreadable to its owner: %v", rel, err)
		}
	}
	// The owner bits are all the first step adds: nothing grants group or other access.
	if strings.Contains(local[0], "go") || strings.Contains(local[0], "a+") {
		t.Fatalf("the restore step touches other bits: %q", local[0])
	}
}

// The chain every surface prints restores the owner bits on exactly the
// folders it returns, before the loosening step and the start, even when no
// file is named (status and the Sidecar API row know no file).
func TestRootLeftoversRemedyRestoresOwnerAccessOnWhatItReturns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_CONFIG", "")
	loose := filepath.Join(home, "active_connector.json")
	remedy := RootLeftoversRemedy(home, []string{loose})
	dirs := shellQuote(home)
	want := `sudo chown -R "$(id -un)" ` + dirs + " && chmod -R u+rwX " + dirs + " && chmod go-rwx " + shellQuote(loose) + " && defenseclaw-gateway start"
	if !strings.HasSuffix(remedy, want) {
		t.Fatalf("remedy = %q, want it to end with %q", remedy, want)
	}
	if plain := rootGatewayRemedyFor("linux", home); !strings.Contains(plain, " && chmod -R u+rwX "+dirs+" && defenseclaw-gateway start") {
		t.Fatalf("the chain without named files lacks the owner restore: %q", plain)
	}
}

// The agent config files a root run wrote in the account home are returned by
// the same chain (GAP-0848); a home with none keeps the chain unchanged.
func TestRootLeftoversRemedyReturnsRootOwnedAgentConfigFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_CONFIG", "")
	old := rootOwnedAgentConfigsOf
	t.Cleanup(func() { rootOwnedAgentConfigsOf = old })
	rootOwnedAgentConfigsOf = func(string) []string { return nil }
	plain := RootLeftoversRemedy(home, nil)
	if strings.Contains(plain, "chmod u+rw") {
		t.Fatalf("chain names agent config files where root owns none: %q", plain)
	}
	files := []string{"/Users/a b/.claude/settings.json", "/Users/a b/.codex/config.toml"}
	rootOwnedAgentConfigsOf = func(string) []string { return files }
	remedy := RootLeftoversRemedy(home, nil)
	quoted := shellQuote(files[0]) + " " + shellQuote(files[1])
	if !strings.Contains(remedy, ` && sudo chown "$(id -un)" `+quoted+" && chmod u+rw "+quoted+" && defenseclaw-gateway start") {
		t.Fatalf("chain does not return the agent config files before the start: %q", remedy)
	}
}
