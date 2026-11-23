// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// kiroUserLint is the user's own hook command in these tests.
const kiroUserLint = "/usr/local/bin/lint"

// kiroForeignWindowsLauncher is another account's launcher: a Windows Kiro
// command that runs it is not this install's, whatever its shape.
const kiroForeignWindowsLauncher = `C:\Other Account\bin\defenseclaw-hook.exe`

// kiroWindowsOlderAndForeignForms are, for each surface, the per-user command
// this account's launcher ran before releases wrote the answering bridge (the
// older form, still owned) and the same bridge for another account's launcher
// (never owned). A Windows command runs the account's launcher, so there is
// no script path or wrapper to tell a form apart: ownership is the exact
// command (kiroWindowsOwnedHookCommandsFor).
func kiroWindowsOlderAndForeignForms(surfaces ...string) (older, foreign []string) {
	launcher := defenseclawHookBinary()
	for _, surface := range surfaces {
		older = append(older, preStartAnswerWindowsKiroHookCommand(launcher, surface))
		foreign = append(foreign, windowsKiroHookCommandForBinary(kiroForeignWindowsLauncher, surface, false))
	}
	return older, foreign
}

// kiroCommandsSetupWritesNow are the commands a Setup of opts writes. On
// Windows ownership also covers the older forms (installHookCommands), so the
// live pair is named there.
func kiroCommandsSetupWritesNow(conn *KiroConnector, opts SetupOpts) []string {
	if runtime.GOOS == "windows" {
		return []string{conn.hookCommand(opts), conn.hookCommandForV3Surface(opts)}
	}
	return conn.installHookCommands(opts)
}

// kiroRequireOwned fails unless every form is a command this install owns.
func kiroRequireOwned(t *testing.T, conn *KiroConnector, opts SetupOpts, forms []string) {
	t.Helper()
	owned := conn.installHookCommands(opts)
	for _, form := range forms {
		if !slices.Contains(owned, form) {
			t.Fatalf("the older form %q is not one this install owns; this test checks nothing", form)
		}
	}
}

// kiroChooseDefaultAgent sets chat.defaultAgent in the Kiro CLI settings of
// home, as the user does.
func kiroChooseDefaultAgent(t *testing.T, home, agent string) {
	t.Helper()
	settings := filepath.Join(home, "settings", "cli.json")
	cfg, err := readJSONObject(settings)
	if err != nil {
		t.Fatal(err)
	}
	cfg[kiroDefaultAgentSettingKey] = agent
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONObject(settings, cfg); err != nil {
		t.Fatal(err)
	}
}

// kiroHookACustomAgentThenSwitchAway makes the user's agent "mine" (with the
// user's own hook) the default, runs Setup again so it hooks that agent, then
// switches the default to "other": only the install's agent record still
// names mine.json, which it returns.
func kiroHookACustomAgentThenSwitchAway(t *testing.T, conn *KiroConnector, opts SetupOpts, home string) string {
	t.Helper()
	mine := filepath.Join(home, "agents", "mine.json")
	if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONObject(mine, map[string]interface{}{"name": "mine", "hooks": map[string]interface{}{
		"preToolUse": []interface{}{map[string]interface{}{"command": kiroUserLint, "matcher": "*"}},
	}}); err != nil {
		t.Fatal(err)
	}
	kiroChooseDefaultAgent(t, home, "mine")
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup with the custom default agent: %v", err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, conn.installHookCommands(opts)); err != nil || !held {
		t.Fatalf("Setup did not hook the custom default agent: %v, %v", held, err)
	}
	kiroChooseDefaultAgent(t, home, "other")
	if paths := conn.agentCleanupPaths(opts); slices.Contains(paths, mine) {
		t.Fatalf("the settings still name %s (%v); this test checks nothing", mine, paths)
	}
	return mine
}

// Review round 5 P2 of rel-1-0-10 GAP-1092/GAP-1174 (Windows): B's Setup
// hooked the custom default agent mine, the user then made "other" the
// default, and `setup remove kiro` of the configured connector neither
// visited mine.json, which only B's agent record names, nor dropped B's
// records. B's launcher entries stayed in mine.json, VerifyClean passed, and
// the record kept B an owner of the account's launcher commands, so after A
// set Kiro up, B's next boot stripped A's live hooks. The removal takes B's
// exact entries out of mine.json, keeps the user's, drops every Kiro record,
// and B then owns none of A's identical Windows entries.
func TestKiroRemoveCleansACustomAgentOnlyItsRecordNamesAndDropsTheRecords(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(dataB, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, opts, home := kiroSetUpForOrphanTest(t, dataB)
	mine := kiroHookACustomAgentThenSwitchAway(t, conn, opts, home)
	own := conn.installHookCommands(opts)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || held {
		t.Errorf("setup remove kiro left install B's entries in the custom agent only its record names: %v, %v", held, err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, []string{kiroUserLint}); err != nil || !held {
		t.Errorf("setup remove kiro removed the user's own hook: %v, %v", held, err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after the removal: %v", err)
	}
	assertReclaimedDataFolderOwnsNoWindowsLauncherEntries(t, conn, home, dataB)
	// Install A's entries, which the helper wrote, survive a reclaim by B
	// (its boot or `connector prune-orphans`) byte for byte.
	shared := []string{filepath.Join(home, "hooks", kiroManagedHooksName), filepath.Join(home, "agents", kiroManagedAgentName+".json")}
	before := readKiroFiles(t, shared)
	reclaim := opts
	reclaim.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), reclaim); err != nil {
		t.Errorf("reclaim Teardown after the removal: %v", err)
	}
	for path, want := range before {
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("install B's reclaim changed another install's %s (%v):\n%s", path, err, got)
		}
	}
}

// The workspace hook file B wrote before claw.workspace_dir changed is named
// only by B's backup record. VerifyClean read only the files the settings
// name, so it passed with B's entries still there, and nothing started the
// reclaim that would remove them. It reports them; the removal takes out B's
// exact entries only (another install's defenseclaw-* entry and the user's
// stay) and VerifyClean then passes.
func TestKiroVerifyCleanReportsTheEntriesOfAFileOnlyItsRecordNames(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	root := t.TempDir()
	dataB := filepath.Join(root, "b", ".defenseclaw")
	w1 := filepath.Join(root, "w1")
	for _, dir := range []string{dataB, w1} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	own := conn.installHookCommands(opts)
	w1Hooks := filepath.Join(w1, ".kiro", "hooks", kiroManagedHooksName)
	other := kiroHookInvocationCommandFor("linux", filepath.Join(root, "a", ".defenseclaw", "hooks", kiroHookScriptName), KiroHookSurfaceV3, false)
	cfg, err := readJSONObject(w1Hooks)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].([]interface{})
	cfg["hooks"] = append(hooks, kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", other), kiroV3Entry("lint", "PostToolUse", kiroUserLint))
	if err := writeJSONObject(w1Hooks, cfg); err != nil {
		t.Fatal(err)
	}
	// Only the record names W1 now, and the files the settings name are gone.
	opts.WorkspaceDir = ""
	for _, path := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(home, "agents", kiroManagedAgentName+".json"),
		filepath.Join(home, "settings", "cli.json"),
	} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.VerifyClean(opts); err == nil || !strings.Contains(err.Error(), "teardown incomplete") || !strings.Contains(err.Error(), w1Hooks) {
		t.Errorf("VerifyClean = %v, want the teardown reported incomplete for %s", err, w1Hooks)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if held, err := kiroV3FileHoldsCommand(w1Hooks, own); err != nil || held {
		t.Errorf("install B's entries stayed in the file only its record names: %v, %v", held, err)
	}
	for _, keep := range []string{other, kiroUserLint} {
		if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{keep}); err != nil || !held {
			t.Errorf("the removal took an entry that is not install B's out of %s (%s): %v, %v", w1Hooks, keep, held, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after the removal: %v", err)
	}
	if names := kiroRecordNames(t, dataB); len(names) != 0 {
		t.Errorf("the removal kept Kiro backup records %v", names)
	}
}

// Review round 4 P3 of rel-1-0-10 GAP-1092/GAP-1174: one file only a record
// names that cannot be parsed failed the whole reclaim and prune, on every
// boot, and a UTF-8 BOM (a Windows editor's) was such a file. A BOM is read
// through, and the reclaim and prune skip a file that is not JSON: its record
// stays and proves nothing, so no boot reclaims on it.
//
// rel-1-0-10 GAP-1298: the skip also made `setup remove kiro` succeed and
// VerifyClean pass with this install's hooks possibly still in that file.
// This test pinned that silent skip; it now pins the loud one: the removal of
// the configured connector fails and names the file, VerifyClean reports it
// (not as "teardown incomplete", which would start a reclaim on every boot),
// the record stays, and once the file parses the removal finishes.
func TestKiroTeardownSkipsARecordedFileItCannotParse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		unreadable bool
	}{
		{"not JSON", `{"hooks": [`, true},
		{"a JSON list", "[]\r\n", true},
		{"empty", "", false},
	} {
		for _, reclaim := range []bool{false, true} {
			mode := "connector teardown"
			if reclaim {
				mode = "reclaim"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				home := t.TempDir()
				KiroHomeOverride = home
				t.Cleanup(func() { KiroHomeOverride = "" })
				root := t.TempDir()
				dataB := filepath.Join(root, "b", ".defenseclaw")
				w1 := filepath.Join(root, "w1")
				for _, dir := range []string{dataB, w1} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				conn := NewKiroConnector()
				// `connector teardown` and `connector verify` report the file
				// (the boot teardowns log it: GAP-1304,
				// TestKiroBootTeardownLogsARecordedFileItCannotParseAndGoesOn).
				opts := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1, ReportUnreadableResidue: true}
				if err := conn.Setup(context.Background(), opts); err != nil {
					t.Fatalf("Setup: %v", err)
				}
				mine := kiroHookACustomAgentThenSwitchAway(t, conn, opts, home)
				own := conn.installHookCommands(opts)
				opts.WorkspaceDir = ""
				w1Hooks := filepath.Join(w1, ".kiro", "hooks", kiroManagedHooksName)
				if err := os.WriteFile(w1Hooks, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(mine)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(mine, append([]byte{0xEF, 0xBB, 0xBF}, data...), 0o600); err != nil {
					t.Fatal(err)
				}

				listed, err := OrphanedHookConfigPaths(conn, opts)
				if err != nil {
					t.Fatalf("prune-orphans failed on the file it cannot parse: %v", err)
				}
				if !slices.Contains(listed, mine) || slices.Contains(listed, w1Hooks) {
					t.Errorf("prune-orphans lists %v, want %s (a BOM is read through) and not %s", listed, mine, w1Hooks)
				}
				opts.ReclaimOwnHooksOnly = reclaim
				err = conn.Teardown(context.Background(), opts)
				opts.ReclaimOwnHooksOnly = false
				if tc.unreadable && !reclaim {
					if err == nil || !strings.Contains(err.Error(), w1Hooks) {
						t.Errorf("connector teardown kiro = %v, want it to fail and name %s, which it cannot parse", err, w1Hooks)
					}
				} else if err != nil {
					t.Fatalf("Teardown failed on the file it cannot parse: %v", err)
				}
				if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || held {
					t.Errorf("install B's entries stayed in the agent saved with a BOM: %v, %v", held, err)
				}
				if held, err := kiroAgentFileHoldsCommand(mine, []string{kiroUserLint}); err != nil || !held {
					t.Errorf("the user's own hook went: %v, %v", held, err)
				}
				if got, err := os.ReadFile(w1Hooks); err != nil || string(got) != tc.body {
					t.Errorf("the file it cannot parse changed (%v): %q", err, got)
				}
				names := kiroRecordNames(t, dataB)
				if !tc.unreadable {
					if len(names) != 0 {
						t.Errorf("Kiro backup records after the teardown = %v, want none", names)
					}
					if err := conn.VerifyClean(opts); err != nil {
						t.Errorf("VerifyClean: %v", err)
					}
					return
				}
				if !slices.Contains(names, kiroBackupLogicalName(w1Hooks)) {
					t.Errorf("Kiro backup records after the teardown = %v, want the record of %s kept for the retry", names, w1Hooks)
				}
				// The record kept for the file proves no ownership of Kiro's
				// commands.
				if kiroDataDirSetUpKiro(dataB) {
					t.Error("the record of a file that cannot be parsed keeps the data folder an owner of Kiro's commands")
				}
				if reclaim {
					// The reclaim finished everything else: the file alone is
					// reported, and not as a teardown the next boot retries.
					err := conn.VerifyClean(opts)
					if err == nil || !strings.Contains(err.Error(), w1Hooks) || strings.Contains(err.Error(), "teardown incomplete") {
						t.Errorf("VerifyClean = %v, want %s reported as a cleanup the boot reclaim does not retry", err, w1Hooks)
					}
					if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || owns {
						t.Errorf("the next boot would reclaim again: %v, %v", owns, err)
					}
					if err := conn.Teardown(context.Background(), opts); err == nil || !strings.Contains(err.Error(), w1Hooks) {
						t.Errorf("connector teardown kiro after the reclaim = %v, want it to fail and name %s", err, w1Hooks)
					}
				} else if err := conn.VerifyClean(opts); err == nil {
					t.Error("VerifyClean passed after connector teardown failed on the file it cannot parse")
				}
				// The user fixes the file; the next removal takes install B's
				// entry out of it, keeps the user's, and finishes.
				fixed := map[string]interface{}{"hooks": []interface{}{
					kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", conn.hookCommandForV3Surface(opts)),
					kiroV3Entry("lint", "PostToolUse", kiroUserLint),
				}}
				if err := writeJSONObject(w1Hooks, fixed); err != nil {
					t.Fatal(err)
				}
				if err := conn.Teardown(context.Background(), opts); err != nil {
					t.Fatalf("connector teardown kiro once the file parses: %v", err)
				}
				if held, err := kiroV3FileHoldsCommand(w1Hooks, conn.installHookCommands(opts)); err != nil || held {
					t.Errorf("install B's entry stayed in the fixed file: %v, %v", held, err)
				}
				if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{kiroUserLint}); err != nil || !held {
					t.Errorf("the user's own hook went from the fixed file: %v, %v", held, err)
				}
				if names := kiroRecordNames(t, dataB); len(names) != 0 {
					t.Errorf("the finished removal kept Kiro backup records %v", names)
				}
				if err := conn.VerifyClean(opts); err != nil {
					t.Errorf("VerifyClean after the finished removal: %v", err)
				}
				if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || owns {
					t.Errorf("after the finished removal the boot would reclaim: %v, %v", owns, err)
				}
			})
		}
	}
}

// rel-1-0-10 GAP-1297: the teardown of the configured connector took out of a
// file only its records name just the commands Setup writes now, so a file
// that held this install's hook script in another command form (a shell or
// env wrapper, an --event binding) was skipped and its record dropped, and
// nothing cleaned it afterwards. Those entries go too; another install's
// script in the same form and the user's hook stay.
func TestKiroRemoveCleansAnOlderCommandFormFromAFileOnlyItsRecordNames(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	root := t.TempDir()
	dataB := filepath.Join(root, "b", ".defenseclaw")
	w1 := filepath.Join(root, "w1")
	for _, dir := range []string{dataB, w1} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	script := filepath.Join(dataB, "hooks", kiroHookScriptName)
	otherScript := filepath.Join(root, "a", ".defenseclaw", "hooks", kiroHookScriptName)
	older := []string{
		"/bin/bash '" + script + "' --hook-surface " + KiroHookSurfaceV3,
		"/usr/bin/env LC_ALL=C " + script + " --event preToolUse",
	}
	keep := []string{"/bin/bash '" + otherScript + "' --hook-surface " + KiroHookSurfaceV3, kiroUserLint}
	if runtime.GOOS == "windows" {
		// A Windows command runs the account's launcher: the older form the
		// account's launcher ran goes, another account's launcher stays.
		var foreign []string
		older, foreign = kiroWindowsOlderAndForeignForms(KiroHookSurfaceV3, "")
		keep = []string{foreign[0], kiroUserLint}
		kiroRequireOwned(t, conn, opts, older)
	}
	w1Hooks := filepath.Join(w1, ".kiro", "hooks", kiroManagedHooksName)
	if err := writeJSONObject(w1Hooks, map[string]interface{}{"version": "v1", "hooks": []interface{}{
		kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", older[0]),
		kiroV3Entry("defenseclaw-prompt", "UserPromptSubmit", older[1]),
		kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", keep[0]),
		kiroV3Entry("lint", "PostToolUse", keep[1]),
	}}); err != nil {
		t.Fatal(err)
	}
	if held, err := kiroV3FileHoldsCommand(w1Hooks, kiroCommandsSetupWritesNow(conn, opts)); err != nil || held {
		t.Fatalf("the file holds a command Setup writes now (%v, %v); this test checks nothing", held, err)
	}
	// Only the record names W1 now.
	opts.WorkspaceDir = ""
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, form := range older {
		if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{form}); err != nil || held {
			t.Errorf("setup remove kiro left install B's %q in the file only its record names: %v, %v", form, held, err)
		}
	}
	for _, form := range keep {
		if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{form}); err != nil || !held {
			t.Errorf("setup remove kiro took %q, which is not install B's, out of %s: %v, %v", form, w1Hooks, held, err)
		}
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after the removal: %v", err)
	}
	if names := kiroRecordNames(t, dataB); len(names) != 0 {
		t.Errorf("the removal kept Kiro backup records %v", names)
	}
}

// blockKiroRecordRemoval makes the Kiro backup records in dataDir impossible
// to remove until the returned function runs: a read-only folder on POSIX, an
// open handle (without delete sharing) on Windows.
func blockKiroRecordRemoval(t *testing.T, dataDir string) func() {
	t.Helper()
	dir := filepath.Join(dataDir, "connector_backups", "kiro")
	if runtime.GOOS == "windows" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var held []*os.File
		for _, entry := range entries {
			f, err := os.Open(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, f)
		}
		if len(held) == 0 {
			t.Fatal("no Kiro backup record to hold")
		}
		return func() {
			for _, f := range held {
				_ = f.Close()
			}
		}
	}
	if os.Geteuid() == 0 {
		t.Skip("root removes files from a read-only folder")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	restore := func() { _ = os.Chmod(dir, 0o700) }
	t.Cleanup(restore)
	return restore
}

// assertKiroTeardownRetries checks that what a failed teardown left flags it
// for a retry (VerifyClean, and the boot reclaim's InstallOwnsHookEntries),
// and that the retry, a reclaim as the boot runs it, finishes it.
func assertKiroTeardownRetries(t *testing.T, conn *KiroConnector, opts SetupOpts, fix func()) {
	t.Helper()
	opts.ReclaimOwnHooksOnly = false
	if err := conn.VerifyClean(opts); err == nil || !strings.Contains(err.Error(), "teardown incomplete") {
		t.Errorf("VerifyClean after the failed teardown = %v, want it reported incomplete so it is retried", err)
	}
	if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || !owns {
		t.Errorf("the boot reclaim would not retry the failed teardown: %v, %v", owns, err)
	}
	fix()
	retry := opts
	retry.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), retry); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if names := kiroRecordNames(t, opts.DataDir); len(names) != 0 {
		t.Errorf("the retry kept Kiro backup records %v", names)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after the retry: %v", err)
	}
	if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || owns {
		t.Errorf("after the retry the boot would reclaim again: %v, %v", owns, err)
	}
}

// Review round 4 P3 of rel-1-0-10 GAP-1092/GAP-1174: discardManagedFileBackup
// ignored a failed os.Remove, so a record that could not be deleted survived
// while the teardown reported success, and nothing retried it. The teardown
// fails and its state flags a retry, which finishes the job.
func TestKiroTeardownKeepsTheRetryStateWhenARecordCannotBeRemoved(t *testing.T) {
	for _, reclaim := range []bool{false, true} {
		t.Run(map[bool]string{false: "setup remove", true: "reclaim"}[reclaim], func(t *testing.T) {
			dataB := filepath.Join(t.TempDir(), ".defenseclaw")
			if err := os.MkdirAll(dataB, 0o700); err != nil {
				t.Fatal(err)
			}
			conn, opts, home := kiroSetUpForOrphanTest(t, dataB)
			// The files changed since Setup (the user added a hook to each),
			// so the teardown takes DefenseClaw's entries out of them rather
			// than putting the copies back.
			hooksFile := filepath.Join(home, "hooks", kiroManagedHooksName)
			cfg, err := readJSONObject(hooksFile)
			if err != nil {
				t.Fatal(err)
			}
			hooks, _ := cfg["hooks"].([]interface{})
			cfg["hooks"] = append(hooks, kiroV3Entry("lint", "PostToolUse", kiroUserLint))
			if err := writeJSONObject(hooksFile, cfg); err != nil {
				t.Fatal(err)
			}
			agentFile := filepath.Join(home, "agents", kiroManagedAgentName+".json")
			agent, err := readJSONObject(agentFile)
			if err != nil {
				t.Fatal(err)
			}
			agentHooks, _ := agent["hooks"].(map[string]interface{})
			agentHooks["agentSpawn"] = []interface{}{map[string]interface{}{"command": kiroUserLint}}
			if err := writeJSONObject(agentFile, agent); err != nil {
				t.Fatal(err)
			}
			unblock := blockKiroRecordRemoval(t, dataB)
			opts.ReclaimOwnHooksOnly = reclaim
			err = conn.Teardown(context.Background(), opts)
			unblock()
			if err == nil {
				t.Error("the teardown reported success with Kiro backup records it could not remove")
			}
			if len(kiroRecordNames(t, dataB)) == 0 {
				t.Fatal("no record is left; this test checks nothing")
			}
			assertKiroTeardownRetries(t, conn, opts, func() {})
			if held, err := kiroV3FileHoldsCommand(hooksFile, []string{kiroUserLint}); err != nil || !held {
				t.Errorf("the user's own hook went: %v, %v", held, err)
			}
		})
	}
}

// Review round 4 P3 of rel-1-0-10 GAP-1092/GAP-1174: the reclaim dropped its
// Kiro records and only then revoked the hook token. A revocation that failed
// left the token on disk and nothing that flagged the teardown, so it was
// never retried. The teardown fails and the token beside the disabled hook
// script flags a retry, which revokes it.
func TestKiroTeardownKeepsTheRetryStateWhenTheTokenIsNotRevoked(t *testing.T) {
	for _, reclaim := range []bool{false, true} {
		t.Run(map[bool]string{false: "setup remove", true: "reclaim"}[reclaim], func(t *testing.T) {
			dataB := filepath.Join(t.TempDir(), ".defenseclaw")
			if err := os.MkdirAll(dataB, 0o700); err != nil {
				t.Fatal(err)
			}
			conn, opts, _ := kiroSetUpForOrphanTest(t, dataB)
			token, err := HookAPITokenFilePath(dataB, "kiro")
			if err != nil {
				t.Fatal(err)
			}
			// A token the teardown cannot remove: a folder in its place.
			if err := os.Remove(token); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(token, "held"), 0o700); err != nil {
				t.Fatal(err)
			}
			opts.ReclaimOwnHooksOnly = reclaim
			if err := conn.Teardown(context.Background(), opts); err == nil {
				t.Error("the teardown reported success with a hook token it could not revoke")
			}
			assertKiroTeardownRetries(t, conn, opts, func() {
				if err := os.RemoveAll(token); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
