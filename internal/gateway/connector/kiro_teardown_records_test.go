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
// through; a file that is not JSON is skipped and keeps its record, which
// then proves nothing, and the other files are cleaned.
func TestKiroTeardownSkipsARecordedFileItCannotParse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		keepRecord bool
	}{
		{"not JSON", `{"hooks": [`, true},
		{"a JSON list", "[]\r\n", true},
		{"empty", "", false},
	} {
		for _, reclaim := range []bool{false, true} {
			mode := "setup remove"
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
				opts := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: w1}
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
				if err := conn.Teardown(context.Background(), opts); err != nil {
					t.Fatalf("Teardown failed on the file it cannot parse: %v", err)
				}
				opts.ReclaimOwnHooksOnly = false
				if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || held {
					t.Errorf("install B's entries stayed in the agent saved with a BOM: %v, %v", held, err)
				}
				if held, err := kiroAgentFileHoldsCommand(mine, []string{kiroUserLint}); err != nil || !held {
					t.Errorf("the user's own hook went: %v, %v", held, err)
				}
				if got, err := os.ReadFile(w1Hooks); err != nil || string(got) != tc.body {
					t.Errorf("the file it cannot parse changed (%v): %q", err, got)
				}
				var want []string
				if tc.keepRecord {
					want = []string{kiroBackupLogicalName(w1Hooks)}
				}
				if names := kiroRecordNames(t, dataB); !slices.Equal(names, want) {
					t.Errorf("Kiro backup records after the teardown = %v, want %v", names, want)
				}
				// The record kept for the file proves nothing and flags
				// nothing, so the next boot does no work.
				if kiroDataDirSetUpKiro(dataB) {
					t.Error("the record of a file that cannot be parsed keeps the data folder an owner of Kiro's commands")
				}
				if err := conn.VerifyClean(opts); err != nil {
					t.Errorf("VerifyClean: %v", err)
				}
				if owns, err := conn.InstallOwnsHookEntries(opts); err != nil || owns {
					t.Errorf("the next boot would reclaim again: %v, %v", owns, err)
				}
			})
		}
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
