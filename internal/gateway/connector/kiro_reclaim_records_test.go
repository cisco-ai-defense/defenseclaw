// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// kiroRecordNames lists the logical names of dataDir's Kiro backup records.
func kiroRecordNames(t *testing.T, dataDir string) []string {
	t.Helper()
	var names []string
	if err := forEachManagedFileBackup(dataDir, func(b managedFileBackup) error {
		if b.Connector == "kiro" {
			names = append(names, b.LogicalName)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return names
}

// kiroV3Entry is a v3 hook entry that runs command.
func kiroV3Entry(name, trigger, command string) map[string]interface{} {
	return map[string]interface{}{"name": name, "trigger": trigger,
		"action": map[string]interface{}{"type": "command", "command": command}}
}

// writeKiroWindowsEntriesOfAnotherInstall writes, as an install that set Kiro
// up after the reclaim would on Windows, the account's launcher command into
// the global hook file and the defenseclaw agent, and returns those files.
func writeKiroWindowsEntriesOfAnotherInstall(t *testing.T, home string) []string {
	t.Helper()
	windows := kiroWindowsOwnedHookCommandsFor(false)
	if len(windows) == 0 {
		t.Fatal("no Windows Kiro command to write")
	}
	hooksFile := filepath.Join(home, "hooks", kiroManagedHooksName)
	agentFile := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	files := map[string]map[string]interface{}{
		hooksFile: {"version": "v1", "hooks": []interface{}{kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", windows[0])}},
		agentFile: {"name": kiroManagedAgentName, "hooks": map[string]interface{}{
			"preToolUse": []interface{}{map[string]interface{}{"command": windows[0], "matcher": "*"}},
		}},
	}
	for path, cfg := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONObject(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	return []string{hooksFile, agentFile}
}

// assertReclaimedDataFolderOwnsNoWindowsLauncherEntries checks, with the
// Windows rules on every host, that a reclaimed data folder keeps no Kiro
// record and so owns none of the launcher entries another install writes
// later (kiroDataDirSetUpKiro).
func assertReclaimedDataFolderOwnsNoWindowsLauncherEntries(t *testing.T, conn *KiroConnector, home, dataDir string) {
	t.Helper()
	if names := kiroRecordNames(t, dataDir); len(names) != 0 {
		t.Errorf("the reclaim kept Kiro backup records %v", names)
	}
	if kiroDataDirSetUpKiro(dataDir) {
		t.Error("a reclaimed data folder still counts as one that set Kiro up")
	}
	writeKiroWindowsEntriesOfAnotherInstall(t, home)
	opts := SetupOpts{DataDir: dataDir}
	if got, err := conn.orphanedHookFilesFor("windows", opts); err != nil || len(got) != 0 {
		t.Errorf("the reclaimed data folder owns another install's Windows Kiro entries: %v, %v", got, err)
	}
	if got, err := orphanedHookConfigPathsFor("windows", conn, opts); err != nil || len(got) != 0 {
		t.Errorf("prune-orphans of the reclaimed data folder would take another install's Windows Kiro entries: %v, %v", got, err)
	}
}

// Review round 4 P2s of rel-1-0-10 GAP-1092/GAP-1174. Data folder B set Kiro
// up with workspace W1; claw.workspace_dir changed later (RHEL-U3-09), so
// only B's backup record still names W1/.kiro/hooks/defenseclaw.json. B's
// reclaim (boot or `connector prune-orphans`) skipped that file, because its
// scope read only the files the current settings name, while prune listed it
// as pruned or not at all; it also kept B's records, so on Windows B stayed an
// owner of the account's launcher commands. The reclaim removes B's exact
// entries from W1, keeps every other entry there, and drops B's records.
func TestKiroReclaimCleansAnOldWorkspaceHookFileOnlyItsRecordNames(t *testing.T) {
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
	if held, err := kiroV3FileHoldsCommand(w1Hooks, own); err != nil || !held {
		t.Fatalf("Setup did not write install B's entries into %s: %v, %v", w1Hooks, held, err)
	}
	// Another data folder's entry and the user's own one share the file.
	other := kiroHookInvocationCommandFor("linux", filepath.Join(root, "a", ".defenseclaw", "hooks", kiroHookScriptName), KiroHookSurfaceV3, false)
	const lint = "/usr/local/bin/lint"
	cfg, err := readJSONObject(w1Hooks)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].([]interface{})
	cfg["hooks"] = append(hooks, kiroV3Entry("defenseclaw-pre-tool", "PreToolUse", other), kiroV3Entry("lint", "PostToolUse", lint))
	if err := writeJSONObject(w1Hooks, cfg); err != nil {
		t.Fatal(err)
	}

	opts.WorkspaceDir = ""
	if listed, err := OrphanedHookConfigPaths(conn, opts); err != nil || !slices.Contains(listed, w1Hooks) {
		t.Errorf("prune-orphans does not list the old workspace file of install B: %v, %v", listed, err)
	}
	reclaim := opts
	reclaim.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), reclaim); err != nil {
		t.Fatalf("reclaim Teardown: %v", err)
	}
	if held, err := kiroV3FileHoldsCommand(w1Hooks, own); err != nil || held {
		t.Errorf("install B's entries stayed in its old workspace file: %v, %v", held, err)
	}
	for _, keep := range []string{other, lint} {
		if held, err := kiroV3FileHoldsCommand(w1Hooks, []string{keep}); err != nil || !held {
			t.Errorf("the reclaim removed an entry that is not install B's (%s): %v, %v", keep, held, err)
		}
	}
	if left, err := OrphanedHookConfigPaths(conn, opts); err != nil || len(left) != 0 {
		t.Errorf("after the reclaim prune-orphans still lists %v, %v", left, err)
	}
	assertReclaimedDataFolderOwnsNoWindowsLauncherEntries(t, conn, home, dataB)
}

// The user deleted ~/.kiro/agents/defenseclaw.json after B set Kiro up. B's
// reclaim cannot prove the default-agent setting is its own without that
// agent, so the setting stays; the settings record it kept made B, on
// Windows, the owner of the identical launcher entries of an install that set
// Kiro up later, which B's next boot or prune then stripped.
func TestKiroReclaimWithADeletedAgentDropsTheSettingsRecord(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(dataB, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, opts, home := kiroSetUpForOrphanTest(t, dataB)
	if !slices.Contains(kiroRecordNames(t, dataB), kiroSettingsLogicalName) {
		t.Fatal("Setup kept no settings record; this test checks nothing")
	}
	if err := os.Remove(filepath.Join(home, "agents", kiroManagedAgentName+".json")); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, "settings", "cli.json")
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	own := conn.installHookCommands(opts)
	opts.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("reclaim Teardown: %v", err)
	}
	if got, err := os.ReadFile(settings); err != nil || string(got) != string(before) {
		t.Errorf("the reclaim changed a setting it cannot prove is its own (%v):\n%s", err, got)
	}
	if held, err := kiroV3FileHoldsCommand(filepath.Join(home, "hooks", kiroManagedHooksName), own); err != nil || held {
		t.Errorf("install B's global hooks stayed: %v, %v", held, err)
	}
	assertReclaimedDataFolderOwnsNoWindowsLauncherEntries(t, conn, home, dataB)
}

// B hooked the custom default agent the user had chosen; the user then chose
// another one, so only B's agent record still names the first. The reclaim,
// which drops that record, removes B's entries from it first and keeps the
// user's.
func TestKiroReclaimCleansACustomAgentOnlyItsRecordNames(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(dataB, 0o700); err != nil {
		t.Fatal(err)
	}
	conn, opts, home := kiroSetUpForOrphanTest(t, dataB)
	settings := filepath.Join(home, "settings", "cli.json")
	choose := func(agent string) {
		t.Helper()
		cfg, err := readJSONObject(settings)
		if err != nil {
			t.Fatal(err)
		}
		cfg[kiroDefaultAgentSettingKey] = agent
		if err := writeJSONObject(settings, cfg); err != nil {
			t.Fatal(err)
		}
	}
	const lint = "/usr/local/bin/lint"
	mine := filepath.Join(home, "agents", "mine.json")
	if err := writeJSONObject(mine, map[string]interface{}{"name": "mine", "hooks": map[string]interface{}{
		"preToolUse": []interface{}{map[string]interface{}{"command": lint, "matcher": "*"}},
	}}); err != nil {
		t.Fatal(err)
	}
	choose("mine")
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	own := conn.installHookCommands(opts)
	if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || !held {
		t.Fatalf("Setup did not hook the custom default agent: %v, %v", held, err)
	}
	choose("other")
	if paths := conn.agentCleanupPaths(opts); slices.Contains(paths, mine) {
		t.Fatalf("the settings still name %s (%v); this test checks nothing", mine, paths)
	}
	opts.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("reclaim Teardown: %v", err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, own); err != nil || held {
		t.Errorf("install B's entries stayed in the custom agent only its record named: %v, %v", held, err)
	}
	if held, err := kiroAgentFileHoldsCommand(mine, []string{lint}); err != nil || !held {
		t.Errorf("the reclaim removed the user's own hook: %v, %v", held, err)
	}
	if names := kiroRecordNames(t, dataB); len(names) != 0 {
		t.Errorf("the reclaim kept Kiro backup records %v", names)
	}
}
