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

func kiroSharedFiles(home string) []string {
	return []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(home, "agents", kiroManagedAgentName+".json"),
		filepath.Join(home, "settings", "cli.json"),
	}
}

func readKiroFiles(t *testing.T, paths []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = string(data)
	}
	return out
}

// Review P2 of rel-1-0-10 GAP-1092: the teardown of an unconfigured connector
// (SetupOpts.ReclaimOwnHooksOnly) touches only the files that hold this
// install's own commands, and in them only those entries. A data folder that
// never set Kiro up removes nothing of the install that guards Kiro, on every
// OS (on Windows it owns no command without its own script or record).
func TestKiroReclaimOfADataFolderThatNeverSetKiroUpTouchesNothing(t *testing.T) {
	_, _, home := kiroSetUpForOrphanTest(t, t.TempDir())
	shared := kiroSharedFiles(home)
	before := readKiroFiles(t, shared)
	other := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: other, APIAddr: "127.0.0.1:18970", ReclaimOwnHooksOnly: true}
	if err := NewKiroConnector().Teardown(context.Background(), opts); err != nil {
		t.Fatalf("reclaim Teardown: %v", err)
	}
	for path, want := range readKiroFiles(t, shared) {
		if want != before[path] {
			t.Errorf("the reclaim of a data folder that never set Kiro up changed %s", path)
		}
	}
}

// Data folder B set Kiro up for a workspace; install A later took over the
// global hook file, the defenseclaw agent and the default-agent setting. B's
// reclaim removes its workspace hooks and leaves A's files byte for byte.
func TestKiroReclaimRemovesOnlyThisInstallsFiles(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	root := t.TempDir()
	dataA := filepath.Join(root, "a", ".defenseclaw")
	dataB := filepath.Join(root, "b", ".defenseclaw")
	workspace := filepath.Join(root, "work")
	for _, dir := range []string{dataA, dataB, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	optsB := SetupOpts{DataDir: dataB, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", WorkspaceDir: workspace}
	optsA := SetupOpts{DataDir: dataA, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), optsB); err != nil {
		t.Fatal(err)
	}
	if err := NewKiroConnector().Setup(context.Background(), optsA); err != nil {
		t.Fatal(err)
	}
	shared := kiroSharedFiles(home)
	before := readKiroFiles(t, shared)
	workspaceHooks := filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName)
	globalHooks, agent := shared[0], shared[1]
	var workspaceCommands []string
	if runtime.GOOS == "windows" {
		// Known limit: two Windows data folders that both set Kiro up run the
		// account's launcher, so their commands are identical and both own
		// them. Each install's proof is the same entries, in the shared files
		// too; the data folder that never set Kiro up owns none (the first
		// test above).
		foundB, err := conn.orphanedHookFiles(optsB)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{workspaceHooks, globalHooks, agent} {
			if !slices.Contains(foundB, want) {
				t.Fatalf("install B's proof = %v, missing %s: on Windows both installs own the launcher entries", foundB, want)
			}
		}
		foundA, err := NewKiroConnector().orphanedHookFiles(optsA)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{globalHooks, agent} {
			if !slices.Contains(foundA, want) {
				t.Fatalf("install A's proof = %v, missing %s", foundA, want)
			}
		}
		workspaceCommands = conn.installHookCommands(optsB)
	} else if found, err := conn.orphanedHookFiles(optsB); err != nil || len(found) != 1 || found[0] != workspaceHooks {
		t.Fatalf("install B's proof = %v, %v; want only its workspace file", found, err)
	}
	optsB.ReclaimOwnHooksOnly = true
	if err := conn.Teardown(context.Background(), optsB); err != nil {
		t.Fatalf("reclaim Teardown: %v", err)
	}
	if runtime.GOOS == "windows" {
		// The shared entries are B's to remove too (the known limit above);
		// what stays exact is B's own workspace copy, which no longer holds
		// its launcher entries, and B owning nothing afterwards.
		if held, err := kiroV3FileHoldsCommand(workspaceHooks, workspaceCommands); err != nil || held {
			t.Errorf("install B's workspace hooks still run its launcher: %v, %v", held, err)
		}
		if found, err := conn.orphanedHookFiles(optsB); err != nil || len(found) != 0 {
			t.Fatalf("after the reclaim install B still owns %v, %v", found, err)
		}
		return
	}
	for path, want := range readKiroFiles(t, shared) {
		if want != before[path] {
			t.Errorf("install B's reclaim changed install A's %s", path)
		}
	}
	if data, err := os.ReadFile(workspaceHooks); err == nil && strings.Contains(string(data), dataB) {
		t.Errorf("install B's workspace hooks stayed:\n%s", data)
	}
	if found, err := conn.orphanedHookFiles(optsB); err != nil || len(found) != 0 {
		t.Fatalf("after the reclaim install B still owns %v, %v", found, err)
	}
	if found, err := NewKiroConnector().orphanedHookFiles(optsA); err != nil || len(found) != 2 {
		t.Fatalf("install A's own files = %v, %v; want its global hooks and agent", found, err)
	}
}

// Review P3: on Windows the generic match of OrphanedHookConfigPaths (the
// native `<launcher> hook --connector kiro` command) names the account's
// launcher, not a data folder, so Kiro's own answer, which asks for proof in
// this data folder, is the whole one there. Checked with the Windows rules on
// every host.
func TestOrphanedKiroHookPathsOnWindowsSkipTheAccountWideMatch(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	agent := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if err := os.MkdirAll(filepath.Dir(agent), 0o700); err != nil {
		t.Fatal(err)
	}
	native := hookInvocationCommandFor("windows", "kiro", "")
	cfg := map[string]interface{}{"name": kiroManagedAgentName, "hooks": map[string]interface{}{
		"preToolUse": []interface{}{map[string]interface{}{"command": native, "matcher": "*"}},
	}}
	if err := writeJSONObject(agent, cfg); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: dataDir}
	decoded, err := decodeHookConfigFile(agent)
	if err != nil {
		t.Fatal(err)
	}
	if !structuredHookCommandReferences(decoded, ownedHookCommandNeedlesFor("windows", opts, conn)) {
		t.Fatal("the account-wide Windows needle no longer matches the native form; this test checks nothing")
	}
	if found, err := orphanedHookConfigPathsFor("windows", conn, opts); err != nil || len(found) != 0 {
		t.Fatalf("a data folder that never set Kiro up finds the account's native Windows hooks: %v, %v", found, err)
	}
}
