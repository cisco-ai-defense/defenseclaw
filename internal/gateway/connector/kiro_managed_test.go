// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The managed (standalone enterprise) Kiro footprint is the user's global
// ~/.kiro/hooks file, which Kiro IDE and kiro-cli --v3 merge into every
// workspace, plus the CLI 2.x agent and its default-agent setting. The
// guardian passes the machine-wide workspace directory to every enrolled
// user; a managed install must not write a workspace copy there, which
// every user would share.
func TestKiroManagedSetupWritesOnlyTheUsersGlobalHooks(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home

	opts := SetupOpts{
		DataDir:           dataDir,
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		WorkspaceDir:      workspace,
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	global := filepath.Join(home, "hooks", kiroManagedHooksName)
	assertKiroV3Hooks(t, global, conn.hookCommandForV3Surface(opts))
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
	assertKiroDefaultAgentSetting(t, filepath.Join(home, "settings", "cli.json"))
	workspaceCopy := filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName)
	if _, err := os.Stat(workspaceCopy); !os.IsNotExist(err) {
		t.Fatalf("managed Setup wrote the workspace copy %s (err=%v)", workspaceCopy, err)
	}

	caps := conn.HookCapabilities(opts)
	if caps.Scope != "user" || caps.ConfigPath != global {
		t.Fatalf("managed hook capability = scope %q path %q, want user %q", caps.Scope, caps.ConfigPath, global)
	}
	for _, path := range conn.AgentPaths(opts).PatchedFiles {
		if path == workspaceCopy {
			t.Fatalf("managed footprint lists the workspace copy %s", path)
		}
	}
	present, err := conn.ownedHookContractPresent(opts)
	if err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}

	// A key added to the CLI settings after Setup, which a later Setup (the
	// guardian's repair) leaves in place, survives teardown: only
	// DefenseClaw's default-agent setting comes out.
	settings := filepath.Join(home, "settings", "cli.json")
	edited := "{\"chat.defaultAgent\": \"" + kiroManagedAgentName + "\", \"chat.enableAutoAgentUpgrade\": false}\n"
	if err := os.WriteFile(settings, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repeated Setup: %v", err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if cfg, err := readJSONObject(settings); err != nil || len(cfg) != 1 || cfg["chat.enableAutoAgentUpgrade"] != false {
		t.Fatalf("settings after teardown = %v (err %v), want only the user's key", cfg, err)
	}
}

func TestKiroManagedTeardownDisablesCachedHookScript(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", ManagedEnterprise: true}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(dataDir, "hooks", kiroHookScriptName))
	if err != nil {
		t.Fatalf("read disabled hook: %v", err)
	}
	if !strings.Contains(string(script), "disabled tombstone") || !strings.Contains(string(script), "exit 0") || strings.Contains(string(script), kiroHookAPIPath) {
		t.Fatalf("Kiro teardown left an active hook script: %s", script)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup after teardown: %v", err)
	}
	script, err = os.ReadFile(filepath.Join(dataDir, "hooks", kiroHookScriptName))
	if err != nil || !strings.Contains(string(script), kiroHookAPIPath) {
		t.Fatalf("Kiro setup did not replace the disabled hook script: %v", err)
	}
}

// A managed install never edits the user's own agents. With a custom
// chat.defaultAgent, it leaves that agent byte for byte and makes the
// defenseclaw agent the default instead, so bare kiro-cli still runs a
// hooked agent; teardown puts the user's setting back.
func TestKiroManagedSetupLeavesTheUsersDefaultAgentAlone(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	custom := filepath.Join(home, "agents", "mine.json")
	settings := filepath.Join(home, "settings", "cli.json")
	for path, body := range map[string]string{
		custom:   "{\n  \"name\": \"mine\",\n  \"tools\": [\"*\"]\n}\n",
		settings: "{\"chat.defaultAgent\": \"mine\"}\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	customBefore, _ := os.ReadFile(custom)
	settingsBefore, _ := os.ReadFile(settings)

	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", ManagedEnterprise: true}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("managed Setup edited the user's agent:\n%s", after)
	}
	assertKiroDefaultAgentSetting(t, settings)
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
	for _, path := range conn.AgentPaths(opts).PatchedFiles {
		if path == custom {
			t.Fatalf("managed footprint lists the user's agent %s", path)
		}
	}
	present, err := conn.ownedHookContractPresent(opts)
	if err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("managed teardown edited the user's agent:\n%s", after)
	}
	if after, _ := os.ReadFile(settings); string(after) != string(settingsBefore) {
		t.Fatalf("managed teardown did not restore the user's default agent: %s", after)
	}

	// A per-user install still guards the custom default agent itself.
	perUser := opts
	perUser.ManagedEnterprise = false
	if err := conn.Setup(context.Background(), perUser); err != nil {
		t.Fatalf("per-user Setup: %v", err)
	}
	if present, err := kiroV2AgentReferencesHook(custom, conn.hookCommand(perUser)); err != nil || !present {
		t.Fatalf("per-user Setup must still hook the custom default agent: %v %v", present, err)
	}
}

// writeKiroCustomDefaultAgent writes the user's own default agent and the CLI
// settings that select it, and returns both paths and their bytes.
func writeKiroCustomDefaultAgent(t *testing.T, home string) (custom, settings string, customBefore, settingsBefore []byte) {
	t.Helper()
	custom = filepath.Join(home, "agents", "mine.json")
	settings = filepath.Join(home, "settings", "cli.json")
	customBefore = []byte("{\n  \"name\": \"mine\",\n  \"tools\": [\"*\"]\n}\n")
	settingsBefore = []byte("{\"chat.defaultAgent\": \"mine\"}\n")
	for path, body := range map[string][]byte{custom: customBefore, settings: settingsBefore} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return custom, settings, customBefore, settingsBefore
}

// An upgrade from the per-user footprint (which hooked the user's custom
// default agent and wrote the workspace copy) to the managed one: managed
// Setup removes what the earlier footprint added to the user's agent and
// the workspace copy before it makes the defenseclaw agent the default, and
// Teardown then puts the user's setting back with nothing of DefenseClaw
// left in their agent.
func TestKiroManagedSetupReclaimsAnEarlierPerUserFootprint(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows enrolls Kiro through the ACP guard, not managed hooks, so
		// no managed Setup follows a per-user one there.
		t.Skip("managed Kiro hooks are enrolled on Linux and macOS only")
	}
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	custom, settings, customBefore, settingsBefore := writeKiroCustomDefaultAgent(t, home)

	perUser := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: workspace, HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), perUser); err != nil {
		t.Fatalf("per-user Setup: %v", err)
	}
	if hooked, err := kiroV2AgentReferencesAnyHook(custom, conn.hookCommand(perUser)); err != nil || !hooked {
		t.Fatalf("per-user Setup must hook the custom default agent: %v %v", hooked, err)
	}
	workspaceCopy := filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName)
	if _, err := os.Stat(workspaceCopy); err != nil {
		t.Fatalf("per-user Setup did not write the workspace copy: %v", err)
	}
	// The per-user footprint itself is unchanged: the workspace copy and
	// the workspace scope it has always reported.
	if got := conn.hookConfigPaths(perUser); len(got) != 2 || got[0] != filepath.Join(home, "hooks", kiroManagedHooksName) || got[1] != workspaceCopy {
		t.Fatalf("per-user hook paths = %v", got)
	}
	if scope := conn.HookCapabilities(perUser).Scope; scope != "workspace" {
		t.Fatalf("per-user scope = %q, want workspace", scope)
	}

	managed := perUser
	managed.ManagedEnterprise = true
	if err := conn.Setup(context.Background(), managed); err != nil {
		t.Fatalf("managed Setup: %v", err)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("managed Setup left the earlier hooks in the user's agent:\n%s", after)
	}
	if _, err := os.Stat(workspaceCopy); !os.IsNotExist(err) {
		t.Fatalf("managed Setup left the earlier workspace copy (err=%v)", err)
	}
	assertKiroDefaultAgentSetting(t, settings)
	// Only the settings backup still names the user's agent now; teardown
	// finds it there.
	if got := kiroPristineDefaultAgentPath(dataDir); got != custom {
		t.Fatalf("the settings backup names %q, want the user's agent %q", got, custom)
	}
	if present, err := conn.ownedHookContractPresent(managed); err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}
	// A repeated managed Setup (the guardian's repair) changes nothing.
	if err := conn.Setup(context.Background(), managed); err != nil {
		t.Fatalf("repeated managed Setup: %v", err)
	}

	if err := conn.Teardown(context.Background(), managed); err != nil {
		t.Fatalf("managed Teardown: %v", err)
	}
	if err := conn.VerifyClean(managed); err != nil {
		t.Fatalf("managed VerifyClean: %v", err)
	}
	if after, _ := os.ReadFile(settings); string(after) != string(settingsBefore) {
		t.Fatalf("teardown did not restore the user's default agent: %s", after)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("teardown left DefenseClaw in the user's agent:\n%s", after)
	}

	// On another home, a managed teardown alone (no managed Setup since the
	// per-user one) also reclaims the earlier workspace copy.
	KiroHomeOverride = t.TempDir()
	earlier := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir(), HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), earlier); err != nil {
		t.Fatalf("earlier per-user Setup: %v", err)
	}
	earlierCopy := filepath.Join(earlier.WorkspaceDir, ".kiro", "hooks", kiroManagedHooksName)
	earlier.ManagedEnterprise = true
	if err := conn.Teardown(context.Background(), earlier); err != nil {
		t.Fatalf("managed Teardown: %v", err)
	}
	if err := conn.VerifyClean(earlier); err != nil {
		t.Fatalf("managed VerifyClean: %v", err)
	}
	if _, err := os.Stat(earlierCopy); !os.IsNotExist(err) {
		t.Fatalf("workspace copy left after teardown (err=%v)", err)
	}
}

// When the earlier workspace copy cannot be removed, managed Setup still
// makes the defenseclaw agent the default before it reports the failure:
// the reclaim already took DefenseClaw's hooks out of the user's own
// agent, which must not stay the default without them.
func TestKiroManagedSetupSwitchesTheDefaultAgentWhenTheReclaimFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows enrolls Kiro through the ACP guard, not managed hooks, so
		// no managed Setup follows a per-user one there.
		t.Skip("managed Kiro hooks are enrolled on Linux and macOS only")
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	custom, settings, _, _ := writeKiroCustomDefaultAgent(t, home)

	perUser := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: workspace, HookFailMode: "closed"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), perUser); err != nil {
		t.Fatalf("per-user Setup: %v", err)
	}
	hooks := filepath.Join(workspace, ".kiro", "hooks")
	if err := os.Chmod(hooks, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooks, 0o700) })

	managed := perUser
	managed.ManagedEnterprise = true
	err := conn.Setup(context.Background(), managed)
	if err == nil || !strings.Contains(err.Error(), "reclaim earlier per-user footprint") {
		t.Fatalf("managed Setup = %v, want the reclaim failure reported", err)
	}
	if hooked, err := kiroV2AgentReferencesAnyHook(custom, conn.hookCommand(perUser)); err != nil || hooked {
		t.Fatalf("premise: the reclaim removed the hooks from the user's agent (hooked=%v err=%v)", hooked, err)
	}
	assertKiroDefaultAgentSetting(t, settings)
	if present, err := conn.ownedHookContractPresent(managed); err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}
}
