// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0165: kiro-cli 3.x loads the agent file's hooks and ~/.kiro/hooks
// together, so DefenseClaw hooks in both audited every tool call twice.

func TestKiroCLIv3Engine(t *testing.T) {
	for raw, want := range map[string]bool{
		"kiro-cli 3.3.0":          true,
		"kiro-cli 3.0.0":          true,
		"kiro-cli v4.1.2":         true,
		"kiro-cli 2.27.1":         false,
		"kiro-cli 2.99.9":         false,
		"1.0.182+kiro-ide":        false,
		"3.3.0":                   false,
		"kiro-cli 3.3.0+kiro-ide": false,
		"":                        false,
		"kiro-cli":                false,
	} {
		if got := kiroCLIv3Engine(raw); got != want {
			t.Errorf("kiroCLIv3Engine(%q) = %v, want %v", raw, got, want)
		}
	}
}

func kiroAgentHooksField(t *testing.T, path string) interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg["name"] != kiroManagedAgentName || cfg["includeMcpJson"] != true {
		t.Fatalf("agent overlay lost: %#v", cfg)
	}
	return cfg["hooks"]
}

func TestKiroSetupV3WritesOnlyTheHooksFile(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", AgentVersion: "kiro-cli 3.3.0"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	assertKiroV3Hooks(t, filepath.Join(home, "hooks", kiroManagedHooksName), conn.hookCommandForV3Surface(opts))
	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if hooks := kiroAgentHooksField(t, agentPath); hooks != nil {
		t.Fatalf("kiro-cli 3.3.0 agent file carries hooks %#v, want none", hooks)
	}
	assertKiroDefaultAgentSetting(t, filepath.Join(home, "settings", "cli.json"))
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("ownedHookContractPresent = %v, %v, want true", present, err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	for _, path := range []string{filepath.Join(home, "hooks", kiroManagedHooksName), agentPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived teardown, err=%v", path, err)
		}
	}
}

// Before the fix, kiro-cli 3.x got the agent hooks too: the same Setup on a
// 2.x banner (or no version) keeps both surfaces, as rel does.
func TestKiroSetupBefore3KeepsTheAgentHooks(t *testing.T) {
	for _, version := range []string{"kiro-cli 2.27.1", ""} {
		home := t.TempDir()
		KiroHomeOverride = home
		opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", AgentVersion: version}
		conn := NewKiroConnector()
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup %q: %v", version, err)
		}
		assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
		if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
			t.Fatalf("%q: ownedHookContractPresent = %v, %v, want true", version, present, err)
		}
		KiroHomeOverride = ""
	}
}

// An install from before the upgrade to kiro-cli 3.x holds the hooks in both
// files: Setup on 3.x strips DefenseClaw's agent entries (either form), keeps
// the user's own, and the contract check reports the doubled install as broken
// until then.
func TestKiroSetupV3StripsEarlierAgentHooks(t *testing.T) {
	for _, form := range []string{"v2", "universal"} {
		home := t.TempDir()
		KiroHomeOverride = home
		t.Cleanup(func() { KiroHomeOverride = "" })
		dataDir := t.TempDir()
		earlier := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
		conn := NewKiroConnector()
		if err := conn.Setup(context.Background(), earlier); err != nil {
			t.Fatalf("earlier Setup: %v", err)
		}
		agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
		command := conn.hookCommand(earlier)
		if form == "universal" {
			cfg, err := readJSONObject(agentPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg["hooks"] = reconcileKiroUniversalHooks([]interface{}{map[string]interface{}{
				"name": "lint", "trigger": "postToolUse", "matcher": "fs_write", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": "npm run lint"},
			}}, command)
			if err := writeJSONObject(agentPath, cfg); err != nil {
				t.Fatal(err)
			}
		}
		now := earlier
		now.AgentVersion = "kiro-cli 3.3.0"
		if present, err := conn.ownedHookContractPresent(now); err != nil || present {
			t.Fatalf("%s: doubled install on 3.3.0: present=%v err=%v, want not present", form, present, err)
		}
		if err := conn.Setup(context.Background(), now); err != nil {
			t.Fatalf("%s: Setup on 3.3.0: %v", form, err)
		}
		held, err := kiroV2AgentReferencesAnyHook(agentPath, command)
		if err != nil || held {
			t.Fatalf("%s: agent file still holds DefenseClaw hooks (held=%v err=%v)", form, held, err)
		}
		hooks := kiroAgentHooksField(t, agentPath)
		if form == "universal" {
			list, _ := hooks.([]interface{})
			if len(list) != 1 {
				t.Fatalf("universal: user's own hook lost: %#v", hooks)
			}
		} else if hooks != nil {
			t.Fatalf("v2: hooks left %#v", hooks)
		}
		assertKiroV3Hooks(t, filepath.Join(home, "hooks", kiroManagedHooksName), conn.hookCommandForV3Surface(now))
		if present, err := conn.ownedHookContractPresent(now); err != nil || !present {
			t.Fatalf("%s: after Setup present=%v err=%v, want present", form, present, err)
		}
	}
}
