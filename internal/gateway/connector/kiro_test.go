// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKiroSetupWritesV3AndDefaultAgentHooks(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() {
		KiroHomeOverride = ""
		KiroHooksPathOverride = ""
	})
	KiroHomeOverride = home

	opts := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: workspace,
		HookFailMode: "open",
	}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	script := filepath.Join(dataDir, "hooks", kiroHookScriptName)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("hook script missing: %v", err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read hook script: %v", err)
	}
	if !strings.Contains(string(body), "/api/v1/kiro/hook") {
		t.Fatalf("hook script does not POST to the Kiro endpoint")
	}
	if !strings.Contains(string(body), "defenseclaw_user_identity_args") {
		t.Fatalf("hook script is missing the identity reader")
	}

	for _, path := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName),
	} {
		// The v3 config carries the surface marker; the 2.x agent config
		// below must stay on the bare command.
		assertKiroV3Hooks(t, path, script+" --hook-surface "+KiroHookSurfaceV3)
	}
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), script)
	assertKiroDefaultAgentSetting(t, filepath.Join(home, "settings", "cli.json"))

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName),
		filepath.Join(home, "agents", kiroManagedAgentName+".json"),
		filepath.Join(home, "settings", "cli.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed after teardown, err=%v", path, err)
		}
	}
}

func TestKiroSetupPreservesForeignHooks(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(func() {
		KiroHomeOverride = ""
	})
	KiroHomeOverride = home

	v3Path := filepath.Join(home, "hooks", kiroManagedHooksName)
	if err := os.MkdirAll(filepath.Dir(v3Path), 0o700); err != nil {
		t.Fatalf("mkdir v3: %v", err)
	}
	if err := os.WriteFile(v3Path, []byte(`{
  "version": "v1",
  "hooks": [
    {
      "name": "lint-on-save",
      "trigger": "PostFileSave",
      "action": {"type": "command", "command": "npm run lint"}
    }
  ]
}
`), 0o600); err != nil {
		t.Fatalf("write foreign v3: %v", err)
	}

	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	if err := os.WriteFile(agentPath, []byte(`{
  "name": "defenseclaw",
  "model": "keep-me",
  "hooks": {
    "preToolUse": [{"command": "echo foreign", "matcher": "write"}]
  }
}
`), 0o600); err != nil {
		t.Fatalf("write foreign agent: %v", err)
	}

	opts := SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "open",
	}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	var v3 map[string]interface{}
	if data, err := os.ReadFile(v3Path); err != nil {
		t.Fatalf("read v3 after teardown: %v", err)
	} else if err := json.Unmarshal(data, &v3); err != nil {
		t.Fatalf("parse v3: %v", err)
	}
	hooks, _ := v3["hooks"].([]interface{})
	if len(hooks) != 1 {
		t.Fatalf("foreign v3 hooks = %#v, want the operator hook only", hooks)
	}

	var agent map[string]interface{}
	if data, err := os.ReadFile(agentPath); err != nil {
		t.Fatalf("read agent after teardown: %v", err)
	} else if err := json.Unmarshal(data, &agent); err != nil {
		t.Fatalf("parse agent: %v", err)
	}
	if agent["model"] != "keep-me" {
		t.Fatalf("agent model = %#v, want keep-me", agent["model"])
	}
	pre, _ := agent["hooks"].(map[string]interface{})["preToolUse"].([]interface{})
	if len(pre) != 1 {
		t.Fatalf("foreign preToolUse = %#v", pre)
	}
}

func TestKiroSetupMigratesInvalidAgentStopKey(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home

	dataDir := t.TempDir()
	script := filepath.Join(dataDir, "hooks", kiroHookScriptName)
	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	if err := os.WriteFile(agentPath, []byte(`{
  "name": "defenseclaw",
  "hooks": {
    "agentStop": [{"command": "`+script+`", "description": "old", "matcher": ".*"}]
  }
}
`), 0o600); err != nil {
		t.Fatalf("write stale agent: %v", err)
	}

	opts := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "open",
	}
	if err := NewKiroConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	assertKiroV2AgentHooks(t, agentPath, script)
}

func TestKiroHookCapabilitiesPointAtInstalledFiles(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	opts := SetupOpts{DataDir: t.TempDir()}
	caps := NewKiroConnector().HookCapabilities(opts)
	if caps.ConfigPath != filepath.Join(home, "hooks", kiroManagedHooksName) {
		t.Fatalf("ConfigPath = %q", caps.ConfigPath)
	}
	if !caps.CanBlock || !caps.SupportsFailClosed {
		t.Fatalf("capabilities = %+v", caps)
	}
}

// The veto surface follows the hook config that invoked us, never the
// release. kiro-cli 2.22.0 is both the 2.x CLI and, with --v3, the v3 CLI,
// so a version comparison cannot distinguish them -- the earlier
// version-gated implementation disabled prompt blocking for every user on
// the latest release with no future version that would restore it.
func TestKiroBlockEventsFollowInvokingSurface(t *testing.T) {
	for _, tc := range []struct {
		name    string
		surface string
		want    []string
	}{
		{"v3 honors prompt submit", KiroHookSurfaceV3, []string{"UserPromptSubmit", "PreToolUse"}},
		{"v3 case insensitive", "V3", []string{"UserPromptSubmit", "PreToolUse"}},
		{"v3 padded", "  v3  ", []string{"UserPromptSubmit", "PreToolUse"}},
		{"cli 2.x vetoes tools only", KiroHookSurfaceV2, []string{"PreToolUse"}},
		// Conservative fallback: a hook config written before the marker
		// existed carries none, and over-claiming a block Kiro ignores is
		// worse than under-claiming one it honors.
		{"unmarked", "", []string{"PreToolUse"}},
		{"unrecognized", "v9", []string{"PreToolUse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := KiroBlockEventsForSurface(tc.surface)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("KiroBlockEventsForSurface(%q) = %v, want %v", tc.surface, got, tc.want)
			}
		})
	}
}

// The declared capability is the v3 surface, so nothing downstream has to
// know about the narrowing to report what Kiro can veto.
func TestKiroDeclaredBlockEventsIncludePromptSubmit(t *testing.T) {
	caps := NewKiroConnector().HookCapabilities(SetupOpts{DataDir: t.TempDir()})
	if strings.Join(caps.BlockEvents, ",") != "UserPromptSubmit,PreToolUse" {
		t.Fatalf("declared BlockEvents = %v", caps.BlockEvents)
	}
}

// Only the v3 config carries the marker. The CLI 2.x agent-hook entry is
// reconciled and removed by exact command equality, so an extra argument
// there would orphan DefenseClaw's own entry on the next setup run.
func TestKiroV3CommandIsMarkedAndV2CommandIsBare(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir()}
	c := NewKiroConnector()
	bare := c.hookCommand(opts)
	marked := c.hookCommandForV3Surface(opts)
	if !strings.HasPrefix(marked, bare) {
		t.Fatalf("marked command %q must extend bare command %q", marked, bare)
	}
	if !strings.HasSuffix(marked, "--hook-surface "+KiroHookSurfaceV3) {
		t.Fatalf("marked command %q is missing the v3 marker", marked)
	}
	if strings.Contains(bare, "--hook-surface") {
		t.Fatalf("bare command %q must stay unmarked for the 2.x agent config", bare)
	}
	// Ownership must survive the extra argument so teardown still reclaims
	// the v3 entry when matching on the bare command.
	if !kiroCommandOwned(marked, bare) {
		t.Fatal("marked v3 command is not recognized as DefenseClaw-owned")
	}
}

func assertKiroV3Hooks(t *testing.T, path, script string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg["version"] != "v1" {
		t.Fatalf("%s version = %#v", path, cfg["version"])
	}
	hooks, _ := cfg["hooks"].([]interface{})
	if len(hooks) != len(kiroV3HookSpecs) {
		t.Fatalf("%s hooks = %d, want %d (%s)", path, len(hooks), len(kiroV3HookSpecs), data)
	}
	seen := map[string]bool{}
	for _, item := range hooks {
		obj, _ := item.(map[string]interface{})
		name := strings.TrimSpace(fmtString(obj["name"]))
		action, _ := obj["action"].(map[string]interface{})
		command := strings.TrimSpace(fmtString(action["command"]))
		if command != script {
			t.Fatalf("%s hook %s command = %q, want %q", path, name, command, script)
		}
		if obj["enabled"] != true {
			t.Fatalf("%s hook %s is not enabled", path, name)
		}
		seen[name] = true
	}
	for _, spec := range kiroV3HookSpecs {
		if !seen[spec.name] {
			t.Fatalf("%s missing hook %s", path, spec.name)
		}
	}
}

func assertKiroV2AgentHooks(t *testing.T, path, script string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg["name"] != kiroManagedAgentName {
		t.Fatalf("agent name = %#v", cfg["name"])
	}
	if cfg["includeMcpJson"] != true {
		t.Fatalf("includeMcpJson = %#v, want true so kiro-cli accepts the overlay", cfg["includeMcpJson"])
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if _, ok := hooks["agentStop"]; ok {
		t.Fatalf("agent still uses invalid agentStop key: %#v", hooks["agentStop"])
	}
	for _, spec := range kiroV2HookSpecs {
		list, _ := hooks[spec.event].([]interface{})
		if len(list) != 1 {
			t.Fatalf("agent %s = %#v", spec.event, hooks[spec.event])
		}
		entry, _ := list[0].(map[string]interface{})
		if entry["command"] != script {
			t.Fatalf("agent %s command = %#v", spec.event, entry["command"])
		}
	}
}

func assertKiroDefaultAgentSetting(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if cfg[kiroDefaultAgentSettingKey] != kiroManagedAgentName {
		t.Fatalf("%s = %#v, want %q", kiroDefaultAgentSettingKey, cfg[kiroDefaultAgentSettingKey], kiroManagedAgentName)
	}
}

func fmtString(value interface{}) string {
	if value == nil {
		return ""
	}
	s, _ := value.(string)
	return s
}
