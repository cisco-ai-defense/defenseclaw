// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

// The two Kiro hook configs need different "every tool" matchers (measured
// live on kiro-cli 2.24.1): the CLI 2.x engine reads an agent hook's matcher
// as a glob, the v3 engine (kiro-cli --v3, and Kiro IDE) reads a .kiro/hooks
// matcher as a regular expression tested unanchored against the tool name.
// Swapping them silences every tool hook of that engine (#953).
func TestKiroMatchersFollowEachEngine(t *testing.T) {
	tools := []string{"shell", "execute_bash", "fs_write", "fs_read", "read_file", "str_replace", "use_aws"}
	re, err := regexp.Compile(kiroV3MatchAllTools)
	if err != nil {
		t.Fatalf("v3 matcher %q is not a regular expression: %v", kiroV3MatchAllTools, err)
	}
	for _, tool := range tools {
		if !re.MatchString(tool) {
			t.Errorf("v3 matcher %q does not match %s", kiroV3MatchAllTools, tool)
		}
		if ok, err := path.Match(kiroV2MatchAllTools, tool); err != nil || !ok {
			t.Errorf("CLI 2.x glob %q does not match %s", kiroV2MatchAllTools, tool)
		}
		// "." is literal in a glob: the matcher earlier releases wrote into
		// the agent ran no CLI 2.x tool hook.
		if ok, _ := path.Match(kiroV3MatchAllTools, tool); ok {
			t.Errorf("the regular expression %q matched %s as a glob", kiroV3MatchAllTools, tool)
		}
	}
	// Kiro's v3 engine drops a hook whose matcher does not compile. The
	// pattern goes through a function so the check stays a runtime one
	// (staticcheck's SA1000 flags an invalid constant pattern).
	compiles := func(pattern string) bool { _, err := regexp.Compile(pattern); return err == nil }
	if compiles(kiroV2MatchAllTools) {
		t.Errorf("the CLI 2.x glob %q compiles as a regular expression; the v3 engine would run it", kiroV2MatchAllTools)
	}
	for _, spec := range kiroV3HookSpecs {
		switch spec.trigger {
		case "PreToolUse", "PostToolUse":
			if spec.matcher != kiroV3MatchAllTools {
				t.Errorf("v3 %s matcher = %q, want %q", spec.trigger, spec.matcher, kiroV3MatchAllTools)
			}
		default:
			if spec.matcher != "" {
				t.Errorf("v3 %s has matcher %q; Kiro ignores it there", spec.trigger, spec.matcher)
			}
		}
	}
	for _, spec := range kiroV2HookSpecs {
		if spec.matcher != kiroV2MatchAllTools {
			t.Errorf("CLI 2.x %s matcher = %q, want %q", spec.event, spec.matcher, kiroV2MatchAllTools)
		}
	}
}

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

	command := conn.hookCommand(opts)
	for _, path := range []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName),
	} {
		// The v3 config carries the surface marker; the 2.x agent config
		// below must stay on the bare command.
		assertKiroV3Hooks(t, path, conn.hookCommandForV3Surface(opts))
	}
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), command)
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
	opts := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "open",
	}
	conn := NewKiroConnector()
	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
		t.Fatalf("mkdir agent: %v", err)
	}
	stale, err := json.Marshal(map[string]interface{}{
		"name": "defenseclaw",
		"hooks": map[string]interface{}{
			"agentStop": []interface{}{map[string]interface{}{
				"command": conn.hookCommand(opts), "description": "old", "matcher": ".*",
			}},
		},
	})
	if err != nil {
		t.Fatalf("marshal stale agent: %v", err)
	}
	if err := os.WriteFile(agentPath, stale, 0o600); err != nil {
		t.Fatalf("write stale agent: %v", err)
	}

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	assertKiroV2AgentHooks(t, agentPath, conn.hookCommand(opts))
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
	if runtime.GOOS == "windows" {
		// Both are the encoded PowerShell script; the marker is inside it.
		if !strings.Contains(decodeKiroWindowsBridge(t, marked), "'hook --connector kiro --hook-surface v3'") || strings.Contains(decodeKiroWindowsBridge(t, bare), "--hook-surface") {
			t.Fatalf("windows commands: marked %q bare %q", marked, bare)
		}
	} else {
		if !strings.HasPrefix(marked, bare) {
			t.Fatalf("marked command %q must extend bare command %q", marked, bare)
		}
		if !strings.HasSuffix(marked, "--hook-surface "+KiroHookSurfaceV3) {
			t.Fatalf("marked command %q is missing the v3 marker", marked)
		}
		if strings.Contains(bare, "--hook-surface") {
			t.Fatalf("bare command %q must stay unmarked for the 2.x agent config", bare)
		}
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
		// Kiro's v3 engine reads the matcher as a regular expression.
		if trigger, _ := obj["trigger"].(string); (trigger == "PreToolUse" || trigger == "PostToolUse") && obj["matcher"] != kiroV3MatchAllTools {
			t.Fatalf("%s hook %s matcher = %#v, want the regular expression %q", path, name, obj["matcher"], kiroV3MatchAllTools)
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
		// kiro-cli 2.x matches tool names as globs: "*" is every tool,
		// ".*" is none.
		if entry["matcher"] != "*" {
			t.Fatalf("agent %s matcher = %#v, want the glob \"*\"", spec.event, entry["matcher"])
		}
		// Kiro's default hook timeout (about 10 s) ignores a slower verdict
		// and runs the tool.
		if entry["timeout_ms"] != float64(kiroV2HookTimeoutMillis) {
			t.Fatalf("agent %s timeout_ms = %#v, want %d", spec.event, entry["timeout_ms"], kiroV2HookTimeoutMillis)
		}
	}
}

// Earlier releases registered the CLI 2.x hooks with the regular expression
// ".*". kiro-cli 2.24.1 reads matchers as globs, so the tool hooks of those
// agent files never ran. Setup (which the gateway runs at every start, so
// also after an upgrade) must rewrite DefenseClaw's entries in place and
// leave the operator's own entries alone.
func TestKiroSetupRewritesRegexToolMatcherFromEarlierReleases(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "open"}
	conn := NewKiroConnector()
	command := conn.hookCommand(opts)

	oldEntry := func(description string) map[string]interface{} {
		return map[string]interface{}{"command": command, "description": description, "matcher": ".*"}
	}
	foreign := map[string]interface{}{"command": "echo operator", "matcher": ".*"}
	earlier := map[string]interface{}{
		"name":           kiroManagedAgentName,
		"description":    "DefenseClaw-guarded Kiro agent",
		"tools":          []interface{}{"*"},
		"includeMcpJson": true,
		"hooks": map[string]interface{}{
			"userPromptSubmit": []interface{}{oldEntry("DefenseClaw prompt inspection")},
			"preToolUse":       []interface{}{foreign, oldEntry("DefenseClaw tool-use inspection")},
			"postToolUse":      []interface{}{oldEntry("DefenseClaw tool-use audit")},
			"stop":             []interface{}{oldEntry("DefenseClaw session stop")},
		},
	}
	// The operator's own default agent, patched by an earlier release too.
	custom := map[string]interface{}{
		"name":  "mine",
		"model": "keep-me",
		"hooks": map[string]interface{}{"preToolUse": []interface{}{oldEntry("DefenseClaw tool-use inspection")}},
	}
	writeJSON := func(path string, v interface{}) {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	customPath := filepath.Join(home, "agents", "mine.json")
	writeJSON(agentPath, earlier)
	writeJSON(customPath, custom)
	writeJSON(filepath.Join(home, "settings", "cli.json"), map[string]interface{}{kiroDefaultAgentSettingKey: "mine"})

	for run := 1; run <= 2; run++ {
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup run %d: %v", run, err)
		}
	}

	readHooks := func(path string) map[string]interface{} {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		hooks, _ := cfg["hooks"].(map[string]interface{})
		return hooks
	}
	agentHooks := readHooks(agentPath)
	for _, spec := range kiroV2HookSpecs {
		var ours []map[string]interface{}
		list, _ := agentHooks[spec.event].([]interface{})
		for _, item := range list {
			entry, _ := item.(map[string]interface{})
			if entry["command"] == command {
				ours = append(ours, entry)
			}
		}
		if len(ours) != 1 || ours[0]["matcher"] != "*" {
			t.Fatalf("%s DefenseClaw entries after upgrade = %#v, want one with matcher \"*\"", spec.event, ours)
		}
	}
	pre, _ := agentHooks["preToolUse"].([]interface{})
	if len(pre) != 2 {
		t.Fatalf("preToolUse = %#v, want the operator entry and DefenseClaw's", pre)
	}
	if first, _ := pre[0].(map[string]interface{}); first["command"] != "echo operator" || first["matcher"] != ".*" {
		t.Fatalf("operator entry changed: %#v", pre[0])
	}

	customHooks := readHooks(customPath)
	for _, spec := range kiroV2HookSpecs {
		list, _ := customHooks[spec.event].([]interface{})
		if len(list) != 1 {
			t.Fatalf("custom agent %s = %#v", spec.event, customHooks[spec.event])
		}
		if entry, _ := list[0].(map[string]interface{}); entry["command"] != command || entry["matcher"] != "*" {
			t.Fatalf("custom agent %s entry = %#v", spec.event, entry)
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

// Kiro's /upgrade-agent (and kiro-cli --v3's "Enable auto-upgrade") rewrites
// the agent's event-keyed hooks into the universal (V2 + V3) array, keeping
// each matcher and writing "timeout": 10 (measured on kiro-cli 2.24.1, which
// reads that form with the same glob matchers). Setup used to replace the
// array with an empty event map, deleting the user's own entries, and
// verification and teardown did not read it (#953).
func TestKiroSetupKeepsAnAgentKiroUpgraded(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970"}
	conn := NewKiroConnector()
	command := conn.hookCommand(opts)
	agentPath := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	// The universal agent Kiro 2.24.1 wrote from an earlier DefenseClaw
	// agent (regex matchers) plus a hook the user added afterwards.
	upgraded := map[string]interface{}{
		"name": kiroManagedAgentName, "description": "DefenseClaw-guarded Kiro agent", "tools": []interface{}{"*"},
		"includeMcpJson": true,
		"hooks": []interface{}{
			map[string]interface{}{"name": "postToolUse-0", "trigger": "postToolUse", "matcher": ".*", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": command}},
			map[string]interface{}{"name": "preToolUse-0", "trigger": "preToolUse", "matcher": ".*", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": command}},
			map[string]interface{}{"name": "lint", "trigger": "postToolUse", "matcher": "fs_write", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": "npm run lint"}},
			map[string]interface{}{"name": "stop-0", "trigger": "stop", "matcher": ".*", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": command}},
			map[string]interface{}{"name": "userPromptSubmit-0", "trigger": "userPromptSubmit", "matcher": ".*", "timeout": 10,
				"action": map[string]interface{}{"type": "command", "command": command}},
		},
	}
	body, _ := json.Marshal(upgraded)
	if err := os.WriteFile(agentPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := kiroV2AgentReferencesHook(agentPath, command); err != nil || present {
		t.Fatalf("upgraded agent with regex matchers: present=%v err=%v, want not present", present, err)
	}

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	var agent map[string]interface{}
	if data, err := os.ReadFile(agentPath); err != nil || json.Unmarshal(data, &agent) != nil {
		t.Fatalf("read agent: %v", err)
	}
	list, ok := agent["hooks"].([]interface{})
	if !ok {
		t.Fatalf("Setup rewrote the universal agent into %T: %s", agent["hooks"], agent["hooks"])
	}
	ours := map[string]int{}
	lint := 0
	for _, item := range list {
		entry := item.(map[string]interface{})
		action := entry["action"].(map[string]interface{})
		if action["command"] == "npm run lint" {
			lint++
			continue
		}
		if action["command"] != command || action["type"] != "command" || entry["matcher"] != kiroV2MatchAllTools ||
			entry["timeout"] != float64(kiroUniversalHookTimeoutSeconds) {
			t.Fatalf("DefenseClaw entry %v", entry)
		}
		ours[entry["trigger"].(string)]++
	}
	if lint != 1 {
		t.Fatalf("the user's own hook was not kept: %v", list)
	}
	for _, spec := range kiroV2HookSpecs {
		if ours[spec.event] != 1 {
			t.Fatalf("%s has %d DefenseClaw entries, want 1: %v", spec.event, ours[spec.event], list)
		}
	}
	if len(ours) != len(kiroV2HookSpecs) {
		t.Fatalf("DefenseClaw entries %v, want one per %d events", ours, len(kiroV2HookSpecs))
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("after Setup: present=%v err=%v", present, err)
	}
	// Setup is idempotent on the universal form.
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	var again map[string]interface{}
	if data, err := os.ReadFile(agentPath); err != nil || json.Unmarshal(data, &again) != nil {
		t.Fatalf("reread agent: %v", err)
	}
	if n := len(again["hooks"].([]interface{})); n != len(list) {
		t.Fatalf("second Setup changed the entry count from %d to %d", len(list), n)
	}

	// Teardown takes DefenseClaw's entries out and keeps the user's hook and
	// the file.
	if err := removeKiroV2AgentHooks(agentPath, command); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if data, err := os.ReadFile(agentPath); err != nil || json.Unmarshal(data, &again) != nil {
		t.Fatalf("agent after removal: %v", err)
	}
	if left := again["hooks"].([]interface{}); len(left) != 1 || left[0].(map[string]interface{})["name"] != "lint" {
		t.Fatalf("hooks after removal = %v, want only the user's", left)
	}
	if present, err := kiroV2AgentReferencesAnyHook(agentPath, command); err != nil || present {
		t.Fatalf("a DefenseClaw entry survived removal: present=%v err=%v", present, err)
	}

	// A universal agent that holds only DefenseClaw's entries is
	// DefenseClaw's overlay: removing them removes the file.
	onlyOurs := map[string]interface{}{"name": kiroManagedAgentName, "tools": []interface{}{"*"},
		"hooks": []interface{}{kiroUniversalHookEntry("preToolUse", kiroV2MatchAllTools, command)}}
	body, _ = json.Marshal(onlyOurs)
	if err := os.WriteFile(agentPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeKiroV2AgentHooks(agentPath, command); err != nil {
		t.Fatalf("remove overlay: %v", err)
	}
	if _, err := os.Stat(agentPath); !os.IsNotExist(err) {
		t.Fatalf("the DefenseClaw-only universal agent was kept: %v", err)
	}
}

// The sidecar verifies an effective hook registration right after Setup and
// rolls the connector back when it reports none. Kiro failed that check, so
// every setup wrote its hook files and immediately deleted them again --
// `/hooks` stayed empty and the connector never became active, while the log
// only said "setup completed without an effective hook registration".
//
// Two independent causes, one per surface:
//   - v3: the generic config walker matches a hook command against the bare
//     script path exactly, and Kiro's v3 entry carries --hook-surface v3.
//   - v2: containsHookScript walked the "hooks" value but not the event keys
//     beneath it, so Kiro 2.x's {"hooks": {"preToolUse": [...]}} never matched.
func TestKiroSetupProducesEffectiveHookRegistration(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	opts := SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970"}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("setup produced no effective hook registration; the sidecar would roll Kiro back")
	}

	// Both surfaces must count. Removing either one has to make the check
	// fail, or a half-registered Kiro would report itself as guarded.
	for _, path := range append(conn.hookConfigPaths(opts), conn.agentConfigPaths(opts)...) {
		saved, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove %s: %v", path, err)
		}
		present, err = OwnedHooksPresent(conn, opts)
		if err != nil {
			t.Fatalf("OwnedHooksPresent without %s: %v", path, err)
		}
		if present {
			t.Errorf("registration still reports present without %s", path)
		}
		if err := os.WriteFile(path, saved, 0o600); err != nil {
			t.Fatalf("restore %s: %v", path, err)
		}
	}

	// kiro-cli 2.x matches tool names, so an agent an earlier build rendered
	// with the regular expression ".*" ran no preToolUse hook. Such an agent
	// must fail the check (the guardian then repairs it), and Setup must
	// render the "*" wildcard that matches every tool.
	agentPath := conn.agentConfigPaths(opts)[0]
	var agent map[string]interface{}
	if data, err := os.ReadFile(agentPath); err != nil || json.Unmarshal(data, &agent) != nil {
		t.Fatalf("read agent %s: %v", agentPath, err)
	}
	for _, list := range agent["hooks"].(map[string]interface{}) {
		for _, item := range list.([]interface{}) {
			item.(map[string]interface{})["matcher"] = ".*"
		}
	}
	stale, _ := json.Marshal(agent)
	if err := os.WriteFile(agentPath, stale, 0o600); err != nil {
		t.Fatalf("write stale agent: %v", err)
	}
	if present, err = OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("agent with the regex matcher: present=%v err=%v, want not present", present, err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if present, err = OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("after repair: present=%v err=%v", present, err)
	}
	if data, err := os.ReadFile(agentPath); err != nil || json.Unmarshal(data, &agent) != nil {
		t.Fatalf("reread agent: %v", err)
	}
	entry := agent["hooks"].(map[string]interface{})["preToolUse"].([]interface{})[0].(map[string]interface{})
	if entry["matcher"] != "*" {
		t.Fatalf("preToolUse matcher = %#v, want \"*\"", entry["matcher"])
	}

	// An agent an earlier build rendered without timeout_ms left Kiro's
	// default hook timeout (about ten seconds) in place, so a slower verdict
	// let the tool run. It fails the check too, and Setup adds the timeout.
	for _, list := range agent["hooks"].(map[string]interface{}) {
		for _, item := range list.([]interface{}) {
			delete(item.(map[string]interface{}), "timeout_ms")
		}
	}
	stale, _ = json.Marshal(agent)
	if err := os.WriteFile(agentPath, stale, 0o600); err != nil {
		t.Fatalf("write agent without timeouts: %v", err)
	}
	if present, err = OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("agent without timeout_ms: present=%v err=%v, want not present", present, err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("repair Setup: %v", err)
	}
	if present, err = OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("after the timeout repair: present=%v err=%v", present, err)
	}
	assertKiroV2AgentHooks(t, agentPath, conn.hookCommand(opts))
}

// containsHookScript is shared by every connector that stores hooks under
// event keys, so pin the traversal directly.
func TestContainsHookScriptWalksEventKeyedHookMaps(t *testing.T) {
	script := "/data/hooks/kiro-hook.sh"
	cfg := map[string]interface{}{
		"name": "defenseclaw",
		"hooks": map[string]interface{}{
			"preToolUse": []interface{}{
				map[string]interface{}{"command": script, "matcher": ".*"},
			},
		},
	}
	if !containsHookScript(cfg, script) {
		t.Error("event-keyed hook map was not traversed")
	}
	if containsHookScript(cfg, "/data/hooks/other-hook.sh") {
		t.Error("an unrelated script must not match")
	}
}

// decodeKiroWindowsBridge returns the PowerShell script inside an encoded
// system PowerShell bridge command.
func decodeKiroWindowsBridge(t *testing.T, command string) string {
	t.Helper()
	const flag = " -EncodedCommand "
	index := strings.LastIndex(command, flag)
	if index < 0 || !strings.HasPrefix(command, windowsSystemPowerShellExe()+" ") {
		t.Fatalf("%q is not the encoded system PowerShell bridge", command)
	}
	raw, err := base64.StdEncoding.DecodeString(command[index+len(flag):])
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("decode %q: %v", command, err)
	}
	wide := make([]uint16, len(raw)/2)
	for i := range wide {
		wide[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(wide))
}

// Kiro honors only exit 2 as a block. The Windows commands used to be
// `& '<launcher>' hook --connector kiro ...`: cmd.exe rejects the call
// operator (exit 1) and PowerShell does not wait for the GUI-subsystem
// release launcher (exit 0), so Kiro went ahead after a block. Both Kiro
// commands are now an encoded system PowerShell script, which starts the
// launcher, waits for it and exits with its status.
func TestKiroWindowsCommandsUseTheAwaitedPowerShellBridge(t *testing.T) {
	launcher := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	t.Cleanup(PinNativeHookExecutableForTest(launcher))
	for surface, want := range map[string]string{
		"":                "[System.Diagnostics.ProcessStartInfo]::new('" + launcher + "','hook --connector kiro')",
		KiroHookSurfaceV3: "[System.Diagnostics.ProcessStartInfo]::new('" + launcher + "','hook --connector kiro --hook-surface v3')",
	} {
		command := hookInvocationCommandFor("windows", "kiro", "")
		if surface != "" {
			command = kiroHookInvocationCommandFor("windows", "", surface)
		}
		if strings.HasPrefix(command, "&") {
			t.Fatalf("surface %q: the call-operator form loses exit 2: %q", surface, command)
		}
		script := decodeKiroWindowsBridge(t, command)
		if !strings.Contains(script, want) || !strings.HasSuffix(script, "exit $hookProcess.ExitCode") {
			t.Fatalf("surface %q: script %q", surface, script)
		}
		if runtime.GOOS == "windows" && !kiroCommandOwned(command, hookInvocationCommandFor("windows", "kiro", "")) {
			t.Fatalf("surface %q: DefenseClaw does not recognize its own command", surface)
		}
	}
	// Other connectors keep their commands.
	if got := hookInvocationCommandFor("windows", "claudecode", ""); !strings.HasPrefix(got, "& '") {
		t.Fatalf("claudecode command changed: %q", got)
	}
}
