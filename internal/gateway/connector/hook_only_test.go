// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookOnlyConnector_CapabilityMatrix(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir()}
	cases := []struct {
		conn       *hookOnlyConnector
		canAsk     bool
		failClosed bool
		scope      string
		configBase string
	}{
		{NewHermesConnector(), false, false, "user", "config.yaml"},
		{NewCursorConnector(), true, true, "user", "hooks.json"},
		{NewWindsurfConnector(), false, false, "user", "hooks.json"},
		{NewGeminiCLIConnector(), false, true, "user", "settings.json"},
		{NewCopilotConnector(), true, false, "user,workspace", "defenseclaw.json"},
		{NewOpenHandsConnector(), false, true, "user,workspace", "hooks.json"},
		{NewAntigravityConnector(), true, false, "user", "hooks.json"},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.HookCapabilities(opts)
			if !caps.CanBlock {
				t.Fatal("CanBlock = false, want true")
			}
			if caps.CanAskNative != tc.canAsk {
				t.Fatalf("CanAskNative = %v, want %v", caps.CanAskNative, tc.canAsk)
			}
			if caps.SupportsFailClosed != tc.failClosed {
				t.Fatalf("SupportsFailClosed = %v, want %v", caps.SupportsFailClosed, tc.failClosed)
			}
			if caps.Scope != tc.scope {
				t.Fatalf("Scope = %q, want %q", caps.Scope, tc.scope)
			}
			if filepath.Base(caps.ConfigPath) != tc.configBase {
				t.Fatalf("ConfigPath = %q, want basename %q", caps.ConfigPath, tc.configBase)
			}
		})
	}
}

func TestHookOnlyConnector_SurfaceCapabilities(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir(), APIAddr: "127.0.0.1:18970"}
	cases := []struct {
		conn             *hookOnlyConnector
		codeGuardTargets []string
		nativeOTLP       bool
		pluginsSupported bool
		// mcpSupported is true for connectors that expose a
		// documented MCP install surface. Antigravity v1 publishes
		// only the hooks surface, so MCP is unsupported there until
		// Google ships an install contract.
		mcpSupported bool
	}{
		// Plugins.Supported is FALSE on every hook-only connector
		// because DefenseClaw plugins are an OpenClaw-only concept
		// (G4). The TUI Plugins panel hides itself for these
		// connectors and `defenseclaw plugin list` prints an
		// OpenClaw-only notice.
		{NewHermesConnector(), []string{"skill"}, false, false, true},
		{NewCursorConnector(), []string{"skill", "rule"}, false, false, true},
		{NewWindsurfConnector(), []string{"rule"}, false, false, true},
		{NewGeminiCLIConnector(), []string{"skill"}, true, false, true},
		{NewCopilotConnector(), []string{"skill", "rule"}, true, false, true},
		{NewOpenHandsConnector(), []string{"skill"}, false, false, true},
		{NewAntigravityConnector(), nil, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.Capabilities(opts)
			if caps.MCP.Supported != tc.mcpSupported {
				t.Fatalf("MCP.Supported = %v, want %v", caps.MCP.Supported, tc.mcpSupported)
			}
			if caps.CodeGuard.Supported != (len(tc.codeGuardTargets) > 0) {
				t.Fatalf("CodeGuard.Supported = %v", caps.CodeGuard.Supported)
			}
			if strings.Join(caps.CodeGuard.InstallTargets, ",") != strings.Join(tc.codeGuardTargets, ",") {
				t.Fatalf("CodeGuard.InstallTargets = %v, want %v", caps.CodeGuard.InstallTargets, tc.codeGuardTargets)
			}
			if caps.CodeGuard.AutoInstall {
				t.Fatal("CodeGuard.AutoInstall = true, want explicit opt-in")
			}
			if caps.Telemetry.NativeOTLP != tc.nativeOTLP {
				t.Fatalf("Telemetry.NativeOTLP = %v, want %v", caps.Telemetry.NativeOTLP, tc.nativeOTLP)
			}
			if caps.Plugins.Supported != tc.pluginsSupported {
				t.Fatalf("Plugins.Supported = %v, want %v", caps.Plugins.Supported, tc.pluginsSupported)
			}
		})
	}
}

func TestHookOnlyConnector_SetupTeardown_BackupRestore(t *testing.T) {
	dir := t.TempDir()
	configDir := t.TempDir()
	overrides := map[string]*string{
		"hermes":      &HermesConfigPathOverride,
		"cursor":      &CursorHooksPathOverride,
		"windsurf":    &WindsurfHooksPathOverride,
		"geminicli":   &GeminiSettingsPathOverride,
		"copilot":     &CopilotHooksPathOverride,
		"openhands":   &OpenHandsHooksPathOverride,
		"antigravity": &AntigravityHooksPathOverride,
	}
	connectors := []*hookOnlyConnector{
		NewHermesConnector(),
		NewCursorConnector(),
		NewWindsurfConnector(),
		NewGeminiCLIConnector(),
		NewCopilotConnector(),
		NewOpenHandsConnector(),
		NewAntigravityConnector(),
	}
	for _, conn := range connectors {
		t.Run(conn.Name(), func(t *testing.T) {
			cfgPath := filepath.Join(configDir, conn.Name(), "config")
			if conn.Name() == "hermes" {
				cfgPath += ".yaml"
			} else {
				cfgPath += ".json"
			}
			ptr := overrides[conn.Name()]
			prev := *ptr
			*ptr = cfgPath
			t.Cleanup(func() { *ptr = prev })

			opts := SetupOpts{DataDir: filepath.Join(dir, conn.Name()), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir()}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			data, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatalf("read config after setup: %v", err)
			}
			if !strings.Contains(string(data), conn.scriptName) {
				t.Fatalf("config after setup does not reference %s:\n%s", conn.scriptName, string(data))
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if _, err := os.Stat(cfgPath); err == nil {
				t.Fatalf("config file still exists after teardown of previously missing config: %s", cfgPath)
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat config after teardown: %v", err)
			}
		})
	}
}

// TestAntigravitySetup_WritesClaudeCodeNestedSchema pins the
// hooks.json shape that agy v1.0.x actually evaluates and is the
// regression guard for two cumulative empirical findings from the
// v0.5.0 smoke test:
//
//  1. **Nested schema, not flat.** An earlier draft wrote a flat
//     {event, matcher, command, description} object per top-level
//     key. agy never evaluated those entries — neither tracer hooks
//     nor DefenseClaw hooks fired. Replacing the file with a
//     Claude-Code-style nested schema (top-level key →
//     {<EventName>: [{matcher, hooks: [{type, command}]}]}) caused
//     agy to invoke the configured command on every tool call. agy
//     binary `strings` confirms only the nested shape is parsed.
//
//  2. **No embedded quotes in command.** Empirical D3 of the smoke
//     test (D1=bare-path-OK, D2=sh -c-OK, D3=direct-exec-FAILS-127)
//     proved agy invokes the configured command via direct exec()
//     not through a shell, so any '/" added by shellWord() would
//     become literal path bytes and the hook would silently
//     no-fire.
//
// Combined assertions:
//
//   - top-level key "defenseclaw-antigravity-pretooluse" exists
//   - its value is a map with key "PreToolUse"
//   - "PreToolUse" is a list with exactly one entry
//   - that entry has matcher="*" and hooks=[{type="command",
//     command=<bare absolute path to antigravity-hook.sh>}]
//   - the inner command field has no quote characters and no
//     surrounding whitespace
//
// If a future agy release pivots back to a flat schema, OR adds
// shell invocation, OR moves the hooks file again, this test must
// be updated in lockstep with patchAntigravityHooks /
// antigravityHooksPath. Until then this test pins the contract.
func TestAntigravitySetup_WritesClaudeCodeNestedSchema(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".gemini", "config", "hooks.json")
	prev := AntigravityHooksPathOverride
	AntigravityHooksPathOverride = cfgPath
	t.Cleanup(func() { AntigravityHooksPathOverride = prev })

	conn := NewAntigravityConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read antigravity hooks.json: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("antigravity hooks.json is not valid JSON: %v\n%s", err, string(data))
	}

	entry, ok := cfg["defenseclaw-antigravity-pretooluse"].(map[string]interface{})
	if !ok {
		t.Fatalf("defenseclaw-antigravity-pretooluse missing or wrong shape: %#v", cfg)
	}

	preToolUse, ok := entry["PreToolUse"].([]interface{})
	if !ok {
		t.Fatalf("PreToolUse is not an array: %#v\nfull entry: %#v", entry["PreToolUse"], entry)
	}
	if len(preToolUse) != 1 {
		t.Fatalf("PreToolUse must hold exactly one matcher group, got %d:\n%#v", len(preToolUse), preToolUse)
	}

	group, ok := preToolUse[0].(map[string]interface{})
	if !ok {
		t.Fatalf("PreToolUse[0] is not an object: %#v", preToolUse[0])
	}
	if group["matcher"] != "*" {
		t.Fatalf("matcher=%#v want *", group["matcher"])
	}

	hooks, ok := group["hooks"].([]interface{})
	if !ok {
		t.Fatalf("hooks is not an array: %#v", group["hooks"])
	}
	if len(hooks) != 1 {
		t.Fatalf("hooks must hold exactly one entry, got %d:\n%#v", len(hooks), hooks)
	}

	hook, ok := hooks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks[0] is not an object: %#v", hooks[0])
	}
	if hook["type"] != "command" {
		t.Fatalf("hook type=%#v want command", hook["type"])
	}
	command, isString := hook["command"].(string)
	if !isString {
		t.Fatalf("command field is not a string: %#v", hook["command"])
	}

	// Primary assertion: no quote characters at all. agy v1.0.x
	// exec()s the command directly, so any '/" would become a
	// literal byte in the path and the hook would silently
	// no-fire.
	if strings.ContainsAny(command, `'"`) {
		t.Fatalf(
			"antigravity command field contains quote characters %q — "+
				"agy v1.0.x exec()s this directly so the quotes become "+
				"literal path bytes. Did shellWord() get re-introduced?",
			command,
		)
	}
	// Secondary: the path resolves cleanly to a file ending in
	// antigravity-hook.sh. Defends against accidentally writing a
	// relative path or a different script name.
	if !strings.HasSuffix(command, "antigravity-hook.sh") {
		t.Fatalf("command=%q does not end with antigravity-hook.sh", command)
	}
	if !filepath.IsAbs(command) {
		t.Fatalf("command=%q is not an absolute path", command)
	}
	// Tertiary: no surrounding whitespace either.
	if command != strings.TrimSpace(command) {
		t.Fatalf("command=%q has surrounding whitespace", command)
	}

	// Quaternary: all five Antigravity 2.0 lifecycle events are
	// registered under their own DefenseClaw-owned outer keys, with
	// the same nested Claude-Code-derived schema. Spec source:
	// Antigravity 2.0 hook docs (PreInvocation, PreToolUse,
	// PostToolUse, PostInvocation, Stop). PreToolUse is the only
	// event empirically verified against agy v1.0.1; the other four
	// keys are registered for spec parity so DefenseClaw is ready
	// when agy starts emitting them upstream — see
	// patchAntigravityHooks docs in hook_only.go for the rationale.
	for _, event := range []string{"PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop"} {
		outerKey := "defenseclaw-antigravity-" + strings.ToLower(event)
		eventEntry, ok := cfg[outerKey].(map[string]interface{})
		if !ok {
			t.Errorf("%s missing or wrong shape: %#v", outerKey, cfg[outerKey])
			continue
		}
		eventList, ok := eventEntry[event].([]interface{})
		if !ok {
			t.Errorf("%s[%q] is not an array: %#v", outerKey, event, eventEntry[event])
			continue
		}
		if len(eventList) != 1 {
			t.Errorf("%s[%q] must hold exactly one matcher group, got %d", outerKey, event, len(eventList))
			continue
		}
		matcherGroup, ok := eventList[0].(map[string]interface{})
		if !ok {
			t.Errorf("%s[%q][0] is not an object: %#v", outerKey, event, eventList[0])
			continue
		}
		if matcherGroup["matcher"] != "*" {
			t.Errorf("%s[%q][0].matcher=%#v want *", outerKey, event, matcherGroup["matcher"])
		}
		hookList, ok := matcherGroup["hooks"].([]interface{})
		if !ok || len(hookList) != 1 {
			t.Errorf("%s[%q][0].hooks not a single-entry array: %#v", outerKey, event, matcherGroup["hooks"])
			continue
		}
		hookEntry, ok := hookList[0].(map[string]interface{})
		if !ok {
			t.Errorf("%s[%q][0].hooks[0] is not an object: %#v", outerKey, event, hookList[0])
			continue
		}
		if hookEntry["type"] != "command" {
			t.Errorf("%s[%q][0].hooks[0].type=%#v want command", outerKey, event, hookEntry["type"])
		}
		eventCommand, ok := hookEntry["command"].(string)
		if !ok || !strings.HasSuffix(eventCommand, "antigravity-hook.sh") {
			t.Errorf("%s[%q][0].hooks[0].command=%#v want absolute path ending antigravity-hook.sh", outerKey, event, hookEntry["command"])
		}
	}
}

func TestOpenHandsSetup_PatchesDocumentedHookSchema(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".openhands", "hooks.json")
	prev := OpenHandsHooksPathOverride
	OpenHandsHooksPathOverride = cfgPath
	t.Cleanup(func() { OpenHandsHooksPathOverride = prev })

	conn := NewOpenHandsConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		WorkspaceDir: dir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read OpenHands hooks.json: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("OpenHands hooks.json is not valid JSON: %v\n%s", err, string(data))
	}
	raw, ok := cfg["pre_tool_use"].([]interface{})
	if !ok || len(raw) == 0 {
		t.Fatalf("pre_tool_use missing from native top-level OpenHands hook schema: %#v", cfg)
	}
	group, ok := raw[0].(map[string]interface{})
	if !ok {
		t.Fatalf("pre_tool_use[0] = %#v, want object", raw[0])
	}
	if group["matcher"] != "*" {
		t.Fatalf("matcher=%#v want *", group["matcher"])
	}
	hooks, ok := group["hooks"].([]interface{})
	if !ok || len(hooks) == 0 {
		t.Fatalf("hooks missing from OpenHands group: %#v", group)
	}
	hook, ok := hooks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks[0] = %#v, want object", hooks[0])
	}
	if hook["type"] != "command" {
		t.Fatalf("hook type=%#v want command", hook["type"])
	}
	command, _ := hook["command"].(string)
	if !strings.Contains(command, "openhands-hook.sh") {
		t.Fatalf("command=%q does not reference openhands-hook.sh", command)
	}
	if _, wrapped := cfg["hooks"]; wrapped {
		t.Fatalf("OpenHands native schema should not add Claude-compatible top-level hooks wrapper: %#v", cfg["hooks"])
	}
}

func TestGeminiSetup_PatchesNativeTelemetryPathToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read gemini settings: %v", err)
	}
	text := string(data)
	// Gemini CLI's settings.json schema only accepts target ∈
	// {"local","gcp"}. To forward telemetry to a custom (loopback)
	// OTLP collector we must set target=local + useCollector=true.
	// See https://geminicli.com/docs/reference/configuration/.
	if !strings.Contains(text, `"target": "local"`) {
		t.Fatalf("gemini settings missing managed telemetry target=local:\n%s", text)
	}
	if !strings.Contains(text, `"useCollector": true`) {
		t.Fatalf("gemini settings missing useCollector=true (required for external OTLP):\n%s", text)
	}
	if !strings.Contains(text, `"otlpProtocol": "http"`) {
		t.Fatalf("gemini settings missing otlpProtocol=http:\n%s", text)
	}
	// Gemini's schema rejects unknown keys at load time, so we MUST
	// NOT write the legacy "managedBy" / "protocol" fields anymore —
	// otherwise `gemini` aborts with "Unrecognized key(s) in object".
	for _, banned := range []string{`"managedBy"`, `"protocol":`} {
		if strings.Contains(text, banned) {
			t.Fatalf("gemini settings contain key rejected by schema (%s):\n%s", banned, text)
		}
	}
	// H-4: settings.json must NOT contain the master gateway bearer
	// (opts.APIToken). The OTLP exporter authenticates via a scoped
	// per-source path-token instead — see EnsureOTLPPathToken /
	// patchGeminiTelemetry.
	if strings.Contains(text, "tok-test") {
		t.Fatalf("gemini settings leaked master gateway token (H4 regression):\n%s", text)
	}
	scoped, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if scoped == "" {
		t.Fatalf("setup did not mint a scoped OTLP token under %s", opts.DataDir)
	}
	if !strings.Contains(text, "/otlp/geminicli/"+scoped) {
		t.Fatalf("gemini settings missing scoped path-token config:\n%s", text)
	}
}

func TestGeminiSetup_MigratesLegacySchemaInPlace(t *testing.T) {
	// Regression: defenseclaw < 0.x wrote `target: "otlp"`,
	// `protocol: "http/json"`, and `managedBy: "defenseclaw"` —
	// all three are rejected by the current Gemini CLI schema, so
	// `gemini` refuses to start until the file is repaired. Running
	// `defenseclaw setup` against a stale settings.json must
	// migrate the keys (not just append).
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	legacy := map[string]interface{}{
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"target":       "otlp",
			"otlpEndpoint": "http://127.0.0.1:18790/otlp/geminicli/legacy-token",
			"protocol":     "http/json",
			"logPrompts":   true,
			"managedBy":    "defenseclaw",
		},
		"userSetting": "keep",
	}
	body, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup over legacy config: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	text := string(data)
	for _, banned := range []string{`"target": "otlp"`, `"protocol": "http/json"`, `"managedBy": "defenseclaw"`} {
		if strings.Contains(text, banned) {
			t.Fatalf("legacy schema key %q survived migration:\n%s", banned, text)
		}
	}
	for _, want := range []string{`"target": "local"`, `"otlpProtocol": "http"`, `"useCollector": true`, `"userSetting": "keep"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("migrated config missing %q:\n%s", want, text)
		}
	}
}

func TestGeminiTeardown_DriftedConfigRemovesManagedTelemetry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read setup config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse setup config: %v", err)
	}
	cfg["userSetting"] = "keep"
	telemetry, _ := cfg["telemetry"].(map[string]interface{})
	if telemetry == nil {
		t.Fatal("setup did not create telemetry object")
	}
	telemetry["userTelemetrySetting"] = "keep"
	drifted, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal drifted config: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(drifted, '\n'), 0o600); err != nil {
		t.Fatalf("write drifted config: %v", err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after teardown: %v", err)
	}
	text := string(restored)
	for _, forbidden := range []string{"geminicli-hook.sh", "/otlp/geminicli/", `"managedBy": "defenseclaw"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("teardown left managed Gemini residue %q:\n%s", forbidden, text)
		}
	}
	for _, want := range []string{`"userSetting": "keep"`, `"userTelemetrySetting": "keep"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("teardown did not preserve user edit %q:\n%s", want, text)
		}
	}
}

func TestHookOnlyTeardown_UsesBackedUpConfigPathWhenWorkspaceChanges(t *testing.T) {
	dir := t.TempDir()
	prevHooks := CopilotHooksPathOverride
	prevWorkspace := CopilotWorkspaceDirOverride
	CopilotHooksPathOverride = ""
	CopilotWorkspaceDirOverride = ""
	t.Cleanup(func() {
		CopilotHooksPathOverride = prevHooks
		CopilotWorkspaceDirOverride = prevWorkspace
	})

	oldWorkspace := filepath.Join(dir, "old-workspace")
	newWorkspace := filepath.Join(dir, "new-workspace")
	conn := NewCopilotConnector()
	setupOpts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: oldWorkspace,
	}
	if err := conn.Setup(context.Background(), setupOpts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	oldPath := filepath.Join(oldWorkspace, ".github", "hooks", "defenseclaw.json")
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("expected old workspace hook config after setup: %v", err)
	}

	teardownOpts := setupOpts
	teardownOpts.WorkspaceDir = newWorkspace
	if err := conn.Teardown(context.Background(), teardownOpts); err != nil {
		t.Fatalf("Teardown with changed workspace: %v", err)
	}
	if _, err := os.Stat(oldPath); err == nil {
		t.Fatalf("old workspace hook config survived teardown: %s", oldPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat old workspace hook config: %v", err)
	}
}

func TestOpenHandsWorkspaceRootFallsBackToHomeWhenDaemonCwdIsDataDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	t.Setenv("HOME", home)

	prevHooks := OpenHandsHooksPathOverride
	prevWorkspace := OpenHandsWorkspaceDirOverride
	OpenHandsHooksPathOverride = ""
	OpenHandsWorkspaceDirOverride = ""
	t.Cleanup(func() {
		OpenHandsHooksPathOverride = prevHooks
		OpenHandsWorkspaceDirOverride = prevWorkspace
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dataDir); err != nil {
		t.Fatalf("chdir data dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	got := openhandsHooksPath(SetupOpts{DataDir: dataDir})
	want := filepath.Join(home, ".openhands", "hooks.json")
	if got != want {
		t.Fatalf("OpenHands hooks path = %q, want SDK-reachable home fallback %q", got, want)
	}
}

func TestCopilotSetupDefaultsToGlobalWhenDaemonCwdIsDataDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	dataDir := filepath.Join(dir, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	t.Setenv("HOME", home)

	prevHooks := CopilotHooksPathOverride
	prevWorkspace := CopilotWorkspaceDirOverride
	CopilotHooksPathOverride = ""
	CopilotWorkspaceDirOverride = ""
	t.Cleanup(func() {
		CopilotHooksPathOverride = prevHooks
		CopilotWorkspaceDirOverride = prevWorkspace
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dataDir); err != nil {
		t.Fatalf("chdir data dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	err = NewCopilotConnector().Setup(context.Background(), SetupOpts{
		DataDir:  dataDir,
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err != nil {
		t.Fatalf("Copilot setup with global home path failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".copilot", "hooks", "defenseclaw.json")); err != nil {
		t.Fatalf("stat global copilot hook config: %v", err)
	}

	err = NewCopilotConnector().Setup(context.Background(), SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: dataDir,
	})
	if err == nil {
		t.Fatal("Copilot setup succeeded with explicit data dir as workspace")
	}
	if !strings.Contains(err.Error(), "workspace must be outside DefenseClaw data dir") {
		t.Fatalf("Copilot setup error = %v, want clear workspace error", err)
	}
}

func TestCursorHooks_FailClosedOnlyWhenExplicit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cursor hooks: %v", err)
	}
	if !strings.Contains(string(data), `"failClosed": true`) {
		t.Fatalf("cursor hooks did not enable failClosed when explicitly requested:\n%s", string(data))
	}
}

func TestHookOnlyHookScripts_RespectFailClosedCapability(t *testing.T) {
	cases := []struct {
		name         string
		connector    *hookOnlyConnector
		wantFailMode string
	}{
		{name: "cursor_supports_fail_closed", connector: NewCursorConnector(), wantFailMode: "closed"},
		{name: "geminicli_supports_fail_closed", connector: NewGeminiCLIConnector(), wantFailMode: "closed"},
		{name: "openhands_supports_fail_closed", connector: NewOpenHandsConnector(), wantFailMode: "closed"},
		{name: "hermes_downgrades_to_fail_open", connector: NewHermesConnector(), wantFailMode: "open"},
		{name: "copilot_downgrades_to_fail_open", connector: NewCopilotConnector(), wantFailMode: "open"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := SetupOpts{
				DataDir:      filepath.Join(dir, "dc"),
				APIAddr:      "127.0.0.1:18970",
				APIToken:     "tok-test",
				HookFailMode: "closed",
				WorkspaceDir: dir,
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dir, "hooks"), opts, tc.connector); err != nil {
				t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "hooks", tc.connector.scriptName))
			if err != nil {
				t.Fatalf("read hook script: %v", err)
			}
			want := `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-` + tc.wantFailMode + `}"`
			if !strings.Contains(string(body), want) {
				t.Fatalf("hook script missing %s:\n%s", want, string(body))
			}
		})
	}
}

func TestOpenHandsHookScript_BlockExitsTwo(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/openhands/hook" {
			t.Fatalf("path=%s want /api/v1/openhands/hook", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hook_output":{"decision":"deny","reason":"policy denied"}}`))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	dir := t.TempDir()
	if err := WriteHookScriptsForConnectorObjectWithOpts(dir, SetupOpts{APIAddr: addr, APIToken: "tok-test", HookFailMode: "closed"}, NewOpenHandsConnector()); err != nil {
		t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
	}
	home := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(dir, "openhands-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"cat /etc/shadow"}}`)
	cmd.Env = append(os.Environ(), "DEFENSECLAW_HOME="+home)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("OpenHands deny hook exited 0, want exit 2; output=%s", string(out))
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("OpenHands deny hook exit=%v want code 2; output=%s", err, string(out))
	}
	if !strings.Contains(string(out), `"decision":"deny"`) {
		t.Fatalf("OpenHands deny hook did not print decision JSON; output=%s", string(out))
	}
}
