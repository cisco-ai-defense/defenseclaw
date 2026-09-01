// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestDevinPatchUserConfigAcceptsJSONCAndPreservesForeignHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	before := []byte(`{
  // Devin accepts JSONC.
  "theme": "dark",
  "hooks": {
    "PreToolUse": [{"matcher":"^exec$","hooks":[{"type":"command","command":"foreign-check"}]}],
  },
}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(t.TempDir(), "devin-hook.sh")
	if err := patchDevinHooks(path, hook); err != nil {
		t.Fatalf("patch Devin hooks: %v", err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg["theme"] != "dark" {
		t.Fatalf("foreign config lost: %+v", cfg)
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok || len(hooks) != len(devinHookEvents) {
		t.Fatalf("hook matrix = %+v", cfg["hooks"])
	}
	pre, _ := hooks["PreToolUse"].([]interface{})
	if len(pre) != 2 || devinHookGroupReferences(pre[0], hook) || !devinHookGroupReferences(pre[1], hook) {
		t.Fatalf("PreToolUse did not preserve foreign-first/managed-last ordering: %+v", pre)
	}
	if err := removeDevinHookReferences(path, hook); err != nil {
		t.Fatalf("remove Devin hooks: %v", err)
	}
	cfg, err = readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ = cfg["hooks"].(map[string]interface{})
	pre, _ = hooks["PreToolUse"].([]interface{})
	if len(pre) != 1 || cfg["theme"] != "dark" {
		t.Fatalf("surgical cleanup lost foreign data: %+v", cfg)
	}
}

func TestDevinPatchProjectHooksUsesWholeDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".devin", "hooks.v1.json")
	hook := "/opt/defenseclaw/hooks/devin-hook.sh"
	if err := patchDevinHooks(path, hook); err != nil {
		t.Fatalf("patch project hooks: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, wrapped := cfg["hooks"]; wrapped {
		t.Fatalf("hooks.v1.json was incorrectly wrapped: %s", body)
	}
	for _, event := range devinHookEvents {
		entries, _ := cfg[event].([]interface{})
		if len(entries) != 1 || !devinHookGroupReferences(entries[0], hook) {
			t.Fatalf("event %s registration = %+v", event, entries)
		}
	}
}

func TestDevinWindowsHookCommandMigratesExactPowerShellPredecessor(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows Devin hook-command migration")
	}
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	hookBinary := filepath.Join(root, "Defense Claw", windowsHookBinaryName)
	setHookBinaryOverride(t, hookBinary)
	opts := SetupOpts{DataDir: filepath.Join(root, "defenseclaw")}
	current := windowsDevinBashHookCommand(hookBinary)
	predecessors := []string{
		legacyWindowsDevinDirectBashHookCommandForBinary(hookBinary),
		legacyWindowsDevinUnquotedPowerShellHookCommandForBinary(hookBinary),
		legacyWindowsDevinPowerShellHookCommandForBinary(hookBinary),
	}
	foreign := `"C:/Other Product/defenseclaw-hook.exe" hook --connector devin`
	seed := map[string]interface{}{
		"theme": "dark",
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": predecessors[0]}}},
				map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": predecessors[1]}}},
				map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": predecessors[2]}}},
				map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": foreign}}},
			},
		},
	}
	if err := writeJSONObject(path, seed); err != nil {
		t.Fatal(err)
	}
	owned := devinOwnedHookCommandsForOS("windows", opts, current)
	if err := patchDevinHooks(path, current, owned...); err != nil {
		t.Fatalf("migrate Devin command: %v", err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := devinHooksObject(path, cfg)
	for _, event := range devinHookEvents {
		entries, _ := hooks[event].([]interface{})
		currentCount := 0
		predecessorCount := 0
		foreignCount := 0
		for _, entry := range entries {
			if devinHookGroupReferences(entry, current) {
				currentCount++
			}
			for _, predecessor := range predecessors {
				if devinHookGroupReferences(entry, predecessor) {
					predecessorCount++
				}
			}
			if devinHookGroupReferences(entry, foreign) {
				foreignCount++
			}
		}
		if currentCount != 1 || predecessorCount != 0 {
			t.Fatalf("event %s current=%d predecessor=%d entries=%+v", event, currentCount, predecessorCount, entries)
		}
		wantForeign := 0
		if event == "PreToolUse" {
			wantForeign = 1
		}
		if foreignCount != wantForeign {
			t.Fatalf("event %s foreign=%d want=%d entries=%+v", event, foreignCount, wantForeign, entries)
		}
	}
	if err := removeDevinHookReferences(path, owned...); err != nil {
		t.Fatalf("remove migrated Devin hooks: %v", err)
	}
	cfg, err = readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks = devinHooksObject(path, cfg)
	entries, _ := hooks["PreToolUse"].([]interface{})
	if len(entries) != 1 || !devinHookGroupReferences(entries[0], foreign) {
		t.Fatalf("foreign hook was not preserved after teardown: %+v", entries)
	}
}

func TestDevinProfileUsesNativeLifecycleContract(t *testing.T) {
	profile := NewDevinConnector().HookProfile(SetupOpts{AgentVersion: "3000.4.25"})
	if profile.ContractID != "devin-hooks-v1" || profile.CompatibilityStatus != HookCompatibilityKnown {
		t.Fatalf("contract = %+v", profile)
	}
	if !slices.Equal(profile.SupportedEvents, devinHookEvents) || profile.NativeOTLP != nil {
		t.Fatalf("events/native OTLP = %v / %+v", profile.SupportedEvents, profile.NativeOTLP)
	}
	req := profile.Decode(map[string]interface{}{
		"hook_event_name": "PostToolUse",
		"session_id":      "session-1",
		"prompt_id":       "prompt-2",
		"tool_name":       "exec",
		"tool_input":      map[string]interface{}{"command": "git status"},
		"tool_response":   map[string]interface{}{"success": true, "output": "clean"},
	})
	if req.SessionID != "session-1" || req.TurnID != "prompt-2" || req.ToolName != "exec" || req.Direction != "tool_result" {
		t.Fatalf("decoded request = %+v", req)
	}
	blocked := profile.Respond(HookRespondInput{
		Req:    HookProfileRequest{ConnectorName: "devin", HookEventName: "PreToolUse", ToolName: "exec"},
		Action: "block", Reason: "unsafe", Caps: profile.Capabilities,
	})
	if blocked.Output["decision"] != "block" || blocked.Output["reason"] == "" {
		t.Fatalf("block response = %+v", blocked)
	}
	context := profile.Respond(HookRespondInput{
		Req:    HookProfileRequest{ConnectorName: "devin", HookEventName: "UserPromptSubmit"},
		Action: "alert", AdditionalContext: "policy context", Caps: profile.Capabilities,
	})
	nested, _ := context.Output["hookSpecificOutput"].(map[string]interface{})
	if nested["hookEventName"] != "UserPromptSubmit" || nested["additionalContext"] != "policy context" {
		t.Fatalf("context response = %+v", context)
	}
	forbidden := profile.Respond(HookRespondInput{
		Req:    HookProfileRequest{ConnectorName: "devin", HookEventName: "PermissionRequest"},
		Action: "alert", RawAction: "confirm", AdditionalContext: "do not invent", Caps: profile.Capabilities,
	})
	if forbidden.Output != nil {
		t.Fatalf("unsupported response fields invented: %+v", forbidden)
	}
}

func TestDefaultRegistryPublishesDevinNotRetiredWindsurf(t *testing.T) {
	registry := NewDefaultRegistry()
	if _, ok := registry.Get("devin"); !ok {
		t.Fatal("default registry omitted Devin")
	}
	if _, ok := registry.Get("windsurf"); ok {
		t.Fatal("retired Windsurf connector remains public")
	}
}

func TestDevinReadinessRequiresExactlyOneManagedGroupPerEvent(t *testing.T) {
	root := t.TempDir()
	opts := SetupOpts{ConfigHome: root, DataDir: filepath.Join(root, "defenseclaw")}
	conn := NewDevinConnector()
	path := devinHooksPath(opts)
	command := conn.hookCommand(opts)
	if err := patchDevinHooks(path, command); err != nil {
		t.Fatal(err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("complete Devin contract present=%t err=%v", present, err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := devinHooksObject(path, cfg)
	delete(hooks, "SessionEnd")
	if err := writeJSONObject(path, cfg); err != nil {
		t.Fatal(err)
	}
	present, err = OwnedHooksPresent(conn, opts)
	if err != nil || present {
		t.Fatalf("incomplete Devin contract present=%t err=%v", present, err)
	}
}

func TestDevinCapabilityPathsAreScopedToDocumentedFiles(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "workspace")
	configHome := filepath.Join(t.TempDir(), "devin")
	opts := SetupOpts{ConfigHome: configHome, WorkspaceDir: workspace}
	caps := NewDevinConnector().Capabilities(opts)
	if slices.Contains(caps.MCP.ConfigPaths, workspace) {
		t.Fatalf("raw workspace root leaked into MCP file inventory: %v", caps.MCP.ConfigPaths)
	}
	if !slices.Contains(caps.MCP.WritePaths, filepath.Join(workspace, ".devin", "mcp_config.json")) {
		t.Fatalf("project MCP target missing: %v", caps.MCP.WritePaths)
	}
	if !slices.Equal(caps.Skills.WritePaths, []string{filepath.Join(workspace, ".devin", "skills")}) {
		t.Fatalf("project skill write paths = %v, want native .devin/skills target", caps.Skills.WritePaths)
	}
	if !caps.Agents.Supported || !caps.Agents.DiscoveryOnly || len(caps.Agents.WritePaths) != 0 {
		t.Fatalf("Devin agents must be read-only discovery: %+v", caps.Agents)
	}
	for _, want := range []string{
		filepath.Join(configHome, "agents"),
		filepath.Join(workspace, ".devin", "agents"),
		filepath.Join(workspace, ".agents", "agents"),
	} {
		if !slices.Contains(caps.Agents.ReadPaths, want) {
			t.Fatalf("Devin agent read paths = %v, missing %q", caps.Agents.ReadPaths, want)
		}
	}
	if caps.Plugins.Supported {
		t.Fatalf("closed-beta Devin plugins were advertised: %+v", caps.Plugins)
	}
}

func TestDevinGlobalSkillWritePathUsesNativeConfigRoot(t *testing.T) {
	configHome := filepath.Join(t.TempDir(), "devin")
	caps := NewDevinConnector().Capabilities(SetupOpts{ConfigHome: configHome})
	if !slices.Equal(caps.Skills.WritePaths, []string{filepath.Join(configHome, "skills")}) {
		t.Fatalf("global skill write paths = %v, want native user config target", caps.Skills.WritePaths)
	}
}
