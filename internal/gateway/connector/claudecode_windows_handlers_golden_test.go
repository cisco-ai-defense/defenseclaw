// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// The Python status and doctor readers (cli/defenseclaw/hook_integrity.py
// claude_launcher_guard_view, cli/tests/test_hook_integrity_layouts.py) read
// testdata/claudecode_windows_handlers.json, so the per-user Windows Claude
// Code handlers Setup writes and the ones status recognises cannot drift: status
// read only the command key, which the launcher guard sets to cmd.exe, and
// reported the hooks missing after every 1.0.1 or later install (GAP-0463).
func TestClaudeCodeWindowsHandlersMatchTheSharedGolden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "claudecode_windows_handlers.json"))
	if err != nil {
		t.Fatal(err)
	}
	type handler struct {
		Type    string   `json:"type"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	var golden struct {
		Launcher     string  `json:"launcher"`
		Guard        handler `json:"guard"`
		PreToolGuard handler `json:"pretool_guard"`
		Exec         handler `json:"exec"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	hookArgs := []string{"hook", "--connector", "claudecode"}
	if !claudeCodeLauncherGuardable(golden.Launcher) {
		t.Fatalf("golden launcher %q is not one per-user Setup guards", golden.Launcher)
	}
	if got := claudeCodeLauncherGuardArgs(golden.Launcher, hookArgs); !reflect.DeepEqual(got, golden.Guard.Args) {
		t.Errorf("guard args Setup writes = %q, golden has %q", got, golden.Guard.Args)
	}
	if golden.Guard.Type != "command" || golden.Guard.Command != `C:\Windows\System32\cmd.exe` {
		t.Errorf("golden guard handler = %+v", golden.Guard)
	}
	want := handler{Type: "command", Command: golden.Launcher, Args: hookArgs}
	if !reflect.DeepEqual(golden.Exec, want) {
		t.Errorf("golden exec handler = %+v, want %+v", golden.Exec, want)
	}
	if got := claudeCodePreToolGuardArgs(golden.Launcher, hookArgs); !reflect.DeepEqual(got, golden.PreToolGuard.Args) {
		t.Errorf("PreToolUse guard args Setup writes = %q, golden has %q", got, golden.PreToolGuard.Args)
	}
	preTool := map[string]interface{}{"type": "command", "command": golden.PreToolGuard.Command,
		"args": stringsToInterfaces(golden.PreToolGuard.Args)}
	if view, ok := claudeCodeExecView(preTool).(map[string]interface{}); golden.PreToolGuard.Type != "command" || !ok ||
		view["command"] != golden.Launcher || !codexValueMatches(view["args"], hookArgs) {
		t.Errorf("claudeCodeExecView(golden PreToolUse guard) = %v", view)
	}
	if runtime.GOOS != "windows" {
		return
	}
	t.Setenv("SystemRoot", `C:\Windows`)
	opts := SetupOpts{HookExecutable: golden.Launcher}
	command, args := claudeCodeWindowsHookInvocation(opts, golden.Launcher)
	if command != golden.Guard.Command || !reflect.DeepEqual(args, golden.Guard.Args) {
		t.Errorf("per-user Windows invocation = %q %q, golden guard = %q %q", command, args, golden.Guard.Command, golden.Guard.Args)
	}
	guard := map[string]interface{}{"type": "command", "command": command, "args": stringsToInterfaces(args)}
	view, ok := claudeCodeExecView(guard).(map[string]interface{})
	if !ok || view["command"] != golden.Launcher {
		t.Errorf("claudeCodeExecView(guard) = %v", view)
	}
}

func stringsToInterfaces(values []string) []interface{} {
	out := make([]interface{}, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}
