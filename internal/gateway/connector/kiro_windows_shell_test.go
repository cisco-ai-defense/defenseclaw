//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	kiroShellChildEnv = "DEFENSECLAW_TEST_KIRO_SHELL_CHILD"
	kiroShellMarker   = "kiro-shell-boundary-marker"
)

// init makes this test binary stand in for the release hook launcher when
// the Kiro shell test runs it through a rendered command. It exits 2, Kiro's
// block, only when the payload arrived on stdin and the arguments are the
// ones Setup renders; 3 and 4 name what went missing.
func init() {
	surface := os.Getenv(kiroShellChildEnv)
	if surface == "" {
		return
	}
	data, _ := io.ReadAll(os.Stdin)
	want := "hook --connector kiro"
	if surface == KiroHookSurfaceV3 {
		want += " --hook-surface " + KiroHookSurfaceV3
	}
	switch {
	case !strings.Contains(string(data), kiroShellMarker):
		os.Exit(4)
	case strings.Join(os.Args[1:], " ") != want:
		os.Exit(3)
	default:
		os.Exit(2)
	}
}

// guiSubsystemCopyOfTestBinary copies this test binary with its PE subsystem
// set to Windows GUI, like the release launcher (-H=windowsgui).
func guiSubsystemCopyOfTestBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	header := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if string(data[header:header+4]) != "PE\x00\x00" {
		t.Fatalf("%s has no PE header", exe)
	}
	// PE signature, COFF file header, then Subsystem at offset 68 of the
	// optional header (PE32 and PE32+).
	binary.LittleEndian.PutUint16(data[header+4+20+68:], pe.IMAGE_SUBSYSTEM_WINDOWS_GUI)
	dst := filepath.Join(t.TempDir(), windowsHookBinaryName)
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := pe.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	optional, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || optional.Subsystem != pe.IMAGE_SUBSYSTEM_WINDOWS_GUI {
		t.Fatalf("copy is not a GUI-subsystem executable: %#v", file.OptionalHeader)
	}
	return dst
}

// Kiro honors only exit 2 as a block and proceeds on any other status. Run
// both rendered Kiro commands, against a GUI-subsystem launcher like the
// release build, the way Kiro can launch them: through cmd.exe as Node's
// shell: true does (`cmd.exe /d /s /c "<command>"`) and as an argument
// vector (`cmd /C <command>`). A block must come back as 2, with the payload
// delivered on stdin. The earlier `& '<launcher>' ...` command exits 1 in
// cmd.exe ("& was unexpected at this time").
//
// A launcher that runs the command with `powershell -Command` turns any
// native status other than 0 into 1 (about_PowerShell_exe); no command
// string that also works in cmd.exe can change that, so it is not tested.
// Which shell Kiro uses is not documented.
func TestKiroWindowsHookCommandsBlockThroughTheShell(t *testing.T) {
	gui := guiSubsystemCopyOfTestBinary(t)
	t.Cleanup(PinNativeHookExecutableForTest(gui))
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: t.TempDir()}
	cmdExe := filepath.Join(trustedWindowsSystemDirectory(), "cmd.exe")
	payload := `{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"` + kiroShellMarker + `"}}`

	run := func(t *testing.T, surface string, command *exec.Cmd) int {
		t.Helper()
		command.Stdin = strings.NewReader(payload)
		command.Env = append(os.Environ(), kiroShellChildEnv+"="+surface)
		out, err := command.CombinedOutput()
		if command.ProcessState == nil {
			t.Fatalf("run %v: %v", command.Args, err)
		}
		if text := strings.TrimSpace(string(out)); text != "" {
			t.Logf("output: %s", text)
		}
		return command.ProcessState.ExitCode()
	}
	for surface, rendered := range map[string]string{
		KiroHookSurfaceV3: conn.hookCommandForV3Surface(opts),
		"v2":              conn.hookCommand(opts),
	} {
		t.Run(surface, func(t *testing.T) {
			node := exec.Command(cmdExe)
			node.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + rendered + `"`}
			if code := run(t, surface, node); code != 2 {
				t.Fatalf("cmd.exe /d /s /c: exit %d, want 2 (Kiro's block)", code)
			}
			if code := run(t, surface, exec.Command(cmdExe, "/C", rendered)); code != 2 {
				t.Fatalf("cmd /C: exit %d, want 2 (Kiro's block)", code)
			}
		})
	}
}

// Earlier builds wrote the `& '<launcher>' hook --connector kiro` command
// into the CLI 2.x agent files, whose entries are matched by exact command.
// Setup must replace that entry with the current command instead of adding
// a second one, and teardown must remove it, keeping the user's own entries.
func TestKiroWindowsSetupReplacesTheCallOperatorAgentHooks(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	launcher := filepath.Join(t.TempDir(), windowsHookBinaryName)
	t.Cleanup(PinNativeHookExecutableForTest(launcher))
	legacy := "& " + powershellQuoteLiteral(launcher) + " hook --connector kiro"
	userEntry := map[string]interface{}{"command": `C:\tools\audit.exe`, "matcher": "*"}
	agent := filepath.Join(home, "agents", kiroManagedAgentName+".json")
	body, err := json.Marshal(map[string]interface{}{
		"name": kiroManagedAgentName,
		"hooks": map[string]interface{}{
			"preToolUse": []interface{}{
				map[string]interface{}{"command": legacy, "matcher": ".*", "description": "DefenseClaw tool-use inspection"},
				userEntry,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(agent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agent, body, 0o600); err != nil {
		t.Fatal(err)
	}

	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: t.TempDir(), HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	commands := kiroAgentCommands(t, agent, "preToolUse")
	if len(commands) != 2 || commands[0] != `C:\tools\audit.exe` || commands[1] != conn.hookCommand(opts) {
		t.Fatalf("preToolUse commands after Setup = %q, want the user's entry and the current DefenseClaw command", commands)
	}

	// Teardown's removal (after the backup restore declines) and its
	// verification recognize the older command too.
	if err := os.WriteFile(agent, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := kiroV2AgentReferencesAnyHook(agent, conn.hookCommand(opts)); err != nil || !present {
		t.Fatalf("teardown verification misses the older command: %v %v", present, err)
	}
	if err := removeKiroV2AgentHooks(agent, conn.hookCommand(opts)); err != nil {
		t.Fatal(err)
	}
	if commands := kiroAgentCommands(t, agent, "preToolUse"); len(commands) != 1 || commands[0] != `C:\tools\audit.exe` {
		t.Fatalf("preToolUse commands after removal = %q, want only the user's entry", commands)
	}
}

func kiroAgentCommands(t *testing.T, path, event string) []string {
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
	list, _ := hooks[event].([]interface{})
	var commands []string
	for _, item := range list {
		entry, _ := item.(map[string]interface{})
		command, _ := entry["command"].(string)
		commands = append(commands, command)
	}
	return commands
}
