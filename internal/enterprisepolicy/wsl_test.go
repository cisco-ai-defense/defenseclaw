// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type fakeWSLRegistry struct {
	machine map[string][]RegValue
	users   map[string]map[string][]RegValue
	open    bool
	homes   []string
}

func (f *fakeWSLRegistry) MachineValues(key string) ([]RegValue, bool, error) {
	values, ok := f.machine[key]
	return append([]RegValue(nil), values...), ok, nil
}
func (f *fakeWSLRegistry) UserValues(key string) (map[string][]RegValue, error) {
	return f.users[key], nil
}
func (f *fakeWSLRegistry) MachineKeyWritableByUsers(string) (bool, error) { return f.open, nil }
func (f *fakeWSLRegistry) SetMachineValue(key string, value RegValue) error {
	f.DeleteMachineValue(key, value.Name)
	f.machine[key] = append(f.machine[key], value)
	return nil
}
func (f *fakeWSLRegistry) DeleteMachineValue(key, name string) error {
	kept := []RegValue{}
	for _, value := range f.machine[key] {
		if !strings.EqualFold(value.Name, name) {
			kept = append(kept, value)
		}
	}
	if _, ok := f.machine[key]; ok {
		f.machine[key] = kept
	}
	return nil
}
func (f *fakeWSLRegistry) ProfileHomes() ([]string, error) { return f.homes, nil }

func withFakeWSLRegistry(t *testing.T, reg *fakeWSLRegistry, inherit ...string) Options {
	t.Helper()
	previousRegistry, previousInherit := wslRegistry, wslInheritSources
	t.Cleanup(func() { wslRegistry, wslInheritSources = previousRegistry, previousInherit })
	wslRegistry = func() WSLRegistry { return reg }
	wslInheritSources = func(Options, WSLRegistry) ([]string, error) { return inherit, nil }
	opts := testOptions(t)
	opts.GOOS = "windows"
	return opts
}

func claudeGate(reg *fakeWSLRegistry) *RegValue {
	return findRegValue(reg.machine[ClaudeDesktopPolicyKey], ClaudeDesktopWSLValue)
}

// The Claude Desktop gate is merged only where Claude Desktop's hive rule
// makes that safe, and removal takes back only what DefenseClaw wrote.
func TestWindowsWSLClaudeDesktopGate(t *testing.T) {
	adminPolicy := RegValue{Name: "isClaudeCodeForDesktopEnabled", Type: RegSZ, String: "true"}

	t.Run("merged into existing machine policy and removed on uninstall", func(t *testing.T) {
		reg := &fakeWSLRegistry{machine: map[string][]RegValue{ClaudeDesktopPolicyKey: {adminPolicy}}}
		opts := withFakeWSLRegistry(t, reg)
		state, err := PublishWindowsWSL(opts)
		if err != nil || !state.Covered || state.OwnedEntries != 1 {
			t.Fatalf("publish: %+v %v", state, err)
		}
		if gate := claudeGate(reg); gate == nil || gate.Type != RegSZ || gate.String != "true" {
			t.Fatalf("gate not written as REG_SZ true: %+v", gate)
		}
		if verify, err := VerifyWindowsWSL(opts, nil); err != nil || !verify.Covered {
			t.Fatalf("verify after publish: %+v %v", verify, err)
		}
		// Once DefenseClaw's gate is the only machine policy it overrides
		// account policy: kept, but not covered.
		reg.machine[ClaudeDesktopPolicyKey] = []RegValue{*claudeGate(reg)}
		if verify, _ := VerifyWindowsWSL(opts, nil); verify.Covered || claudeGate(reg) == nil {
			t.Fatalf("a gate that is the only machine policy must be a conflict: %+v", verify)
		}
		reg.machine[ClaudeDesktopPolicyKey] = append(reg.machine[ClaudeDesktopPolicyKey], adminPolicy)
		if _, err := RemoveWindowsWSL(opts); err != nil {
			t.Fatal(err)
		}
		if claudeGate(reg) != nil || findRegValue(reg.machine[ClaudeDesktopPolicyKey], adminPolicy.Name) == nil {
			t.Fatalf("removal must delete only DefenseClaw's value: %+v", reg.machine)
		}
	})

	t.Run("an empty key needs create and must not drop user policy", func(t *testing.T) {
		// A REG_QWORD is invisible to Claude Desktop, so the key holds no
		// machine policy. Nothing turns WSL sessions on, so Claude Desktop's
		// managed-device default applies: verify passes and says how to make
		// the gate explicit.
		reg := &fakeWSLRegistry{machine: map[string][]RegValue{ClaudeDesktopPolicyKey: {{Name: "rolloutRing", Type: RegQWORD, Number: 2}}}}
		opts := withFakeWSLRegistry(t, reg)
		state, _ := PublishWindowsWSL(opts)
		if !state.Covered || claudeGate(reg) != nil || !strings.Contains(strings.Join(state.Pending, "\n"), "claude_desktop_key: create") {
			t.Fatalf("merge must not create machine policy, and must not fail verify for it: %+v", state)
		}
		reg.open = true
		if state, _ := VerifyWindowsWSL(opts, nil); state.Covered {
			t.Fatalf("a key a standard account can change must fail verify: %+v", state)
		}
		reg.open = false
		opts.WSL.ClaudeDesktopKey = config.WSLClaudeDesktopKeyCreate
		reg.users = map[string]map[string][]RegValue{ClaudeDesktopPolicyKey: {"S-1-5-21-1-2-3-1001": {adminPolicy}}}
		if state, _ := PublishWindowsWSL(opts); state.Covered || claudeGate(reg) != nil {
			t.Fatalf("create must not override an account's HKCU policy: %+v", state)
		}
		reg.users = nil
		home := t.TempDir()
		library := filepath.Join(home, "AppData", "Local", "Claude-3p", "configLibrary")
		if err := os.MkdirAll(library, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(library, "org.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		reg.homes = []string{home}
		if state, _ := PublishWindowsWSL(opts); state.Covered || claudeGate(reg) != nil {
			t.Fatalf("create must not disable local third-party configuration: %+v", state)
		}
		reg.homes = nil
		if state, err := PublishWindowsWSL(opts); err != nil || !state.Covered || claudeGate(reg) == nil {
			t.Fatalf("create with nothing to lose must write the gate: %+v %v", state, err)
		}
	})

	t.Run("administrator values and an open key", func(t *testing.T) {
		reg := &fakeWSLRegistry{machine: map[string][]RegValue{ClaudeDesktopPolicyKey: {{Name: ClaudeDesktopWSLValue, Type: RegDWORD, Number: 0}}}}
		opts := withFakeWSLRegistry(t, reg, `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`)
		state, _ := PublishWindowsWSL(opts)
		if state.Covered || len(state.Conflicts) != 2 {
			t.Fatalf("enabled WSL sessions and inherited Windows settings must both conflict: %+v", state)
		}
		opts.WSL.AgentSessions = config.WSLAgentSessionsAllow
		if state, _ := VerifyWindowsWSL(opts, nil); !state.Covered {
			t.Fatalf("agent_sessions: allow accepts them: %+v", state)
		}
		reg.machine[ClaudeDesktopPolicyKey] = []RegValue{adminPolicy}
		reg.open = true
		opts.WSL.AgentSessions = ""
		if state, _ := PublishWindowsWSL(opts); state.Covered || claudeGate(reg) != nil {
			t.Fatalf("a key standard accounts can write must not get the gate: %+v", state)
		}
	})

	t.Run("a REG_EXPAND_SZ value is machine policy", func(t *testing.T) {
		reg := &fakeWSLRegistry{machine: map[string][]RegValue{ClaudeDesktopPolicyKey: {{Name: "managedMcpServers", Type: RegExpandSZ, String: "[]"}}}}
		if state, err := PublishWindowsWSL(withFakeWSLRegistry(t, reg)); err != nil || !state.Covered || claudeGate(reg) == nil {
			t.Fatalf("merge must join REG_EXPAND_SZ machine policy: %+v %v", state, err)
		}
	})

	t.Run("export", func(t *testing.T) {
		opts := testOptions(t)
		opts.WSL.Platform = config.WSLPlatformDisable
		data, err := ExportWSL(opts, "reg")
		want := "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Claude]\r\n\"disableWslSessions\"=\"true\"\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\WSL]\r\n\"AllowWSL\"=dword:00000000\r\n"
		if err != nil || string(data) != want {
			t.Fatalf("reg export:\n%q\n%q %v", data, want, err)
		}
		opts.WSL = config.EnterpriseWindowsWSLPolicy{AgentSessions: config.WSLAgentSessionsAllow}
		if _, err := ExportWSL(opts, "json"); err == nil {
			t.Fatal("nothing to export must be an error")
		}
	})

	t.Run("platform disable turns WSL off and retires on leave", func(t *testing.T) {
		reg := &fakeWSLRegistry{machine: map[string][]RegValue{}}
		opts := withFakeWSLRegistry(t, reg)
		opts.WSL.Platform = config.WSLPlatformDisable
		state, err := PublishWindowsWSL(opts)
		allow := findRegValue(reg.machine[WSLPolicyKey], WSLAllowValue)
		if err != nil || !state.Covered || allow == nil || allow.Type != RegDWORD || allow.Number != 0 {
			t.Fatalf("disable must write AllowWSL=0 and cover the gaps: %+v %+v %v", state, allow, err)
		}
		opts.WSL.Platform = config.WSLPlatformLeave
		if _, err := PublishWindowsWSL(opts); err != nil || findRegValue(reg.machine[WSLPolicyKey], WSLAllowValue) != nil {
			t.Fatalf("leave must retire DefenseClaw's AllowWSL: %+v %v", reg.machine, err)
		}
	})
}

// The Codex IDE extension's WSL switch is reset in place: only the top-level
// true becomes false, and comments, trailing commas and CRLF survive.
func TestWSLEditorSettingsRepair(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "Code", "User")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	original := "{\r\n  // team settings\r\n  \"[python]\": { \"chatgpt.runCodexInWindowsSubsystemForLinux\": true },\r\n  \"chatgpt.runCodexInWindowsSubsystemForLinux\": /* on */ true,\r\n  \"chatgpt.cliExecutable\": \"C:\\\\tools\\\\codex.exe\",\r\n}\r\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanWSLEditorSettings(home)
	if err != nil || len(findings) != 1 || !findings[0].WSL || !findings[0].CLIExecutable || findings[0].Repaired {
		t.Fatalf("scan: %+v %v", findings, err)
	}
	if findings, err = RepairWSLEditorSettings(home); err != nil || len(findings) != 1 || !findings[0].Repaired {
		t.Fatalf("repair: %+v %v", findings, err)
	}
	got, _ := os.ReadFile(path)
	want := strings.Replace(original, "/* on */ true", "/* on */ false", 1)
	if string(got) != want {
		t.Fatalf("repair must change only the top-level value:\n%q\n%q", got, want)
	}
	if findings, err = ScanWSLEditorSettings(home); err != nil || len(findings) != 1 || findings[0].WSL {
		t.Fatalf("after repair: %+v %v", findings, err)
	}
}
