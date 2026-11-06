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

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"gopkg.in/yaml.v3"
)

func gap0625CommandForms(path string) map[string]string {
	return map[string]string{
		"double quoted": `"` + path + `"`,
		"environment":   "env -i " + shellWord(path),
		"system env":    "/usr/bin/env -i " + shellWord(path),
		"clean env":     "/usr/bin/../bin/env -i " + shellWord(path),
		"shell option":  "bash -e " + shellWord(path),
		"system shell":  "/bin/bash -e " + shellWord(path),
		"shell flags":   "bash -eu " + shellWord(path),
		"exec":          "exec " + shellWord(path),
		"exec name":     "exec -a hook " + shellWord(path),
		"command":       "command " + shellWord(path),
		"command path":  "command -p " + shellWord(path),
		"nested":        "env -i bash -e " + shellWord(path),
	}
}

func gap0625SetHermesCommand(t *testing.T, path, command string) {
	t.Helper()
	cfg, err := readYAMLObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	entries := hooks["pre_tool_call"].([]interface{})
	entries[0].(map[string]interface{})["command"] = command
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGAP0625HermesLiteralFormsReconcileAndKeepUserHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	for name, form := range gap0625CommandForms("PLACEHOLDER") {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			command := strings.ReplaceAll(form, "PLACEHOLDER", renamed)
			gap0625SetHermesCommand(t, configPath, command)
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if len(commands) != 1 || commands[0] != userHook {
				t.Fatalf("remaining commands = %q; want the user hook", commands)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after Teardown: %v", err)
			}
		})
	}
}

func TestGAP0625HermesEvaluatedManagedCommandIsRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	for _, managed := range []bool{true, false} {
		t.Run(map[bool]string{true: "managed", false: "user"}[managed], func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			target := userHook
			if managed {
				target = renamed
			}
			command := "HOOK=" + shellWord(target) + `; "$HOOK"`
			gap0625SetHermesCommand(t, configPath, command)
			verifyErr := conn.VerifyClean(opts)
			if managed != (verifyErr != nil) {
				t.Fatalf("VerifyClean before Teardown = %v; managed=%v", verifyErr, managed)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			want := []string{command, userHook}
			if managed {
				want = []string{userHook}
			}
			if commands := gap0625PreToolCommands(t, configPath); strings.Join(commands, "\n") != strings.Join(want, "\n") {
				t.Fatalf("remaining commands = %q; want %q", commands, want)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after Teardown: %v", err)
			}
		})
	}
}

// A user program given the managed hook path as an argument names the
// managed directory, so the entry is an edited DefenseClaw entry (lead
// ruling r5 for GAP-0625: ownership is read from the text, not evaluated).
func TestGAP0625ExternalProgramNamingHookDirIsRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	for _, name := range []string{"command", "bash", "env"} {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			program := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(program, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			gap0625SetHermesCommand(t, configPath, shellWord(program)+" "+shellWord(renamed))
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if commands := gap0625PreToolCommands(t, configPath); len(commands) != 1 || commands[0] != userHook {
				t.Fatalf("remaining commands = %q; want the user hook", commands)
			}
		})
	}
}

func gap0625DevinConfig(t *testing.T, command string) (string, string) {
	t.Helper()
	path := filepath.Join(testenv.PrivateTempDir(t), "devin", "config.json")
	user := filepath.Join(t.TempDir(), "user-hook.sh")
	hooks := map[string]interface{}{
		"PreToolUse": []interface{}{
			map[string]interface{}{"matcher": "", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": command}}},
			map[string]interface{}{"matcher": "", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": user}}},
		},
	}
	if err := writeJSONObject(path, map[string]interface{}{"hooks": hooks}); err != nil {
		t.Fatal(err)
	}
	return path, user
}

func TestGAP0625DevinLiteralFormsReconcileAndKeepUserHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	for name, form := range gap0625CommandForms("PLACEHOLDER") {
		t.Run(name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "devin-hook.sh")
			renamed := filepath.Join(root, "hooks", "hookX")
			command := strings.ReplaceAll(form, "PLACEHOLDER", renamed)
			path, user := gap0625DevinConfig(t, command)
			if present, err := devinConfigReferencesHook(path, script); err != nil || !present {
				t.Fatalf("managed entry present=%v err=%v", present, err)
			}
			conn := NewDevinConnector()
			if err := conn.VerifyClean(SetupOpts{DataDir: root, ConfigHome: filepath.Dir(path)}); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := removeDevinHookReferences(path, script); err != nil {
				t.Fatalf("remove Devin entry: %v", err)
			}
			commands := devinConfigCommands(t, path)
			if len(commands) != 1 || commands[0] != "PreToolUse="+user {
				t.Fatalf("remaining commands = %q; want the user hook", commands)
			}
			if err := conn.VerifyClean(SetupOpts{DataDir: root, ConfigHome: filepath.Dir(path)}); err != nil {
				t.Fatalf("VerifyClean after removal: %v", err)
			}
		})
	}
}

func TestGAP0625DevinRepairReplacesRenamedHookAndKeepsUserHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, "hooks", "devin-hook.sh")
	path, user := gap0625DevinConfig(t, "bash -e "+shellWord(filepath.Join(root, "hooks", "hookX")))
	if err := patchDevinHooks(path, script); err != nil {
		t.Fatalf("repair Devin hooks: %v", err)
	}
	commands := devinConfigCommands(t, path)
	if len(commands) != len(devinHookEvents)+1 {
		t.Fatalf("repaired commands = %q", commands)
	}
	var managed, preserved int
	for _, command := range commands {
		if command == "PreToolUse="+script {
			managed++
		}
		if command == "PreToolUse="+user {
			preserved++
		}
	}
	if managed != 1 || preserved != 1 {
		t.Fatalf("managed=%d user=%d in %q", managed, preserved, commands)
	}
}

func TestGAP0625DevinEvaluatedManagedCommandIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, "hooks", "devin-hook.sh")
	command := "HOOK=" + shellWord(filepath.Join(root, "hooks", "hookX")) + `; "$HOOK"`
	path, user := gap0625DevinConfig(t, command)
	if present, err := devinConfigReferencesHook(path, script); err != nil || !present {
		t.Fatalf("managed entry present=%v err=%v", present, err)
	}
	if err := patchDevinHooks(path, script); err != nil {
		t.Fatalf("repair Devin hooks: %v", err)
	}
	commands := devinConfigCommands(t, path)
	if len(commands) != len(devinHookEvents)+1 || strings.Contains(strings.Join(commands, "\n"), "$HOOK") ||
		!strings.Contains(strings.Join(commands, "\n"), "PreToolUse="+user) {
		t.Fatalf("repaired commands = %q", commands)
	}
	if err := removeDevinHookReferences(path, script); err != nil {
		t.Fatalf("remove Devin entries: %v", err)
	}
	if commands := devinConfigCommands(t, path); len(commands) != 1 || commands[0] != "PreToolUse="+user {
		t.Fatalf("remaining commands = %q; want the user hook", commands)
	}
}

func TestGAP0625DevinMixedGroupKeepsUserHandler(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, "hooks", "devin-hook.sh")
	renamed := filepath.Join(root, "hooks", "hookX")
	user := filepath.Join(t.TempDir(), "user-hook.sh")
	path := filepath.Join(t.TempDir(), "config.json")
	group := map[string]interface{}{
		"matcher": "^exec$",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "env -i " + shellWord(renamed)},
			map[string]interface{}{"type": "command", "command": user},
		},
	}
	if err := writeJSONObject(path, map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{group}}}); err != nil {
		t.Fatal(err)
	}
	if err := removeDevinHookReferences(path, script); err != nil {
		t.Fatal(err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	groups := hooks["PreToolUse"].([]interface{})
	if len(groups) != 1 {
		t.Fatalf("remaining groups = %v; want one user group", groups)
	}
	remaining := groups[0].(map[string]interface{})
	entries := remaining["hooks"].([]interface{})
	if remaining["matcher"] != "^exec$" || len(entries) != 1 || entries[0].(map[string]interface{})["command"] != user {
		t.Fatalf("user handler changed: %v", remaining)
	}
}

func TestGAP0625DevinReadinessRejectsExtraManagedHandlerInOneGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	opts := SetupOpts{DataDir: root, ConfigHome: filepath.Join(root, "devin")}
	conn := NewDevinConnector()
	script := conn.hookCommand(opts)
	path := devinHooksPath(opts)
	if err := patchDevinHooks(path, script); err != nil {
		t.Fatal(err)
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := devinHooksObject(path, cfg)
	groups := hooks[devinHookEvents[0]].([]interface{})
	group := groups[0].(map[string]interface{})
	group["hooks"] = append(group["hooks"].([]interface{}),
		map[string]interface{}{"type": "command", "command": "env -i " + shellWord(filepath.Join(root, "hooks", "hookX"))})
	if err := writeJSONObject(path, cfg); err != nil {
		t.Fatal(err)
	}
	if present, err := devinOwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("readiness accepted an extra managed handler: present=%v err=%v", present, err)
	}
}

func gap0625CursorConfig(t *testing.T, command string) (string, string) {
	t.Helper()
	path := filepath.Join(testenv.PrivateTempDir(t), "cursor", "hooks.json")
	user := filepath.Join(t.TempDir(), "user-hook.sh")
	hooks := map[string]interface{}{
		cursorHookEvents[0]: []interface{}{
			map[string]interface{}{"type": "command", "command": command},
			map[string]interface{}{"type": "command", "command": user},
		},
	}
	if err := writeJSONObject(path, map[string]interface{}{"version": 1, "hooks": hooks}); err != nil {
		t.Fatal(err)
	}
	return path, user
}

func TestGAP0625CursorLiteralFormsReconcileAndKeepUserHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	for name, form := range gap0625CommandForms("PLACEHOLDER") {
		t.Run(name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "cursor-hook.sh")
			renamed := filepath.Join(root, "hooks", "hookX")
			command := strings.ReplaceAll(form, "PLACEHOLDER", renamed)
			path, user := gap0625CursorConfig(t, command)
			previous := CursorHooksPathOverride
			CursorHooksPathOverride = path
			t.Cleanup(func() { CursorHooksPathOverride = previous })
			conn := NewCursorConnector()
			if err := conn.VerifyClean(SetupOpts{DataDir: root}); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := removeCursorHookReferencesProfile(path, false, script); err != nil {
				t.Fatalf("remove Cursor entry: %v", err)
			}
			cfg, err := readJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			hooks := cfg["hooks"].(map[string]interface{})
			entries := hooks[cursorHookEvents[0]].([]interface{})
			if len(entries) != 1 || entries[0].(map[string]interface{})["command"] != user {
				t.Fatalf("remaining entries = %v; want the user hook", entries)
			}
			if err := conn.VerifyClean(SetupOpts{DataDir: root}); err != nil {
				t.Fatalf("VerifyClean after removal: %v", err)
			}
		})
	}
}

func TestGAP0625CursorRepairReplacesRenamedHookAndKeepsUserHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, "hooks", "cursor-hook.sh")
	path, user := gap0625CursorConfig(t, "env -i "+shellWord(filepath.Join(root, "hooks", "hookX")))
	if err := patchCursorHooks(path, script, script, false); err != nil {
		t.Fatalf("repair Cursor hooks: %v", err)
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	entries := hooks[cursorHookEvents[0]].([]interface{})
	if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != user || entries[1].(map[string]interface{})["command"] != shellWord(script) {
		t.Fatalf("repaired entries = %v; want user and current managed", entries)
	}
}

func TestGAP0625CursorEvaluatedManagedCommandIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script commands")
	}
	root := testenv.PrivateTempDir(t)
	script := filepath.Join(root, "hooks", "cursor-hook.sh")
	command := "HOOK=" + shellWord(filepath.Join(root, "hooks", "hookX")) + `; "$HOOK"`
	path, user := gap0625CursorConfig(t, command)
	if err := patchCursorHooks(path, script, script, false); err != nil {
		t.Fatalf("repair Cursor hooks: %v", err)
	}
	entries := gap0625CursorEntries(t, path)
	if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != user || entries[1].(map[string]interface{})["command"] != shellWord(script) {
		t.Fatalf("repaired entries = %v; want user and current managed", entries)
	}
	if err := removeCursorHookReferencesProfile(path, false, script); err != nil {
		t.Fatalf("remove Cursor entries: %v", err)
	}
	if entries := gap0625CursorEntries(t, path); len(entries) != 1 || entries[0].(map[string]interface{})["command"] != user {
		t.Fatalf("remaining entries = %v; want the user hook", entries)
	}
}
