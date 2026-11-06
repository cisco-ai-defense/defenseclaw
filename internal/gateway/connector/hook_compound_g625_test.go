// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// gap0625NamedDirForms are hook commands that name the managed hook
// directory in another shell form. Each one is an edited DefenseClaw entry.
func gap0625NamedDirForms() map[string]string {
	return map[string]string{
		"sequence":            "HOOKPATH; /bin/true",
		"and before":          "/bin/true && HOOKPATH",
		"pipeline":            "HOOKPATH | /bin/cat",
		"conditional":         "if /bin/true; then HOOKPATH; fi",
		"subshell":            "(HOOKPATH)",
		"shell command":       "bash -c HOOKPATH",
		"shell option group":  "bash -Ec HOOKPATH",
		"shell long option":   "bash --noediting -c HOOKPATH",
		"exec shell":          "exec bash -c HOOKPATH",
		"known value":         "HOOK=HOOKPATH; \"$HOOK\" && /bin/true",
		"call-local value":    "f() { \"$HOOK\"; }; HOOK=HOOKPATH f",
		"eval value":          "HOOK=HOOKPATH; eval \"$HOOK\"",
		"dot value":           "HOOK=HOOKPATH; . \"$HOOK\"",
		"managed argument":    "/bin/printf '%s' HOOKPATH && /bin/true",
		"shell text argument": "bash -c '/bin/printf %s HOOKPATH'",
	}
}

func TestGAP0625CommandNamingHookDirIsRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	for name, form := range gap0625NamedDirForms() {
		t.Run(name+"/Hermes", func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			gap0625SetHermesCommand(t, configPath, strings.ReplaceAll(form, "HOOKPATH", shellWord(renamed)))
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if commands := gap0625PreToolCommands(t, configPath); len(commands) != 1 || commands[0] != userHook {
				t.Fatalf("remaining commands = %q; want only the user hook", commands)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after Teardown: %v", err)
			}
		})
		t.Run(name+"/Devin", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "devin-hook.sh")
			path, user := gap0625DevinConfig(t, strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX"))))
			if present, err := devinConfigReferencesHook(path, script); err != nil || !present {
				t.Fatalf("read-back missed managed entry: present=%v err=%v", present, err)
			}
			if err := removeDevinHookReferences(path, script); err != nil {
				t.Fatalf("remove Devin entry: %v", err)
			}
			if commands := devinConfigCommands(t, path); len(commands) != 1 || commands[0] != "PreToolUse="+user {
				t.Fatalf("remaining commands = %q; want the user hook", commands)
			}
		})
		t.Run(name+"/Cursor", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "cursor-hook.sh")
			path, user := gap0625CursorConfig(t, strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX"))))
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
			entries := gap0625CursorEntries(t, path)
			if len(entries) != 1 || entries[0].(map[string]interface{})["command"] != user {
				t.Fatalf("remaining entries = %v; want the user hook", entries)
			}
			if err := conn.VerifyClean(SetupOpts{DataDir: root}); err != nil {
				t.Fatalf("VerifyClean after removal: %v", err)
			}
		})
	}
}

func gap0625CursorEntries(t *testing.T, path string) []interface{} {
	t.Helper()
	cfg, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := cfg["hooks"].(map[string]interface{})[cursorHookEvents[0]].([]interface{})
	return entries
}

func TestGAP0625UserCommandsOutsideHookDirRemainUnowned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	forms := map[string]string{
		"known user value": "HOOK=USERPATH; \"$HOOK\" && /bin/true",
		"user arguments":   "USERPATH --event pre_tool_call",
		"adjacent folder":  "ADJACENT",
	}
	for name, form := range forms {
		t.Run(name+"/Hermes", func(t *testing.T) {
			conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
			command := strings.NewReplacer("USERPATH", shellWord(userHook), "ADJACENT", shellWord(filepath.Join(opts.DataDir, "hooks-old", "hookX"))).Replace(form)
			gap0625SetHermesCommand(t, configPath, command)
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("user command marked managed: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if commands := gap0625PreToolCommands(t, configPath); len(commands) != 2 || commands[0] != command || commands[1] != userHook {
				t.Fatalf("user entries changed: %q", commands)
			}
		})
		t.Run(name+"/Devin", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "devin-hook.sh")
			command := strings.NewReplacer("USERPATH", shellWord(filepath.Join(t.TempDir(), "user-hook")), "ADJACENT", shellWord(filepath.Join(root, "hooks-old", "hookX"))).Replace(form)
			path, user := gap0625DevinConfig(t, command)
			if present, err := devinConfigReferencesHook(path, script); err != nil || present {
				t.Fatalf("user entry read-back: present=%v err=%v", present, err)
			}
			if err := removeDevinHookReferences(path, script); err != nil {
				t.Fatal(err)
			}
			if commands := devinConfigCommands(t, path); len(commands) != 2 || commands[0] != "PreToolUse="+command || commands[1] != "PreToolUse="+user {
				t.Fatalf("user entries changed: %q", commands)
			}
		})
		t.Run(name+"/Cursor", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "cursor-hook.sh")
			command := strings.NewReplacer("USERPATH", shellWord(filepath.Join(t.TempDir(), "user-hook")), "ADJACENT", shellWord(filepath.Join(root, "hooks-old", "hookX"))).Replace(form)
			path, user := gap0625CursorConfig(t, command)
			previous := CursorHooksPathOverride
			CursorHooksPathOverride = path
			t.Cleanup(func() { CursorHooksPathOverride = previous })
			if err := NewCursorConnector().VerifyClean(SetupOpts{DataDir: root}); err != nil {
				t.Fatalf("user command marked managed: %v", err)
			}
			if err := removeCursorHookReferencesProfile(path, false, script); err != nil {
				t.Fatal(err)
			}
			entries := gap0625CursorEntries(t, path)
			if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != command || entries[1].(map[string]interface{})["command"] != user {
				t.Fatalf("user entries changed: %v", entries)
			}
		})
	}
}
