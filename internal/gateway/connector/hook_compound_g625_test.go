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
)

func gap0625CompoundForms() map[string]string {
	return map[string]string{
		"sequence":          "HOOKPATH; /bin/true",
		"and after":         "HOOKPATH && /bin/true",
		"and before":        "/bin/true && HOOKPATH",
		"or after":          "HOOKPATH || /bin/true",
		"pipeline":          "HOOKPATH | /bin/cat",
		"conditional":       "if /bin/true; then HOOKPATH; fi",
		"subshell":          "(HOOKPATH)",
		"shell command":     "bash -c HOOKPATH",
		"env shell command": "env -i bash -c HOOKPATH",
		"known value":       "HOOK=HOOKPATH; \"$HOOK\" && /bin/true",
		"exported value":    "export HOOK=HOOKPATH; \"$HOOK\"",
	}
}

func TestGAP0625CompoundKnownExecutableStaysReviewable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	for name, form := range gap0625CompoundForms() {
		t.Run(name+"/Hermes", func(t *testing.T) {
			conn, opts, configPath, renamed, _ := gap0625HermesConfig(t, true)
			command := strings.ReplaceAll(form, "HOOKPATH", shellWord(renamed))
			gap0625SetHermesCommand(t, configPath, command)
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := conn.Teardown(context.Background(), opts); err == nil {
				t.Fatal("Teardown accepted a compound managed hook entry")
			}
			after, err := os.ReadFile(configPath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("reviewable command changed: err=%v", err)
			}
		})
		t.Run(name+"/Devin", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "devin-hook.sh")
			command := strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX")))
			path, _ := gap0625DevinConfig(t, command)
			if present, err := devinConfigReferencesHook(path, script); err != nil || !present {
				t.Fatalf("read-back missed managed entry: present=%v err=%v", present, err)
			}
			if err := removeDevinHookReferences(path, script); err == nil {
				t.Fatal("removal accepted a compound managed hook entry")
			}
		})
		t.Run(name+"/Cursor", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "cursor-hook.sh")
			command := strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX")))
			path, _ := gap0625CursorConfig(t, command)
			previous := CursorHooksPathOverride
			CursorHooksPathOverride = path
			t.Cleanup(func() { CursorHooksPathOverride = previous })
			if err := NewCursorConnector().VerifyClean(SetupOpts{DataDir: root}); err == nil {
				t.Fatal("VerifyClean accepted a remaining managed hook entry")
			}
			if err := removeCursorHookReferencesProfile(path, false, script); err == nil {
				t.Fatal("removal accepted a compound managed hook entry")
			}
		})
	}
}

func TestGAP0625CompoundUserCommandsRemainUnowned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	forms := map[string]string{
		"known user value":      "HOOK=USERPATH; \"$HOOK\" && /bin/true",
		"managed path argument": "/bin/printf '%s' HOOKPATH && /bin/true",
		"shell text argument":   "bash -c '/bin/printf %s HOOKPATH'",
	}
	for name, form := range forms {
		t.Run(name+"/Hermes", func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			command := strings.ReplaceAll(strings.ReplaceAll(form, "HOOKPATH", shellWord(renamed)), "USERPATH", shellWord(userHook))
			gap0625SetHermesCommand(t, configPath, command)
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("user command marked managed: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if len(commands) != 2 || commands[0] != command || commands[1] != userHook {
				t.Fatalf("user entries changed: %q", commands)
			}
		})
		t.Run(name+"/Devin", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "devin-hook.sh")
			command := strings.ReplaceAll(strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX"))), "USERPATH", shellWord(filepath.Join(t.TempDir(), "user-hook")))
			path, user := gap0625DevinConfig(t, command)
			if present, err := devinConfigReferencesHook(path, script); err != nil || present {
				t.Fatalf("user entry read-back: present=%v err=%v", present, err)
			}
			if err := removeDevinHookReferences(path, script); err != nil {
				t.Fatal(err)
			}
			commands := devinConfigCommands(t, path)
			if len(commands) != 2 || commands[0] != "PreToolUse="+command || commands[1] != "PreToolUse="+user {
				t.Fatalf("user entries changed: %q", commands)
			}
		})
		t.Run(name+"/Cursor", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			script := filepath.Join(root, "hooks", "cursor-hook.sh")
			command := strings.ReplaceAll(strings.ReplaceAll(form, "HOOKPATH", shellWord(filepath.Join(root, "hooks", "hookX"))), "USERPATH", shellWord(filepath.Join(t.TempDir(), "user-hook")))
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
			cfg, err := readJSONObject(path)
			if err != nil {
				t.Fatal(err)
			}
			entries := cfg["hooks"].(map[string]interface{})[cursorHookEvents[0]].([]interface{})
			if len(entries) != 2 || entries[0].(map[string]interface{})["command"] != command || entries[1].(map[string]interface{})["command"] != user {
				t.Fatalf("user entries changed: %v", entries)
			}
		})
	}
}
