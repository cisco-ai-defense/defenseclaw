// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"gopkg.in/yaml.v3"
)

func gap0625HermesConfig(t *testing.T, failClosed bool) (*hookOnlyConnector, SetupOpts, string, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Unix Hermes registration uses a script path")
	}
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(root, ".defenseclaw")}
	renamed := filepath.Join(opts.DataDir, "hooks", "hookX")
	userHook := filepath.Join(root, "user-hooks", "hookX")
	hooks := map[string]interface{}{
		"pre_tool_call": []interface{}{
			map[string]interface{}{"command": renamed, "fail_closed": failClosed, "matcher": ".*", "timeout": 30},
			map[string]interface{}{"command": userHook},
		},
	}
	data, err := yaml.Marshal(map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	return NewHermesConnector(), opts, configPath, renamed, userHook
}

func gap0625PreToolCommands(t *testing.T, configPath string) []string {
	t.Helper()
	cfg, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	var commands []string
	for _, raw := range hooks["pre_tool_call"].([]interface{}) {
		entry := raw.(map[string]interface{})
		commands = append(commands, entry["command"].(string))
	}
	return commands
}

func TestGAP0625HermesVerifyCleanRejectsRenamedHook(t *testing.T) {
	conn, opts, _, _, _ := gap0625HermesConfig(t, true)
	if err := conn.VerifyClean(opts); err == nil {
		t.Fatal("VerifyClean accepted a remaining hook in the account's DefenseClaw hooks directory")
	}
}

func TestGAP0625HermesTeardownRemovesRenamedHookAndKeepsUserHook(t *testing.T) {
	for _, failClosed := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "fail_closed"}[failClosed], func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, failClosed)
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			commands := gap0625PreToolCommands(t, configPath)
			if len(commands) != 1 || commands[0] != userHook {
				t.Fatalf("remaining commands = %q; want only the user hook, without %q", commands, renamed)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
		})
	}
}

func TestGAP0625HermesRepairReplacesRenamedHookAndKeepsUserHook(t *testing.T) {
	conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
		t.Fatalf("repair Hermes hooks: %v", err)
	}
	commands := gap0625PreToolCommands(t, configPath)
	want := hermesConfiguredHookCommand(conn.hookCommand(opts), "")
	if len(commands) != 2 || commands[0] != want || commands[1] != userHook {
		t.Fatalf("repaired commands = %q; want %q and %q, without %q", commands, want, userHook, renamed)
	}
}

func TestGAP0625HermesTeardownRemovesRenamedHookWithPlainArguments(t *testing.T) {
	conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(string(data), renamed, renamed+" --event pre_tool_call", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	commands := gap0625PreToolCommands(t, configPath)
	if len(commands) != 1 || commands[0] != userHook {
		t.Fatalf("remaining commands = %q; want only the user hook", commands)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after teardown: %v", err)
	}
}

func TestGAP0625HermesTeardownUsesNamedDirectoryBoundary(t *testing.T) {
	conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(userHook), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userHook, []byte("user hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ownedFile := filepath.Join(hookDir, "owned-file")
	if err := os.WriteFile(ownedFile, []byte("managed hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	insideLinkToUser := filepath.Join(hookDir, "user-link")
	if err := os.Symlink(userHook, insideLinkToUser); err != nil {
		t.Fatal(err)
	}
	outsideLinkToOwned := filepath.Join(filepath.Dir(opts.DataDir), "owned-link")
	if err := os.Symlink(ownedFile, outsideLinkToOwned); err != nil {
		t.Fatal(err)
	}
	insideMissing := filepath.Join(hookDir, "sub", "hookX")
	adjacent := filepath.Join(opts.DataDir+"-hooks", "hookX")
	commands := []string{insideMissing, outsideLinkToOwned, insideLinkToUser, adjacent, userHook}
	var entries []interface{}
	for _, command := range commands {
		entries = append(entries, map[string]interface{}{"command": command})
	}
	data, err := yaml.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"pre_tool_call": entries}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	got := gap0625PreToolCommands(t, configPath)
	// A path in the managed directory, or a link that resolves into it, is
	// DefenseClaw's; a link in the managed directory names that directory.
	if len(got) != 2 || got[0] != adjacent || got[1] != userHook {
		t.Fatalf("remaining commands = %q; want the two user locations", got)
	}
}

func TestGAP0625HermesCombinedCommandIsDefenseClaws(t *testing.T) {
	for _, suffix := range []string{" ; ", "; ", " --event pre_tool_call; "} {
		t.Run(suffix, func(t *testing.T) {
			conn, opts, configPath, renamed, userHook := gap0625HermesConfig(t, true)
			combined := renamed + suffix + userHook
			gap0625SetHermesCommand(t, configPath, combined)
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("repair Hermes hooks: %v", err)
			}
			want := hermesConfiguredHookCommand(conn.hookCommand(opts), "")
			if commands := gap0625PreToolCommands(t, configPath); len(commands) != 2 || commands[0] != want || commands[1] != userHook {
				t.Fatalf("repaired commands = %q; want %q and the user hook", commands, want)
			}
			gap0625SetHermesCommand(t, configPath, combined)
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

func TestGAP0625HermesTeardownKeepsCopyAndReportsEditedEntry(t *testing.T) {
	conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var notice bytes.Buffer
	previous := hermesSetupWarningOutput
	hermesSetupWarningOutput = &notice
	t.Cleanup(func() { hermesSetupWarningOutput = previous })
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if commands := gap0625PreToolCommands(t, configPath); len(commands) != 1 || commands[0] != userHook {
		t.Fatalf("remaining commands = %q; want the user hook", commands)
	}
	kept, err := os.ReadFile(configPath + hermesEditedHooksBackupSuffix)
	if err != nil || !bytes.Equal(kept, before) {
		t.Fatalf("copy of the previous file: err=%v equal=%v", err, bytes.Equal(kept, before))
	}
	if lines := strings.Count(notice.String(), "\n"); lines != 1 || !strings.Contains(notice.String(), "removed 1 edited DefenseClaw hook entries") {
		t.Fatalf("notice = %q; want one line", notice.String())
	}
}

func TestGAP0625HermesRecordedEntryRemovalWritesNoCopy(t *testing.T) {
	conn, opts, configPath, _, userHook := gap0625HermesConfig(t, true)
	gap0625SetHermesCommand(t, configPath, hermesConfiguredHookCommand(conn.hookCommand(opts), ""))
	var notice bytes.Buffer
	previous := hermesSetupWarningOutput
	hermesSetupWarningOutput = &notice
	t.Cleanup(func() { hermesSetupWarningOutput = previous })
	if err := removeHermesHooks(configPath, conn.hookCommand(opts), nil); err != nil {
		t.Fatalf("remove Hermes hooks: %v", err)
	}
	if commands := gap0625PreToolCommands(t, configPath); len(commands) != 1 || commands[0] != userHook {
		t.Fatalf("remaining commands = %q; want the user hook", commands)
	}
	if _, err := os.Stat(configPath + hermesEditedHooksBackupSuffix); !os.IsNotExist(err) {
		t.Fatalf("copy written for a recorded entry: %v", err)
	}
	if notice.Len() != 0 {
		t.Fatalf("notice for a recorded entry: %q", notice.String())
	}
}
