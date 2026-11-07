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

// hermesHookDirFixture writes a Hermes config.yaml whose pre_tool_call event
// holds the given commands (each as a flat entry) and points the connector at it.
func hermesHookDirFixture(t *testing.T, commands func(dataDir, root string) []string) (*hookOnlyConnector, SetupOpts, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Unix Hermes registration uses a script path")
	}
	root := testenv.PrivateTempDir(t)
	t.Setenv("HOME", root)
	configPath := filepath.Join(root, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(root, ".defenseclaw")}
	var entries []interface{}
	for _, command := range commands(opts.DataDir, root) {
		entries = append(entries, map[string]interface{}{"command": command, "fail_closed": true, "matcher": ".*", "timeout": 30})
	}
	writeHermesPreToolEntries(t, configPath, entries)
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	return NewHermesConnector(), opts, configPath, root
}

func writeHermesPreToolEntries(t *testing.T, configPath string, entries []interface{}) {
	t.Helper()
	data, err := yaml.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"pre_tool_call": entries}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hermesPreToolCommands(t *testing.T, configPath string) []string {
	t.Helper()
	cfg, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	var commands []string
	list, _ := hooks["pre_tool_call"].([]interface{})
	for _, raw := range list {
		commands = append(commands, raw.(map[string]interface{})["command"].(string))
	}
	return commands
}

func captureHermesNotices(t *testing.T) *bytes.Buffer {
	t.Helper()
	var notice bytes.Buffer
	previous := hermesSetupWarningOutput
	hermesSetupWarningOutput = &notice
	t.Cleanup(func() { hermesSetupWarningOutput = previous })
	return &notice
}

func TestHermesRenamedHookInManagedDirIsRemovedAndNotVerified(t *testing.T) {
	forms := map[string]func(dataDir, root string) string{
		"absolute":     func(dataDir, _ string) string { return filepath.Join(dataDir, "hooks", "hookX") },
		"missing file": func(dataDir, _ string) string { return filepath.Join(dataDir, "hooks", "sub", "gone.sh") },
		"arguments": func(dataDir, _ string) string {
			return filepath.Join(dataDir, "hooks", "hookX") + " --event pre_tool_call"
		},
		"quoted":        func(dataDir, _ string) string { return "\"" + filepath.Join(dataDir, "hooks", "hookX") + "\"" },
		"after wrapper": func(dataDir, _ string) string { return "bash " + filepath.Join(dataDir, "hooks", "hookX") },
		"tilde":         func(_, _ string) string { return "~/.defenseclaw/hooks/hookX" },
		"home variable": func(_, _ string) string { return "$HOME/.defenseclaw/hooks/hookX" },
		"braced home":   func(_, _ string) string { return "${HOME}/.defenseclaw/hooks/hookX" },
		"combined":      func(dataDir, _ string) string { return filepath.Join(dataDir, "hooks", "hookX") + "; true" },
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			var user string
			conn, opts, configPath, _ := hermesHookDirFixture(t, func(dataDir, root string) []string {
				user = filepath.Join(root, "user-hooks", "hookX")
				return []string{form(dataDir, root), user}
			})
			notice := captureHermesNotices(t)
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted an entry that names the DefenseClaw hooks directory")
			}
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != user {
				t.Fatalf("remaining commands = %q; want only the user hook", got)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
			kept, err := os.ReadFile(configPath + hermesEditedHooksBackupSuffix)
			if err != nil || !bytes.Equal(kept, before) {
				t.Fatalf("copy of the previous file: err=%v equal=%v", err, bytes.Equal(kept, before))
			}
			if !strings.Contains(notice.String(), "removed 1 edited DefenseClaw hook entries") {
				t.Fatalf("notice = %q; want the removal reported", notice.String())
			}
		})
	}
}

func TestHermesRepairReplacesRenamedHookInManagedDirAndKeepsUserHook(t *testing.T) {
	var user string
	conn, opts, configPath, _ := hermesHookDirFixture(t, func(dataDir, root string) []string {
		user = filepath.Join(root, "user-hooks", "hookX")
		return []string{filepath.Join(dataDir, "hooks", "hookX"), user}
	})
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
		t.Fatalf("repair Hermes hooks: %v", err)
	}
	want := hermesConfiguredHookCommand(conn.hookCommand(opts), "")
	got := hermesPreToolCommands(t, configPath)
	if len(got) != 2 || got[0] != want || got[1] != user {
		t.Fatalf("repaired commands = %q; want %q then %q", got, want, user)
	}
}

func TestHermesUserEntriesOutsideManagedDirStayAndRecordedEntryWritesNoCopy(t *testing.T) {
	var recorded, user string
	conn, opts, configPath, _ := hermesHookDirFixture(t, func(dataDir, root string) []string {
		user = filepath.Join(root, "user-hooks", "hookX")
		recorded = hermesConfiguredHookCommand(filepath.Join(dataDir, "hooks", hermesHookScriptName), "")
		return []string{recorded, user}
	})
	notice := captureHermesNotices(t)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != user {
		t.Fatalf("remaining commands = %q; want only the user hook", got)
	}
	if _, err := os.Stat(configPath + hermesEditedHooksBackupSuffix); !os.IsNotExist(err) {
		t.Fatalf("copy written for a recorded entry: %v", err)
	}
	if notice.Len() != 0 {
		t.Fatalf("notice for a recorded entry: %q", notice.String())
	}
}

// A command that does not name the managed directory is the user: an adjacent
// directory, a ".." step out of it, a relative word, a variable-held
// directory and a link elsewhere. Teardown keeps each and VerifyClean passes
// (documented limit: an entry that reaches a managed hook without naming its
// directory is not DefenseClaw owned).
func TestHermesCommandsNotNamingManagedDirAreUserEntries(t *testing.T) {
	forms := map[string]func(dataDir, root string) string{
		"adjacent directory": func(dataDir, _ string) string { return dataDir + "-hooks/hookX" },
		"longer name":        func(dataDir, _ string) string { return filepath.Join(dataDir, "hooks-extra", "hookX") },
		"dotdot out":         func(dataDir, _ string) string { return filepath.Join(dataDir, "hooks", "..", "..", "user", "hookX") },
		"inside other path":  func(dataDir, _ string) string { return filepath.Join("/srv/mirror", dataDir, "hooks", "hookX") },
		"relative word":      func(_, _ string) string { return "cd .defenseclaw/hooks && bash ./hookX" },
		"variable held": func(dataDir, _ string) string {
			return "D=" + filepath.Dir(dataDir) + "; cd \"$D/.defenseclaw/hooks\" && bash ./hookX"
		},
		"link elsewhere": func(_, root string) string { return filepath.Join(root, "bin", "linked-hook") },
		"user script":    func(_, root string) string { return filepath.Join(root, "user-hooks", "hookX") },
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			var command string
			conn, opts, configPath, _ := hermesHookDirFixture(t, func(dataDir, root string) []string {
				command = form(dataDir, root)
				return []string{command}
			})
			captureHermesNotices(t)
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean rejected a user entry: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
				t.Fatalf("remaining commands = %q; want the user entry %q kept", got, command)
			}
		})
	}
}

func TestHermesTeardownWarnsAboutKeptEntryThatMentionsDefenseClaw(t *testing.T) {
	var command string
	conn, opts, configPath, _ := hermesHookDirFixture(t, func(dataDir, root string) []string {
		command = "cd " + filepath.Join(root, "work", ".defenseclaw") + " && bash ./linked-hook"
		return []string{command}
	})
	notice := captureHermesNotices(t)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
		t.Fatalf("remaining commands = %q; want the entry kept", got)
	}
	if !strings.Contains(notice.String(), "kept hook entries") || !strings.Contains(notice.String(), "pre_tool_call") || strings.Count(notice.String(), "\n") != 1 {
		t.Fatalf("notice = %q; want one warning line naming the event", notice.String())
	}
}
