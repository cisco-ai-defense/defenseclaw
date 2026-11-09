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
// holds the given commands (each as a flat entry) and points the connector at
// it. The account home is root/home; withHome names a directory of that home
// (for example one with an apostrophe or a space) or "" for the plain one.
func hermesHookDirFixture(t *testing.T, withHome string, commands func(dataDir, home string) []string) (*hookOnlyConnector, SetupOpts, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Unix Hermes registration uses a script path")
	}
	home := testenv.PrivateTempDir(t)
	if withHome != "" {
		home = filepath.Join(home, withHome)
	}
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}
	var entries []interface{}
	for _, command := range commands(opts.DataDir, home) {
		entries = append(entries, map[string]interface{}{"command": command, "fail_closed": true, "matcher": ".*", "timeout": 30})
	}
	writeHermesPreToolEntries(t, configPath, entries)
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	return NewHermesConnector(), opts, configPath, home
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

// hermesSetUp runs Setup on the fixture config, which leaves the record of the
// entries Setup wrote that the kept-entry notice reads.
func hermesSetUp(t *testing.T, conn *hookOnlyConnector, opts SetupOpts, configPath string) {
	t.Helper()
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
		t.Fatalf("Setup: %v", err)
	}
}

// hermesRewriteHooks lets edit change the hook entries of the config the way a
// person edits the file by hand.
func hermesRewriteHooks(t *testing.T, configPath string, edit func(hooks map[string]interface{})) {
	t.Helper()
	cfg, err := readYAMLObject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	edit(hooks)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// hermesSetUpAndEditTheEntry runs Setup and then rewrites the command of the
// pre_tool_call entry Setup wrote, in place, as a person does; the entries of the
// other events go, so the file holds that one entry.
func hermesSetUpAndEditTheEntry(t *testing.T, conn *hookOnlyConnector, opts SetupOpts, configPath, command string) {
	t.Helper()
	hermesSetUp(t, conn, opts, configPath)
	hermesRewriteHooks(t, configPath, func(hooks map[string]interface{}) {
		for event, raw := range hooks {
			if event != "pre_tool_call" {
				delete(hooks, event)
				continue
			}
			for _, entry := range raw.([]interface{}) {
				entry.(map[string]interface{})["command"] = command
			}
		}
	})
}

// hermesSetupCommandIn is the command Setup writes for a data directory.
func hermesSetupCommandIn(dataDir string) string {
	return hermesConfiguredHookCommand(filepath.Join(dataDir, "hooks", hermesHookScriptName), "")
}

// An entry is DefenseClaw's when its command is a string Setup writes, byte for
// byte, whatever the account home is called: apostrophes, spaces and double
// quotes in the home all come back out of the same quoting Setup used. The
// entry is removed, VerifyClean refuses it before and accepts the file after,
// and the user hook beside it stays.
func TestHermesTeardownRemovesTheCommandsSetupWroteWhateverTheHomeIsCalled(t *testing.T) {
	for _, withHome := range []string{"", "o'brien", "operator with space", "say \"hi\""} {
		t.Run(withHome, func(t *testing.T) {
			var recorded, user string
			conn, opts, configPath, _ := hermesHookDirFixture(t, withHome, func(dataDir, home string) []string {
				user = filepath.Join(home, "user-hooks", "hookX")
				recorded = hermesConfiguredHookCommand(filepath.Join(dataDir, "hooks", hermesHookScriptName), "")
				return []string{recorded, user}
			})
			notice := captureHermesNotices(t)
			if err := conn.VerifyClean(opts); err == nil {
				t.Fatal("VerifyClean accepted an entry Setup wrote")
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
			// The user hook that stays names nothing of DefenseClaw's, so teardown
			// says nothing about it (GAP-0940).
			if notice.Len() != 0 {
				t.Fatalf("notice = %q; want none for the kept user hook", notice.String())
			}
			if matches, _ := filepath.Glob(configPath + ".*"); len(matches) != 0 {
				t.Fatalf("teardown wrote extra files next to the config: %q", matches)
			}
		})
	}
}

// The generated script kept at another path (the GAP-0906 rule) is still
// DefenseClaw's: it is the script Setup generates, not a command that merely
// resembles one.
func TestHermesTeardownRemovesTheGeneratedScriptAtAnEditedPath(t *testing.T) {
	var user string
	conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(_, home string) []string {
		user = filepath.Join(home, "user-hooks", "hookX")
		return []string{"/opt/old/.defenseclaw/hooks/" + hermesHookScriptName, user}
	})
	captureHermesNotices(t)
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != user {
		t.Fatalf("remaining commands = %q; want only the user hook", got)
	}
}

// A command that is not a string Setup writes is the user's, however it spells
// a path under the hooks directory: the REVIEW-18 cases (an apostrophe in the
// account home inside double quotes; a path with a space that steps out of the
// hooks directory to an ordinary user script) and the spellings of earlier
// reviews. Teardown keeps each entry, VerifyClean accepts the file, and the
// user's script is untouched. Teardown and repair each warn once, whatever the
// command says.
func TestHermesCommandsSetupDidNotWriteAreUserEntriesKeptAndListed(t *testing.T) {
	forms := map[string]struct {
		home    string
		command func(dataDir, home string) string
	}{
		"apostrophe in account home, double quoted": {"o'brien", func(d, _ string) string { return "bash \"" + filepath.Join(d, "hooks", "hookX") + "\"" }},
		"after shell -c": {"", func(d, _ string) string {
			return "sh -c \"" + filepath.Join(d, "hooks", "hookX") + " --event pre_tool_call\""
		}},
		"renamed hook, absolute":        {"", func(d, _ string) string { return filepath.Join(d, "hooks", "hookX") }},
		"renamed hook, tilde":           {"", func(_, _ string) string { return "~/.defenseclaw/hooks/hookX" }},
		"renamed hook, home var":        {"", func(_, _ string) string { return "$HOME/.defenseclaw/hooks/hookX" }},
		"renamed hook, arguments":       {"", func(d, _ string) string { return filepath.Join(d, "hooks", "hookX") + " --event pre_tool_call" }},
		"renamed hook, after bash":      {"", func(d, _ string) string { return "bash " + filepath.Join(d, "hooks", "hookX") }},
		"relative word":                 {"", func(_, _ string) string { return "cd .defenseclaw/hooks && bash ./hookX" }},
		"setup command, leading space":  {"", func(d, _ string) string { return " " + hermesSetupCommandIn(d) }},
		"setup command, trailing space": {"", func(d, _ string) string { return hermesSetupCommandIn(d) + " " }},
		"setup command, trailing tab":   {"", func(d, _ string) string { return hermesSetupCommandIn(d) + "\t" }},
		"edited path script, padded": {"", func(d, _ string) string {
			return " " + filepath.Join(d, "hooks", "hermes-hook.sh.off") + " --event pre_tool_call"
		}},
		"echo of the script name": {"", func(_, _ string) string { return "echo hermes-hook.sh" }},
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, home := hermesHookDirFixture(t, form.home, func(string, string) []string { return nil })
			command := form.command(opts.DataDir, home)
			hermesSetUpAndEditTheEntry(t, conn, opts, configPath, command)
			userScript := filepath.Join(home, "user-hook.sh")
			if err := os.WriteFile(userScript, []byte("#!/bin/sh\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			notice := captureHermesNotices(t)
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean rejected a user entry: %v", err)
			}
			// Repair adds the current entry beside the edited one, keeps the
			// edited one and warns once, and never refuses.
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("repair refused a user entry: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 2 || got[0] != command || got[1] != hermesConfiguredHookCommand(conn.hookCommand(opts), "") {
				t.Fatalf("repaired commands = %q; want the edited entry %q then the current one", got, command)
			}
			if !strings.Contains(notice.String(), "kept hook entries") || !strings.Contains(notice.String(), "pre_tool_call") || strings.Count(notice.String(), "\n") != 1 {
				t.Fatalf("repair notice = %q; want one line naming pre_tool_call", notice.String())
			}
			// Repair again: the entry is still kept, so the notice still comes.
			notice.Reset()
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("second repair: %v", err)
			}
			if !strings.Contains(notice.String(), "pre_tool_call") {
				t.Fatalf("second repair notice = %q; want pre_tool_call listed", notice.String())
			}
			notice.Reset()
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
				t.Fatalf("remaining commands = %q; want the user entry %q kept", got, command)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean after teardown: %v", err)
			}
			if _, err := os.Stat(userScript); err != nil {
				t.Fatalf("user script: %v", err)
			}
			if !strings.Contains(notice.String(), "kept hook entries") || !strings.Contains(notice.String(), "pre_tool_call") || strings.Count(notice.String(), "\n") != 1 {
				t.Fatalf("notice = %q; want one line naming pre_tool_call", notice.String())
			}
			if matches, _ := filepath.Glob(configPath + ".*"); len(matches) != 0 {
				t.Fatalf("teardown wrote extra files next to the config: %q", matches)
			}
		})
	}
}

// A user's own hook that names nothing of DefenseClaw's is kept as it is and
// listed in no notice: the notice tells the user to remove entries that run a
// DefenseClaw hook, which is no advice for a hook of theirs (GAP-0940). Teardown
// and repair keep it, VerifyClean accepts the file, and neither says a word.
func TestHermesAUserHookThatNamesNothingOfDefenseClawIsKeptWithoutANotice(t *testing.T) {
	forms := map[string]struct {
		home    string
		command func(dataDir, home string) string
	}{
		"adjacent directory":        {"", func(d, _ string) string { return d + "-hooks/hookX" }},
		"user script":               {"", func(_, home string) string { return filepath.Join(home, "user-hooks", "hookX") }},
		"user script in spaced dir": {"operator with space", func(_, home string) string { return "'" + filepath.Join(home, "my hooks", "hookX") + "'" }},
		"hooks-backup folder": {"", func(_, home string) string {
			return filepath.Join(home, ".defenseclaw", "hooks-backup", "my-audit.sh")
		}},
		"hooks folder of another name": {"", func(_, home string) string {
			return "bash " + filepath.Join(home, ".defenseclaw", "hooks.d", "audit")
		}},
		"script named like the generated one": {"", func(_, home string) string {
			return filepath.Join(home, "bin", "my-hermes-hook.sh")
		}},
		"generated name with a suffix": {"", func(_, home string) string {
			return filepath.Join(home, "bin", hermesHookScriptName+"-audit")
		}},
		"hooks folder left by dotdot": {"", func(_, home string) string {
			return filepath.Join(home, ".defenseclaw", "hooks") + "/../user-hook.sh"
		}},
		"space and dotdot out to a user script": {"", func(d, _ string) string {
			return "bash \"" + d + "/hooks/folder with space/../../../user-hook.sh\""
		}},
		"user script with arguments": {"", func(_, home string) string {
			return filepath.Join(home, "user-hooks", "hookX") + " --event pre_tool_call"
		}},
		"shell-escaped space in a user script": {"", func(_, home string) string {
			return "bash " + filepath.Join(home, "bin") + `/my\ ` + hermesHookScriptName
		}},
		"shell-escaped operator in a user script": {"", func(_, home string) string {
			return filepath.Join(home, "bin") + `/audit\;` + hermesHookScriptName
		}},
		"shell-escaped quote in a user script": {"", func(_, home string) string {
			return "bash " + filepath.Join(home, "bin") + `/my\"` + hermesHookScriptName
		}},
	}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			var command string
			conn, opts, configPath, home := hermesHookDirFixture(t, form.home, func(dataDir, home string) []string {
				command = form.command(dataDir, home)
				return []string{command}
			})
			notice := captureHermesNotices(t)
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean rejected a user entry: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
				t.Fatalf("remaining commands = %q; want the user entry %q kept", got, command)
			}
			if notice.Len() != 0 {
				t.Fatalf("teardown notice = %q; want none for a user's own hook (home %s)", notice.String(), home)
			}
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("repair refused a user entry: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 2 || got[0] != command {
				t.Fatalf("repaired commands = %q; want the user entry %q first", got, command)
			}
			if notice.Len() != 0 {
				t.Fatalf("repair notice = %q; want none for a user's own hook", notice.String())
			}
		})
	}
}

// Repair replaces the entries Setup wrote with the current one and leaves every
// other entry, including one that names a file in the hooks directory.
func TestHermesRepairReplacesTheCommandsSetupWroteAndKeepsOtherEntries(t *testing.T) {
	var user, renamed string
	conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(dataDir, home string) []string {
		user = filepath.Join(home, "user-hooks", "hookX")
		renamed = filepath.Join(dataDir, "hooks", "hookX")
		return []string{"/opt/old/.defenseclaw/hooks/" + hermesHookScriptName, renamed, user}
	})
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
		t.Fatalf("repair Hermes hooks: %v", err)
	}
	want := hermesConfiguredHookCommand(conn.hookCommand(opts), "")
	got := hermesPreToolCommands(t, configPath)
	if len(got) != 3 || got[0] != want || got[1] != renamed || got[2] != user {
		t.Fatalf("repaired commands = %q; want %q, %q, %q", got, want, renamed, user)
	}
}

// VerifyClean reads hook registrations, not the file text: a comment that only
// names the generated script is not a registration, and a user hook beside it
// stays untouched.
func TestHermesVerifyCleanIgnoresACommentThatNamesTheScript(t *testing.T) {
	var user string
	conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(_, home string) []string {
		user = filepath.Join(home, "user-hooks", "hookX")
		return []string{user}
	})
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte("# the old hermes-hook.sh was removed by hand\n"), data...)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean rejected a comment: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != user {
		t.Fatalf("remaining commands = %q; want the user hook", got)
	}
	// The same file with an entry Setup wrote still fails verification.
	conn, opts, _, _ = hermesHookDirFixture(t, "", func(dataDir, _ string) []string {
		return []string{hermesSetupCommandIn(dataDir)}
	})
	if err := conn.VerifyClean(opts); err == nil {
		t.Fatal("VerifyClean accepted a file with an entry Setup wrote")
	}
}

// The kept-entry notice does not depend on how the data directory is spelled: an
// account whose data directory is not called defenseclaw still gets the notice
// for a hand-edited or padded entry, from teardown and from repair.
func TestHermesKeptEntryNoticeIgnoresTheDataDirectoryName(t *testing.T) {
	for name, edit := range map[string]func(dataDir string) string{
		"edited script name": func(d string) string { return "bash " + filepath.Join(d, "hooks", "hookX") },
		"padded command":     func(d string) string { return " " + hermesSetupCommandIn(d) },
	} {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, home := hermesHookDirFixture(t, "", func(string, string) []string { return nil })
			opts.DataDir = filepath.Join(home, "state")
			command := edit(opts.DataDir)
			hermesSetUpAndEditTheEntry(t, conn, opts, configPath, command)
			notice := captureHermesNotices(t)
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("repair: %v", err)
			}
			if !strings.Contains(notice.String(), "pre_tool_call") {
				t.Fatalf("repair notice = %q; want pre_tool_call listed", notice.String())
			}
			notice.Reset()
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
				t.Fatalf("remaining commands = %q; want the user entry %q kept", got, command)
			}
			if !strings.Contains(notice.String(), "pre_tool_call") {
				t.Fatalf("teardown notice = %q; want pre_tool_call listed", notice.String())
			}
		})
	}
}

// The notice is printed for an entry Setup wrote and a person edited, found by
// the record Setup made, and never for the words of a command: a hook of the
// user that only names a DefenseClaw hook, as data or in a comment, gets none
// beside the entry Setup wrote (repair, teardown), and an edited entry gets
// none either when no record of Setup exists.
func TestHermesTheKeptEntryNoticeIsDecidedByTheSetupRecordNotByTheWordsOfACommand(t *testing.T) {
	mentions := map[string]string{
		"printf data":         `printf '%s' 'hermes-hook.sh' >/dev/null`,
		"comment":             `true # hermes-hook.sh`,
		"echo":                `echo hermes-hook.sh`,
		"folder in a comment": `true # ~/.defenseclaw/hooks/hermes-hook.sh`,
		"folder as data":      `printf '%s' "$HOME/.defenseclaw/hooks/hermes-hook.sh"`,
		"launcher flag":       `echo hook --connector hermes`,
		"script of the user":  `bash /opt/tools/audit.sh`,
	}
	for name, command := range mentions {
		t.Run(name, func(t *testing.T) {
			conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(string, string) []string { return nil })
			hermesSetUp(t, conn, opts, configPath)
			hermesRewriteHooks(t, configPath, func(hooks map[string]interface{}) {
				for _, event := range []string{"pre_tool_call", "post_tool_call"} {
					hooks[event] = append([]interface{}{
						map[string]interface{}{"command": command, "matcher": ".*", "timeout": 30},
					}, hooks[event].([]interface{})...)
				}
			})
			notice := captureHermesNotices(t)
			if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
				t.Fatalf("repair refused a user entry: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := hermesPreToolCommands(t, configPath); len(got) != 1 || got[0] != command {
				t.Fatalf("remaining commands = %q; want only the user entry %q", got, command)
			}
			if notice.Len() != 0 {
				t.Fatalf("notice = %q; want none for a user hook that names a DefenseClaw hook as data", notice.String())
			}
		})
	}

	t.Run("an edited entry without a record of Setup", func(t *testing.T) {
		conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(string, string) []string { return nil })
		hermesSetUp(t, conn, opts, configPath)
		if err := os.Remove(filepath.Join(opts.DataDir, hermesHomeSetUpFileName)); err != nil {
			t.Fatal(err)
		}
		hermesRewriteHooks(t, configPath, func(hooks map[string]interface{}) {
			for _, entry := range hooks["pre_tool_call"].([]interface{}) {
				entry.(map[string]interface{})["command"] = " " + hermesSetupCommandIn(opts.DataDir)
			}
		})
		notice := captureHermesNotices(t)
		if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
			t.Fatalf("repair: %v", err)
		}
		if err := conn.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		if notice.Len() != 0 {
			t.Fatalf("notice = %q; want none without the record", notice.String())
		}
	})

	t.Run("a hook of the user added after Setup is not an edited entry", func(t *testing.T) {
		conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(string, string) []string { return nil })
		hermesSetUp(t, conn, opts, configPath)
		hermesRewriteHooks(t, configPath, func(hooks map[string]interface{}) {
			hooks["pre_tool_call"] = append(hooks["pre_tool_call"].([]interface{}),
				map[string]interface{}{"command": "/opt/tools/audit", "matcher": ".*", "timeout": 30})
		})
		notice := captureHermesNotices(t)
		if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
			t.Fatalf("repair: %v", err)
		}
		if notice.Len() != 0 {
			t.Fatalf("notice = %q; want none while the entry Setup wrote is intact", notice.String())
		}
	})
}

// Go writes the record that Python reads (hermes_recorded_kept_commands): an
// entry Setup kept is named by the sha256 of its command, under its event.
func TestHermesSetupRecordNamesAKeptEntryByTheHashOfItsCommand(t *testing.T) {
	conn, opts, configPath, _ := hermesHookDirFixture(t, "", func(string, string) []string { return nil })
	hermesSetUpAndEditTheEntry(t, conn, opts, configPath, "/opt/tools/audit --old")
	captureHermesNotices(t)
	if err := patchHermesHooks(configPath, conn.hookCommand(opts), ""); err != nil {
		t.Fatalf("repair: %v", err)
	}
	record := readHermesSetUpRecord(opts.DataDir)
	const hash = "043eaf7fcdff435feeb38ee9f79e6c7e49f6125e8663f452f1d4a264ea1c7b91"
	if got := record.Hooks["pre_tool_call"].Kept; len(got) != 1 || got[0] != hash {
		t.Fatalf("kept = %q; want [%s]", got, hash)
	}
	if got := record.Hooks["post_tool_call"].Kept; len(got) != 0 {
		t.Fatalf("post_tool_call kept = %q; want none", got)
	}
}
