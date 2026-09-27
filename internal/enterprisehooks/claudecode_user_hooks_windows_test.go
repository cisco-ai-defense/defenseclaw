// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// windowsClaudeUserHooksTarget returns the fixture's target and the target's
// folders, with the guardian's impersonation and Known Folder lookups
// replaced for the test. The returned counter reports the impersonations.
func windowsClaudeUserHooksTarget(t *testing.T, f windowsCursorUserHooksFixture) (windowsGenericManagedTarget, string, string, *int) {
	t.Helper()
	sid, err := windows.StringToSid("S-1-5-21-1000000001-1000000002-1000000003-1001")
	if err != nil {
		t.Fatal(err)
	}
	localAppData := filepath.Join(f.home, "AppData", "Local")
	programs := filepath.Join(localAppData, "Programs")
	impersonations := 0
	originalImpersonation := windowsEnterpriseTargetImpersonation
	originalFolders := windowsCursorTargetUserFolders
	windowsEnterpriseTargetImpersonation = func(target *windows.SID, home string, fn func() error) error {
		if !target.Equals(sid) || home != f.home {
			t.Errorf("impersonation of %s for %s, want the target", target, home)
		}
		impersonations++
		return runWindowsTestThreadImpersonatedAsSelf(fn)
	}
	windowsCursorTargetUserFolders = func() (string, string, error) {
		return localAppData, programs, nil
	}
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = originalImpersonation
		windowsCursorTargetUserFolders = originalFolders
	})
	return windowsGenericManagedTarget{home: f.home, dataDir: f.dataDir, sid: sid}, localAppData, programs, &impersonations
}

func windowsClaudeUserHooksJSONPath(path string) string {
	return strings.ReplaceAll(path, `\`, `\\`)
}

// The managed Cursor hook also checks %USERPROFILE%\.claude\settings.json, so
// the guardian's Cursor cleanup removes per-user Claude Code setup's
// registrations from it too: as the target, keeping the rest of the file and
// a backup, and logging the removal. It cleans that file even when it cannot
// clean the Cursor file, leaves a file it cannot edit as it was with a
// warning, and logs nothing when there is nothing to remove.
func TestCleanupWindowsCursorPerUserHookRegistrationsCleansTheClaudeCodeSettings(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	target, localAppData, programs, impersonations := windowsClaudeUserHooksTarget(t, f)
	logged := redirectWindowsCursorTestStderr(t)
	settings := filepath.Join(f.home, ".claude", "settings.json")
	backup := filepath.Join(f.home, ".claude", "settings.json.defenseclaw-backup")

	launcher := filepath.Join(localAppData, "DefenseClaw", "HookRuntime", "defenseclaw-hook.exe")
	current := `{"type":"command","command":"` + windowsClaudeUserHooksJSONPath(launcher) +
		`","args":["hook","--connector","claudecode"],"timeout":30}`
	earlier := `{"type":"command","command":"\"` +
		windowsClaudeUserHooksJSONPath(filepath.Join(programs, "DefenseClaw", "bin", "defenseclaw-gateway.exe")) +
		`\" hook --connector claudecode","timeout":30}`
	audit := `{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.cmd"}]}`
	original := "{\r\n  \"env\": {\"OTEL_LOGS_EXPORTER\": \"otlp\"},\r\n  \"hooks\": {\r\n" +
		"    \"PreToolUse\": [{\"matcher\": \"*\", \"hooks\": [" + current + "]}, " + audit + "],\r\n" +
		"    \"Stop\": [{\"hooks\": [" + earlier + "]}]\r\n  }\r\n}\r\n"
	want := "{\r\n  \"env\": {\"OTEL_LOGS_EXPORTER\": \"otlp\"},\r\n  \"hooks\": {\r\n" +
		"    \"PreToolUse\": [" + audit + "],\r\n" +
		"    \"Stop\": []\r\n  }\r\n}\r\n"
	f.write(t, settings, original)

	cleanupWindowsCursorPerUserHookRegistrations(target)
	if *impersonations != 1 {
		t.Fatalf("impersonations = %d, want one as the target", *impersonations)
	}
	if got := readWindowsCursorTestFile(t, settings); got != want {
		t.Fatalf("settings.json after cleanup:\n%q\nwant:\n%q", got, want)
	}
	if got := readWindowsCursorTestFile(t, backup); got != original {
		t.Fatalf("backup = %q, want the previous file", got)
	}
	line := logged()
	for _, fragment := range []string{"[enterprise-hooks] Claude Code: removed 2 per-user DefenseClaw hook registration(s)", settings, backup} {
		if !strings.Contains(line, fragment) {
			t.Fatalf("guardian log %q does not contain %q", line, fragment)
		}
	}

	// The Claude Code file is cleaned even when the Cursor file cannot be.
	invalidCursor := `{"version":1,"hooks":{"preToolUse":[` + f.entry(t) + `]}`
	f.write(t, f.hooks, invalidCursor)
	f.write(t, settings, original)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if got := readWindowsCursorTestFile(t, f.hooks); got != invalidCursor {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	if got := readWindowsCursorTestFile(t, settings); got != want {
		t.Fatalf("settings.json with an invalid hooks.json = %q, want it cleaned", got)
	}
	line = logged()
	if !strings.Contains(line, "[enterprise-hooks] WARN: Cursor:") || !strings.Contains(line, "[enterprise-hooks] Claude Code: removed 2") {
		t.Fatalf("guardian log = %q, want the Cursor warning and the Claude Code removal", line)
	}
	if err := os.Remove(f.hooks); err != nil {
		t.Fatal(err)
	}

	// A file it cannot edit is left as it was, and the reason is logged.
	invalid := "{\"hooks\":{\"PreToolUse\":[{\"hooks\":[" + current + "]}]} // per-user\n}"
	f.write(t, settings, invalid)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if got := readWindowsCursorTestFile(t, settings); got != invalid {
		t.Fatalf("settings.json = %q, want it unchanged", got)
	}
	if line := logged(); !strings.Contains(line, "[enterprise-hooks] WARN: Claude Code: per-user DefenseClaw hook registrations in "+settings+" were not removed") {
		t.Fatalf("guardian log = %q, want a warning naming the file", line)
	}

	// Nothing to remove: no log line.
	f.write(t, settings, want)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if line := logged(); line != "" {
		t.Fatalf("guardian log = %q, want nothing for a file without DefenseClaw registrations", line)
	}
	if got := readWindowsCursorTestFile(t, settings); got != want {
		t.Fatalf("settings.json = %q, want it unchanged", got)
	}
}

func TestRemoveWindowsClaudePerUserHookRegistrationsLeavesFilesItShouldNotRewrite(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	_, localAppData, programs, _ := windowsClaudeUserHooksTarget(t, f)
	install := connector.ClaudeCodePerUserInstall{LocalAppData: localAppData, UserProgramFiles: programs}
	claudeDir := filepath.Join(f.home, ".claude")
	settings := filepath.Join(claudeDir, "settings.json")
	backup := filepath.Join(claudeDir, windowsClaudeUserSettingsBackupName)
	launcher := filepath.Join(localAppData, "DefenseClaw", "HookRuntime", "defenseclaw-hook.exe")
	body := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + windowsClaudeUserHooksJSONPath(launcher) +
		`","args":["hook","--connector","claudecode"]}]}]}}`

	// No .claude folder, then no settings.json: nothing to do.
	if cleanup, err := removeWindowsClaudePerUserHookRegistrations(f.home, install); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no .claude folder: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, claudeDir)
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if cleanup, err := removeWindowsClaudePerUserHookRegistrations(f.home, install); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no settings.json: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, settings)
	assertWindowsCursorTestFileAbsent(t, backup)

	// Another hard link to settings.json.
	f.write(t, settings, body)
	other := filepath.Join(f.home, "other.json")
	if err := os.Link(settings, other); err != nil {
		t.Fatal(err)
	}
	if _, err := removeWindowsClaudePerUserHookRegistrations(f.home, install); err == nil {
		t.Fatal("a hard-linked settings.json was rewritten")
	}
	if got := readWindowsCursorTestFile(t, other); got != body {
		t.Fatalf("linked file = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, backup)
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}

	// A backup path that is not a regular file.
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := removeWindowsClaudePerUserHookRegistrations(f.home, install); err == nil {
		t.Fatal("settings.json was rewritten without a backup")
	}
	if got := readWindowsCursorTestFile(t, settings); got != body {
		t.Fatalf("settings.json = %q, want it unchanged", got)
	}
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}

	// A .claude folder that is a link to another folder.
	elsewhere := filepath.Join(f.home, "elsewhere")
	if err := os.Rename(claudeDir, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, claudeDir); err != nil {
		t.Logf("symbolic link not created (%v); skipping the link case", err)
		return
	}
	if _, err := removeWindowsClaudePerUserHookRegistrations(f.home, install); err == nil {
		t.Fatal("settings.json behind a linked .claude folder was rewritten")
	}
	if got := readWindowsCursorTestFile(t, filepath.Join(elsewhere, "settings.json")); got != body {
		t.Fatalf("settings.json behind the link = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, filepath.Join(elsewhere, windowsClaudeUserSettingsBackupName))
}

func createWindowsTestJunction(t *testing.T, link, target string) {
	t.Helper()
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create junction %s: %v: %s", link, err, output)
	}
}

// A hook file the cleanup does not edit is reported in the guardian log only
// when it holds a registration the cleanup would remove. A repeated key, a
// linked folder or file, or another hard link is not why the managed Cursor
// hook denies when the file holds none, so the log does not say it is. The
// file is left as it was either way.
func TestCleanupWindowsCursorPerUserHookRegistrationsReportsOnlyFilesThatHoldThem(t *testing.T) {
	for _, label := range []string{"Claude Code", "Cursor"} {
		t.Run(label, func(t *testing.T) {
			f := newWindowsCursorUserHooksFixture(t)
			target, localAppData, _, _ := windowsClaudeUserHooksTarget(t, f)
			logged := redirectWindowsCursorTestStderr(t)
			folder, name := filepath.Join(f.home, ".cursor"), "hooks.json"
			owned := `{"version":1,"hooks":{"preToolUse":[` + f.entry(t) + `]}}`
			foreign := `{"version":1,"hooks":{"preToolUse":[{"command":"node audit.js"}]}}`
			repeated := `{"version":1,"version":1,"hooks":{"preToolUse":[{"command":"node audit.js"}]}}`
			if label == "Claude Code" {
				folder, name = filepath.Join(f.home, ".claude"), "settings.json"
				launcher := filepath.Join(localAppData, "DefenseClaw", "HookRuntime", "defenseclaw-hook.exe")
				owned = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + windowsClaudeUserHooksJSONPath(launcher) +
					`","args":["hook","--connector","claudecode"]}]}]}}`
				foreign = `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"notify.cmd"}]}]}}`
				repeated = `{"model":"a","model":"b","hooks":{"Stop":[{"hooks":[{"type":"command","command":"notify.cmd"}]}]}}`
			}
			path := filepath.Join(folder, name)
			warning := "[enterprise-hooks] WARN: " + label + ": per-user DefenseClaw hook registrations in " + path + " were not removed"
			expect := func(step, body string, warned bool) {
				t.Helper()
				cleanupWindowsCursorPerUserHookRegistrations(target)
				line := logged()
				if strings.Contains(line, warning) != warned || !warned && line != "" {
					t.Fatalf("%s: guardian log = %q, want a warning: %v", step, line, warned)
				}
				if body != "" {
					if got := readWindowsCursorTestFile(t, path); got != body {
						t.Fatalf("%s: %s = %q, want it unchanged", step, name, got)
					}
				}
			}

			f.write(t, path, repeated)
			expect("a repeated key", repeated, false)

			f.write(t, path, foreign)
			other := filepath.Join(f.home, "other.json")
			if err := os.Link(path, other); err != nil {
				t.Fatal(err)
			}
			expect("another hard link, without them", foreign, false)
			f.write(t, path, owned)
			expect("another hard link, with them", owned, true)
			if err := os.Remove(other); err != nil {
				t.Fatal(err)
			}

			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			elsewhere := filepath.Join(f.home, "elsewhere")
			if err := os.Rename(folder, elsewhere); err != nil {
				t.Fatal(err)
			}
			createWindowsTestJunction(t, folder, elsewhere)
			expect("a linked folder without the file", "", false)
			f.write(t, filepath.Join(elsewhere, name), foreign)
			expect("a linked folder, without them", foreign, false)
			f.write(t, filepath.Join(elsewhere, name), owned)
			expect("a linked folder, with them", owned, true)
			assertWindowsCursorTestFileAbsent(t, filepath.Join(elsewhere, name+".defenseclaw-backup"))
			if err := os.Remove(folder); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(elsewhere, folder); err != nil {
				t.Fatal(err)
			}

			linked := filepath.Join(f.home, "linked.json")
			f.write(t, linked, foreign)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(linked, path); err != nil {
				t.Logf("symbolic link not created (%v); skipping the linked file case", err)
				return
			}
			expect("a linked file, without them", foreign, false)
			f.write(t, linked, owned)
			expect("a linked file, with them", owned, true)
			assertWindowsCursorTestFileAbsent(t, path+".defenseclaw-backup")
		})
	}
}
