// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type windowsCursorUserHooksFixture struct {
	home    string
	dataDir string
	hooks   string
	backup  string
	command string
}

func newWindowsCursorUserHooksFixture(t *testing.T) windowsCursorUserHooksFixture {
	t.Helper()
	home := filepath.Join(t.TempDir(), "profile")
	f := windowsCursorUserHooksFixture{
		home:    home,
		dataDir: filepath.Join(home, ".defenseclaw"),
		hooks:   filepath.Join(home, ".cursor", "hooks.json"),
		backup:  filepath.Join(home, ".cursor", windowsCursorUserHooksBackupName),
	}
	// The registration per-user setup writes on Windows.
	f.command = "& '" + filepath.Join(f.dataDir, "hooks", "cursor-hook.ps1") + "'"
	if err := os.MkdirAll(f.home, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f windowsCursorUserHooksFixture) entry(t *testing.T) string {
	t.Helper()
	return `{"type":"command","command":"& '` +
		strings.ReplaceAll(filepath.Join(f.dataDir, "hooks", "cursor-hook.ps1"), `\`, `\\`) +
		`'","timeout":30,"failClosed":false}`
}

func (f windowsCursorUserHooksFixture) write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readWindowsCursorTestFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func assertWindowsCursorTestFileAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists (err %v), want it absent", path, err)
	}
}

func TestRemoveWindowsCursorPerUserHookRegistrationsKeepsOtherEntriesAndABackup(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	original := "{\r\n  \"version\": 1,\r\n  \"hooks\": {\r\n" +
		"    \"preToolUse\": [\r\n      {\"command\": \"node audit.js\"},\r\n      " + f.entry(t) + "\r\n    ],\r\n" +
		"    \"stop\": [" + f.entry(t) + "]\r\n  }\r\n}\r\n"
	want := "{\r\n  \"version\": 1,\r\n  \"hooks\": {\r\n" +
		"    \"preToolUse\": [\r\n      {\"command\": \"node audit.js\"}\r\n    ],\r\n" +
		"    \"stop\": []\r\n  }\r\n}\r\n"
	f.write(t, f.hooks, original)

	cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup.removed) != 2 || cleanup.removed[0].Command != f.command || cleanup.path != f.hooks || cleanup.backup != f.backup {
		t.Fatalf("cleanup = %#v, want two removals of %q", cleanup, f.command)
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != want {
		t.Fatalf("hooks.json after cleanup:\n%q\nwant:\n%q", got, want)
	}
	if got := readWindowsCursorTestFile(t, f.backup); got != original {
		t.Fatalf("backup = %q, want the previous file", got)
	}

	// The next install or repair finds nothing to remove and leaves both
	// files as they are.
	again, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir)
	if err != nil || len(again.removed) != 0 {
		t.Fatalf("second cleanup = (%#v, %v), want a no-op", again, err)
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != want {
		t.Fatalf("hooks.json after the second cleanup = %q", got)
	}
	if got := readWindowsCursorTestFile(t, f.backup); got != original {
		t.Fatalf("backup after the second cleanup = %q, want the previous file", got)
	}
}

func TestRemoveWindowsCursorPerUserHookRegistrationsLeavesFilesWithoutThemAlone(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no .cursor folder: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, filepath.Dir(f.hooks))

	if err := os.MkdirAll(filepath.Dir(f.hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no hooks.json: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, f.hooks)
	assertWindowsCursorTestFileAbsent(t, f.backup)

	foreign := `{"version":1,"hooks":{"preToolUse":[{"command":"node audit.js"}]}}`
	f.write(t, f.hooks, foreign)
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no DefenseClaw entries: (%#v, %v), want a no-op", cleanup, err)
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != foreign {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, f.backup)
}

func TestRemoveWindowsCursorPerUserHookRegistrationsRefusesFilesItShouldNotRewrite(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	body := `{"version":1,"hooks":{"preToolUse":[` + f.entry(t) + `]}}`

	// Another hard link to hooks.json.
	f.write(t, f.hooks, body)
	other := filepath.Join(f.home, "other.json")
	if err := os.Link(f.hooks, other); err != nil {
		t.Fatal(err)
	}
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err == nil {
		t.Fatal("a hard-linked hooks.json was rewritten")
	}
	if got := readWindowsCursorTestFile(t, other); got != body {
		t.Fatalf("linked file = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, f.backup)
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}

	// A file that is not one JSON object.
	invalid := body + ` // per-user`
	f.write(t, f.hooks, invalid)
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err == nil {
		t.Fatal("an invalid hooks.json was rewritten")
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != invalid {
		t.Fatalf("invalid hooks.json = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, f.backup)

	// A backup path that is not a regular file.
	f.write(t, f.hooks, body)
	if err := os.Mkdir(f.backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err == nil {
		t.Fatal("hooks.json was rewritten without a backup")
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != body {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	if err := os.Remove(f.backup); err != nil {
		t.Fatal(err)
	}

	// A symbolic link standing in for hooks.json.
	target := filepath.Join(f.home, "target.json")
	f.write(t, target, body)
	if err := os.Remove(f.hooks); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.hooks); err != nil {
		t.Logf("symbolic link not created (%v); skipping the link case", err)
		return
	}
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.dataDir); err == nil {
		t.Fatal("a linked hooks.json was rewritten")
	}
	if got := readWindowsCursorTestFile(t, target); got != body {
		t.Fatalf("link target = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, f.backup)
}

func TestCleanupWindowsCursorPerUserHookRegistrationsRunsAsTheTargetAndLogs(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	sid, err := windows.StringToSid("S-1-5-21-1000000001-1000000002-1000000003-1001")
	if err != nil {
		t.Fatal(err)
	}
	var impersonated []string
	originalImpersonation := windowsEnterpriseTargetImpersonation
	originalLog := windowsCursorUserHookCleanupLog
	var log bytes.Buffer
	windowsEnterpriseTargetImpersonation = func(target *windows.SID, home string, fn func() error) error {
		impersonated = append(impersonated, target.String()+"|"+home)
		return fn()
	}
	windowsCursorUserHookCleanupLog = &log
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = originalImpersonation
		windowsCursorUserHookCleanupLog = originalLog
	})
	target := windowsGenericManagedTarget{home: f.home, dataDir: f.dataDir, sid: sid}

	f.write(t, f.hooks, `{"version":1,"hooks":{"preToolUse":[`+f.entry(t)+`]}}`)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if len(impersonated) != 1 || impersonated[0] != sid.String()+"|"+f.home {
		t.Fatalf("impersonation calls = %v, want one as the target", impersonated)
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != `{"version":1,"hooks":{"preToolUse":[]}}` {
		t.Fatalf("hooks.json after cleanup = %q", got)
	}
	line := log.String()
	for _, want := range []string{"[enterprise-hooks] Cursor: removed 1 per-user DefenseClaw hook registration(s)", f.hooks, f.backup} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q does not contain %q", line, want)
		}
	}

	// A file it cannot clean is left as it was, the install goes on, and
	// the reason is logged.
	log.Reset()
	invalid := `{"version":1,"hooks":{"preToolUse":[` + f.entry(t) + `]}`
	f.write(t, f.hooks, invalid)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if got := readWindowsCursorTestFile(t, f.hooks); got != invalid {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	if line := log.String(); !strings.Contains(line, "[enterprise-hooks] WARN: Cursor: per-user DefenseClaw hook registrations in "+f.hooks+" were not removed") {
		t.Fatalf("log = %q, want a warning naming the file", line)
	}

	// Nothing to remove: no log line.
	log.Reset()
	f.write(t, f.hooks, `{"version":1,"hooks":{}}`)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if log.Len() != 0 {
		t.Fatalf("log = %q, want nothing for a file without DefenseClaw entries", log.String())
	}
}
