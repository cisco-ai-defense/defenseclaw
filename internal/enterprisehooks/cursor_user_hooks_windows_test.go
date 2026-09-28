// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

func (f windowsCursorUserHooksFixture) install() connector.CursorPerUserInstall {
	return connector.CursorPerUserInstall{DataDir: f.dataDir}
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

	cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install())
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
	again, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install())
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
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no .cursor folder: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, filepath.Dir(f.hooks))

	if err := os.MkdirAll(filepath.Dir(f.hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err != nil || len(cleanup.removed) != 0 {
		t.Fatalf("no hooks.json: (%#v, %v), want a no-op", cleanup, err)
	}
	assertWindowsCursorTestFileAbsent(t, f.hooks)
	assertWindowsCursorTestFileAbsent(t, f.backup)

	foreign := `{"version":1,"hooks":{"preToolUse":[{"command":"node audit.js"}]}}`
	f.write(t, f.hooks, foreign)
	if cleanup, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err != nil || len(cleanup.removed) != 0 {
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
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err == nil {
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
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err == nil {
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
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err == nil {
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
	if _, err := removeWindowsCursorPerUserHookRegistrations(f.home, f.install()); err == nil {
		t.Fatal("a linked hooks.json was rewritten")
	}
	if got := readWindowsCursorTestFile(t, target); got != body {
		t.Fatalf("link target = %q, want it unchanged", got)
	}
	assertWindowsCursorTestFileAbsent(t, f.backup)
}

// redirectWindowsCursorTestStderr points os.Stderr at a new file for the rest
// of the test, the way the guardian service points it at hook-guardian.log
// after this package is loaded. The returned function reads what was written
// since its previous call.
func redirectWindowsCursorTestStderr(t *testing.T) func() string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook-guardian.log")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = file
	t.Cleanup(func() {
		os.Stderr = original
		_ = file.Close()
	})
	seen := 0
	return func() string {
		t.Helper()
		all := readWindowsCursorTestFile(t, path)
		fresh := all[seen:]
		seen = len(all)
		return fresh
	}
}

func TestCleanupWindowsCursorPerUserHookRegistrationsRunsAsTheTargetAndLogs(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	sid, err := windows.StringToSid("S-1-5-21-1000000001-1000000002-1000000003-1001")
	if err != nil {
		t.Fatal(err)
	}
	var impersonated []string
	originalImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(target *windows.SID, home string, fn func() error) error {
		impersonated = append(impersonated, target.String()+"|"+home)
		return runWindowsTestThreadImpersonatedAsSelf(fn)
	}
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = originalImpersonation
	})
	// The lines must reach the file os.Stderr names when they are written,
	// not the stderr the process started with.
	logged := redirectWindowsCursorTestStderr(t)
	target := windowsGenericManagedTarget{home: f.home, dataDir: f.dataDir, sid: sid}

	f.write(t, f.hooks, `{"version":1,"hooks":{"preToolUse":[`+f.entry(t)+`]}}`)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if len(impersonated) != 1 || impersonated[0] != sid.String()+"|"+f.home {
		t.Fatalf("impersonation calls = %v, want one as the target", impersonated)
	}
	if got := readWindowsCursorTestFile(t, f.hooks); got != `{"version":1,"hooks":{"preToolUse":[]}}` {
		t.Fatalf("hooks.json after cleanup = %q", got)
	}
	line := logged()
	for _, want := range []string{"[enterprise-hooks] Cursor: removed 1 per-user DefenseClaw hook registration(s)", f.hooks, f.backup} {
		if !strings.Contains(line, want) {
			t.Fatalf("guardian log %q does not contain %q", line, want)
		}
	}

	// A file it cannot clean is left as it was, the install goes on, and
	// the reason is logged.
	invalid := `{"version":1,"hooks":{"preToolUse":[` + f.entry(t) + `]}`
	f.write(t, f.hooks, invalid)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if got := readWindowsCursorTestFile(t, f.hooks); got != invalid {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	if line := logged(); !strings.Contains(line, "[enterprise-hooks] WARN: Cursor: per-user DefenseClaw hook registrations in "+f.hooks+" were not removed") {
		t.Fatalf("guardian log = %q, want a warning naming the file", line)
	}

	// Nothing to remove: no log line.
	f.write(t, f.hooks, `{"version":1,"hooks":{}}`)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if line := logged(); line != "" {
		t.Fatalf("guardian log = %q, want nothing for a file without DefenseClaw entries", line)
	}
}

// The guardian's own Known Folder lookups name LocalSystem's folders, so the
// cleanup resolves the target's folders while it impersonates the target and
// removes the older direct native commands found there.
func TestCleanupWindowsCursorPerUserHookRegistrationsUsesTheTargetsFolders(t *testing.T) {
	f := newWindowsCursorUserHooksFixture(t)
	sid, err := windows.StringToSid("S-1-5-21-1000000001-1000000002-1000000003-1001")
	if err != nil {
		t.Fatal(err)
	}
	localAppData := filepath.Join(f.home, "AppData", "Local")
	programs := filepath.Join(localAppData, "Programs")
	impersonating := false
	resolvedWhileImpersonating := 0
	resolveErr := error(nil)
	originalImpersonation := windowsEnterpriseTargetImpersonation
	originalFolders := windowsCursorTargetUserFolders
	windowsEnterpriseTargetImpersonation = func(_ *windows.SID, _ string, fn func() error) error {
		impersonating = true
		defer func() { impersonating = false }()
		return fn()
	}
	windowsCursorTargetUserFolders = func() (string, string, error) {
		if impersonating {
			resolvedWhileImpersonating++
		}
		return localAppData, programs, resolveErr
	}
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation = originalImpersonation
		windowsCursorTargetUserFolders = originalFolders
	})
	logged := redirectWindowsCursorTestStderr(t)
	target := windowsGenericManagedTarget{home: f.home, dataDir: f.dataDir, sid: sid}

	native := func(binary string) string {
		return `{"command":"\"` + strings.ReplaceAll(binary, `\`, `\\`) + `\" hook --connector cursor"}`
	}
	foreign := native(filepath.Join(programs, "Other", "bin", "defenseclaw-hook.exe"))
	body := `{"version":1,"hooks":{"preToolUse":[` +
		native(filepath.Join(localAppData, "DefenseClaw", "HookRuntime", "defenseclaw-hook.exe")) + `,` +
		native(filepath.Join(programs, "DefenseClaw", "bin", "defenseclaw-hook.exe")) + `,` +
		native(filepath.Join(programs, "DefenseClaw", "bin", "defenseclaw-gateway.exe")) + `,` +
		foreign + `]}}`

	// A failed lookup leaves the file as it was and is logged.
	resolveErr = errors.New("test Known Folder failure")
	f.write(t, f.hooks, body)
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if got := readWindowsCursorTestFile(t, f.hooks); got != body {
		t.Fatalf("hooks.json = %q, want it unchanged", got)
	}
	if line := logged(); !strings.Contains(line, "were not removed: test Known Folder failure") {
		t.Fatalf("guardian log = %q, want the lookup failure", line)
	}

	resolveErr = nil
	cleanupWindowsCursorPerUserHookRegistrations(target)
	if resolvedWhileImpersonating != 2 {
		t.Fatalf("folders resolved %d times while impersonating, want 2", resolvedWhileImpersonating)
	}
	if got, want := readWindowsCursorTestFile(t, f.hooks), `{"version":1,"hooks":{"preToolUse":[`+foreign+`]}}`; got != want {
		t.Fatalf("hooks.json after cleanup = %q, want %q", got, want)
	}
	if line := logged(); !strings.Contains(line, "removed 3 per-user DefenseClaw hook registration(s)") {
		t.Fatalf("guardian log = %q, want three removals", line)
	}
}

// The lookup reads the impersonation token: with one it names that user's
// folders, and without one it fails instead of naming the process user's.
func TestResolveWindowsImpersonatedUserFoldersReadsTheThreadToken(t *testing.T) {
	wantLocal, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	wantPrograms, err := winfolders.UserProgramFiles()
	if err != nil {
		t.Fatal(err)
	}
	var local, programs string
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		local, programs, err = resolveWindowsImpersonatedUserFolders()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(local, filepath.Clean(wantLocal)) || !strings.EqualFold(programs, wantPrograms) {
		t.Fatalf("impersonated folders = (%q, %q), want (%q, %q)", local, programs, wantLocal, wantPrograms)
	}

	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, _, err := resolveWindowsImpersonatedUserFolders()
		result <- err
	}()
	if err := <-result; !errors.Is(err, windows.ERROR_NO_TOKEN) {
		t.Fatalf("lookup without an impersonation token: %v, want ERROR_NO_TOKEN", err)
	}
}
