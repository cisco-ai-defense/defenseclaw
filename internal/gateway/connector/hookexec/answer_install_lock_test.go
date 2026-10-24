// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nativeHookForm is one way an agent runs the native hook before a tool
// call: a connector, the event its registration binds, and the hook dialect
// (surface) when the connector has more than one.
type nativeHookForm struct{ connector, event, surface string }

// nativeToolHookForms lists every native hook form that gates a tool call
// (toolGateEvent), so every one gets an answer deadline and a watchdog. The
// Copilot VS Code Local dialect binds PascalCase events, which have no
// answer deadline and so no watchdog.
var nativeToolHookForms = []nativeHookForm{
	{"claudecode", "PreToolUse", ""},
	{"claudecode", "PermissionRequest", ""},
	{"codex", "PreToolUse", ""},
	{"codex", "PermissionRequest", ""},
	{"devin", "PreToolUse", ""},
	{"devin", "PermissionRequest", ""},
	{"kiro", "PreToolUse", ""},
	{"kiro", "PreToolUse", "v3"},
	{"antigravity", "PreToolUse", ""},
	{"copilot", "preToolUse", ""},
	{"copilot", "permissionRequest", ""},
	{"cursor", "preToolUse", ""},
	{"cursor", "beforeShellExecution", ""},
	{"cursor", "beforeMCPExecution", ""},
	{"cursor", "beforeReadFile", ""},
	{"cursor", "beforeTabFileRead", ""},
	{"hermes", "pre_tool_call", ""},
	{"opencode", "tool.execute.before", ""},
	{"amp", "tool.call", ""},
}

func (f nativeHookForm) String() string {
	name := f.connector + "/" + f.event
	if f.surface != "" {
		name += "/" + f.surface
	}
	return name
}

// nativeAnswerBlocks reports a native answer that stops the tool call: a
// blocking exit status, or a structured deny or block (the connectors use
// different native contracts).
func nativeAnswerBlocks(code int, stdout string) bool {
	return code != 0 || strings.Contains(stdout, "deny") || strings.Contains(stdout, "block")
}

// stubInstallLockLstat replaces the install lock read for one test: the
// first `real` reads are the file system's, every later one is look.
func stubInstallLockLstat(t *testing.T, real int, look func(string) (fs.FileInfo, error)) {
	t.Helper()
	previous := installLockLstat
	var calls atomic.Int32
	installLockLstat = func(path string) (fs.FileInfo, error) {
		if int(calls.Add(1)) <= real {
			return previous(path)
		}
		return look(path)
	}
	t.Cleanup(func() { installLockLstat = previous })
}

// stalledLook is a lock read held on a stalled disk until the test ends.
func stalledLook(t *testing.T) func(string) (fs.FileInfo, error) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	return func(path string) (fs.FileInfo, error) {
		<-release
		return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist}
	}
}

func unreadableLook(path string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrPermission}
}

// GAP-0862: the hook command arms the answer watchdog before Run, and a
// per-user hook in fail mode open prepared an open answer then. When the
// runtime resolution before Run stalled past the deadline during an install
// or upgrade, the watchdog allowed the tool call before Run could read the
// install lock. Every native tool hook form now answers closed while the
// installer holds the data directory: a lock there when the watchdog is
// armed, one taken before the deadline, and a lock whose state cannot be
// read in time (unreadable, or a read held on a stalled disk, at arming or
// at the deadline). Without a lock the call blocks too: since
// fix/r104-sa-hook-pause no answer closes every hook outside Secure Client,
// whatever the account's fail mode.
func TestEarlyAnswerWatchdogAnswersClosedDuringInstallInEveryHookForm(t *testing.T) {
	const budget = 150 * time.Millisecond
	shortAnswerBudget(t, budget)
	covered := map[string]bool{}
	for _, form := range nativeToolHookForms {
		covered[form.connector] = true
	}
	for connector := range specs {
		if !covered[connector] {
			t.Errorf("connector %s has no native tool hook form in this test", connector)
		}
	}
	cases := []struct {
		name    string
		blocks  bool
		prepare func(t *testing.T, home string) (afterArm func())
	}{
		{"no install lock (control)", true, func(*testing.T, string) func() { return nil }},
		{"lock held when armed", true, func(t *testing.T, home string) func() {
			mkdirInstallLock(t, home)
			return nil
		}},
		{"lock taken before the deadline", true, func(t *testing.T, home string) func() {
			return func() { mkdirInstallLock(t, home) }
		}},
		{"lock unreadable at the deadline", true, func(t *testing.T, _ string) func() {
			stubInstallLockLstat(t, 1, unreadableLook)
			return nil
		}},
		{"lock read stalls at the deadline", true, func(t *testing.T, _ string) func() {
			stubInstallLockLstat(t, 1, stalledLook(t))
			return nil
		}},
		{"lock read stalls when armed", true, func(t *testing.T, _ string) func() {
			stubInstallLockLstat(t, 0, stalledLook(t))
			return nil
		}},
	}
	for _, form := range nativeToolHookForms {
		for _, tc := range cases {
			t.Run(form.String()+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				afterArm := tc.prepare(t, home)
				stdout, stderr := &firstWriteRecorder{}, &firstWriteRecorder{}
				exited := make(chan int, 1)
				started := time.Now()
				watchdog := ArmAnswerWatchdog(Options{
					Connector:   form.connector,
					Event:       form.event,
					HookSurface: form.surface,
					FailMode:    "open",
					Home:        home,
					StartedAt:   started,
					Stdout:      stdout,
					Stderr:      stderr,
					Exit:        func(code int) { exited <- code },
				}, []byte(`{"tool_name":"Bash","tool_input":{"command":"echo ok"}}`))
				if watchdog == nil {
					t.Fatalf("no watchdog for %s", form)
				}
				if afterArm != nil {
					afterArm()
				}
				var code int
				select {
				case code = <-exited:
				case <-time.After(5 * time.Second):
					t.Fatal("no answer while the work before Run was held")
				}
				out, first := stdout.read()
				errOut, _ := stderr.read()
				if late := first.Sub(started); !first.IsZero() && late > budget+time.Second {
					t.Fatalf("the answer came %s after the call started, want by the %s budget", late, budget)
				}
				if got := nativeAnswerBlocks(code, out); got != tc.blocks {
					t.Fatalf("%s: exit %d stdout %q stderr %q blocks=%v, want blocks=%v",
						form, code, out, errOut, got, tc.blocks)
				}
			})
		}
	}
}

// The watchdog Run adopted carries Run's own data directory: an install
// that starts while the gateway has not answered closes the call at the
// deadline, though Run found no lock when it started (GAP-0862). Without an
// install the call blocks too: no answer closes every hook outside Secure
// Client (fix/r104-sa-hook-pause).
func TestAdoptedAnswerWatchdogAnswersClosedWhenAnInstallStartsMidCall(t *testing.T) {
	const budget = 300 * time.Millisecond
	shortAnswerBudget(t, budget)
	for _, form := range []nativeHookForm{
		{"claudecode", "PreToolUse", ""},
		{"codex", "PreToolUse", ""},
		{"cursor", "beforeShellExecution", ""},
		{"kiro", "PreToolUse", ""},
		{"devin", "PreToolUse", ""},
		{"antigravity", "PreToolUse", ""},
	} {
		for _, install := range []bool{false, true} {
			name := form.String() + "/no install"
			if install {
				name = form.String() + "/install starts mid-call"
			}
			t.Run(name, func(t *testing.T) {
				release := make(chan struct{})
				stdout := &firstWriteRecorder{}
				exited := make(chan int, 1)
				homes := make(chan string, 1)
				returned := make(chan runResult, 1)
				done := make(chan struct{})
				// Run's held request ends with the test, and the test waits
				// for Run: nothing of it outlives the test's settings.
				t.Cleanup(func() {
					close(release)
					<-done
				})
				started := time.Now()
				go func() {
					defer close(done)
					returned <- run(t, form.connector, &stubRT{status: http.StatusOK, body: `{"action":"allow"}`}, func(opts *Options) {
						opts.Event = form.event
						opts.FailMode = "open"
						opts.StartedAt = started
						opts.Stdout = stdout
						opts.Exit = func(code int) { exited <- code }
						opts.HTTPClient = &http.Client{Transport: ignoringContextRT{release: release}}
						homes <- opts.Home
					})
				}()
				home := <-homes
				if install {
					time.Sleep(budget / 3)
					mkdirInstallLock(t, home)
				}
				var code int
				select {
				case code = <-exited:
				case result := <-returned:
					t.Fatalf("Run answered before its deadline: %+v", result)
				case <-time.After(5 * time.Second):
					t.Fatal("no answer 5 s after the call started")
				}
				out, _ := stdout.read()
				if got := nativeAnswerBlocks(code, out); !got {
					t.Fatalf("exit %d stdout %q blocks=%v, want blocks=true", code, out, got)
				}
			})
		}
	}
}

// A lock that cannot be read for any reason but its absence is held: Run's
// own install check closes the call too (GAP-0862).
func TestPerUserInstallLockThatCannotBeReadIsHeld(t *testing.T) {
	home := t.TempDir()
	if perUserInstallInProgress(Options{Home: home}) {
		t.Fatal("a missing lock is held")
	}
	stubInstallLockLstat(t, 0, unreadableLook)
	if !perUserInstallInProgress(Options{Home: home}) {
		t.Fatal("an unreadable lock is not held")
	}
	if perUserInstallInProgress(Options{Home: home, ManagedEnterprise: true}) {
		t.Fatal("a managed hook read the per-user install lock")
	}
}

func mkdirInstallLock(t *testing.T, home string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(home, ".install.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
}
