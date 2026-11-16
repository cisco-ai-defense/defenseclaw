// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const installWindowText = "being installed or upgraded for this account"

// GAP-2440: during a per-user upgrade, a call whose gateway took it and did
// not answer was blocked with "the gateway did not answer in time" and a
// call that found its token set aside with "missing gateway token": the
// watchdog renders its prepared answer with no home, so the install lock was
// no longer seen, and the missing-token answer never looked. Both are
// closed, as before; the answer the agent shows now names the install.
func TestPerUserInstallWindowNoAnswerNamesTheInstall(t *testing.T) {
	const budget = 200 * time.Millisecond
	shortAnswerBudget(t, budget)
	for _, form := range []nativeHookForm{
		{"claudecode", "PreToolUse", ""},
		{"codex", "PreToolUse", ""},
		{"cursor", "beforeShellExecution", ""},
		{"opencode", "tool.execute.before", ""},
	} {
		t.Run(form.String()+"/armed during the install", func(t *testing.T) {
			home := t.TempDir()
			mkdirInstallLock(t, home)
			stdout, stderr := &firstWriteRecorder{}, &firstWriteRecorder{}
			exited := make(chan int, 1)
			watchdog := ArmAnswerWatchdog(Options{
				Connector: form.connector, Event: form.event, HookSurface: form.surface,
				FailMode: "open", Home: home, StartedAt: time.Now(),
				Stdout: stdout, Stderr: stderr, Exit: func(code int) { exited <- code },
			}, []byte(`{"tool_name":"Bash","tool_input":{"command":"echo ok"}}`))
			if watchdog == nil {
				t.Fatal("no watchdog")
			}
			var code int
			select {
			case code = <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("no answer")
			}
			out, _ := stdout.read()
			errOut, _ := stderr.read()
			assertNamesTheInstall(t, code, out, errOut)
		})
		t.Run(form.String()+"/Run took the call during the install", func(t *testing.T) {
			release := make(chan struct{})
			stdout := &firstWriteRecorder{}
			exited := make(chan int, 1)
			done := make(chan struct{})
			t.Cleanup(func() {
				close(release)
				<-done
			})
			started := time.Now()
			go func() {
				defer close(done)
				run(t, form.connector, &stubRT{status: http.StatusOK, body: `{"action":"allow"}`}, func(opts *Options) {
					mkdirInstallLock(t, opts.Home)
					opts.Event = form.event
					opts.FailMode = "open"
					opts.StartedAt = started
					opts.Stdout = stdout
					opts.Exit = func(code int) { exited <- code }
					opts.HTTPClient = &http.Client{Transport: ignoringContextRT{release: release}}
				})
			}()
			var code int
			select {
			case code = <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("no answer")
			}
			out, _ := stdout.read()
			assertNamesTheInstall(t, code, out, "")
		})
	}
}

func TestPerUserInstallWindowMissingTokenNamesTheInstall(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, install := range []bool{true, false} {
			name := connector + "/install window"
			if !install {
				name = connector + "/no install (control)"
			}
			t.Run(name, func(t *testing.T) {
				result := run(t, connector, ok(`{"action":"allow"}`), func(opts *Options) {
					if err := os.Remove(filepath.Join(opts.HookDir, ".token")); err != nil {
						t.Fatal(err)
					}
					opts.FailMode = "closed"
					if install {
						mkdirInstallLock(t, opts.Home)
					}
				})
				if result.rt.requests != 0 {
					t.Fatalf("a call with no token reached the gateway %d times", result.rt.requests)
				}
				if !install {
					if !strings.Contains(result.stderr, "missing gateway token") || strings.Contains(result.stdout+result.stderr, installWindowText) {
						t.Fatalf("control: stdout %q stderr %q", result.stdout, result.stderr)
					}
					return
				}
				assertNamesTheInstall(t, result.code, result.stdout, result.stderr)
			})
		}
	}
}

func assertNamesTheInstall(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if !nativeAnswerBlocks(code, stdout) {
		t.Fatalf("not blocked: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	shown := stdout
	if strings.TrimSpace(shown) == "" {
		shown = stderr
	}
	if !strings.Contains(shown, installWindowText) {
		t.Fatalf("the answer does not name the install: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	for _, other := range []string{"did not answer in time", "missing gateway token", "hook failed closed"} {
		if strings.Contains(shown, other) {
			t.Fatalf("the answer says %q in the install window: stdout %q stderr %q", other, stdout, stderr)
		}
	}
}
