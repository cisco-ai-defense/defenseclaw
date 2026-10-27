// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0094, GAP-0102, GAP-0107: a per-user hook whose own gateway restarts
// (defenseclaw-gateway restart, an upgrade) is answered by the gateway that
// comes up, from its policy, instead of failing or waiting out the restart.
func TestPerUserHookIsAnsweredByTheGatewayThatRestarts(t *testing.T) {
	fastRestartRetries(t)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"connection refused", syscall.ECONNREFUSED},
		{"connection dropped unanswered", io.EOF},
		{"connection reset", syscall.ECONNRESET},
	} {
		t.Run(test.name, func(t *testing.T) {
			closed := func(opts *Options) { opts.FailMode = "closed" }
			allowed := run(t, "codex", failingThen(3, test.err, `{"action":"allow"}`), closed)
			if allowed.code != 0 || allowed.rt.requests != 4 || strings.Contains(allowed.stdout, "deny") {
				t.Fatalf("allow after restart: code=%d requests=%d stdout=%q stderr=%q",
					allowed.code, allowed.rt.requests, allowed.stdout, allowed.stderr)
			}
			denied := run(t, "codex", failingThen(2, test.err, `{"action":"block","reason":"marker rule"}`), closed)
			if denied.rt.requests != 3 || !strings.Contains(denied.stdout+denied.stderr, "marker rule") {
				t.Fatalf("policy deny after restart: code=%d requests=%d stdout=%q stderr=%q",
					denied.code, denied.rt.requests, denied.stdout, denied.stderr)
			}
		})
	}
}

// A restart or outage longer than the budget blocks the call within it, with
// the restart named, and never allows it (fail mode closed, the default of
// an action-mode connector).
func TestPerUserHookBlocksWhenTheRestartOutlastsTheBudget(t *testing.T) {
	fastRestartRetries(t)
	for _, connector := range []string{"codex", "claudecode"} {
		t.Run(connector, func(t *testing.T) {
			started := time.Now()
			result := run(t, connector, &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
				opts.FailMode = "closed"
				opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
			})
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("the hook waited %s past its restart budget", elapsed)
			}
			if result.rt.requests < 2 {
				t.Fatalf("requests = %d, want the call sent again within the budget", result.rt.requests)
			}
			blocked := result.code == 2 || strings.Contains(result.stdout, `"permissionDecision":"deny"`)
			if !blocked {
				t.Fatalf("an unanswered per-user call was not blocked: code=%d stdout=%q", result.code, result.stdout)
			}
			if !strings.Contains(result.stdout+result.stderr, "restarting or not running") {
				t.Fatalf("stdout=%q stderr=%q, want the restart named", result.stdout, result.stderr)
			}
		})
	}
}

// A connector the account runs fail open (observe mode) keeps its choice
// after the budget, and is told that the gateway is restarting.
func TestPerUserFailOpenHookNamesTheRestart(t *testing.T) {
	fastRestartRetries(t)
	// The default tier opens a per-user outage (its config, at call time).
	result := run(t, "claudecode", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
		opts.OutageFailModeNow = func() string { return "open" }
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
	})
	var notice map[string]string
	if result.code != 0 || json.Unmarshal([]byte(result.stdout), &notice) != nil ||
		!strings.Contains(notice["systemMessage"], "restarting or not running") {
		t.Fatalf("code=%d stdout=%q, want the restart notice", result.code, result.stdout)
	}

	// GAP-0649: an install or upgrade (.install.lock) is not an outage, so
	// the open hook blocks the call and names the install.
	installing := run(t, "claudecode", &stubRT{err: syscall.ECONNREFUSED}, func(opts *Options) {
		opts.OutageFailModeNow = func() string { return "open" }
		opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
		if err := os.Mkdir(filepath.Join(opts.Home, ".install.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(installing.stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(installing.stdout, "being installed or upgraded") ||
		!strings.Contains(installing.stdout, "run the installer again") ||
		strings.Contains(installing.stdout, "defenseclaw-gateway start") {
		t.Fatalf("code=%d stdout=%q, want the call blocked with the install named", installing.code, installing.stdout)
	}
}

// Copilot consumes a native denial, not an exit status. While an installer
// holds the account lock, both actionable events must deny every failure even
// if the per-user hook was previously configured open and its gateway cannot
// answer. A call the gateway answers keeps its answer
// (TestPerUserInstallWindowKeepsTheGatewaysAnswer).
func TestPerUserCopilotDeniesDuringInstall(t *testing.T) {
	fastRestartRetries(t)
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		for _, failure := range []struct {
			name string
			rt   func() *stubRT
		}{
			{"gateway refused", func() *stubRT { return &stubRT{err: syscall.ECONNREFUSED} }},
			{"gateway error", func() *stubRT { return &stubRT{status: 503} }},
			{"invalid verdict", func() *stubRT { return ok(`{"action":"unknown"}`) }},
		} {
			t.Run(event+"/"+failure.name, func(t *testing.T) {
				result := run(t, "copilot", failure.rt(), func(opts *Options) {
					opts.Event = event
					opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
					if err := os.Mkdir(filepath.Join(opts.Home, installLockName), 0o700); err != nil {
						t.Fatal(err)
					}
				})
				want := `"permissionDecision":"deny"`
				if event == "permissionRequest" {
					want = `"behavior":"deny"`
				}
				if result.code != 0 || !strings.Contains(result.stdout, want) ||
					!strings.Contains(result.stdout, "being installed or upgraded") ||
					!strings.Contains(result.stdout, "run the installer again") ||
					strings.Contains(result.stdout, "defenseclaw-gateway start") {
					t.Fatalf("install call allowed: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// The installer can acquire the lock after the hook starts but before a
// gateway failure is returned. That failure must still produce a native deny.
func TestPerUserCopilotDeniesWhenInstallStartsDuringGatewayRequest(t *testing.T) {
	fastRestartRetries(t)
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		for _, failure := range []struct {
			name   string
			status int
			body   string
		}{
			{"gateway error", http.StatusServiceUnavailable, ""},
			{"invalid verdict", http.StatusOK, `{"action":"unknown"}`},
		} {
			t.Run(event+"/"+failure.name, func(t *testing.T) {
				var lock string
				rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
					if err := os.Mkdir(lock, 0o700); err != nil && !os.IsExist(err) {
						return nil, err
					}
					return &http.Response{
						StatusCode: failure.status,
						Body:       io.NopCloser(strings.NewReader(failure.body)),
						Header:     make(http.Header),
					}, nil
				}}
				result := run(t, "copilot", rt, func(opts *Options) {
					opts.Event = event
					opts.StartedAt = time.Now().Add(-gatewayRestartBudget + 150*time.Millisecond)
					lock = filepath.Join(opts.Home, installLockName)
				})
				want := `"permissionDecision":"deny"`
				if event == "permissionRequest" {
					want = `"behavior":"deny"`
				}
				if result.code != 0 || !strings.Contains(result.stdout, want) ||
					!strings.Contains(result.stdout, "being installed or upgraded") {
					t.Fatalf("in-flight install call allowed: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
				}
			})
		}
	}
}

// GAP-1372 (owner decision 2026-10-24): during this account's install or
// upgrade window a call the running gateway answers keeps the gateway's
// answer in the default and permissive tiers. Copilot denied such an allow at
// hook entry and again when the answer came (a benign false block), while
// every other connector kept it. Every native tool hook form now keeps the
// gateway's allow and its block, with the lock taken before the call, during
// the request, or while the answer is read, in every outage tier; failures in
// the window still block (TestPerUserCopilotDeniesDuringInstall,
// TestNativeHookAnswersClosedWhenAnInstallStartsDuringTheCall).
func TestPerUserInstallWindowKeepsTheGatewaysAnswer(t *testing.T) {
	for _, form := range nativeToolHookForms {
		for _, when := range []string{"before the call", "during the request", "while the answer is read"} {
			for _, tier := range []string{"open", "closed"} {
				for _, verdict := range []string{"allow", "block"} {
					t.Run(form.String()+"/"+when+"/outage "+tier+"/"+verdict, func(t *testing.T) {
						body := `{"action":"allow"}`
						if verdict == "block" {
							deny := `{"permissionDecision":"deny","decision":"deny","behavior":"deny","permission":"deny","reason":"policy"}`
							body = `{"action":"block","reason":"policy","hook_output":` + deny + `,"claude_code_output":` + deny +
								`,"codex_output":` + deny + `}`
						}
						var home string
						rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
							response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
								Body: io.NopCloser(strings.NewReader(body))}
							switch when {
							case "during the request":
								mkdirInstallLock(t, home)
							case "while the answer is read":
								response.Body = &installOnBodyRead{t: t, home: home, body: strings.NewReader(body)}
							}
							return response, nil
						}}
						payload := `{"hook_event_name":"` + form.event + `","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
						result := run(t, form.connector, rt, func(opts *Options) {
							home = opts.Home
							opts.Event = form.event
							opts.HookSurface = form.surface
							opts.FailMode = "closed"
							opts.OutageFailModeNow = func() string { return tier }
							opts.Stdin = strings.NewReader(payload)
							if when == "before the call" {
								mkdirInstallLock(t, opts.Home)
							}
						})
						if _, err := os.Lstat(filepath.Join(home, installLockName)); err != nil {
							t.Fatalf("the install lock was not held: %v", err)
						}
						blocks := nativeAnswerBlocks(result.code, result.stdout)
						if blocks != (verdict == "block") {
							t.Fatalf("gateway %s during the install window: code=%d stdout=%q stderr=%q blocks=%v",
								verdict, result.code, result.stdout, result.stderr, blocks)
						}
						if verdict == "allow" && strings.Contains(result.stdout+result.stderr, "being installed or upgraded") {
							t.Fatalf("an answered call was refused as an install: stdout=%q stderr=%q", result.stdout, result.stderr)
						}
					})
				}
			}
		}
	}
}

func TestPerUserCopilotDeniesWhenInstallLockIsUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions")
	}
	result := run(t, "copilot", &stubRT{status: http.StatusServiceUnavailable}, func(opts *Options) {
		opts.Event = "preToolUse"
		if err := os.Mkdir(filepath.Join(opts.Home, installLockName), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(opts.Home, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(opts.Home, 0o700) })
	})
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("unreadable install lock allowed: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// reservedLoopbackAddr returns a loopback address nobody listens on.
func reservedLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// The real transport (Linux, macOS, Windows): a gateway that comes back on
// its port within the budget answers the call.
func TestPerUserHookAnswersFromAGatewayThatComesBackOnItsPort(t *testing.T) {
	addr := reservedLoopbackAddr(t)
	served := make(chan struct{})
	go func() {
		time.Sleep(500 * time.Millisecond)
		var listener net.Listener
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			var err error
			if listener, err = net.Listen("tcp", addr); err == nil {
				break
			}
		}
		close(served)
		if listener == nil {
			return
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"action":"allow"}`)
		}), ReadHeaderTimeout: time.Second}
		t.Cleanup(func() { _ = server.Close() })
		_ = server.Serve(listener)
	}()
	started := time.Now()
	result := run(t, "codex", &stubRT{}, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = nil
		opts.FailMode = "closed"
	})
	<-served
	if elapsed := time.Since(started); elapsed > gatewayRestartBudget+time.Second {
		t.Fatalf("the call took %s", elapsed)
	}
	if result.code != 0 || strings.Contains(result.stdout, "deny") {
		t.Fatalf("code=%d stdout=%q stderr=%q, want the answer of the gateway that came back", result.code, result.stdout, result.stderr)
	}
}

// The real transport: nothing listens on the port for the whole budget. The
// call is blocked within about the budget (a connect to a closed port takes
// about 2 s on Windows, and a try still connecting at the end is ended).
func TestPerUserHookBlocksWithinTheBudgetWhenNothingListens(t *testing.T) {
	addr := reservedLoopbackAddr(t)
	started := time.Now()
	result := run(t, "codex", &stubRT{}, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = nil
		opts.FailMode = "closed"
	})
	elapsed := time.Since(started)
	if elapsed < gatewayRestartBudget-time.Second || elapsed > gatewayRestartBudget+1500*time.Millisecond {
		t.Fatalf("the call was blocked after %s, want about %s", elapsed, gatewayRestartBudget)
	}
	if !strings.Contains(result.stdout, `"permissionDecision":"deny"`) || !strings.Contains(result.stdout, "restarting or not running") {
		t.Fatalf("stdout=%q stderr=%q, want a deny naming the restart", result.stdout, result.stderr)
	}
}
