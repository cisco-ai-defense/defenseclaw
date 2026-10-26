// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// installInFlightShellCase is one rendered per-user shell hook invocation.
type installInFlightShellCase struct {
	name   string
	conn   Connector
	invoke hookArgvCase
}

func installInFlightShellCases(t *testing.T) []installInFlightShellCase {
	t.Helper()
	var cases []installInFlightShellCase
	for _, conn := range hookArgvShellConnectors {
		cases = append(cases, installInFlightShellCase{conn.Name(), conn, hookArgvConnectorCase(t, conn.Name())})
	}
	cases = append(cases, installInFlightShellCase{"copilot-permissionRequest", NewCopilotConnector(), hookArgvCase{
		script: "copilot-hook.sh", args: []string{"--event", "permissionRequest"},
		stdin: `{"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo marker"}}`,
	}})
	for _, invoke := range hookArgvInspectCases() {
		if len(invoke.stdin) <= 4096 {
			cases = append(cases, installInFlightShellCase{invoke.script, NewCodexConnector(), invoke})
		}
	}
	return cases
}

// shellHookBlocked reports a rendered hook answer that stops the call: a
// non-zero exit, or a structured deny or block.
func shellHookBlocked(err error, stdout string) bool {
	return err != nil || strings.Contains(stdout, `"deny"`) || strings.Contains(stdout, `"block"`) ||
		strings.Contains(stdout, `"continue":false`)
}

// GAP-0894: a per-user shell hook in fail mode open read .install.lock once,
// when it started. An install or upgrade that began while the hook waited
// for the gateway left it open, and the failure that followed (the
// installer stops the gateway) allowed the call. Every rendered shell hook
// now reads the install state again in every failure answer: a connection
// the gateway drops, an outage or error status, no verdict and no JSON.
// Without an install the account's open choice still applies to an outage.
func TestPerUserShellHookAnswersClosedWhenAnInstallStartsDuringTheCall(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	failures := []struct {
		name    string
		answer  func(w http.ResponseWriter)
		control bool // open mode allows this failure without an install
	}{
		{"gateway drops the connection", func(w http.ResponseWriter) {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
		}, false},
		{"gateway answers HTTP 503", func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }, true},
		{"gateway answers HTTP 401", func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }, false},
		{"gateway answers no verdict", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"action":"maybe"}`)) }, false},
		{"gateway answers no JSON", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`not json`)) }, false},
	}
	for _, tc := range installInFlightShellCases(t) {
		for _, failure := range failures {
			for _, install := range []bool{false, true} {
				if !install && !failure.control {
					continue
				}
				name := tc.name + "/" + failure.name + "/no install"
				if install {
					name = tc.name + "/" + failure.name + "/install starts during the call"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					data := t.TempDir()
					var once sync.Once
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						if install {
							once.Do(func() {
								if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
									t.Error(err)
								}
							})
						}
						failure.answer(w)
					}))
					t.Cleanup(server.Close)
					stdout, stderr, err := runInstallInFlightShellHook(t, tc, data, strings.TrimPrefix(server.URL, "http://"), nil)
					// A per-user hook is closed whatever mode it was set up with
					// (sa-port-peer): the failure blocks with or without an install.
					if got := shellHookBlocked(err, stdout); !got {
						t.Fatalf("blocks=%v, want true (install %v): err=%v stdout=%q stderr=%q", got, install, err, stdout, stderr)
					}
				})
			}
		}
	}
}

// An install that starts while the agent is still writing the payload
// closes the oversized-payload answer too (GAP-0894).
func TestPerUserShellHookOversizedPayloadClosesWhenAnInstallStartsDuringTheRead(t *testing.T) {
	for _, tc := range installInFlightShellCases(t) {
		// Every per-user hook form must make the same bounded, audited
		// balanced-tier choice; an active installer still closes it.
		for _, install := range []bool{false, true} {
			name := tc.name + "/no install"
			if install {
				name = tc.name + "/install starts during the read"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				data := t.TempDir()
				installNativeHookPostForHookTest(t, data)
				// The balanced tier is the config's rule pack, read at call
				// time (fix/r104-oss-outage-open), not the render's mode.
				installOutageOpenRuntimeForHookTest(t, data, data)
				write := func(stdin io.WriteCloser) {
					// The hook has started and selected its mode before the
					// agent is done writing.
					time.Sleep(time.Second)
					if install {
						if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
							t.Error(err)
						}
					}
					_, _ = io.WriteString(stdin, `{"hook_event_name":"PreToolUse","tool_input":{"command":"echo ok","description":"`+strings.Repeat("a", 16<<10)+`"}}`)
					_ = stdin.Close()
				}
				stdout, stderr, err := runInstallInFlightShellHook(t, tc, data, freeAPIAddr(t), write, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				if got := shellHookBlocked(err, stdout); got != install {
					t.Fatalf("blocks=%v, want %v (install %v): err=%v stdout=%q stderr=%q", got, install, install, err, stdout, stderr)
				}
				if !install {
					// The one outage warning is stderr, or the systemMessage
					// Claude Code and Codex show (fix/r104-oss-outage-open).
					rows, readErr := os.ReadFile(filepath.Join(data, "logs", "hook-failures.jsonl"))
					if readErr != nil || !strings.Contains(string(rows), `"outcome":"fail_open"`) || !(strings.Contains(stderr, "allowing") || strings.Contains(stdout, "DefenseClaw is not checking this session")) {
						t.Fatalf("balanced audit/warning: %q %q %v", rows, stderr, readErr)
					}
				}
			})
		}
	}
}

func TestPerUserShellOversizedProtectedPrefixGetsGatewayBlock(t *testing.T) {
	cases := []struct {
		name, payload string
	}{
		{"cursor", `{"hook_event_name":"beforeReadFile","file_path":"/home/user/.defenseclaw/audit.db","content":"` + strings.Repeat("x", 8192) + `"}`},
		{"claudecode", `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/home/user/.ssh/authorized_keys","content":"` + strings.Repeat("x", 8192) + `"}}`},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"file_path":"/home/user/.defenseclaw/hooks/codex-hook.sh","content":"` + strings.Repeat("x", 8192) + `"}}`},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			var got []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"action":"block","mode":"action","hook_output":{"decision":"deny","reason":"protected target"}}`)
			}))
			t.Cleanup(server.Close)
			data := t.TempDir()
			installNativeHookPostForHookTest(t, data)
			tc := installInFlightShellCase{item.name, nil, hookArgvConnectorCase(t, item.name)}
			switch item.name {
			case "cursor":
				tc.conn = NewCursorConnector()
			case "claudecode":
				tc.conn = NewClaudeCodeConnector()
			case "codex":
				tc.conn = NewCodexConnector()
			}
			tc.invoke.stdin = item.payload
			stdout, stderr, err := runInstallInFlightShellHook(t, tc, data, strings.TrimPrefix(server.URL, "http://"), nil)
			if !shellHookBlocked(err, stdout) || !bytes.Contains(got, []byte(`"bounded_prefix_review":true`)) || !bytes.Contains(got, []byte(`"file_path":`)) {
				t.Fatalf("protected oversized input must reach gateway and block: err=%v stdout=%q stderr=%q request=%q", err, stdout, stderr, got)
			}
		})
	}
}

// runInstallInFlightShellHook renders tc's per-user hooks into data in fail
// mode open and runs the hook once against addr. write, when set, writes
// the hook's stdin; otherwise the case's payload is.
func runInstallInFlightShellHook(t *testing.T, tc installInFlightShellCase, data, addr string, write func(io.WriteCloser), env ...string) (string, string, error) {
	t.Helper()
	hooks := filepath.Join(data, "hooks")
	if tc.conn.Name() == "cursor" {
		// Cursor's connector setup renders its action hook closed in every
		// mode; the open render is the one an observe install runs.
		if err := writeHookScriptsCommonWithFailMode(hooks, addr, "test-token", "open", []string{"cursor-hook.sh"}); err != nil {
			t.Fatal(err)
		}
		if err := writeHookConfigSidecar(hooks, addr, "cursor", "open", false); err != nil {
			t.Fatal(err)
		}
	} else {
		opts := SetupOpts{DataDir: data, APIAddr: addr, APIToken: "test-token", HookFailMode: "open", GuardrailMode: "action", WorkspaceDir: data}
		if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, opts, tc.conn); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(hooks, tc.invoke.script)}, tc.invoke.args...)...)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+data, "DEFENSECLAW_HOME="+data, "DEFENSECLAW_HOOK_MAX_BODY=4096")
	cmd.Env = append(cmd.Env, tc.invoke.env...)
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if write == nil {
		cmd.Stdin = strings.NewReader(tc.invoke.stdin)
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	write(stdin)
	err = cmd.Wait()
	return stdout.String(), stderr.String(), err
}
