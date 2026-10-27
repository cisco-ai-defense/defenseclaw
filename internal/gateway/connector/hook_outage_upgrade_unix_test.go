// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// outageToolCall is one tool call each per-user shell hook answers for
// itself while its gateway is down.
type outageToolCall struct {
	script string
	args   []string
	stdin  string
}

var outageToolCalls = map[string]outageToolCall{
	"copilot": {"copilot-hook.sh", []string{"--event", "preToolUse"},
		`{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work","toolName":"bash","toolArgs":{"command":"ls"}}`},
	"cursor": {"cursor-hook.sh", nil,
		`{"hook_event_name":"beforeShellExecution","conversation_id":"c1","command":"ls","cwd":"/work"}`},
	"antigravity": {"antigravity-hook.sh", []string{"PreToolUse"},
		`{"toolName":"run_command","toolInput":{"CommandLine":"ls"}}`},
}

func requireShellHookToolsForTest(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required to run the shell hooks", tool)
		}
	}
}

// closedLoopbackAddrForTest is a loopback address nothing listens on: a
// gateway that is down.
func closedLoopbackAddrForTest(t *testing.T) string {
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

// runOutageToolCall runs the hook in dataDir/hooks for one tool call while
// the gateway is stopped (gateway.stopped: no restart wait, no cold start)
// and reports whether the agent blocks it: exit 2, or the agent's native
// denial on stdout (Copilot permissionDecision, Cursor permission,
// Antigravity decision).
func runOutageToolCall(t *testing.T, home, dataDir string, call outageToolCall) (bool, string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(dataDir, "hooks", call.script)}, call.args...)...)
	cmd.Stdin = strings.NewReader(call.stdin)
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DEFENSECLAW_") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "HOME="+home, "DEFENSECLAW_HOME="+dataDir, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %s: %v", call.script, err)
		}
		code = exitErr.ExitCode()
	}
	out := stdout.String()
	return code == 2 || strings.Contains(out, `"deny"`), fmt.Sprintf("exit %d stdout=%q stderr=%q", code, out, stderr.String())
}

// The per-user hooks of agents without a fail-closed hook contract of their
// own, and Cursor, follow the outage mode of their current policy tier
// (oss-outage-open, owner decision 2026-10-23): with the gateway down, the
// strict tier blocks the tool call and the default or permissive tier lets it
// run, in observe and action mode alike. The rendered mode does not decide.
func TestPerUserHooksBlockAToolCallWhileTheGatewayIsDown(t *testing.T) {
	requireShellHookToolsForTest(t)
	addr := closedLoopbackAddrForTest(t)
	for _, test := range []struct {
		name, connector string
		opts            SetupOpts
		block           bool
	}{
		{"copilot unset", "copilot", SetupOpts{}, true},
		{"copilot closed", "copilot", SetupOpts{HookFailMode: "closed"}, true},
		{"copilot open", "copilot", SetupOpts{HookFailMode: "open"}, false},
		{"antigravity unset", "antigravity", SetupOpts{}, true},
		{"antigravity open", "antigravity", SetupOpts{HookFailMode: "open"}, false},
		{"cursor observe unset", "cursor", SetupOpts{GuardrailMode: "observe"}, true},
		{"cursor observe open", "cursor", SetupOpts{GuardrailMode: "observe", HookFailMode: "open"}, false},
		{"cursor action strict", "cursor", SetupOpts{GuardrailMode: "action", HookFailMode: "closed"}, true},
		{"cursor action open", "cursor", SetupOpts{GuardrailMode: "action", HookFailMode: "open"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, ok := NewDefaultRegistry().Get(test.connector)
			if !ok {
				t.Fatalf("no %s connector", test.connector)
			}
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			opts := test.opts
			opts.DataDir, opts.APIAddr, opts.HookAPIToken = dataDir, addr, "outage-test-token"
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dataDir, "hooks"), opts, conn); err != nil {
				t.Fatal(err)
			}
			// The config the outage-open hook reads gives the open tier.
			installOutageOpenRuntimeForHookTest(t, home, dataDir)
			if test.block {
				writeOutageTierConfig(t, dataDir, outageStrictTierConfig)
			}
			blocked, detail := runOutageToolCall(t, home, dataDir, outageToolCalls[test.connector])
			if blocked != test.block {
				t.Fatalf("blocked = %v, want %v: %s", blocked, test.block, detail)
			}
			// The setup sidecar keeps the rendered metadata; the hook reads
			// the current config at call time for the outage decision.
			want := "open"
			if test.block {
				want = "closed"
			}
			state := readHookConfigSidecarForTest(t, filepath.Join(dataDir, "hooks"))
			if state.FailModes[test.connector] != want || state.FailModeSources[test.connector] != HookFailModeSourceConfig {
				t.Fatalf("sidecar %+v, want %s from the config", state, want)
			}
		})
	}
}

// The installers run the new gateway's refresh-fail-modes before the old
// gateway stops. The hooks it refreshes are an earlier release's own scripts,
// which keep answering until the new gateway renders its own:
// testdata/released-hooks holds the per-user Copilot, Cursor (observe) and
// Antigravity hooks and the _hardening.sh they source, as 0.8.10, 1.0.0 and
// 1.0.3 rendered them for an unset fail mode. Each lets a tool call run while
// the gateway is down. After a refresh that resolves closed every one of
// them blocks it, Copilot's 1.0.x hook included (its failure functions exit 0
// whatever FAIL_MODE says). A refresh to open closes them too: a released
// script and its released helper have no outage-only open, and the setup
// that follows renders this release's hooks, which read their outage mode
// from the runtime record.
func TestRefreshMakesReleasedHooksBlockWhileTheGatewayIsDown(t *testing.T) {
	requireShellHookToolsForTest(t)
	addr := closedLoopbackAddrForTest(t)
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, connector := range []string{"copilot", "cursor", "antigravity"} {
			for _, mode := range []string{"closed", "open"} {
				t.Run(release+"/"+connector+"/"+mode, func(t *testing.T) {
					call := outageToolCalls[connector]
					home := t.TempDir()
					dataDir := filepath.Join(home, ".defenseclaw")
					hookDir := filepath.Join(dataDir, "hooks")
					if err := os.MkdirAll(hookDir, 0o700); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"_hardening.sh", call.script} {
						body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
						if err != nil {
							t.Fatal(err)
						}
						// The renders baked a placeholder gateway address.
						if name == call.script {
							if !bytes.Contains(body, []byte(`API_ADDR="127.0.0.1:9"`)) {
								t.Fatalf("%s %s bakes no gateway address", release, name)
							}
							body = bytes.ReplaceAll(body, []byte(`API_ADDR="127.0.0.1:9"`), []byte(`API_ADDR="`+addr+`"`))
						}
						if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=outage-test-token\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					blockedBefore, detail := runOutageToolCall(t, home, dataDir, call)
					if blockedBefore {
						t.Fatalf("precondition: the %s hook blocks before the refresh: %s", release, detail)
					}

					if _, err := RefreshHookFailModes(hookDir, func(string) string { return mode }); err != nil {
						t.Fatal(err)
					}
					blocked, detail := runOutageToolCall(t, home, dataDir, call)
					if !blocked {
						t.Fatalf("after a refresh to %s: blocked = %v: %s", mode, blocked, detail)
					}
				})
			}
		}
	}
}

// TestRefreshClosesReleasedCopilotEarlyFailures: a released per-user
// copilot-hook.sh refreshed before the old gateway stops denies a tool call
// whose helper or token is missing, not only a gateway failure (GAP-0345).
func TestRefreshClosesReleasedCopilotEarlyFailures(t *testing.T) {
	requireShellHookToolsForTest(t)
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, mode := range []string{"closed", "open"} {
			t.Run(release+"/"+mode, func(t *testing.T) {
				home := t.TempDir()
				dataDir := filepath.Join(home, ".defenseclaw")
				hookDir := filepath.Join(dataDir, "hooks")
				if err := os.MkdirAll(hookDir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"_hardening.sh", "copilot-hook.sh"} {
					body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := RefreshHookFailModes(hookDir, func(string) string { return mode }); err != nil {
					t.Fatal(err)
				}
				hook := filepath.Join(hookDir, "copilot-hook.sh")
				helper, err := os.ReadFile(filepath.Join(hookDir, "_hardening.sh"))
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range []string{"preToolUse", "permissionRequest"} {
					if err := os.Remove(filepath.Join(hookDir, "_hardening.sh")); err != nil {
						t.Fatal(err)
					}
					out, code := runReleasedCopilotEarlyFailure(t, hook, home, dataDir, event)
					if code != 0 || !copilotEarlyDenial(out, event) {
						t.Fatalf("missing helper %s: exit %d stdout=%q", event, code, out)
					}
					if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), helper, 0o700); err != nil {
						t.Fatal(err)
					}
					out, code = runReleasedCopilotEarlyFailure(t, hook, home, dataDir, event)
					if code != 0 || !copilotEarlyDenial(out, event) {
						t.Fatalf("missing token %s: exit %d stdout=%q", event, code, out)
					}
				}
				// A second refresh leaves the closed script as it is.
				before, _ := os.ReadFile(hook)
				if _, err := RefreshHookFailModes(hookDir, func(string) string { return mode }); err != nil {
					t.Fatal(err)
				}
				if after, _ := os.ReadFile(hook); !bytes.Equal(before, after) {
					t.Fatal("a second refresh changed the closed Copilot hook")
				}
			})
		}
	}
}

// TestRefreshedReleasedCopilotHookDeniesAnEarlyExitOfStatusZero: an early
// exit of status 0 is a failure too. macOS /bin/bash 3.2 runs the EXIT trap
// with $? 0 when the sourced helper is missing, so a trap that tested the
// status let the tool run there (GAP-2141); a helper that exits 0 while it
// is sourced gives the same status on every bash.
func TestRefreshedReleasedCopilotHookDeniesAnEarlyExitOfStatusZero(t *testing.T) {
	requireShellHookToolsForTest(t)
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for _, mode := range []string{"closed", "open"} {
			t.Run(release+"/"+mode, func(t *testing.T) {
				home := t.TempDir()
				dataDir := filepath.Join(home, ".defenseclaw")
				hookDir := filepath.Join(dataDir, "hooks")
				if err := os.MkdirAll(hookDir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"_hardening.sh", "copilot-hook.sh"} {
					body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(hookDir, name), body, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := RefreshHookFailModes(hookDir, func(string) string { return mode }); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), []byte("exit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				hook := filepath.Join(hookDir, "copilot-hook.sh")
				for _, event := range []string{"preToolUse", "permissionRequest"} {
					out, code := runReleasedCopilotEarlyFailure(t, hook, home, dataDir, event)
					if code != 0 || !copilotEarlyDenial(out, event) {
						t.Fatalf("helper exit 0 %s: exit %d stdout=%q", event, code, out)
					}
				}
			})
		}
	}
}

// copilotEarlyDenial reports one JSON object on stdout that denies event
// with Copilot's native field for it: two objects are not an answer Copilot
// reads.
func copilotEarlyDenial(out, event string) bool {
	var answer map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &answer); err != nil {
		return false
	}
	if event == "permissionRequest" {
		return answer["behavior"] == "deny"
	}
	return answer["permissionDecision"] == "deny"
}

func runReleasedCopilotEarlyFailure(t *testing.T, hook, home, dataDir, event string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", hook, "--event", event)
	cmd.Stdin = strings.NewReader(`{"sessionId":"s","toolName":"bash","toolArgs":{"command":"echo ok"}}`)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+dataDir)
	out, err := cmd.Output()
	return string(out), exitCodeOf(err)
}
