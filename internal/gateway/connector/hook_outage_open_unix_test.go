// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
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

// oss-outage-open (owner decision 2026-10-23): a per-user shell hook in the
// default or permissive policy tier (outage mode open) lets a call run with
// one warning and a hook-failures.jsonl row only while this account's gateway
// is not running. The strict tier (outage mode closed) blocks it. In every
// tier an answer the gateway gave (malformed, cut off, an error status), a
// gateway that took the call and did not answer, strict availability and the
// install window block. The real native helper (hook-post) carries every
// call, as on an installed host.
func TestPerUserShellHookOutageOpenOnlyForAnOutage(t *testing.T) {
	type scenario struct {
		name    string
		handler http.HandlerFunc // nil: no gateway listens
		env     []string
		lock    bool
		// opens reports whether the outage-open tier lets this call run.
		opens bool
	}
	allow := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","severity":"NONE","hook_output":{}}`))
	}
	scenarios := []scenario{
		{name: "gateway up", handler: allow, opens: true},
		{name: "gateway down", opens: true},
		{name: "gateway down, strict availability", env: []string{"DEFENSECLAW_STRICT_AVAILABILITY=1"}},
		{name: "gateway down, install in progress", lock: true},
		{name: "gateway took the call and did not answer", handler: func(_ http.ResponseWriter, r *http.Request) {
			// Read the body so the server notices the hook hang up.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-time.After(30 * time.Second):
			}
		}},
		{name: "malformed answer", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"action":"allow" garbage`))
		}},
		{name: "partial answer", handler: func(w http.ResponseWriter, _ *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, buf, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"action\":\"allow\"")
			_ = buf.Flush()
		}},
		{name: "gateway error status", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}},
	}
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewCopilotConnector(), NewCursorConnector(),
		NewDevinConnector(), NewKiroConnector(), NewAntigravityConnector(), NewHermesConnector()} {
		for _, tier := range []struct{ name, mode, config string }{
			{"default or permissive", "open", outageDefaultTierConfig},
			{"strict", "closed", outageStrictTierConfig},
		} {
			for _, sc := range scenarios {
				t.Run(conn.Name()+"/"+tier.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel()
					invoke := hookArgvConnectorCase(t, conn.Name())
					home := t.TempDir()
					installNativeGatewayForHookTest(t, home)
					writeOutageTierConfig(t, home, tier.config)
					var addr string
					if sc.handler != nil {
						server := httptest.NewServer(sc.handler)
						defer server.Close()
						addr = strings.TrimPrefix(server.URL, "http://")
					} else {
						addr = freeLoopbackAddrForOutageTest(t)
					}
					hookDir := filepath.Join(home, "hooks")
					opts := SetupOpts{DataDir: home, APIAddr: addr, APIToken: "scoped-test-token", HookFailMode: tier.mode}
					if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
						t.Fatal(err)
					}
					if sc.lock {
						if err := os.WriteFile(filepath.Join(home, ".install.lock"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
					cmd.Env = append(cmd.Env, sc.env...)
					output, err := cmd.CombinedOutput()
					blocked := hookCallBlocked(err, string(output))
					wantRun := sc.name == "gateway up" || (sc.opens && tier.mode == "open")
					if blocked == wantRun {
						t.Fatalf("blocked=%v, want %v (exit %v):\n%s", blocked, !wantRun, err, output)
					}
					if sc.name != "gateway down" {
						return
					}
					records := hookFailureRecords(t, home)
					if len(records) == 0 {
						t.Fatalf("no hook-failures.jsonl row for the outage:\n%s", output)
					}
					last := records[len(records)-1]
					if tier.mode == "closed" {
						if last["outcome"] != "fail_closed" {
							t.Fatalf("strict tier outage row = %+v, want fail_closed", last)
						}
						return
					}
					if last["outcome"] != "fail_open" || last["fail_mode"] != "open" || last["category"] != "transport" {
						t.Fatalf("outage row = %+v, want a fail_open transport row with fail mode open", last)
					}
					text := string(output)
					for _, want := range []string{"defenseclaw-gateway start", "defenseclaw doctor", outageOpenWarningForTest(conn.Name())} {
						if !strings.Contains(text, want) {
							t.Fatalf("the warning does not name %q:\n%s", want, text)
						}
					}
					if strings.Contains(text, "WARNING hook fail-open") {
						t.Fatalf("the outage gave a second, generic warning:\n%s", text)
					}
				})
			}
		}
	}
}

// A setup-time record cannot override the current policy tier, including a
// record left by an earlier strict render or a missing legacy record.
func TestPerUserShellHookOutageIgnoresStaleRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record string // "" removes the record
	}{
		{"no record", ""},
		{"no config source", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n"},
		{"another connector", "DEFENSECLAW_CONNECTOR=claudecode\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config\n"},
		{"cut short", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config"},
		{"closed", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\nFAIL_MODE_SOURCE=config\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			invoke := hookArgvConnectorCase(t, "codex")
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			// The current config gives the open outage mode.
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewCodexConnector()); err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(hookDir, hookConfigSidecarName+".codex")
			if tc.record == "" {
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(record, []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			// An inherited transport status cannot stand in for the call's own.
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0", "_DC_TRANSPORT_STATUS=7")
			output, err := cmd.CombinedOutput()
			if hookCallBlocked(err, string(output)) {
				t.Fatalf("an outage with record %q blocked the call:\n%s", tc.record, output)
			}
		})
	}
}

// The runtime record is what the gateway or the last refresh wrote. A
// rule-pack change made since (strict selected while the gateway is stopped,
// for every connector or for this one) and a config this release cannot read
// close the outage, whatever the record says; the default and permissive
// packs and another connector's strict pack leave it open.
func TestPerUserShellHookOutageFollowsTheConfigNow(t *testing.T) {
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewCopilotConnector(), NewCursorConnector(),
		NewDevinConnector(), NewKiroConnector(), NewAntigravityConnector(), NewHermesConnector()} {
		other := "claudecode"
		if conn.Name() == other {
			other = "codex"
		}
		for _, tc := range []struct {
			name, config string
			opens        bool
		}{
			{"default pack after a strict render", outageDefaultTierConfig, true},
			{"permissive pack", outageDefaultTierConfig + "  rule_pack: permissive\n", true},
			{"strict pack", outageStrictTierConfig, false},
			{"strict pack for this connector", outageDefaultTierConfig + "  connectors:\n    " + conn.Name() + ":\n      rule_pack: strict\n", false},
			{"strict pack for another connector", outageDefaultTierConfig + "  connectors:\n    " + other + ":\n      rule_pack: strict\n", true},
			{"no config", "", false},
			{"config this release cannot read", "config_version: 9\nguardrail: [\n", false},
		} {
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				invoke := hookArgvConnectorCase(t, conn.Name())
				home := t.TempDir()
				installNativeGatewayForHookTest(t, home)
				hookDir := filepath.Join(home, "hooks")
				// A strict render can remain installed when the gateway is stopped.
				opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "closed"}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				writeOutageTierConfig(t, home, tc.config)
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
				cmd.Stdin = strings.NewReader(invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				output, err := cmd.CombinedOutput()
				if blocked := hookCallBlocked(err, string(output)); blocked == tc.opens {
					t.Fatalf("blocked=%v, want %v (exit %v):\n%s", blocked, !tc.opens, err, output)
				}
				records := hookFailureRecords(t, home)
				if len(records) == 0 {
					t.Fatalf("no hook-failures.jsonl row for the outage:\n%s", output)
				}
				want := "fail_closed"
				if tc.opens {
					want = "fail_open"
				}
				if last := records[len(records)-1]; last["outcome"] != want {
					t.Fatalf("outage row = %+v, want %s", last, want)
				}
				if tc.opens && !strings.Contains(string(output), outageOpenWarningForTest(conn.Name())) {
					t.Fatalf("open outage omitted its warning:\n%s", output)
				}
			})
		}
	}
}

// outageOpenWarningForTest is the one outage warning a connector's shell
// hook shows: Claude Code and Codex show it as their user-visible
// systemMessage, the others on stderr.
func outageOpenWarningForTest(connector string) string {
	if connector == "claudecode" || connector == "codex" {
		return "DefenseClaw is not checking this session"
	}
	return "fail mode open for an outage"
}

// freeLoopbackAddrForOutageTest is a loopback address no process listens on.
// It comes from below the ephemeral range (Linux 32768-60999, macOS
// 49152-65535), where no parallel subtest's httptest server (port 0) can take
// it after this probe, and no two callers get the same port.
func freeLoopbackAddrForOutageTest(t *testing.T) string {
	t.Helper()
	outagePortsMu.Lock()
	defer outagePortsMu.Unlock()
	for port := 21000 + rand.IntN(8000); ; port++ {
		if port >= 29000 {
			port = 21000
		}
		if outagePortsUsed[port] {
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		outagePortsUsed[port] = true
		return addr
	}
}

var (
	outagePortsMu   sync.Mutex
	outagePortsUsed = map[int]bool{}
)
