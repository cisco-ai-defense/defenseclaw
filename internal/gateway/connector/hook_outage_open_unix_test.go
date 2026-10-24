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

// Per-user shell hooks block an outage in every policy tier, including when
// an older config supplies open. The real native helper (hook-post) carries
// every call, as on an installed host.
func TestPerUserShellHookOutageFailsClosed(t *testing.T) {
	type scenario struct {
		name    string
		handler http.HandlerFunc // nil: no gateway listens
		env     []string
		lock    bool
	}
	allow := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow","raw_action":"allow","severity":"NONE","hook_output":{}}`))
	}
	scenarios := []scenario{
		{name: "gateway up", handler: allow},
		{name: "gateway down"},
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
		for _, tier := range []struct{ name, mode string }{{"default or permissive", "open"}, {"strict", "closed"}} {
			for _, sc := range scenarios {
				t.Run(conn.Name()+"/"+tier.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel()
					invoke := hookArgvConnectorCase(t, conn.Name())
					home := t.TempDir()
					installNativeGatewayForHookTest(t, home)
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
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
					cmd.Env = append(cmd.Env, sc.env...)
					output, err := cmd.CombinedOutput()
					blocked := hookCallBlocked(err, string(output))
					wantRun := sc.name == "gateway up"
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
					if last["outcome"] != "fail_closed" {
						t.Fatalf("per-user outage row = %+v, want fail_closed", last)
					}
				})
			}
		}
	}
}

// An outage record the hook cannot trust (a record without the config
// source, one that names another connector or is malformed, or none) keeps
// the outage closed.
func TestPerUserShellHookOutageNeedsItsOwnRecord(t *testing.T) {
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
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "_DC_TRANSPORT_STATUS=7")
			output, err := cmd.CombinedOutput()
			if !hookCallBlocked(err, string(output)) {
				t.Fatalf("an outage with record %q ran the call:\n%s", tc.record, output)
			}
		})
	}
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
