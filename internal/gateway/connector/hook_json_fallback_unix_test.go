// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The awk tier runs where neither jq nor a usable python3 is available.
// It must validate the whole answer before an action can allow a tool.
func TestShellFallbackRejectsMalformedGatewayJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body, action string
		valid              bool
	}{
		{"ordinary allow", `{"action":"allow","extra":{"n":[true,2,null]}}`, "allow", true},
		{"invalid nested literal", `{"action":"allow","extra":[invalid]}`, "", false},
		{"truncated nested object", `{"action":"allow","extra":{"n":1}`, "", false},
		{"missing comma", `{"action":"allow" "extra":1}`, "", false},
		{"bad escape", `{"action":"allow","extra":"\q"}`, "", false},
		{"bad number", `{"action":"allow","extra":01}`, "", false},
		{"duplicate action", `{"action":"block","action":"allow"}`, "", false},
		{"duplicate nested key", `{"action":"allow","extra":{"x":1,"x":2}}`, "", false},
		{"escaped duplicate key", `{"action":"allow","act\u0069on":"block"}`, "", false},
		{"trailing document", `{"action":"allow"}{}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source hooks/_hardening.sh; defenseclaw_json_string_field "$1" action strict`, "--", tc.body)
			out, err := cmd.CombinedOutput()
			if tc.valid {
				if err != nil || strings.TrimSpace(string(out)) != tc.action {
					t.Fatalf("valid response: output %q error %v", out, err)
				}
			} else if err == nil {
				t.Fatalf("malformed response accepted: %q", out)
			}
		})
	}
}

// A gateway that has sent HTTP 200 cannot become an outage because curl
// reports an incomplete transfer. A request that times out before headers
// also has no usable answer. Every shell connector closes both cases in
// per-user open mode, as the native hook does.
func TestPerUserShellHTTP200FailuresBlockEveryConnector(t *testing.T) {
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		t.Run(conn.Name(), func(t *testing.T) {
			t.Parallel()
			for _, tc := range []struct {
				name, body    string
				partial       bool
				stall         bool
				beforeHeaders bool
			}{
				{"malformed", `{"action":"allow","extra":[invalid]}`, false, false, false},
				{"truncated 200", `{"action":"allow"}`, true, false, false},
				{"stalled 200", `{"action":"allow"}`, true, true, false},
				{"no answer before headers", `{"action":"allow"}`, false, false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						if tc.beforeHeaders {
							time.Sleep(1100 * time.Millisecond)
						}
						if tc.partial {
							w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)+64))
						}
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(tc.body))
						if tc.partial {
							w.(http.Flusher).Flush()
							if tc.stall {
								time.Sleep(1100 * time.Millisecond)
							}
							panic(http.ErrAbortHandler)
						}
					}))
					defer server.Close()
					invoke := hookArgvConnectorCase(t, conn.Name())
					home := t.TempDir()
					hooks := filepath.Join(home, "hooks")
					if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, SetupOpts{
						DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-token", HookFailMode: "open",
					}, conn); err != nil {
						t.Fatal(err)
					}
					if tc.stall || tc.beforeHeaders {
						// Keep the real HTTP timeout case fast while preserving curl's
						// behavior after response headers have arrived.
						helper := filepath.Join(hooks, "_hardening.sh")
						script, err := os.ReadFile(helper)
						if err != nil {
							t.Fatal(err)
						}
						short := strings.Replace(string(script), `--max-time "$_dc_post_max_time"`, `--max-time 1`, 1)
						if short == string(script) {
							t.Fatal("curl timeout not found")
						}
						if err := os.WriteFile(helper, []byte(short), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
					out, err := cmd.CombinedOutput()
					if !hookCallBlocked(err, string(out)) {
						t.Fatalf("%s HTTP 200 allowed %s in open mode: %v %s", tc.name, conn.Name(), err, out)
					}
				})
			}
		})
	}
}

// A per-user hook_fail_mode open is the user's outage choice (owner rule,
// BALANCED-DEFAULTS 2026-10-23): a gateway that refuses the connection lets
// the shell hook's tool call run with a fail-open record. A gateway that
// answered, here with HTTP 503 or a 400, is no outage and blocks in the same
// open render (the HTTP 200 variants are in
// TestPerUserShellHTTP200FailuresBlockEveryConnector).
func TestPerUserOpenShellAllowsOnlyAConfirmedOutage(t *testing.T) {
	answered := map[string]*httptest.Server{}
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusBadRequest} {
		status := status
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"x"}`))
		}))
		t.Cleanup(server.Close)
		answered[strconv.Itoa(status)] = server
	}
	run := func(t *testing.T, conn Connector, addr string) (string, error) {
		invoke := hookArgvConnectorCase(t, conn.Name())
		home := t.TempDir()
		hooks := filepath.Join(home, "hooks")
		if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, SetupOpts{
			DataDir: home, APIAddr: addr, APIToken: "test-token", HookFailMode: "open", ConfiguredHookFailMode: "open",
		}, conn); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
		cmd.Stdin = strings.NewReader(invoke.stdin)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, conn := range hookArgvShellConnectors {
		conn := conn
		t.Run(conn.Name(), func(t *testing.T) {
			t.Parallel()
			if out, err := run(t, conn, "127.0.0.1:1"); hookCallBlocked(err, out) || !strings.Contains(out, "fail-open") {
				t.Fatalf("%s blocked a refused connection in open mode: %v %s", conn.Name(), err, out)
			}
			for status, server := range answered {
				if out, err := run(t, conn, strings.TrimPrefix(server.URL, "http://")); !hookCallBlocked(err, out) {
					t.Fatalf("%s allowed an HTTP %s answer in open mode: %v %s", conn.Name(), status, err, out)
				}
			}
		})
	}
}

// Shared inspect hooks must also close a gateway response that has started,
// including with an administrator's outage-open choice. These scripts serve
// Claude Code and OpenCode paths that predate the connector-specific hooks.
func TestManagedOpenSharedInspectHooksBlockUnusableHTTP200(t *testing.T) {
	for _, tc := range []struct {
		name, body     string
		partial, stall bool
	}{
		{"malformed", `{"action":"block","action":"allow"}`, false, false},
		{"truncated 200", `{"action":"allow"}`, true, false},
		{"stalled 200", `{"action":"allow"}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.partial {
					w.Header().Set("Content-Length", strconv.Itoa(len(tc.body)+64))
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
				if tc.partial {
					w.(http.Flusher).Flush()
					if tc.stall {
						time.Sleep(1500 * time.Millisecond)
					}
					panic(http.ErrAbortHandler)
				}
			}))
			defer server.Close()
			home := t.TempDir()
			hooks := filepath.Join(home, "hooks")
			if err := writeHookScriptsCommonWithTransport(hooks, strings.TrimPrefix(server.URL, "http://"), "test-token", "open", HookFailModeSourceConfig, nil, true, "codex", true, "", "", false, false); err != nil {
				t.Fatal(err)
			}
			if tc.stall {
				helper := filepath.Join(hooks, "_hardening.sh")
				body, err := os.ReadFile(helper)
				if err != nil {
					t.Fatal(err)
				}
				short := strings.Replace(string(body), `--max-time "$_dc_post_max_time"`, `--max-time 1`, 1)
				if short == string(body) {
					t.Fatal("curl timeout not found")
				}
				if err := os.WriteFile(helper, []byte(short), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"inspect-request.sh", "inspect-tool.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
				t.Run(name, func(t *testing.T) {
					cmd := exec.Command("bash", filepath.Join(hooks, name))
					cmd.Stdin = strings.NewReader(`{"tool":"Bash","content":"marker"}`)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
					out, err := cmd.CombinedOutput()
					if !hookCallBlocked(err, string(out)) {
						t.Fatalf("managed outage-open hook allowed an unusable 200: %v %s", err, out)
					}
				})
			}
		})
	}
}

// Check the real jq path as well as the Python fallback; both previously
// collapsed duplicate keys or ignored a second JSON document.
func TestShellResponseParsersRejectAmbiguousJSON(t *testing.T) {
	for _, tier := range []string{"jq", "python"} {
		t.Run(tier, func(t *testing.T) {
			if tier == "jq" {
				if _, err := exec.LookPath("jq"); err != nil {
					t.Skip("jq is unavailable")
				}
			}
			parserPath := t.TempDir()
			for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					if entry.IsDir() || (entry.Name() == "jq" && tier != "jq") ||
						(strings.HasPrefix(entry.Name(), "python") && tier != "python") {
						continue
					}
					link := filepath.Join(parserPath, entry.Name())
					if _, err := os.Lstat(link); os.IsNotExist(err) {
						_ = os.Symlink(filepath.Join(dir, entry.Name()), link)
					}
				}
			}
			for i, body := range []string{`{"action":"block","action":"allow"}`, `{"action":"allow"}{}`} {
				t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						_, _ = w.Write([]byte(body))
					}))
					defer server.Close()
					conn := NewCodexConnector()
					invoke := hookArgvConnectorCase(t, conn.Name())
					home := t.TempDir()
					hooks := filepath.Join(home, "hooks")
					if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, SetupOpts{
						DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-token", HookFailMode: "open",
					}, conn); err != nil {
						t.Fatal(err)
					}
					bakeHookPathForTest(t, filepath.Join(hooks, invoke.script), parserPath)
					cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
					out, err := cmd.CombinedOutput()
					if !hookCallBlocked(err, string(out)) {
						t.Fatalf("%s parser allowed ambiguous answer %q: %v %s", tier, body, err, out)
					}
				})
			}
		})
	}
}

func TestShellFallbackUpgradeReplacesV9Helper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(path, []byte("#!/bin/bash\n# defenseclaw-managed-hook v9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookHelpers(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if parseHookSchemaVersion(got) != 10 || !strings.Contains(string(got), "function obj(level") {
		t.Fatal("upgrade retained the old shell decision parser")
	}
}

func TestShellMalformedHTTP200CannotUseOpenMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow","extra":[invalid]}`))
	}))
	defer server.Close()

	// Keep curl, bash, awk and sed, but force the supported awk parser tier.
	path := t.TempDir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == "jq" || strings.HasPrefix(entry.Name(), "python") {
				continue
			}
			link := filepath.Join(path, entry.Name())
			if _, err := os.Lstat(link); os.IsNotExist(err) {
				_ = os.Symlink(filepath.Join(dir, entry.Name()), link)
			}
		}
	}
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			invoke := hookArgvConnectorCase(t, conn.Name())
			if conn.Name() == "claudecode" {
				invoke.stdin = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
			}
			home := t.TempDir()
			hooks := filepath.Join(home, "hooks")
			if err := WriteHookScriptsForConnectorObjectWithOpts(hooks, SetupOpts{
				DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "test-token", HookFailMode: "open",
			}, conn); err != nil {
				t.Fatal(err)
			}
			bakeHookPathForTest(t, filepath.Join(hooks, invoke.script), path)
			cmd := exec.Command("bash", append([]string{filepath.Join(hooks, invoke.script)}, invoke.args...)...)
			cmd.Stdin = strings.NewReader(invoke.stdin)
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
			out, err := cmd.CombinedOutput()
			if !hookCallBlocked(err, string(out)) {
				t.Fatalf("malformed HTTP 200 allowed a tool: %v %s", err, out)
			}
		})
	}
}
