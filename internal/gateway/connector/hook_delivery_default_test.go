// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the generated managed scripts, not just their rendered FAIL_MODE.
// This is the Secure Client delivery contract (#1163): unset delivers open.
func TestManagedHookDeliveryDefaultAndExplicitClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	// Codex handlers are registered with their bound event and contract, and
	// Cursor names its events in lower camel case.
	for _, agent := range []struct {
		conn    Connector
		script  string
		args    []string
		payload string
	}{
		{NewCodexConnector(), "codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v1"}, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"private-payload-marker"}}`},
		{NewClaudeCodeConnector(), "claude-code-hook.sh", nil, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"private-payload-marker"}}`},
		{NewCursorConnector(), "cursor-hook.sh", nil, `{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"private-payload-marker"}}`},
	} {
		for _, mode := range []string{"", "open", "closed"} {
			for _, scenario := range []string{"outage", "malformed", "missing-token", "oversized", "policy-deny", "strict-outage"} {
				t.Run(agent.conn.Name()+"/"+mode+"/"+scenario, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Header.Get("Authorization") == "" {
							t.Error("hook attempted an unauthenticated request")
						}
						if scenario == "policy-deny" {
							_, _ = w.Write([]byte(`{"action":"block","reason":"blocked by policy","hook_output":{"continue":false,"permission":"deny"}}`))
						} else {
							_, _ = w.Write([]byte("not-json"))
						}
					}))
					defer server.Close()
					addr := strings.TrimPrefix(server.URL, "http://")
					if scenario == "outage" || scenario == "strict-outage" {
						addr = "127.0.0.1:1"
					}
					home := t.TempDir()
					hookDir := filepath.Join(home, "hooks")
					opts := SetupOpts{DataDir: home, APIAddr: addr, APIToken: "scoped-test-token", ManagedEnterprise: true, HookFailMode: mode, SecureClientHookDelivery: true}
					if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, agent.conn); err != nil {
						t.Fatal(err)
					}
					if scenario == "missing-token" {
						token, err := HookTokenFilePath(hookDir, agent.conn.Name())
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(token); err != nil {
							t.Fatal(err)
						}
					}
					cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, agent.script)}, agent.args...)...)
					cmd.Stdin = strings.NewReader(agent.payload)
					// An inherited open flag must not downgrade explicit managed closed.
					cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_FAIL_MODE=open"}
					if scenario == "strict-outage" {
						cmd.Env = append(cmd.Env, "DEFENSECLAW_STRICT_AVAILABILITY=1")
					}
					if scenario == "oversized" {
						cmd.Env = append(cmd.Env, "DEFENSECLAW_HOOK_MAX_BODY=1")
					}
					out, err := cmd.CombinedOutput()
					closed := mode == "closed" || scenario == "strict-outage" || scenario == "policy-deny"
					blocked := err != nil || strings.Contains(string(out), `"decision":"block"`) || strings.Contains(string(out), `"permission":"deny"`)
					if blocked != closed {
						t.Fatalf("blocked=%t want=%t err=%v output=%s", blocked, closed, err, out)
					}
					failure, logErr := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
					if scenario == "policy-deny" {
						if !os.IsNotExist(logErr) || strings.Contains(string(out), "inspection bypassed") {
							t.Fatalf("policy denial mislabeled: log=%s err=%v output=%s", failure, logErr, out)
						}
						return
					}
					if logErr != nil {
						t.Fatal(logErr)
					}
					var record map[string]string
					if err := json.Unmarshal(failure, &record); err != nil {
						t.Fatalf("expected one failure record: %v: %s", err, failure)
					}
					want := "fail_open"
					if closed {
						want = "fail_closed"
					}
					if record["connector"] != agent.conn.Name() || record["outcome"] != want || strings.Contains(string(out), "WARNING hook fail-open") == closed {
						t.Fatalf("incorrect diagnostic: record=%+v output=%s", record, out)
					}
					for _, secret := range []string{"private-payload-marker", "scoped-test-token"} {
						if strings.Contains(string(failure)+string(out), secret) {
							t.Fatalf("diagnostic leaked %q", secret)
						}
					}
				})
			}
		}
	}
}

func TestManagedNativeHookSidecarDeliveryModes(t *testing.T) {
	for _, mode := range []string{"", "open", "closed", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := ReconcileManagedNativeHookRuntime(dir, "127.0.0.1:18970", "codex", "scoped-token", mode); err != nil {
				t.Fatal(err)
			}
			if err := ValidateManagedNativeHookRuntime(dir, "127.0.0.1:18970", "codex", mode); err != nil {
				t.Fatal(err)
			}
			other := "closed"
			if normalizeHookFailMode(mode) == "closed" {
				other = "open"
			}
			if err := ValidateManagedNativeHookRuntime(dir, "127.0.0.1:18970", "codex", other); err == nil {
				t.Fatal("sidecar accepted a mode different from protected installation state")
			}
		})
	}
}

func TestShellFailOpenWarningEscapingAndLogWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	for _, writable := range []bool{true, false} {
		t.Run(map[bool]string{true: "writable", false: "unwritable"}[writable], func(t *testing.T) {
			home := t.TempDir()
			hooks := filepath.Join(home, "hooks")
			if err := WriteHookScriptsWithToken(hooks, "127.0.0.1:1", "test-token"); err != nil {
				t.Fatal(err)
			}
			if !writable {
				if err := os.WriteFile(filepath.Join(home, "logs"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `. "$1"; FAIL_MODE=open; defenseclaw_log_hook_delivery_failure codex codex-hook $'offline\nforged' transport open`, "test", filepath.Join(hooks, "_hardening.sh"))
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_HOME=" + home}
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "WARNING hook fail-open") || strings.Count(string(out), "\n") != 1 {
				t.Fatalf("warning failed or forged line: err=%v output=%q", err, out)
			}
			if writable {
				failure, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				var record map[string]string
				if err := json.Unmarshal(failure, &record); err != nil || record["reason"] != "offline forged" || record["outcome"] != "fail_open" {
					t.Fatalf("invalid escaped record: %v: %s", err, failure)
				}
			}
		})
	}
}

// TestNormalizeHookFailModeOpenIgnoresCase mirrors the config resolvers: the
// "open" sentinel is case-insensitive after trimming; anything else, empty
// included, stays closed.
func TestNormalizeHookFailModeOpenIgnoresCase(t *testing.T) {
	for raw, want := range map[string]string{
		"":         "closed",
		"  ":       "closed",
		"open":     "open",
		"Open":     "open",
		" OPEN ":   "open",
		"closed":   "closed",
		"Closed":   "closed",
		"opn":      "closed",
		"open-ish": "closed",
	} {
		if got := normalizeHookFailMode(raw); got != want {
			t.Errorf("normalizeHookFailMode(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestManagedHookDeliveryOutsideSecureClientFailsClosed keeps origin/main's
// managed contract for every profile but Secure Client: an unset mode renders
// closed, and a managed hook blocks on a gateway outage or a missing token
// even when its baked mode is open. Response failures follow the baked mode.
func TestManagedHookDeliveryOutsideSecureClientFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows uses the authenticated hook executor")
	}
	for _, mode := range []string{"", "open", "closed"} {
		for _, scenario := range []string{"outage", "missing-token", "malformed"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("not-json"))
				}))
				defer server.Close()
				addr := strings.TrimPrefix(server.URL, "http://")
				if scenario == "outage" {
					addr = "127.0.0.1:1"
				}
				home := t.TempDir()
				hookDir := filepath.Join(home, "hooks")
				// A standalone managed install names its administrator-owned
				// hook binary, so the hook is not a Secure Client hook.
				opts := SetupOpts{DataDir: home, APIAddr: addr, APIToken: "scoped-test-token", ManagedEnterprise: true,
					HookFailMode: mode, ManagedHookBinary: "/usr/local/libexec/defenseclaw-hook"}
				conn := NewCodexConnector()
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				script, err := os.ReadFile(filepath.Join(hookDir, "codex-hook.sh"))
				if err != nil {
					t.Fatal(err)
				}
				wantBaked := "closed"
				if mode == "open" {
					wantBaked = "open"
				}
				if !strings.Contains(string(script), `FAIL_MODE="`+wantBaked+`"`) || !strings.Contains(string(script), "_DC_SECURE_CLIENT_HOOK=0") {
					t.Fatalf("managed non-Secure-Client hook baked the wrong delivery mode (want %s)", wantBaked)
				}
				if scenario == "missing-token" {
					token, err := HookTokenFilePath(hookDir, conn.Name())
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(token); err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.Command("bash", filepath.Join(hookDir, "codex-hook.sh"), "--event", "PreToolUse", "--hook-contract", "codex-hooks-v1")
				cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DEFENSECLAW_FAIL_MODE=open"}
				out, err := cmd.CombinedOutput()
				blocked := err != nil || strings.Contains(string(out), `"decision":"block"`)
				// The baked mode is the administrator's (owner decision
				// 2026-10-20): open lets an outage and an unusable answer
				// through; a missing token is a broken install and blocks.
				wantBlocked := scenario == "missing-token" || wantBaked == "closed"
				if blocked != wantBlocked {
					t.Fatalf("blocked=%t want=%t err=%v output=%s", blocked, wantBlocked, err, out)
				}
			})
		}
	}
}

// TestResolveHookFailModeSecureClientOnlyOpenDefault is the renderer half of
// the owner rule: an unset mode renders open only under Secure Client, and
// Cursor's action/observe rule applies everywhere else. Under Secure Client
// an explicit mode wins for every connector (#1163).
func TestResolveHookFailModeSecureClientOnlyOpenDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts SetupOpts
		conn Connector
		want string
	}{
		{"oss codex unset", SetupOpts{}, NewCodexConnector(), "closed"},
		{"oss claudecode unset", SetupOpts{}, NewClaudeCodeConnector(), "closed"},
		{"managed codex unset", SetupOpts{ManagedEnterprise: true}, NewCodexConnector(), "closed"},
		{"oss cursor action explicit open", SetupOpts{GuardrailMode: "action", HookFailMode: "open"}, NewCursorConnector(), "closed"},
		{"oss cursor observe explicit closed", SetupOpts{GuardrailMode: "observe", HookFailMode: "closed"}, NewCursorConnector(), "open"},
		{"oss explicit Open", SetupOpts{HookFailMode: " Open "}, NewCodexConnector(), "open"},
		{"secure client codex unset", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true}, NewCodexConnector(), "open"},
		{"secure client claudecode unset with enforcement", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, ClaudeCodeEnforcement: true}, NewClaudeCodeConnector(), "open"},
		{"secure client cursor action unset", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, GuardrailMode: "action"}, NewCursorConnector(), "open"},
		{"secure client cursor observe explicit closed", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, GuardrailMode: "observe", HookFailMode: "closed"}, NewCursorConnector(), "closed"},
		{"secure client codex explicit closed", SetupOpts{ManagedEnterprise: true, SecureClientHookDelivery: true, HookFailMode: "closed"}, NewCodexConnector(), "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveHookFailMode(tc.opts, tc.conn); got != tc.want {
				t.Fatalf("resolveHookFailMode = %q, want %q", got, tc.want)
			}
		})
	}
}
