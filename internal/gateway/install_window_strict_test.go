// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// installWindowCalls are benign calls of every hook surface a per-user
// install registers, each sent as its hook sends it. actionable calls are
// tool calls and prompts the connector can refuse; the others are lifecycle,
// stop and result events, which the install window never gates.
var installWindowCalls = []struct {
	name, connector, route, header, event, body string
	actionable                                  bool
}{
	{"claude code tool call", "claudecode", "/api/v1/claude-code/hook", "", "PreToolUse",
		`{"hook_event_name":"PreToolUse","session_id":"s-iw","tool_name":"Bash","tool_input":{"command":"echo ok"},"cwd":"/tmp"}`, true},
	{"claude code prompt", "claudecode", "/api/v1/claude-code/hook", "", "UserPromptSubmit",
		`{"hook_event_name":"UserPromptSubmit","session_id":"s-iw","prompt":"list the files","cwd":"/tmp"}`, true},
	{"codex tool call", "codex", "/api/v1/codex/hook", "X-DefenseClaw-Hook-Event", "PreToolUse",
		`{"hook_event_name":"PreToolUse","session_id":"s-iw","tool_name":"Bash","tool_input":{"command":"echo ok"},"cwd":"/tmp"}`, true},
	{"copilot tool call", "copilot", "/api/v1/copilot/hook", "X-DefenseClaw-Copilot-Event", "preToolUse",
		`{"sessionId":"s-iw","timestamp":1,"cwd":"/tmp","toolName":"bash","toolArgs":{"command":"echo ok"}}`, true},
	{"cursor shell", "cursor", "/api/v1/cursor/hook", "", "beforeShellExecution",
		`{"hook_event_name":"beforeShellExecution","conversation_id":"c1","generation_id":"g1","command":"ls","cwd":"/tmp","workspace_roots":["/tmp"]}`, true},
	{"opencode tool call", "opencode", "/api/v1/opencode/hook", "", "tool.execute.before",
		`{"hook_event_name":"tool.execute.before","session_id":"s-iw","tool_name":"bash","tool_input":{"command":"echo ok"},"cwd":"/tmp"}`, true},
	{"hermes tool call", "hermes", "/api/v1/hermes/hook", "", "pre_tool_call", nativeHookEventShapes[5].body, true},
	{"claude code session start", "claudecode", "/api/v1/claude-code/hook", "", "SessionStart",
		`{"hook_event_name":"SessionStart","session_id":"s-iw","source":"startup","cwd":"/tmp"}`, false},
	{"claude code stop", "claudecode", "/api/v1/claude-code/hook", "", "Stop",
		`{"hook_event_name":"Stop","session_id":"s-iw","stop_hook_active":false,"cwd":"/tmp"}`, false},
	{"claude code tool result", "claudecode", "/api/v1/claude-code/hook", "", "PostToolUse",
		`{"hook_event_name":"PostToolUse","session_id":"s-iw","tool_name":"Bash","tool_input":{"command":"echo ok"},"tool_response":{"stdout":"ok"},"cwd":"/tmp"}`, false},
	{"opencode lifecycle", "opencode", "/api/v1/opencode/hook", "", "session.idle", nativeHookEventShapes[1].body, false},
	{"hermes session start", "hermes", "/api/v1/hermes/hook", "", "on_session_start", nativeHookEventShapes[3].body, false},
}

// installWindowServer is a per-user gateway whose connector uses the built-in
// pack of tier, in guardrail mode, with its data directory at dataDir.
func installWindowServer(t *testing.T, connectorName, tier, mode, dataDir string, edit func(*config.Config)) *APIServer {
	t.Helper()
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier)
	if edit != nil {
		edit(cfg)
	}
	store, logger := testStoreAndLogger(t)
	return &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
}

func sendInstallWindowCall(t *testing.T, api *APIServer, call struct {
	name, connector, route, header, event, body string
	actionable                                  bool
}) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, call.route, strings.NewReader(call.body))
	req.Header.Set("Content-Type", "application/json")
	if call.header != "" {
		req.Header.Set(call.header, call.event)
	}
	if call.connector == "codex" {
		req.Header.Set("X-DefenseClaw-Hook-Contract", api.hookProfileForRequest(t.Context(), "codex").ContractID)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body.String()
}

func holdInstallLock(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, ".install.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// GAP-1438 (owner decision 2026-10-24, GAP-1372): while an install or
// upgrade of the account holds its data directory, a per-user gateway in the
// strict tier blocks every tool call and prompt with the install reason,
// although its policy allows the call, in action and observe mode. The
// default and permissive tiers keep the gateway's answer. Lifecycle, stop
// and result events are never gated, and without the lock (control) every
// tier answers as before.
func TestStrictTierBlocksAnsweredCallsDuringTheInstallWindow(t *testing.T) {
	for _, call := range installWindowCalls {
		for _, tier := range []string{"strict", "default", "permissive"} {
			for _, mode := range []string{"action", "observe"} {
				t.Run(call.name+"/"+tier+"/"+mode, func(t *testing.T) {
					t.Setenv("DEFENSECLAW_HOME", t.TempDir())
					dataDir := t.TempDir()
					api := installWindowServer(t, call.connector, tier, mode, dataDir, nil)
					code, body := sendInstallWindowCall(t, api, call)
					if code != http.StatusOK || strings.Contains(body, hookInstallWindowStrictRuleID) || strings.Contains(body, `"action":"block"`) {
						t.Fatalf("no install lock (control): status=%d body=%s, want the policy's allow", code, body)
					}
					holdInstallLock(t, dataDir)
					code, body = sendInstallWindowCall(t, api, call)
					if code != http.StatusOK {
						t.Fatalf("install window: status=%d body=%s", code, body)
					}
					blocked := strings.Contains(body, `"action":"block"`) && strings.Contains(body, hookInstallWindowStrictRuleID) &&
						strings.Contains(body, "strict policy tier lets no call run")
					if want := tier == "strict" && call.actionable; blocked != want {
						t.Fatalf("install window, %s tier: blocked=%v, want %v: %s", tier, blocked, want, body)
					}
					if !blocked && (strings.Contains(body, hookInstallWindowStrictRuleID) || strings.Contains(body, `"action":"block"`)) {
						t.Fatalf("install window, %s tier: the gateway's allow was not kept: %s", tier, body)
					}
				})
			}
		}
	}
}

// The installer takes the lock in the directory DEFENSECLAW_HOME names; a
// gateway whose data_dir is elsewhere sees it there too. A lock of another
// type (a file, a symlink) is held as the hooks read it.
func TestStrictInstallWindowReadsTheInstallersLockLocation(t *testing.T) {
	call := installWindowCalls[0]
	for _, kind := range []string{"DEFENSECLAW_HOME folder", "data_dir file", "data_dir symlink"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			dataDir := t.TempDir()
			api := installWindowServer(t, call.connector, "strict", "action", dataDir, nil)
			lock := filepath.Join(dataDir, ".install.lock")
			switch kind {
			case "DEFENSECLAW_HOME folder":
				holdInstallLock(t, home)
			case "data_dir file":
				if err := os.WriteFile(lock, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "data_dir symlink":
				if err := os.Symlink(filepath.Join(dataDir, "missing"), lock); err != nil {
					t.Skipf("symlink: %v", err)
				}
			}
			if _, body := sendInstallWindowCall(t, api, call); !strings.Contains(body, hookInstallWindowStrictRuleID) {
				t.Fatalf("%s lock not held: %s", kind, body)
			}
		})
	}
}

// Managed and Secure Client gateways never read the per-user install lock:
// their own lifecycle closes their hooks, and a user's lock cannot change an
// administrator's answer.
func TestStrictInstallWindowLeavesManagedGatewaysAlone(t *testing.T) {
	call := installWindowCalls[0]
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	dataDir := t.TempDir()
	api := installWindowServer(t, call.connector, "strict", "action", dataDir, func(cfg *config.Config) {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	})
	holdInstallLock(t, dataDir)
	if api.perUserInstallWindowHeld() {
		t.Fatal("a managed gateway reads the per-user install lock")
	}
}

// One warning per install window in the default tier: the first answered
// call logs it, later calls do not, and a call after the lock is released
// arms it for the next window.
func TestDefaultTierInstallWindowWarnsOncePerWindow(t *testing.T) {
	call := installWindowCalls[0]
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	dataDir := t.TempDir()
	api := installWindowServer(t, call.connector, "default", "action", dataDir, nil)
	holdInstallLock(t, dataDir)
	sendInstallWindowCall(t, api, call)
	if !api.installWindowWarned.Load() {
		t.Fatal("no install-window warning in the default tier")
	}
	if api.installWindowWarned.CompareAndSwap(false, true) {
		t.Fatal("warning not recorded as given")
	}
	if err := os.Remove(filepath.Join(dataDir, ".install.lock")); err != nil {
		t.Fatal(err)
	}
	sendInstallWindowCall(t, api, call)
	if api.installWindowWarned.Load() {
		t.Fatal("the warning is not armed again after the install window")
	}
}
