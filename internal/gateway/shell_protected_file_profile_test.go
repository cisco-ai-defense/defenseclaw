// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellProtectedFileHome is a home with the protected files of the
// GAP-0675 class and DefenseClaw state, beside a project.
func shellProtectedFileHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "notes.txt"),
	} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "keyslink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}

// shellProtectedFileRoute sends one shell command on the hook route of one
// connector (OpenClaw: its /inspect/tool route), per-user or managed, with
// the rule pack of posture, and returns the action and its rule ids.
func shellProtectedFileRoute(t *testing.T, home, cwd, connectorName, posture string, managed bool, command string) (string, []string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	ctx := context.Background()
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		// The managed hook client sends its reading of the write operands
		// with every shell call (hookpaths.Resolve).
		if body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}}); err == nil {
			if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
				ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
			}
		}
	}
	args := func(key string) json.RawMessage {
		raw, err := json.Marshal(map[string]string{key: command})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if connectorName == "openclaw" {
		verdict := api.inspectToolPolicyCtx(ctx, &ToolInspectRequest{
			Tool: "exec", Args: args("command"), Direction: "tool_call", Connector: "openclaw",
		})
		var ids []string
		for _, finding := range verdict.DetailedFindings {
			ids = append(ids, finding.RuleID)
		}
		return verdict.Action, ids
	}
	req := agentHookRequest{ConnectorName: connectorName, CWD: cwd}
	switch connectorName {
	case "claudecode":
		req.HookEventName, req.ToolName, req.ToolArgs = "PreToolUse", "Bash", args("command")
	case "codex":
		req.HookEventName, req.ToolName, req.ToolArgs = "PreToolUse", "Bash", args("command")
	case "copilot":
		req.HookEventName, req.ToolName, req.ToolArgs = "preToolUse", "bash", args("command")
	case "opencode":
		req.HookEventName, req.ToolName, req.ToolArgs = "tool.execute.before", "bash", args("command")
	case "hermes":
		req.HookEventName, req.ToolName, req.ToolArgs = "pre_tool_call", "terminal", args("command")
	default:
		t.Fatalf("no route for %s", connectorName)
	}
	resp := api.evaluateAgentHook(ctx, req)
	var ids []string
	for _, finding := range resp.Findings {
		ids = append(ids, strings.SplitN(finding, ":", 2)[0])
	}
	return resp.Action, ids
}

// rel-1-0-6:GAP-0675 (wave-3 steer 2): a protected file or link that a shell
// command names, directly, through a value it sets or through a link, blocks
// in every profile on every hook route, per-user and managed; the shell
// startup file write is at least an alert in every profile and blocks in
// strict; DefenseClaw self-protection blocks in every profile and an ordinary
// write is allowed in every profile. One test per connector, so no test
// holds a CI shard for minutes.
func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteClaudeCode(t *testing.T) {
	shellProtectedFileEveryRoute(t, "claudecode")
}

func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteCodex(t *testing.T) {
	shellProtectedFileEveryRoute(t, "codex")
}

func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteCopilot(t *testing.T) {
	shellProtectedFileEveryRoute(t, "copilot")
}

func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteOpenCode(t *testing.T) {
	shellProtectedFileEveryRoute(t, "opencode")
}

func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteHermes(t *testing.T) {
	shellProtectedFileEveryRoute(t, "hermes")
}

func TestGAP0675ShellProtectedFileKeepsItsBlockOnEveryRouteOpenClaw(t *testing.T) {
	shellProtectedFileEveryRoute(t, "openclaw")
}

// shellProtectedFileEveryRoute judges every row on the per-user and the
// managed route of one connector.
func shellProtectedFileEveryRoute(t *testing.T, connectorName string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	const keysRule, profileRule, stateRule = "persistence.ssh_authorized_keys_command", "persistence.shell_profile_write", "tamper.detector_state_write"
	everywhere := map[string]string{"default": "block", "permissive": "block", "strict": "block"}
	rows := []struct {
		name, command string
		// want is the action per posture; rule is the rule id an alert or
		// block must carry.
		want map[string]string
		rule string
	}{
		{"keys append", "echo marker >> ~/.ssh/authorized_keys", everywhere, keysRule},
		{"keys copy", "cp notes.txt ~/.ssh/authorized_keys", everywhere, keysRule},
		{"keys through a known value", `dst=~/.ssh/authorized_keys; echo marker >> "$dst"`, everywhere, keysRule},
		{"keys through a link", "echo marker >> ~/project/keyslink", everywhere, keysRule},
		{"keys copy onto a link", "cp ~/project/notes.txt ~/project/keyslink", everywhere, keysRule},
		{"shell profile append", "echo marker >> ~/.bashrc",
			map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}, profileRule},
		{"DefenseClaw state append", "printf changed >> ~/.defenseclaw/config.yaml", everywhere, stateRule},
		{"shell profile append after a patch word", "echo apply_patch; echo marker >> ~/.bashrc",
			map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}, profileRule},
		{"keys append after a patch header word", "echo '*** Begin Patch'; echo marker >> ~/.ssh/authorized_keys", everywhere, keysRule},
		{"ordinary write", "echo marker >> notes.txt",
			map[string]string{"default": "allow", "permissive": "allow", "strict": "allow"}, ""},
		{"ordinary write, patch word", "echo apply_patch >> notes.txt",
			map[string]string{"default": "allow", "permissive": "allow", "strict": "allow"}, ""},
		{"ordinary write, harmless word", "printf defenseclaw >> notes.txt",
			map[string]string{"default": "allow", "permissive": "allow", "strict": "allow"}, ""},
	}
	// Each row is judged in one profile on one gateway; the cell moves one
	// step a row and one step a connector, so every row meets every profile,
	// per-user and managed, across the six connector tests.
	type cell struct {
		posture string
		managed bool
	}
	var cells []cell
	for _, managed := range []bool{false, true} {
		for _, posture := range []string{"default", "permissive", "strict"} {
			cells = append(cells, cell{posture, managed})
		}
	}
	offset := slices.Index([]string{"claudecode", "codex", "copilot", "opencode", "hermes", "openclaw"}, connectorName)
	for index, row := range rows {
		c := cells[(index+offset)%len(cells)]
		name := fmt.Sprintf("%s %s managed=%t %s", connectorName, c.posture, c.managed, row.name)
		t.Run(name, func(t *testing.T) {
			action, rules := shellProtectedFileRoute(t, home, cwd, connectorName, c.posture, c.managed, row.command)
			if want := row.want[c.posture]; action != want {
				t.Fatalf("action=%q want %q rules=%v", action, want, rules)
			}
			if row.rule != "" && !slices.Contains(rules, row.rule) {
				t.Errorf("rules=%v want %s", rules, row.rule)
			}
		})
	}
}

// The profile floor reads only the class mark and the self-protection
// rules: a native write tool and a rule outside the class set no floor, a
// finding that could not block sets none either, a class finding is at least
// an alert and a self-protection finding at least a block in every posture,
// and the Secure Client integration changes nothing.
func TestGAP0675ShellProtectedFileFloorDecision(t *testing.T) {
	marked := RuleFinding{RuleID: "persistence.shell_profile_write", Severity: "HIGH", shellProtectedFile: true}
	native := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	state := RuleFinding{RuleID: "tamper.detector_state_write", Severity: "HIGH"}
	detection := RuleFinding{RuleID: "PATH-SSH-DIR", Severity: "HIGH", shellProtectedFile: true, enforcement: findingEnforcementDetectionOnly}
	stateDetection := RuleFinding{RuleID: "tamper.detector_state_write", Severity: "HIGH", enforcement: findingEnforcementDetectionOnly}
	for _, tc := range []struct {
		name         string
		findings     []RuleFinding
		secureClient bool
		floor        string
	}{
		{"class", []RuleFinding{marked, native, detection}, false, "alert"},
		{"class with Secure Client", []RuleFinding{marked}, true, "allow"},
		{"native tool", []RuleFinding{native}, false, "allow"},
		{"self-protection", []RuleFinding{state, marked}, false, "block"},
		{"self-protection with Secure Client", []RuleFinding{state}, true, "allow"},
		{"detection only sets no floor", []RuleFinding{detection, stateDetection, native}, false, "allow"},
	} {
		before := slices.Clone(tc.findings)
		if floor := profileClassFloor(tc.findings, tc.secureClient); floor != tc.floor {
			t.Errorf("%s: floor=%q want %q", tc.name, floor, tc.floor)
		}
		if !reflect.DeepEqual(before, tc.findings) {
			t.Fatalf("%s: the floor changed the caller findings", tc.name)
		}
	}
	for _, tc := range []struct {
		tool, command string
		shell         bool
	}{
		{"Bash", "", true}, {"shell", "", true}, {"exec_command", "", true}, {"terminal", "", true},
		{"write_file", "", false}, {"Write", "", false}, {"apply_patch", "x", false}, {"persist", "", false},
		{"anything", "echo x", true},
		// The word apply_patch in a shell call does not take the call out of
		// the class: a separate write in the same call keeps its floor.
		{"Bash", "echo apply_patch; echo x >> ~/.bashrc", true},
		{"exec_command", "cat k.patch | applypatch", true},
	} {
		marks := markShellProtectedFileFindings(trustedActionRequest{Input: actionfacts.Input{Tool: tc.tool, Command: tc.command}},
			[]RuleFinding{{RuleID: "PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND"}, {RuleID: "tamper.detector_state_write"}})
		if marks[0].shellProtectedFile != tc.shell || marks[1].shellProtectedFile {
			t.Errorf("%s %q: marks=%v,%v want %v,false", tc.tool, tc.command, marks[0].shellProtectedFile, marks[1].shellProtectedFile, tc.shell)
		}
	}
}

// rel-1-0-6:GAP-0675: the class covers shell commands only. A native write
// tool that writes the authorized-keys file keeps its block in the default
// profile, per-user and managed.
func TestGAP0675NativeWriteToolKeepsItsBlockInDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home, cwd := shellProtectedFileHome(t)
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	args, err := json.Marshal(map[string]string{"file_path": filepath.Join(home, ".ssh", "authorized_keys"), "content": "marker\n"})
	if err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{false, true} {
		ctx := context.Background()
		if managed {
			ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		}
		resp := api.evaluateAgentHook(ctx, agentHookRequest{
			ConnectorName: "claudecode", HookEventName: "PreToolUse", ToolName: "Write", ToolArgs: args, CWD: cwd,
		})
		if resp.Action != "block" {
			t.Errorf("managed=%v: Write to authorized_keys action=%q findings=%v, want block", managed, resp.Action, resp.Findings)
		}
	}
}

// rel-1-0-6:GAP-0675: on the Claude Code hook route the audit row records the
// action the profile answered with and the rule id: a call that names the keys
// file blocks in the default and strict profiles, a shell startup file write
// is an alert in the default and permissive profiles and a block in strict.
func TestGAP0675ShellProtectedFileAuditRowRecordsTheDecision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	_, cwd := shellProtectedFileHome(t)
	const keys, profile = "persistence.ssh_authorized_keys_command", "persistence.shell_profile_write"
	for _, tc := range []struct{ name, posture, command, want, rule string }{
		{"default keys", "default", "echo marker >> ~/.ssh/authorized_keys", "block", keys},
		{"strict keys", "strict", "echo marker >> ~/.ssh/authorized_keys", "block", keys},
		{"default startup file", "default", "echo marker >> ~/.bashrc", "alert", profile},
		{"permissive startup file", "permissive", "echo marker >> ~/.bashrc", "alert", profile},
		{"strict startup file", "strict", "echo marker >> ~/.bashrc", "block", profile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", tc.posture)
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tc.posture)
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg, health: NewSidecarHealth()}
			body, err := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "gap0675-" + tc.name, "tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]any{"command": tc.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(w, req)
			var answer struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || answer.Action != tc.want {
				t.Fatalf("answer=%s err=%v, want action %q", w.Body.String(), err, tc.want)
			}
			row := soleHookDecisionForTest(t, store)
			recorded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			if row.Structured["action"] != tc.want || !strings.Contains(string(recorded), tc.rule) {
				t.Fatalf("audit row=%s, want action %q with %s", recorded, tc.want, tc.rule)
			}
		})
	}
}
