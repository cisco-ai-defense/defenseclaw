// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// ampShellToolHook sends one Amp plugin tool.call (the plugin's body fields)
// through evaluateAgentHook in the given guardrail mode.
func ampShellToolHook(t *testing.T, mode, tool, args string) agentHookResponse {
	t.Helper()
	session := t.TempDir()
	args = strings.ReplaceAll(args, "{PROJ}", session)
	body := `{"hook_event_name":"tool.call","session_id":"T-g694","thread_id":"T-g694","turn_id":"t1","message_id":"t1",` +
		`"tool_call_id":"tc-1","source_event_id":"e-1","source_sequence":"1","executor_kind":"local","cwd":"` + session + `",` +
		`"tool_name":"` + tool + `","tool_input":` + args + `,"delegation_boundary":false}`
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	profile := connectorProfileForHostTest(t, connector.NewDefaultRegistry(), "amp")
	req := normalizeAgentHookRequestWithRawProfileEvent("amp", payload, []byte(body), profile, "", "")
	req.CWD = hookCWDForContext(context.Background(), req.CWD)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = "amp"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	return api.evaluateAgentHook(context.Background(), req)
}

// TestAmpBashExtraArgumentKeys: Amp's Bash tool (also reported as bash)
// holds its command under cmd. Called with cmd alone or cmd and cwd it was
// projected onto the shell shape and blocked; any other key next to cmd
// (timeout_ms, a note, an unknown key), or the key command instead of cmd
// with another key, left the parse partial and the tool was not a shell
// tool to the command-alone check, so the same command was allowed as
// detection-only in action mode (GAP-0694). Benign commands stay allowed
// and observe mode stays observe.
func TestAmpBashExtraArgumentKeys(t *testing.T) {
	installSandboxMarkerRules(t)
	const m = `"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"`
	for _, tool := range []string{"Bash", "bash"} {
		for _, row := range []struct{ name, args, rule string }{
			{"cmd", `{"cmd":` + m + `}`, "E2E-SANDBOX-MARKER"},
			{"cmd-cwd", `{"cmd":` + m + `,"cwd":"{PROJ}"}`, "E2E-SANDBOX-MARKER"},
			{"cmd-timeout", `{"cmd":` + m + `,"timeout_ms":5000}`, "E2E-SANDBOX-MARKER"},
			{"cmd-note", `{"cmd":` + m + `,"note":"x"}`, "E2E-SANDBOX-MARKER"},
			{"cmd-unknown", `{"cmd":` + m + `,"zz":1}`, "E2E-SANDBOX-MARKER"},
			{"cmd-cwd-unknown", `{"cmd":` + m + `,"cwd":"{PROJ}","zz":null}`, "E2E-SANDBOX-MARKER"},
			{"cmd-cwd-mistyped", `{"cmd":` + m + `,"cwd":7}`, "E2E-SANDBOX-MARKER"},
			{"command", `{"command":` + m + `}`, "E2E-SANDBOX-MARKER"},
			{"command-unknown", `{"command":` + m + `,"zz":1}`, "E2E-SANDBOX-MARKER"},
			{"command-cwd-timeout", `{"command":` + m + `,"cwd":"{PROJ}","timeout_ms":5000}`, "E2E-SANDBOX-MARKER"},
			{"both-same", `{"cmd":` + m + `,"command":` + m + `,"zz":1}`, "E2E-SANDBOX-MARKER"},
			// Two different commands: no single command to judge, a block
			// (conflicting or unverified arguments) either way round.
			{"both-differ", `{"cmd":"true","command":` + m + `}`, ""},
			{"both-differ-marker-in-cmd", `{"cmd":` + m + `,"command":"true"}`, ""},
			{"no-command", `{"cwd":"{PROJ}","zz":1}`, unverifiedShellCommandRuleID},
			// Hard negatives: benign commands with extra keys stay allowed.
			{"benign-cmd-timeout", `{"cmd":"ls -la","timeout_ms":5000}`, "allow"},
			{"benign-cmd-cwd-note", `{"cmd":"git status","cwd":"{PROJ}","note":"x"}`, "allow"},
			{"benign-command-unknown", `{"command":"ls","zz":1}`, "allow"},
			{"benign-marker-in-dropped-key", `{"cmd":"ls","note":"DCE2E-BLOCK-MARKER"}`, "allow"},
		} {
			t.Run(tool+"/"+row.name, func(t *testing.T) {
				resp := ampShellToolHook(t, "action", tool, row.args)
				if row.rule == "allow" {
					if resp.RawAction == "block" || resp.Action == "block" {
						t.Fatalf("benign call blocked: action %q raw %q reason %q", resp.Action, resp.RawAction, resp.Reason)
					}
					return
				}
				if resp.Action != "block" || resp.RawAction != "block" || !strings.Contains(resp.Reason, row.rule) {
					t.Fatalf("action %q raw %q reason %q; want block with %s", resp.Action, resp.RawAction, resp.Reason, row.rule)
				}
			})
		}
	}
	// Observe mode stays observe: the same calls are recorded, not blocked.
	for _, args := range []string{`{"cmd":` + m + `,"timeout_ms":5000}`, `{"command":` + m + `,"zz":1}`} {
		resp := ampShellToolHook(t, "observe", "Bash", args)
		if resp.Action == "block" {
			t.Fatalf("observe mode blocked %s: %+v", args, resp)
		}
	}
}

// TestRefusedShellProjectionKeepsTheCallsDirectory: a shell call whose
// projection is refused (an extra or mistyped argument) still names the
// directory its command runs in; the command judged on its own is judged
// there, not in the session's (GAP-0694: Amp's Bash and agy's run_command).
func TestRefusedShellProjectionKeepsTheCallsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app")
	for _, tc := range []struct{ connector, tool, args string }{
		{"amp", "Bash", `{"cmd":"ls","cwd":"` + dir + `","zz":1}`},
		{"amp", "bash", `{"cmd":"ls","cwd":"` + dir + `","timeout_ms":5}`},
		{"antigravity", "run_command", `{"CommandLine":"ls","Cwd":"` + dir + `","toolAction":"a","Extra":"b"}`},
		{"amp", "shell_command", `{"command":"ls","workdir":"` + dir + `","timeout_ms":"soon"}`},
	} {
		got, cwd := agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
		if string(got) != tc.args || cwd != dir {
			t.Errorf("%s %s: args %s cwd %q; want the call unchanged and cwd %q", tc.connector, tc.tool, got, cwd, dir)
		}
	}
}
