// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestShellToolConflictingCommandKeysWithAnExtraKey pins rel-1-0-6:GAP-0132:
// a shell tool call whose cmd and command keys hold two different commands
// has no one command to verify, also when one more key the projection does
// not know comes with it. On every shell tool name it is blocked in action
// mode, as Bash and bash are; the same value under both keys is the one
// command it names (GAP-0696), judged by its own rules.
// newAmpShellToolHooks is ampShellToolHook for one guardrail mode, with one
// audit store, gateway and session directory shared by every call (the
// store and its migrations are the slow part of a call). Each call names its
// own session, so no call sees the state of another.
func newAmpShellToolHooks(t *testing.T, mode string) func(t *testing.T, session, tool, args string) agentHookResponse {
	t.Helper()
	dir := t.TempDir()
	profile := connectorProfileForHostTest(t, connector.NewDefaultRegistry(), "amp")
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = mode
	cfg.Guardrail.Connector = "amp"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	return func(t *testing.T, session, tool, args string) agentHookResponse {
		t.Helper()
		id := "T-g132-" + session
		body := `{"hook_event_name":"tool.call","session_id":"` + id + `","thread_id":"` + id + `","turn_id":"t1","message_id":"t1",` +
			`"tool_call_id":"tc-1","source_event_id":"e-1","source_sequence":"1","executor_kind":"local","cwd":"` + dir + `",` +
			`"tool_name":"` + tool + `","tool_input":` + args + `,"delegation_boundary":false}`
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatal(err)
		}
		req := normalizeAgentHookRequestWithRawProfileEvent("amp", payload, []byte(body), profile, "", "")
		req.CWD = hookCWDForContext(context.Background(), req.CWD)
		return api.evaluateAgentHook(context.Background(), req)
	}
}

func TestShellToolConflictingCommandKeysWithAnExtraKey(t *testing.T) {
	installSandboxMarkerRules(t)
	action, observe := newAmpShellToolHooks(t, "action"), newAmpShellToolHooks(t, "observe")
	const m = `"echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt"`
	for _, tool := range []string{"async_shell_command", "run_command", "terminal", "exec", "shell_command", "Shell", "Bash", "bash"} {
		for _, row := range []struct {
			name, args string
			block      bool
		}{
			{"command-marker+cmd-benign+zz", `{"command":` + m + `,"cmd":"true","zz":1}`, true},
			{"cmd-marker+command-benign+zz", `{"cmd":` + m + `,"command":"true","zz":1}`, true},
			{"both-marker+zz", `{"command":` + m + `,"cmd":` + m + `,"zz":1}`, true},
			{"command-benign+cmd-other+zz", `{"command":"ls","cmd":"date","zz":1}`, true},
			{"command-marker+cmd-benign", `{"command":` + m + `,"cmd":"true"}`, true},
			// Hard negatives: one command under both keys, with or without
			// an extra key, and one key with an extra key.
			{"benign-both-same+zz", `{"command":"ls -la","cmd":"ls -la","zz":1}`, false},
			{"benign-both-same", `{"command":"ls -la","cmd":"ls -la"}`, false},
			{"benign-command+zz", `{"command":"ls -la","zz":1}`, false},
		} {
			t.Run(tool+"/"+row.name, func(t *testing.T) {
				// One shared gateway serves concurrent hook calls, as it
				// does in production; the marker rules stay installed
				// until every subtest is done.
				t.Parallel()
				resp := action(t, tool+"-"+row.name, tool, row.args)
				blocked := resp.Action == "block" && resp.RawAction == "block"
				if blocked != row.block {
					t.Fatalf("blocked = %t, want %t: action %q raw %q reason %q", blocked, row.block, resp.Action, resp.RawAction, resp.Reason)
				}
			})
		}
	}
	resp := observe(t, "observe", "async_shell_command", `{"command":"ls","cmd":"date","zz":1}`)
	if resp.Action == "block" {
		t.Fatalf("observe mode blocked: %+v", resp)
	}
}
