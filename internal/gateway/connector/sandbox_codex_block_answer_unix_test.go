// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// codexBlockReason is the reason a Codex block object on stdout shows.
func codexBlockReason(stdout string) string {
	var answer map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &answer) != nil {
		return ""
	}
	nested, _ := answer["hookSpecificOutput"].(map[string]any)
	decision, _ := nested["decision"].(map[string]any)
	for _, v := range []any{answer["reason"], answer["stopReason"], nested["permissionDecisionReason"], decision["message"]} {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// breakSandboxHookAfterHardening keeps the sandbox helper and makes
// defenseclaw_harden_env run FAIL once it has done its work; reached is
// created first, so a test knows the failure ran after hardening.
func breakSandboxHookAfterHardening(t *testing.T, h *sandboxHookHarness, fail, reached string) {
	t.Helper()
	path := filepath.Join(h.path(SandboxHookDir), "_hardening.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("\neval \"_dc_test_real_$(declare -f defenseclaw_harden_env)\"\n"+
		"defenseclaw_harden_env() {\n  _dc_test_real_defenseclaw_harden_env\n  : >"+shellSingleQuote(reached)+"\n  "+fail+"\n}\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sandboxCodexArgs(event string) []string {
	return []string{"--event", event, "--hook-contract", "codex-hooks-v4"}
}

// GAP-1769: the OpenShell sandbox Codex hook had the GAP-1755 shape. Every
// block (an ingress outage, an answer it cannot use, input too large to
// inspect, a missing binding token, a binding error, a block without
// codex_output, a helper that does not load) exited 2, with stderr or a
// generic block object. Codex v0.130+ reads a non-zero UserPromptSubmit
// status as a hook failure, not a block: Codex showed a hook error instead of
// the DefenseClaw block. codexBlockAnswer is Codex's exit-code contract: only
// exit 0 with one block object of the registered event is a block. Every
// block of the sandbox hook is now that answer, and it says why.
func TestSandboxCodexHookBlocksEveryEventItCanBlockInCodexsShape(t *testing.T) {
	token := map[string]string{SandboxTokenEnv: "tok"}
	failures := []struct {
		name      string
		responses []string
		env       map[string]string
		payload   func(event string) string
		breaks    func(t *testing.T, h *sandboxHookHarness)
		reason    string
	}{
		{name: "the ingress is down", responses: []string{"exit:7", "exit:7"}, env: token,
			reason: "DefenseClaw blocked this: DefenseClaw on the user's machine does not answer"},
		{name: "the managed gateway is down", env: token,
			responses: []string{`502|{"error":"the managed DefenseClaw gateway is not reachable"}`, `502|{"error":"the managed DefenseClaw gateway is not reachable"}`},
			reason:    "the DefenseClaw gateway service on the user's machine does not answer"},
		{name: "the relay answers 500", responses: []string{`500|placeholder did not resolve`}, env: token, reason: "HTTP 500"},
		{name: "the ingress refuses the token", responses: []string{`401|{"error":"bad token"}`}, env: token,
			reason: "could not be used (gateway returned HTTP 401"},
		{name: "the gateway limits requests", responses: []string{`429|{"error":"slow down"}`}, env: token, reason: "limiting requests"},
		{name: "the answer is not JSON", responses: []string{`200|<html>proxy</html>`}, env: token, reason: "could not be used"},
		{name: "the answer has no verdict", responses: []string{`200|{"action":"maybe"}`}, env: token, reason: "could not be used"},
		{name: "the gateway blocks without codex_output", responses: []string{`200|{"action":"block","reason":"policy says no"}`}, env: token,
			reason: "policy says no"},
		{name: "the input is too large to inspect", responses: []string{allowResponse},
			env: map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "99999999"},
			payload: func(event string) string {
				return strings.Replace(codexEventPayload(event), `"echo hi"`, `"`+strings.Repeat("a", 1<<20)+`"`, 1)
			},
			reason: "too large for DefenseClaw to inspect"},
		{name: "the binding token is missing", responses: []string{allowResponse}, reason: "no valid DefenseClaw binding token"},
		{name: "the payload names another event", responses: []string{allowResponse}, env: token,
			payload: func(string) string { return codexEventPayload("Notification") }, reason: "registration does not match this call"},
		{name: "the sandbox helper is missing", responses: []string{allowResponse}, env: token,
			breaks: func(t *testing.T, h *sandboxHookHarness) {
				if err := os.Remove(filepath.Join(h.path(SandboxHookDir), "_sandbox.sh")); err != nil {
					t.Fatal(err)
				}
			},
			reason: "its sandbox hook failed (sandbox hooks fail closed)"},
	}
	for _, failure := range failures {
		h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
		if failure.breaks != nil {
			failure.breaks(t, h)
		}
		for _, event := range codexControlledEvents {
			t.Run(event+"/"+failure.name, func(t *testing.T) {
				payload := codexEventPayload(event)
				if failure.payload != nil {
					payload = failure.payload(event)
				}
				run := h.run(t, SandboxHookDir+"/codex-hook.sh", sandboxCodexArgs(event), payload, failure.env, failure.responses)
				if !codexBlockAnswer(event, run.exitCode, run.stdout) {
					t.Fatalf("exit %d stdout %q stderr %q, want Codex's own %s block on stdout with exit 0", run.exitCode, run.stdout, run.stderr, event)
				}
				if got := codexBlockReason(run.stdout); !strings.Contains(got, failure.reason) {
					t.Fatalf("block reason %q, want it to say %q", got, failure.reason)
				}
			})
		}
	}
}

// GAP-1769 (GAP-1757 shape): an unexpected failure of the sandbox Codex hook
// after hardening (a set -e failure, an unbound variable, bash 3.2's
// unmarked exit 0, any other status) ended the hook with that status: exit 1
// is a non-blocking error for Codex, so the call ran. The exit guard now
// blocks it in Codex's shape, sandbox hooks being closed whatever the
// render's fail mode, and writes one hook-failures.jsonl record.
func TestSandboxCodexHookUnexpectedFailureBlocksAndIsRecorded(t *testing.T) {
	for name, fail := range shellExitGuardFailures {
		for _, failMode := range []string{"closed", "open"} {
			rt, err := resolveSandboxTarget("codex", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0"})
			if err != nil {
				t.Fatal(err)
			}
			rt.failMode = failMode
			files, err := renderSandboxHookFiles("codex", rt)
			if err != nil {
				t.Fatal(err)
			}
			h := newSandboxHookHarnessFiles(t, files, SandboxHookPATH)
			reached := filepath.Join(t.TempDir(), "harden-reached")
			breakSandboxHookAfterHardening(t, h, fail, reached)
			logPath := h.path(SandboxHookLogDir + "/hook-failures.jsonl")
			for _, event := range codexControlledEvents {
				t.Run(failMode+"/"+event+"/"+strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
					_ = os.Remove(logPath)
					_ = os.Remove(reached)
					run := h.run(t, SandboxHookDir+"/codex-hook.sh", sandboxCodexArgs(event), codexEventPayload(event),
						map[string]string{SandboxTokenEnv: "tok"}, []string{allowResponse})
					if _, err := os.Stat(reached); err != nil {
						t.Fatalf("the failure did not run after hardening: %v; stderr %q", err, run.stderr)
					}
					if !codexBlockAnswer(event, run.exitCode, run.stdout) || len(run.calls) != 0 {
						t.Fatalf("exit %d calls %d stdout %q stderr %q, want Codex's own %s block and no request", run.exitCode, len(run.calls), run.stdout, run.stderr, event)
					}
					data, err := os.ReadFile(logPath)
					if err != nil {
						t.Fatalf("want one unexpected-failure record: %v", err)
					}
					lines := strings.Split(strings.TrimSpace(string(data)), "\n")
					var row map[string]string
					if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &row) != nil ||
						row["category"] != "internal" || row["outcome"] != "fail_closed" || row["fail_mode"] != "closed" ||
						!strings.Contains(row["reason"], "unexpected hook failure") {
						t.Fatalf("want one unexpected-failure record (internal, fail_closed), got %q", data)
					}
				})
			}
		}
	}
}

// GAP-1769: _sandbox.sh drops every exported variable it does not keep. The
// exit guard's state is assigned before it runs, so a workload that exports
// the same names must neither unset it (the guard would end on an unbound
// variable, exit 1, with no block) nor choose it, and an exported
// BASH_XTRACEFD must not close the stdout the block answer is written to.
func TestSandboxCodexHookGuardStateSurvivesTheScrub(t *testing.T) {
	inherited := map[string]string{
		SandboxTokenEnv:          "tok",
		"_DC_EXIT_INTENDED":      "1",
		"_DC_HOOK_FAIL_MODE":     "open",
		"_DC_CODEX_EVENT":        "Stop",
		"_DC_CODEX_CONTRACT":     "codex-hooks-v1",
		"_DC_CODEX_BLOCK_REASON": "inherited reason",
	}
	for _, tc := range []struct {
		name  string
		fail  string
		reply []string
	}{
		{"the ingress is down", "", []string{"exit:7", "exit:7"}},
		{"an unbound variable after hardening", `: "$_DC_TEST_UNSET_AFTER_HARDEN"`, []string{allowResponse}},
		{"an unmarked exit 2 after hardening", "builtin exit 2", []string{allowResponse}},
		{"the gateway blocks", "", []string{`200|{"action":"block","reason":"policy says no"}`}},
	} {
		h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
		if tc.fail != "" {
			breakSandboxHookAfterHardening(t, h, tc.fail, filepath.Join(t.TempDir(), "harden-reached"))
		}
		// An exported BASH_XTRACEFD=1 is dropped too: unsetting it closed
		// stdout, every block object was lost and the hook ended with exit 0
		// and nothing printed, a Codex allow (RV-OP2E).
		for _, traceFD := range []string{"", "1"} {
			env := inherited
			if traceFD != "" {
				env = map[string]string{"BASH_XTRACEFD": traceFD}
				for k, v := range inherited {
					env[k] = v
				}
			}
			for _, event := range codexControlledEvents {
				name := strings.ReplaceAll(tc.name, " ", "_") + "/" + event
				if traceFD != "" {
					name += "/BASH_XTRACEFD=" + traceFD
				}
				t.Run(name, func(t *testing.T) {
					run := h.run(t, SandboxHookDir+"/codex-hook.sh", sandboxCodexArgs(event), codexEventPayload(event), env, tc.reply)
					if !codexBlockAnswer(event, run.exitCode, run.stdout) || strings.Contains(run.stdout, "inherited reason") {
						t.Fatalf("exit %d stdout %q stderr %q, want Codex's own %s block, not the inherited state", run.exitCode, run.stdout, run.stderr, event)
					}
				})
			}
		}
	}
}

// GAP-1769 (RV-OP2E): when the block object cannot be written (the hook's
// stdout is closed), codex_closed_answer still ended with exit 0 and nothing
// printed, which Codex reads as an allow. A failed write now exits 2, which
// blocks the events whose block is a status.
func TestSandboxCodexHookUnwritableBlockIsNoExitZero(t *testing.T) {
	h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
	const closed = "/closed-stdout.sh"
	wrapper := "#!/bin/bash\nexec 1>&-\nexec " + shellSingleQuote(h.path(SandboxHookDir+"/codex-hook.sh")) + " \"$@\"\n"
	if err := os.WriteFile(h.path(closed), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, reply := range map[string][]string{
		"the ingress is down": {"exit:7", "exit:7"},
		"the gateway blocks":  {`200|{"action":"block","reason":"policy says no"}`},
	} {
		for _, event := range codexControlledEvents {
			t.Run(strings.ReplaceAll(name, " ", "_")+"/"+event, func(t *testing.T) {
				run := h.run(t, closed, sandboxCodexArgs(event), codexEventPayload(event), map[string]string{SandboxTokenEnv: "tok"}, reply)
				if run.exitCode != 2 {
					t.Fatalf("exit %d stderr %q, want exit 2 when the block object cannot be written", run.exitCode, run.stderr)
				}
			})
		}
	}
}
