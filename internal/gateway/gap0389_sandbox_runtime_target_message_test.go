// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0389SandboxRuntimeWriteTargetBlockSaysWhyAndWhatToDo: in a
// copy-mode actor, cd <absolute folder> && eval '... > $x' stays blocked (the
// gateway cannot place a write the call builds at run time without the
// sandbox's files, a known limit of 1.0.10), but the block names that reason
// and a form the gateway can place, not an SSH authorized keys mutation the
// call does not make (substrate-1 GAP-0389). The verdicts do not change: the
// laptop alerts CMD-EVAL, and a real authorized_keys write in the actor keeps
// the SSH rule's title.
func TestGAP0389SandboxRuntimeWriteTargetBlockSaysWhyAndWhatToDo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	const keysTitle = "SSH authorized keys mutation"
	type answer struct {
		action string
		rules  []string
		reason string
		agent  string
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			hook := func(ctx context.Context, body []byte) answer {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
				var out struct {
					Action string   `json:"action"`
					Rules  []string `json:"rule_ids"`
					Reason string   `json:"reason"`
					Output struct {
						Specific struct {
							Reason string `json:"permissionDecisionReason"`
						} `json:"hookSpecificOutput"`
					} `json:"claude_code_output"`
				}
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
					t.Fatalf("hook status=%d: %.400s", rec.Code, rec.Body.String())
				}
				slices.Sort(out.Rules)
				return answer{out.Action, slices.Compact(out.Rules), out.Reason, out.Output.Specific.Reason}
			}
			call := func(command string) []byte {
				body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0389",
					"cwd": sandboxauth.SandboxHome + "/app", "tool_name": "Bash", "tool_input": map[string]any{"command": command},
					"tool_use_id": "gap0389"})
				return body
			}
			for _, command := range []string{"cd /tmp && eval 'x=f; echo m > $x'", "cd " + sandboxauth.SandboxHome + "/app && eval 'x=notes.txt; echo m >> $x'"} {
				body := call(command)
				got := hook(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil), body)
				if got.action != "block" || !slices.Equal(got.rules, []string{"CMD-EVAL", "persistence.ssh_authorized_keys_command"}) {
					t.Errorf("%q: actor %s %v, want the block it had (CMD-EVAL, persistence.ssh_authorized_keys_command)", command, got.action, got.rules)
				}
				for name, text := range map[string]string{"reason": got.reason, "agent reason": got.agent} {
					if !strings.Contains(text, sandboxRuntimeWriteTargetTitle) || strings.Contains(text, keysTitle) {
						t.Errorf("%q: actor %s %q, want the runtime target title and not %q", command, name, text, keysTitle)
					}
				}
				if !strings.Contains(got.agent, "Use a relative path or a direct write instead of eval") {
					t.Errorf("%q: actor agent reason %q names no next step", command, got.agent)
				}
				if laptop := hook(context.Background(), body); laptop.action != "alert" || !slices.Equal(laptop.rules, []string{"CMD-EVAL"}) {
					t.Errorf("%q: laptop %s %v, want the alert it had (CMD-EVAL)", command, laptop.action, laptop.rules)
				}
			}
			body := call("echo k >> " + sandboxauth.SandboxHome + "/.ssh/authorized_keys")
			got := hook(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil), body)
			if got.action != "block" || !strings.Contains(got.agent, keysTitle) || strings.Contains(got.agent, sandboxRuntimeWriteTargetTitle) {
				t.Errorf("authorized_keys append: actor %s %v %q, want a block named %q", got.action, got.rules, got.agent, keysTitle)
			}
			body = call(`cd /tmp && eval "echo m > $F"`)
			if got := hook(gap0545Actor(actor, "claudecode", "PreToolUse", body, nil), body); got.action == "block" ||
				strings.Contains(got.reason, sandboxRuntimeWriteTargetTitle) {
				t.Errorf("eval with an outer variable: actor %s %v %q, want the alert it had", got.action, got.rules, got.reason)
			}
		})
	}
}
