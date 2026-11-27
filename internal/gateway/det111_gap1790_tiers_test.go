// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1790: named non-root switch-user wrappers retain the pre-effects
// low-severity sudo verdict across every posture and connector. Controls keep
// the current stronger effects for plain sudo and root authorized_keys.
func TestGAP1790NamedForeignUserWrapperKeepsBaselineVerdict(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	t.Setenv("HOME", home)
	state := filepath.Join(home, ".defenseclaw", ".ci-helper.lock")
	token := filepath.Join(home, ".defenseclaw", "hooks", ".ci-helper.token")
	routes := []struct{ connector, tool string }{{"claudecode", "Bash"}, {"codex", "Bash"}}
	tiers := []struct {
		name, posture, want string
		managed             bool
	}{
		{"default", "default", "allow", false},
		{"permissive", "permissive", "allow", false},
		{"strict", "strict", "alert", false},
		{"managed", "default", "allow", true},
		{"managed-strict", "strict", "alert", true},
	}
	foreignCommands := []string{
		fmt.Sprintf("sudo -iu buildrunner rm -f -- %q %q", state, token),
	}
	controls := []string{
		fmt.Sprintf("sudo rm -f -- %q", token),
		"sudo tee -a /root/.ssh/authorized_keys",
	}
	for _, tier := range tiers {
		for _, route := range routes {
			t.Run(tier.name+"/"+route.connector, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, route.connector, tier.posture)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = route.connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.posture)
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				ctx := context.Background()
				if tier.managed {
					ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
				}
				hook := hookRuntimeForProfile(api.hookProfileForRequest(ctx, route.connector))
				calls := 0
				evaluate := func(command string) (string, string) {
					calls++
					id := "gap1790-" + tier.name + "-" + route.connector + "-" + strconv.Itoa(calls)
					args, err := json.Marshal(map[string]string{"command": command})
					if err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(map[string]any{
						"session_id": id, "turn_id": "turn-1", "hook_event_name": "PreToolUse", "cwd": cwd,
						"model": "fixture-model", "tool_name": route.tool, "tool_use_id": "call-" + id,
						"tool_input": map[string]any{"command": command},
					})
					if err != nil {
						t.Fatal(err)
					}
					var payload map[string]interface{}
					if err := json.Unmarshal(raw, &payload); err != nil {
						t.Fatal(err)
					}
					resp, panicked := api.safeEvaluateHook(ctx, route.connector, agentHookRequest{
						ConnectorName: route.connector, CWD: cwd, HookEventName: "PreToolUse",
						ToolName: route.tool, ToolArgs: args,
					}, raw, payload, hook)
					if panicked {
						t.Fatalf("%s %s/%s %q: hook evaluator panicked", tier.name, route.connector, route.tool, command)
					}
					return resp.Action, strings.Join(resp.Findings, "; ")
				}
				for _, command := range foreignCommands {
					action, findings := evaluate(command)
					if action != tier.want {
						t.Errorf("%q: got %s [%s], want 1.0.10 baseline action %s", command, action, findings, tier.want)
					}
				}
				for _, command := range controls {
					action, findings := evaluate(command)
					if action == "allow" {
						t.Errorf("control %q lost its stronger verdict: %s [%s]", command, action, findings)
					}
				}
			})
		}
	}
}
