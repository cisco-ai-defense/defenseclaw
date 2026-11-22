// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10 GAP-1665: on a POSIX host scp and rsync to
// localhost:///home/u/.ssh/authorized_keys write the local key file. In every
// tier and on each connector's own hook route the call takes the verdict of
// the localhost:/home/u/... spelling, as at rel 8e58b26846, never allow. A
// drive-letter spelling (C:///...) is no URL either (rel-1-0-10:GAP-1661).
func TestGAP1665HostTripleSlashKeyWriteKeepsItsVerdict(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, f := range []string{".ssh/authorized_keys", "proj/x.json"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, f)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, f), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	key := home + "/.ssh/authorized_keys"
	control := "scp x.json localhost:" + key
	rows := []string{
		"scp x.json localhost://" + key,
		"rsync x.json localhost://" + key,
		"scp x.json u@localhost://" + key,
		"cp x.json C://" + key,
	}
	routes := []struct{ connector, tool string }{
		{"claudecode", "Bash"},
		{"codex", "Bash"},
	}
	tiers := []struct {
		name, posture string
		managed       bool
	}{
		{"default", "default", false},
		{"permissive", "permissive", false},
		{"strict", "strict", false},
		{"managed", "default", true},
		{"managed-strict", "strict", true},
	}
	for _, tier := range tiers {
		for _, route := range routes {
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
				id := tier.name + "-" + route.connector + "-" + strconv.Itoa(calls)
				raw, err := json.Marshal(map[string]any{
					"session_id": "gap1665-" + id, "turn_id": "turn-1", "hook_event_name": "PreToolUse", "cwd": cwd,
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
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				resp, panicked := api.safeEvaluateHook(ctx, route.connector, agentHookRequest{ConnectorName: route.connector, CWD: cwd, HookEventName: "PreToolUse", ToolName: route.tool, ToolArgs: args}, raw, payload, hook)
				if panicked {
					t.Fatalf("%s %s/%s %q: hook evaluator panicked", tier.name, route.connector, route.tool, command)
				}
				return resp.Action, strings.Join(resp.Findings, "; ")
			}
			wantAction, wantFindings := evaluate(control)
			if wantAction == "allow" {
				t.Fatalf("%s %s/%s control %q: allow, the control is void", tier.name, route.connector, route.tool, control)
			}
			for _, command := range rows {
				if action, findings := evaluate(command); action != wantAction || findings != wantFindings {
					t.Errorf("%s %s/%s %q: %s [%s], want %s [%s] as %q", tier.name, route.connector, route.tool, command, action, findings, wantAction, wantFindings, control)
				}
			}
		}
	}
}
