// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// This test reuses the bridge fixture command (tixgCommand), which the
// !windows bridge test file defines.

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap1096HookAPI is a laptop gateway in action mode for claudecode, the hook
// route the GAP-1096 probe drove.
func gap1096HookAPI(unknown string) *APIServer {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Cascade.Unknown = unknown
	return &APIServer{scannerCfg: cfg}
}

func gap1096Hook(t *testing.T, a *APIServer, tool, args string) agentHookResponse {
	t.Helper()
	if !json.Valid([]byte(args)) {
		t.Fatalf("test arguments are not JSON")
	}
	return a.evaluateAgentHook(t.Context(), agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
		ToolName: tool, ToolArgs: json.RawMessage(args)})
}

// gap1096Padded is the command argument of tixgCommand with padding around
// it that passes one bound of the shared argument reading.
func gap1096Padded(shape string) string {
	cmd, _ := json.Marshal(tixgCommand)
	command := `"command":` + string(cmd)
	switch shape {
	case "small":
		return `{` + command + `}`
	case "string-66k":
		return `{"a":"` + strings.Repeat("A", 66000) + `",` + command + `}`
	case "members-600":
		members := make([]string, 0, 601)
		for i := range 600 {
			members = append(members, fmt.Sprintf(`"a%04d":"x"`, i))
		}
		return `{` + strings.Join(append(members, command), ",") + `}`
	case "depth-17":
		return `{"n":` + strings.Repeat(`{"n":`, 16) + `0` + strings.Repeat(`}`, 16) + `,` + command + `}`
	case "key-5k":
		return `{"` + strings.Repeat("K", 5000) + `":"x",` + command + `}`
	case "total-300k":
		pads := make([]string, 0, 6)
		for i := range 5 {
			pads = append(pads, fmt.Sprintf(`"a%d":"%s"`, i, strings.Repeat("A", 60000)))
		}
		return `{` + strings.Join(append(pads, command), ",") + `}`
	}
	panic(shape)
}

// TestGAP1096HookMCPOverBoundArgumentsAreJudged (substrate-1:GAP-1096): a
// laptop PreToolUse on an MCP tool whose arguments pass a bound of the shared
// argument reading (a string over 64 KiB, more than 512 members, deeper than
// 16, a key over 4 KiB, over 256 KiB in all) gave the structured rules no
// facts, so padding turned a blocked command into a silent allow. Every shape
// is now blocked as the small call is.
func TestGAP1096HookMCPOverBoundArgumentsAreJudged(t *testing.T) {
	a := gap1096HookAPI("")
	small := gap1096Hook(t, a, "mcp__notes__read_file", gap1096Padded("small"))
	if small.Action != "block" {
		t.Fatalf("small call action=%s rules=%v, want block (the fixture command)", small.Action, small.RuleIDs)
	}
	for _, shape := range []string{"string-66k", "members-600", "depth-17", "key-5k", "total-300k"} {
		t.Run(shape, func(t *testing.T) {
			got := gap1096Hook(t, a, "mcp__notes__read_file", gap1096Padded(shape))
			if got.Action != "block" {
				t.Fatalf("padded call action=%s rules=%v, want block as the small call", got.Action, got.RuleIDs)
			}
		})
	}
}

// TestGAP1096HookMCPOverBoundBenignFloor: a large benign MCP call is never a
// silent allow where the bounded projections leave unread a part the
// structured reading reads (here a long command value): it is allowed with
// the evaluation-limit finding at defaults (the unknown tier of the default
// pack) and blocked where guardrail.cascade.unknown says block. Padding the
// structured reading does not read (a large payload) is read whole by the
// projections and stays a plain allow in both, as a small call does
// (FIXLEAD3 ruling: floor only what the projections leave unread).
func TestGAP1096HookMCPOverBoundBenignFloor(t *testing.T) {
	words := strings.Repeat("hello ", 12000)
	longCommand := `{"command":"echo ` + words + `"}`
	largePayload := `{"path":"/notes/a.txt","content":"` + words + `"}`
	small := `{"path":"/notes/a.txt","content":"hello"}`
	for _, unknown := range []string{"", config.CascadeBlock} {
		a := gap1096HookAPI(unknown)
		for name, args := range map[string]string{"small": small, "large payload": largePayload} {
			if got := gap1096Hook(t, a, "mcp__notes__write_note", args); got.Action != "allow" || len(got.RuleIDs) != 0 {
				t.Errorf("unknown=%q %s benign call action=%s rules=%v, want a plain allow", unknown, name, got.Action, got.RuleIDs)
			}
		}
		got := gap1096Hook(t, a, "mcp__notes__run_note", longCommand)
		if !slices.Contains(got.RuleIDs, evaluationLimitRuleID) {
			t.Errorf("unknown=%q long command action=%s rules=%v, want %s", unknown, got.Action, got.RuleIDs, evaluationLimitRuleID)
		}
		if wantBlock := unknown == config.CascadeBlock; (got.Action == "block") != wantBlock {
			t.Errorf("unknown=%q long command action=%s rules=%v, want block=%v", unknown, got.Action, got.RuleIDs, wantBlock)
		}
	}
}
