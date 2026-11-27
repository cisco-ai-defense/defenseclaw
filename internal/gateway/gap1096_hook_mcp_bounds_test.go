// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

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
// silent allow and never a block at defaults: it is allowed with the
// evaluation-limit finding (the unknown tier of the default pack), and
// blocked where guardrail.cascade.unknown says block. A small benign call
// stays a plain allow in both.
func TestGAP1096HookMCPOverBoundBenignFloor(t *testing.T) {
	large := `{"path":"/notes/a.txt","content":"` + strings.Repeat("hello ", 12000) + `"}`
	small := `{"path":"/notes/a.txt","content":"hello"}`
	a := gap1096HookAPI("")
	if got := gap1096Hook(t, a, "mcp__notes__write_note", small); got.Action != "allow" || len(got.RuleIDs) != 0 {
		t.Fatalf("small benign call action=%s rules=%v, want a plain allow", got.Action, got.RuleIDs)
	}
	got := gap1096Hook(t, a, "mcp__notes__write_note", large)
	if got.Action == "block" || !slices.Contains(got.RuleIDs, evaluationLimitRuleID) {
		t.Fatalf("large benign call action=%s rules=%v, want no block with %s", got.Action, got.RuleIDs, evaluationLimitRuleID)
	}
	strict := gap1096HookAPI(config.CascadeBlock)
	if got := gap1096Hook(t, strict, "mcp__notes__write_note", large); got.Action != "block" ||
		!slices.Contains(got.RuleIDs, evaluationLimitRuleID) {
		t.Fatalf("large benign call with cascade.unknown block action=%s rules=%v, want block", got.Action, got.RuleIDs)
	}
	if got := gap1096Hook(t, strict, "mcp__notes__write_note", small); got.Action != "allow" || len(got.RuleIDs) != 0 {
		t.Fatalf("small benign call with cascade.unknown block action=%s rules=%v, want a plain allow", got.Action, got.RuleIDs)
	}
}
