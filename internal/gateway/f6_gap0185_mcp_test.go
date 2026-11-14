// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0185 (E20): the runtime MCP scan runs in the shipped gateway's hook
// route. A blocked server's tool calls, and calls that add a blocked server,
// are refused closed (kit.MCPRefusedCode); an unreadable config follows the
// fail mode; SessionStart alerts.

type fakeMCPScanner struct {
	decisions []SubstrateMCPDecision
	calls     int
}

func (s *fakeMCPScanner) ScanMCP(context.Context, json.RawMessage, []SubstrateAttachedFile) ([]SubstrateMCPDecision, error) {
	s.calls++
	return s.decisions, nil
}

func gap0185Post(t *testing.T, block bool, sc *fakeMCPScanner, event, tool string) (int, map[string]string, []string) {
	t.Helper()
	var alerts []string
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.MCP = sc
		c.BlockUnscannedSkills = func(string) bool { return block }
	})
	f.api.substrateState().alert = func(_ context.Context, sev, summary string, _ map[string]any) {
		alerts = append(alerts, sev+" "+summary)
	}
	pl, _ := json.Marshal(map[string]any{"hook_event_name": event, "session_id": "s1", "tool_name": tool,
		"tool_input": map[string]any{}, "cwd": "/work"})
	b, _ := json.Marshal(map[string]any{"v": substrateEnvelopeVersion, "connector": "claudecode", "event": event,
		"mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(pl),
		"facts": map[string]any{"files": []map[string]any{{"role": "mcp_config", "path": "/work/.mcp.json", "size": 2, "sha256": "x", "content": []byte("{}")}}}})
	rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", string(b))
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, alerts
}

func TestGAP0185RepoMCPServerIsRefused(t *testing.T) {
	evil := []SubstrateMCPDecision{{Source: "/work/.mcp.json", Server: "evil.srv", Attached: true, Block: true, Reason: "fetch-and-exec stdio command"},
		{Source: "/work/.mcp.json", Server: "good", Attached: true}}
	for _, block := range []bool{false, true} {
		code, out, alerts := gap0185Post(t, block, &fakeMCPScanner{decisions: evil}, "PreToolUse", "mcp__evil_srv__run")
		if code != http.StatusForbidden || out["reason"] != kit.MCPRefusedCode || !strings.Contains(out["message"], "evil.srv") {
			t.Fatalf("block=%v: a call of the blocked server answered %d %v", block, code, out)
		}
		if len(alerts) != 1 || !strings.HasPrefix(alerts[0], "HIGH") {
			t.Fatalf("alerts %v", alerts)
		}
		if code, out, _ := gap0185Post(t, block, &fakeMCPScanner{decisions: evil}, "PreToolUse", "mcp__good__list"); code == http.StatusForbidden {
			t.Fatalf("a call of the clean server was refused: %v", out)
		}
		if code, out, _ := gap0185Post(t, block, &fakeMCPScanner{decisions: evil}, "PreToolUse", "Bash"); code == http.StatusForbidden {
			t.Fatalf("a non-MCP call was refused for the repository config: %v", out)
		}
	}
	// A call that adds a blocked server (Write of a config, mcp add) is
	// refused whatever the tool.
	adds := []SubstrateMCPDecision{{Source: "mcp add-json", Server: "x", Block: true, Reason: "fetch-and-exec"}}
	if code, out, _ := gap0185Post(t, false, &fakeMCPScanner{decisions: adds}, "PreToolUse", "Bash"); code != http.StatusForbidden {
		t.Fatalf("mcp add of a blocked server: %d %v", code, out)
	}
	// SessionStart cannot stop the agent's start of the servers: it alerts.
	code, _, alerts := gap0185Post(t, true, &fakeMCPScanner{decisions: evil}, "SessionStart", "")
	if code == http.StatusForbidden || len(alerts) != 1 || !strings.HasPrefix(alerts[0], "HIGH") {
		t.Fatalf("SessionStart: %d %v", code, alerts)
	}
}

func TestGAP0185UnreadableConfigFollowsTheFailMode(t *testing.T) {
	cut := []SubstrateMCPDecision{{Source: "/work/.mcp.json", Attached: true, Unreadable: true, Reason: "cut by the attach cap"}}
	code, out, alerts := gap0185Post(t, true, &fakeMCPScanner{decisions: cut}, "PreToolUse", "mcp__any__tool")
	if code != http.StatusForbidden || out["reason"] != kit.MCPRefusedCode {
		t.Fatalf("managed/strict: %d %v", code, out)
	}
	if len(alerts) != 1 || !strings.HasPrefix(alerts[0], "HIGH") {
		t.Fatalf("alerts %v", alerts)
	}
	code, out, alerts = gap0185Post(t, false, &fakeMCPScanner{decisions: cut}, "PreToolUse", "mcp__any__tool")
	if code == http.StatusForbidden || len(alerts) != 1 || !strings.HasPrefix(alerts[0], "MEDIUM") {
		t.Fatalf("OSS: %d %v %v", code, out, alerts)
	}
}
