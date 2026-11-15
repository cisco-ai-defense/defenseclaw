// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-0619. Hermes shows the command it runs only as text: the
// first report of its terminal tool is kind execute with the content block
// "$ <command>" and no rawInput. The gateway judged that report as prose, so
// a rule that reads a tool call never saw the command and nothing was
// recorded. The report is now judged as the shell call it shows, and (the
// agent having run it already) a block is an alert that would have blocked,
// with its finding in the audit row.
//
// The commands are not written here: they are the shell commands of the
// existing S7 corpora (testdata/acp_parity_cases.jsonl, by case id). Each is
// sent as Hermes reports it and as an agent that carries rawInput reports it;
// the two must get the same verdict and the same rule ids, in every tier.

// acpHermesReport is the first report of a terminal call as Hermes sends it.
func acpHermesReport(t *testing.T, id, command string, extra map[string]any) []byte {
	t.Helper()
	update := map[string]any{
		"sessionUpdate": "tool_call", "toolCallId": id, "kind": "execute", "locations": []any{},
		"title":   "terminal: " + command,
		"content": []any{map[string]any{"type": "content", "content": map[string]any{"type": "text", "text": "$ " + command}}},
	}
	for key, value := range extra {
		update[key] = value
	}
	return acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": update})
}

// acpRawInputReport is the same report from an agent that carries rawInput.
func acpRawInputReport(t *testing.T, id, command string) []byte {
	t.Helper()
	return acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
		"sessionUpdate": "tool_call", "toolCallId": id, "kind": "execute", "title": "terminal: " + command,
		"rawInput": map[string]any{"command": command}}})
}

func acpHermesTier(t *testing.T, name string) (env *acpActionEnv, posture string) {
	t.Helper()
	for _, tier := range boundedTestTiers {
		if tier.name == name {
			env = newACPActionEnvFor(t, tier.posture, "hermes", tier.managed)
			if got := env.acpAPI.boundedTier(t.Context(), "hermes"); got != tier.tier {
				t.Fatalf("tier %s: the hermes route judges in tier %d, want %d", name, got, tier.tier)
			}
			return env, tier.posture
		}
	}
	t.Fatalf("no tier %s", name)
	return nil, ""
}

// TestACPHermesDisplayedCommandIsJudgedAsTheShellCall: the displayed command
// gets the verdict and the rule ids of the same command in rawInput, in the
// five tiers, and what the pack blocks is an alert that would have blocked
// with its finding stored (GAP-0619).
func TestACPHermesDisplayedCommandIsJudgedAsTheShellCall(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	var commands []acpParityPair
	for _, pair := range pairs {
		if command, _ := pair.hookInput["command"].(string); pair.method == "terminal/create" && command != "" && len(command) < 4<<10 {
			commands = append(commands, pair)
		}
	}
	if len(commands) < 100 {
		t.Fatalf("only %d shell commands in the corpus", len(commands))
	}
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			env, _ := acpHermesTier(t, tier.name)
			var tried, flagged int
			var ids [][2]string
			for i, pair := range commands {
				if i%4 != 0 { // a quarter of the corpus per tier keeps the five tiers fast
					continue
				}
				command, _ := pair.hookInput["command"].(string)
				twin := env.evaluate(t, acp.AgentToClient, acpRawInputReport(t, "t", command))
				shown := env.evaluate(t, acp.AgentToClient, acpHermesReport(t, "t", command, nil))
				tried++
				if shown.Action != twin.Action || shown.RawAction != twin.RawAction || shown.WouldBlock != twin.WouldBlock || shown.Severity != twin.Severity {
					t.Errorf("%s: displayed %+v, rawInput twin %+v", pair.id, shown, twin)
				}
				if shown.JudgedBlock() {
					flagged++
					if shown.Action != "alert" || !shown.WouldBlock {
						t.Errorf("%s: a report the pack blocks is %+v, want an alert that would have blocked", pair.id, shown)
					}
				}
				ids = append(ids, [2]string{pair.id, ""})
			}
			events := readStoredGuardrailEventsV8(t, env.capture.store.DatabasePath())
			if len(events) != 2*tried {
				t.Fatalf("%d events for %d reports", len(events), 2*tried)
			}
			for i := range ids {
				twin, shown := acpVerdictRuleIDs(t, events[2*i].Body), acpVerdictRuleIDs(t, events[2*i+1].Body)
				slices.Sort(twin)
				slices.Sort(shown)
				if !slices.Equal(twin, shown) {
					t.Errorf("%s: stored rule ids %v, rawInput twin %v", ids[i][0], shown, twin)
				}
			}
			t.Logf("%s: %d commands, %d judged a block (alert that would have blocked)", tier.name, tried, flagged)
			if flagged < 5 {
				t.Errorf("only %d of %d displayed commands were judged a block; the report is still read as prose", flagged, tried)
			}
		})
	}
}

// TestACPHermesDisplayedBenignCommandsAreNotNewlyFlagged: the routine
// commands of a coding session, as Hermes reports them, are a plain allow in
// the default, permissive and managed tiers, as the rawInput twin is.
func TestACPHermesDisplayedBenignCommandsAreNotNewlyFlagged(t *testing.T) {
	benign := []string{
		"echo ok", "git status", "git diff", "git log --oneline -5", "go build ./...", "go test ./...", "npm test",
		"make test", "pytest -q", "ls -la", "pwd", "cat README.md", "grep -rn TODO src", "mkdir -p build", "gofmt -l .",
	}
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			env, _ := acpHermesTier(t, tier.name)
			for _, command := range benign {
				shown := env.evaluate(t, acp.AgentToClient, acpHermesReport(t, "t", command, nil))
				twin := env.evaluate(t, acp.AgentToClient, acpRawInputReport(t, "t", command))
				if shown.Action != twin.Action || shown.RawAction != twin.RawAction || shown.WouldBlock != twin.WouldBlock {
					t.Errorf("%q: displayed %+v, rawInput twin %+v", command, shown, twin)
				}
				if tier.tier != bounded.TierStrict && (shown.Action != "allow" || shown.RawAction != "allow" || shown.WouldBlock) {
					t.Errorf("%q: %+v, want a plain allow in the %s tier", command, shown, tier.name)
				}
			}
		})
	}
}

// TestACPHermesTerminalReportThatShowsNoCommandIsUnknown: a terminal report
// whose command the gateway cannot read is never clean: a block of an unread
// action, which for a report is an alert that would have blocked, in every
// tier. Other tools of the agent (the display of a browser click) and other
// agents' frames of this shape name no action, as before.
func TestACPHermesTerminalReportThatShowsNoCommandIsUnknown(t *testing.T) {
	noCommand := acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
		"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": "terminal", "locations": []any{}}})
	emptyCommand := acpHermesReport(t, "t", " ", nil)
	otherTool := acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
		"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": "browser_click: @e5",
		"content": []any{map[string]any{"type": "content", "content": map[string]any{"type": "text", "text": "$ click"}}}}})
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			env, _ := acpHermesTier(t, tier.name)
			for name, frame := range map[string][]byte{"no content": noCommand, "blank command": emptyCommand} {
				got := env.evaluate(t, acp.AgentToClient, frame)
				if got.Action != "alert" || got.RawAction != "block" || !got.WouldBlock {
					t.Errorf("%s: %+v, want an alert that would have blocked", name, got)
				}
			}
			if got := env.evaluate(t, acp.AgentToClient, otherTool); got.Action != "allow" || got.WouldBlock {
				t.Errorf("another Hermes tool: %+v, want a plain allow", got)
			}
		})
	}
	// The shape is Hermes's: the same frame from Kiro is not read this way.
	frame := acpHermesReport(t, "t", "echo ok", nil)
	msg := acpParsedFrame(t, frame)
	if got, isAction := acpFrameToolCalls(acp.Evaluation{
		AgentID: "kiro", Direction: acp.AgentToClient, Surface: acp.Classify(msg, acp.AgentToClient), Method: msg.Method, Payload: frame,
	}, "linux"); isAction {
		t.Errorf("a kiro report that shows its command as text mapped to %+v, want no action", got)
	}
}
