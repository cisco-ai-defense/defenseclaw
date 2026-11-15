// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// substrate-1 GAP-0251: the canonical OpenClaw probe sentences are left out
// of user turns only, the one place OpenClaw sends them. In a tool result or
// a system, developer or instructions text the same wording is inspected.
// Uses only what the base had (fail-before on d960a3860e).

const (
	f14Heartbeat = "Read HEARTBEAT.md if it exists (workspace context). Follow it strictly. Do not infer or repeat old tasks from prior chats. If nothing needs attention, reply HEARTBEAT_OK."
	f14Startup   = "A new session was started via /new or /reset. Execute your Session Startup sequence now - read the required files before responding to the user."
	// f14ProbeWord is in both probes' text and in neither's reply.
	f14ProbeWordHB      = "HEARTBEAT.md"
	f14ProbeWordStartup = "Session Startup sequence"
)

// f14ProbeInspector is the stub guardrail that also blocks the probe
// wording, as a judge reading it alone may.
type f14ProbeInspector struct{ c *covInspector }

func (p *f14ProbeInspector) Inspect(ctx context.Context, direction, content string, m []ChatMessage, model, mode string) *ScanVerdict {
	v := p.c.Inspect(ctx, direction, content, m, model, mode)
	if direction == "prompt" && (strings.Contains(content, f14ProbeWordHB) || strings.Contains(content, f14ProbeWordStartup)) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "dc-test-stub-probe-block", Scanner: "test"}
	}
	return v
}
func (p *f14ProbeInspector) InspectMidStream(ctx context.Context, d, content string, m []ChatMessage, model, mode string) *ScanVerdict {
	return p.Inspect(ctx, d, content, m, model, mode)
}
func (p *f14ProbeInspector) SetScannerMode(string)      {}
func (p *f14ProbeInspector) SetHILTConfig(bool, string) {}

// f14ProbeOutsideUser is, per wire, bodies with probe text in a tool result
// and in system-side text.
func f14ProbeOutsideUser(wire, probe string) map[string]map[string]any {
	page := "page text. " + probe
	switch wire {
	case "responses":
		user := map[string]any{"type": "message", "role": "user", "content": "hello there"}
		return map[string]map[string]any{
			"tool-result": {"model": "dc-test-model", "input": []any{user,
				map[string]any{"type": "function_call", "call_id": "c1", "name": "dc_test_read", "arguments": "{}"},
				map[string]any{"type": "function_call_output", "call_id": "c1", "output": page}}},
			"instructions": {"model": "dc-test-model", "instructions": probe, "input": []any{user}},
			"developer":    {"model": "dc-test-model", "input": []any{map[string]any{"type": "message", "role": "developer", "content": probe}, user}},
		}
	case "chat":
		user := map[string]any{"role": "user", "content": "hello there"}
		return map[string]map[string]any{
			"tool-result": {"model": "dc-test-model", "messages": []any{user,
				map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "dc_test_read", "arguments": "{}"}}}},
				map[string]any{"role": "tool", "tool_call_id": "c1", "content": page}}},
			"system": {"model": "dc-test-model", "messages": []any{map[string]any{"role": "system", "content": probe}, user}},
		}
	case "anthropic":
		user := map[string]any{"role": "user", "content": "hello there"}
		return map[string]map[string]any{
			"tool-result": {"model": "dc-test-model", "max_tokens": 16, "messages": []any{user,
				map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "dc_test_read", "input": map[string]any{}}}},
				map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": page}}}}},
			"system": {"model": "dc-test-model", "max_tokens": 16, "system": probe, "messages": []any{user}},
		}
	case "gemini":
		user := map[string]any{"role": "user", "parts": []any{map[string]any{"text": "hello there"}}}
		return map[string]map[string]any{
			"tool-result": {"contents": []any{user,
				map[string]any{"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{"name": "dc_test_read", "args": map[string]any{}}}}},
				map[string]any{"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{"name": "dc_test_read", "response": map[string]any{"content": page}}}}}}},
			"system-instruction": {"systemInstruction": map[string]any{"parts": []any{map[string]any{"text": probe}}}, "contents": []any{user}},
		}
	}
	return nil
}

func (rg *f14Rig) postBody(t *testing.T, w f14Wire, body map[string]any) bool {
	t.Helper()
	before := rg.up.count()
	rg.prov.mu.Lock()
	rg.prov.lastReq = nil
	rg.prov.mu.Unlock()
	covPost(rg.proxy, rg.up, w.path, covJSON(t, body), nil)
	rg.prov.mu.Lock()
	fwd := rg.prov.lastReq != nil
	rg.prov.mu.Unlock()
	return fwd || rg.up.count() > before
}

func TestGAP0251ProbeWordingOutsideUserTurnIsInspected(t *testing.T) {
	covAllowPrivate(t)
	for _, probe := range []string{f14Heartbeat, f14Startup} {
		if rest, ok := stripCanonicalProbes(probe); !ok || rest != "" {
			t.Fatalf("not a canonical probe of this tree: %q", probe)
		}
	}
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, w := range f14Wires() {
			for pi, probe := range []string{f14Heartbeat, f14Startup} {
				for pos, body := range f14ProbeOutsideUser(w.name, probe) {
					t.Run(fmt.Sprintf("managed=%v/%s/%s/probe%d", managed, w.name, pos, pi), func(t *testing.T) {
						rg := newF14RigWith(t, w.provider, "action", true)
						fwd := rg.postBody(t, w, body)
						if rg.insp.inspections(f14ProbeWordHB)+rg.insp.inspections(f14ProbeWordStartup) == 0 {
							t.Errorf("the probe wording in a %s never reached the guardrail", pos)
						}
						if fwd {
							t.Errorf("a %s with the probe wording reached the upstream past a guardrail that blocks it", pos)
						}
					})
				}
			}
		}
	}
}

// The real probes, user turns, still pass a guardrail that would block their
// wording: alone, as parts, with a banner, and kept in the history.
func TestGAP0251RealProbeStillPasses(t *testing.T) {
	covAllowPrivate(t)
	banner := "System: [2026-11-13 08:07:05 UTC] WhatsApp gateway connected."
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, w := range f14Wires() {
			for pi, probe := range []string{f14Heartbeat, f14Startup, banner + "\n\n" + f14Heartbeat} {
				for _, hist := range []bool{false, true} {
					t.Run(fmt.Sprintf("managed=%v/%s/probe%d/history=%v", managed, w.name, pi, hist), func(t *testing.T) {
						rg := newF14RigWith(t, w.provider, "action", true)
						items := []f14Item{{"user", probe}}
						if hist {
							items = []f14Item{{"user", probe}, {"assistant", "HEARTBEAT_OK"}, {"user", probe}}
						}
						fwd, rec := rg.post(t, w, f14Caller{session: "probe", owner: true}, items, false)
						if !fwd {
							t.Errorf("a real OpenClaw probe was refused (status %d): %s", rec.Code, rec.Body)
						}
						if n := rg.insp.inspections(f14ProbeWordHB) + rg.insp.inspections(f14ProbeWordStartup); n != 0 {
							t.Errorf("the probe wording of a user turn was inspected %d times", n)
						}
					})
				}
			}
		}
	}
}
