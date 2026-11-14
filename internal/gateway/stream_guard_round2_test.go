// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestStreamGuardTruncationFollowsThePackTier: a stream cut short by a bound
// (rel-1-0-10:GAP-0368, GAP-0369) blocks where the pack's unknown tier
// blocks (strict) and goes on with an alert where it alerts (default,
// permissive); the final verdict always carries the evaluation-limit
// finding, so the truncation is never silent.
func TestStreamGuardTruncationFollowsThePackTier(t *testing.T) {
	for _, tier := range []bounded.Tier{bounded.TierDefault, bounded.TierPermissive, bounded.TierStrict} {
		check, _ := streamGuardTestCheck()
		guard := newCompletionStreamGuard(check, 64).withLimit(func(set bounded.CapSet) *ScanVerdict {
			if bounded.Floor(bounded.Allow, set, tier) != bounded.Block {
				return nil
			}
			return streamTruncationVerdict(set, guardrailActionBlock)
		})
		if _, v := guard.Push(streamGuardFiller(400), []byte("a")); v != nil {
			t.Fatalf("tier %d: clean text blocked", tier)
		}
		v := guard.Truncate(bounded.Bytes)
		if (v != nil) != (tier == bounded.TierStrict) {
			t.Fatalf("tier %d: truncation verdict %+v, want a block only in strict", tier, v)
		}
		if !guard.Truncated().Has(bounded.Bytes) {
			t.Fatalf("tier %d: the cap is not reported", tier)
		}
		final := withStreamTruncation(allowVerdict("local-pattern"), guard.Truncated())
		if final.Action != guardrailActionAlert || !strings.HasPrefix(final.Findings[0], evaluationLimitRuleID+":") {
			t.Fatalf("tier %d: final verdict %+v, want an alert with the evaluation-limit finding", tier, final)
		}
	}
}

// TestStreamGuardConfirmAskedOncePerResponse: the 4 KiB overlap means later
// windows still hold a confirm finding; the person is asked once and every
// later window takes that answer (review P4-7).
func TestStreamGuardConfirmAskedOncePerResponse(t *testing.T) {
	for _, answer := range []string{guardrailActionAllow, guardrailActionBlock} {
		asked := 0
		confirm := confirmOnce(func(v *ScanVerdict) {
			asked++
			v.Action = answer
		})
		for i := 0; i < 6; i++ {
			v := confirm(&ScanVerdict{Action: guardrailActionConfirm, Severity: "HIGH"})
			if v.Action != answer {
				t.Fatalf("answer %s: window %d got %s", answer, i, v.Action)
			}
		}
		if asked != 1 {
			t.Fatalf("answer %s: asked %d times, want once", answer, asked)
		}
	}
}

// TestStreamGuardCloudLaneCadence: the cloud lane (Cisco AI Defense) runs
// every streamGuardCloudEvery bytes and at the end, not on every local
// window (review P3-4).
func TestStreamGuardCloudLaneCadence(t *testing.T) {
	check, _ := streamGuardTestCheck()
	local, cloud := 0, 0
	guard := newCompletionStreamGuard(func(w string) *ScanVerdict { local++; return check(w) }, streamGuardScanEvery).
		withCloud(func(w string) *ScanVerdict { cloud++; return check(w) })
	text := streamGuardFiller(40 << 10)
	released := 0
	for off := 0; off < len(text); off += 24 {
		end := min(off+24, len(text))
		units, v := guard.Push(text[off:end], []byte(text[off:end]))
		if v != nil {
			t.Fatal("clean stream blocked")
		}
		for _, u := range units {
			released += len(u)
		}
	}
	units, _ := guard.Finish()
	for _, u := range units {
		released += len(u)
	}
	if released != len(text) {
		t.Fatalf("released %d of %d bytes", released, len(text))
	}
	maxCloud := len(text)/streamGuardCloudEvery + 2
	if cloud < 2 || cloud > maxCloud || local < 4*cloud {
		t.Fatalf("cloud checks %d (want 2..%d), local checks %d", cloud, maxCloud, local)
	}
}

// TestStreamGuardOpenPEMBlockIsBoundedAndLinear: an unclosed private-key
// header holds the stream up to the PEM bound and no further, and costs no
// more checks than the same stream without it (rel-1-0-10:GAP-0369).
func TestStreamGuardOpenPEMBlockIsBoundedAndLinear(t *testing.T) {
	header := resprevPEMHeader(t)
	check, _ := streamGuardTestCheck()
	scanned := map[string]int{}
	held := map[string]int{}
	for _, name := range []string{"plain", "open header"} {
		text := "Example key layout:\n" + streamGuardFiller(80<<10)
		if name == "open header" {
			text = "Example key layout:\n" + header + streamGuardFiller(80<<10)
		}
		guard := newCompletionStreamGuard(func(w string) *ScanVerdict {
			scanned[name] += len(w)
			return check(w)
		}, streamGuardScanEvery)
		for off := 0; off < len(text); off += 24 {
			end := min(off+24, len(text))
			if _, v := guard.Push(text[off:end], []byte(text[off:end])); v != nil {
				t.Fatalf("%s blocked", name)
			}
			held[name] = max(held[name], guard.Held())
		}
		if _, v := guard.Finish(); v != nil {
			t.Fatalf("%s blocked at the end", name)
		}
	}
	if held["open header"] > streamGuardPEMBound+streamGuardScanEvery+24 {
		t.Fatalf("open header held %d bytes, past the %d byte PEM bound", held["open header"], streamGuardPEMBound)
	}
	if held["plain"] > 512 {
		t.Fatalf("plain stream held %d bytes", held["plain"])
	}
	if scanned["open header"] > 2*scanned["plain"]+2*streamGuardPEMBound {
		t.Fatalf("open header scanned %d bytes against %d for the same stream without it", scanned["open header"], scanned["plain"])
	}
}

// TestPassthroughStreamedToolCallIsCheckedBeforeRelease: a streamed
// passthrough tool call is assembled and checked by the tool-call rules
// before any of its frames reach the client; a blocked call ends the stream
// with the in-band notice (rel-1-0-10:GAP-0370). The call is a tool-call row
// of the regex security suite the tool-call rules block.
func TestPassthroughStreamedToolCallIsCheckedBeforeRelease(t *testing.T) {
	_, insp := streamGuardTestCheck()
	proxy := newTestProxy(t, &mockProvider{}, insp, "action")
	var name, args string
	for _, c := range readJSONL[regexCase](t, "regex", "corpus.jsonl") {
		if c.Direction != "tool_call" || !c.IsAttack || c.ToolName == "" {
			continue
		}
		calls, _ := json.Marshal([]map[string]interface{}{{"type": "function",
			"function": map[string]string{"name": c.ToolName, "arguments": c.Content}}})
		if v := proxy.inspectToolCalls(context.Background(), calls); v != nil && v.Action == guardrailActionBlock {
			name, args = c.ToolName, c.Content
			break
		}
	}
	if name == "" {
		t.Skip("no suite tool-call row blocks")
	}
	toolFrames := func(input string) []string {
		start, _ := json.Marshal(map[string]interface{}{"type": "content_block_start", "index": 1,
			"content_block": map[string]interface{}{"type": "tool_use", "id": "toolu_1", "name": name, "input": map[string]string{}}})
		frames := []string{
			anthFrame(t, map[string]string{"type": "text_delta", "text": "Running it now."}),
			"event: content_block_start\ndata: " + string(start) + "\n\n",
		}
		for off := 0; off < len(input); off += 7 {
			end := min(off+7, len(input))
			delta, _ := json.Marshal(map[string]interface{}{"type": "content_block_delta", "index": 1,
				"delta": map[string]string{"type": "input_json_delta", "partial_json": input[off:end]}})
			frames = append(frames, "event: content_block_delta\ndata: "+string(delta)+"\n\n")
		}
		return append(frames, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}
	out := resprevPassthrough(t, "anthropic", "/v1/messages", toolFrames(args))
	if strings.Contains(out, "tool_use") || strings.Contains(out, "input_json_delta") {
		t.Fatalf("a blocked tool call reached the client")
	}
	if !strings.Contains(out, "[DefenseClaw]") || !strings.Contains(out, "message_stop") {
		t.Fatalf("the blocked stream did not end with the in-band notice: %q", out)
	}
	benign := `{"path":"README.md"}`
	name = "read_file"
	out = resprevPassthrough(t, "anthropic", "/v1/messages", toolFrames(benign))
	if !strings.Contains(out, "input_json_delta") || strings.Contains(out, "[DefenseClaw]") {
		t.Fatalf("a clean tool call was not released whole")
	}
}

// TestPassthroughBlockedStreamEndsWithNotice: a blocked passthrough stream
// ends with the block notice in the client's own stream format, not a bare
// stop (review P4-6).
func TestPassthroughBlockedStreamEndsWithNotice(t *testing.T) {
	secret := resprevSecret(t)
	out := resprevPassthrough(t, "openai", "/v1/passthrough-stream", []string{
		oaiFrame(t, "data: ", streamGuardFiller(600)), oaiFrame(t, "data: ", "\n"+secret+"\n"), "data: [DONE]\n\n",
	})
	if strings.Contains(out, secret) {
		t.Fatal("secret released")
	}
	if !strings.Contains(out, "[DefenseClaw]") || !strings.HasSuffix(strings.TrimSpace(out), "data: [DONE]") {
		t.Fatalf("no in-band notice at the end of the blocked stream: %q", out[max(0, len(out)-400):])
	}
}
