// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// streamGuardFiller is benign assistant prose with no detector match.
func streamGuardFiller(n int) string {
	sentences := []string{
		"The build passed on the second run after the cache was cleared.",
		"I updated the handler so the retry loop stops after three attempts.",
		"Next, the table test covers the empty input and the long input.",
		"The function returns early when the list is empty, which keeps the hot path short.",
		"Let me know if you want the same change in the other two packages.",
	}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(sentences[i%len(sentences)])
		if i%4 == 3 {
			b.WriteString("\n\n")
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func streamGuardTestCheck() (func(string) *ScanVerdict, *GuardrailInspector) {
	insp := NewGuardrailInspector("local", nil, nil)
	ctx := context.Background()
	return func(window string) *ScanVerdict {
		return insp.InspectMidStream(ctx, "completion", window, []ChatMessage{{Role: "assistant", Content: window}}, "test", "action")
	}, insp
}

func verdictHasRule(v *ScanVerdict, ruleID string) bool {
	if v == nil {
		return false
	}
	for _, f := range v.Findings {
		if strings.HasPrefix(f, ruleID+":") {
			return true
		}
	}
	return false
}

// streamChunks splits text at random rune boundaries, 1..maxChunk bytes each.
func streamChunks(rng *rand.Rand, text string, maxChunk int) []string {
	var out []string
	for off := 0; off < len(text); {
		end := off + 1 + rng.Intn(maxChunk)
		if end > len(text) {
			end = len(text)
		}
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end++
		}
		out = append(out, text[off:end])
		off = end
	}
	return out
}

// TestCompletionStreamGuardFindsSecretUnderAnyChunking is the GAP-0212 property: for any chunking of a completion that holds a
// secret rule fixture (head, middle or tail, any scan interval), the guard's checks find the secret, a blocking secret stops the
// stream before any of its bytes are released, and nothing is released that no check covered.
func TestCompletionStreamGuardFindsSecretUnderAnyChunking(t *testing.T) {
	check, _ := streamGuardTestCheck()
	filler := streamGuardFiller(3 << 10)
	rng := rand.New(rand.NewSource(20261113))
	blocking := 0
	for _, fx := range secretRuleTruePositives() {
		whole := check("Here is the value:\n" + fx.input + "\n")
		if !verdictHasRule(whole, fx.wantID) {
			continue // the rule needs context the bare value lacks; its own test covers it
		}
		blocks := whole.Action == guardrailActionBlock
		if blocks {
			blocking++
		}
		for trial := 0; trial < 60; trial++ {
			pos := 0
			switch trial % 3 {
			case 1:
				pos = len(filler)
			case 2:
				pos = rng.Intn(len(filler))
				if sp := strings.LastIndexByte(filler[:pos], ' '); sp >= 0 {
					pos = sp + 1
				}
			}
			text := filler[:pos] + "\n" + fx.input + "\n" + filler[pos:]
			secretStart := pos + 1
			found := false
			guard := newCompletionStreamGuard(func(window string) *ScanVerdict {
				v := check(window)
				found = found || verdictHasRule(v, fx.wantID)
				return v
			}, 1+rng.Intn(600))
			var released strings.Builder
			var blocked *ScanVerdict
			for _, chunk := range streamChunks(rng, text, 1+rng.Intn(120)) {
				units, v := guard.Push(chunk, []byte(chunk))
				for _, u := range units {
					released.Write(u)
				}
				if v != nil {
					blocked = v
					break
				}
			}
			if blocked == nil {
				units, v := guard.Finish()
				for _, u := range units {
					released.Write(u)
				}
				blocked = v
			}
			if !found {
				t.Fatalf("%s trial %d (secret at %d of %d): no check found %s", fx.name, trial, secretStart, len(text), fx.wantID)
			}
			if !strings.HasPrefix(text, released.String()) {
				t.Fatalf("%s trial %d: released bytes are not a prefix of the stream", fx.name, trial)
			}
			if blocks {
				if blocked == nil {
					t.Fatalf("%s trial %d: the stream was not blocked", fx.name, trial)
				}
				if released.Len() > secretStart {
					t.Fatalf("%s trial %d: %d bytes released, past the secret at %d", fx.name, trial, released.Len(), secretStart)
				}
			} else if blocked == nil && released.String() != text {
				t.Fatalf("%s trial %d: an alert-only stream did not release all of its text", fx.name, trial)
			}
		}
	}
	if blocking < 10 {
		t.Fatalf("only %d blocking secret fixtures exercised", blocking)
	}
}

// TestCompletionStreamGuardReleasesCleanStreamInOrder: a clean stream reaches the client whole and in order, units without
// text (metadata frames) keep their place, and the guard holds back at most a bounded tail between checks.
func TestCompletionStreamGuardReleasesCleanStreamInOrder(t *testing.T) {
	check, _ := streamGuardTestCheck()
	text := streamGuardFiller(16 << 10)
	rng := rand.New(rand.NewSource(7))
	guard := newCompletionStreamGuard(check, streamGuardScanEvery)
	var want, got strings.Builder
	maxHeld := 0
	for i, chunk := range streamChunks(rng, text, 48) {
		unit := "data:" + chunk + "\n"
		want.WriteString(unit)
		units, v := guard.Push(chunk, []byte(unit))
		if v != nil {
			t.Fatalf("clean stream blocked: %s", v.Reason)
		}
		for _, u := range units {
			got.Write(u)
		}
		if i%10 == 0 {
			meta := "event:ping\n"
			want.WriteString(meta)
			units, _ := guard.Push("", []byte(meta))
			for _, u := range units {
				got.Write(u)
			}
		}
		if h := guard.Held(); h > maxHeld {
			maxHeld = h
		}
	}
	units, v := guard.Finish()
	if v != nil {
		t.Fatalf("clean tail blocked: %s", v.Reason)
	}
	for _, u := range units {
		got.Write(u)
	}
	if got.String() != want.String() {
		t.Fatalf("released stream differs from the upstream stream")
	}
	if limit := streamGuardScanEvery + streamGuardHoldback + 200; maxHeld > limit {
		t.Fatalf("guard held %d bytes, want at most %d", maxHeld, limit)
	}
}

// TestCompletionStreamGuardWithoutCheckReleasesAtOnce: a mode that does not enforce streams unchanged.
func TestCompletionStreamGuardWithoutCheckReleasesAtOnce(t *testing.T) {
	guard := newCompletionStreamGuard(nil, 0)
	units, v := guard.Push("partial", []byte("a"))
	if v != nil || len(units) != 1 {
		t.Fatalf("observe-mode push held output: %d units, verdict %v", len(units), v)
	}
}

// BenchmarkCompletionStreamGuard is the per-stream cost of the guard on a 16 KiB benign completion in 24-byte chunks.
func BenchmarkCompletionStreamGuard(b *testing.B) {
	check, _ := streamGuardTestCheck()
	text := streamGuardFiller(16 << 10)
	chunks := streamChunks(rand.New(rand.NewSource(1)), text, 24)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	scans, held := 0, 0
	for i := 0; i < b.N; i++ {
		guard := newCompletionStreamGuard(check, streamGuardScanEvery)
		for _, c := range chunks {
			_, _ = guard.Push(c, []byte(c))
			if h := guard.Held(); h > held {
				held = h
			}
		}
		_, _ = guard.Finish()
		scans = guard.Scans()
	}
	b.ReportMetric(float64(scans), "scans/stream")
	b.ReportMetric(float64(held), "max-held-bytes")
}

// BenchmarkCompletionStreamPreGuard is the check cost of the scheme the guard replaced (the whole accumulated text every 500
// bytes, no hold-back), on the same stream, for the latency comparison in the GAP-0212 report.
func BenchmarkCompletionStreamPreGuard(b *testing.B) {
	check, _ := streamGuardTestCheck()
	text := streamGuardFiller(16 << 10)
	chunks := streamChunks(rand.New(rand.NewSource(1)), text, 24)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var acc strings.Builder
		last := 0
		for _, c := range chunks {
			acc.WriteString(c)
			if acc.Len()-last >= 500 {
				_ = check(acc.String())
				last = acc.Len()
			}
		}
	}
}

// TestStreamingProxyBlocksSecretInLastBytes is GAP-0212 end to end on the /llm streaming path: a secret fixture split across
// small chunks at the very end of a long completion is withheld and the stream ends with the block notice.
func TestStreamingProxyBlocksSecretInLastBytes(t *testing.T) {
	var secret string
	for _, fx := range secretRuleTruePositives() {
		if fx.wantID == "SEC-GITHUB-TOKEN" {
			secret = fx.input
		}
	}
	if secret == "" {
		t.Fatal("GitHub token fixture missing")
	}
	text := streamGuardFiller(2600) + "\n" + secret
	chunks := []StreamChunk{{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}}}}
	for off := 0; off < len(text); off += 7 {
		end := off + 7
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: text[off:end]}}}})
	}
	_, insp := streamGuardTestCheck()
	proxy := newTestProxy(t, &mockProvider{streamChunks: chunks}, insp, "action")
	rec := postChat(t, proxy, mustJSON(t, map[string]interface{}{
		"model": "gpt-4", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "summarize the change"}},
	}))
	body := rec.Body.String()
	if !strings.Contains(body, "blocked") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("stream did not end with the block notice")
	}
	var sent strings.Builder
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var chunk StreamChunk
		if json.Unmarshal([]byte(data), &chunk) == nil && chunk.ID != "chatcmpl-blocked" && len(chunk.Choices) > 0 && chunk.Choices[0].Delta != nil {
			sent.WriteString(chunk.Choices[0].Delta.Content)
		}
	}
	if !strings.HasPrefix(text, sent.String()) {
		t.Fatalf("the client received text that is not the model's")
	}
	if secretStart := len(text) - len(secret); sent.Len() > secretStart {
		t.Fatalf("%d bytes sent, past the secret at %d", sent.Len(), secretStart)
	}
	if sent.Len() == 0 {
		t.Fatalf("the clean text before the secret was never released")
	}
}
