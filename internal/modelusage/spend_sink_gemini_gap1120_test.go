// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// substrate-1:GAP-1120: Gemini sends usageMetadata in every chunk of a
// stream, a running count until the chunk with the finishReason. A stream
// cut before that chunk was charged as known with the running count (input
// and the output so far), so the unknown-cost deny never fired for Gemini.
// The usage is final only from the finishReason chunk on; before it a cut
// stream is of unknown cost, as an Anthropic stream cut before message_delta
// is (rel-1-0-10:GAP-1715).
func TestChargeBudgetsGeminiStreamCutBeforeFinishIsUnknown(t *testing.T) {
	e := NewEngine(newCapture())
	charges := &nativeChargeSink{}
	e.SetSpendSink(charges)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	const (
		running = `{"candidates":[{"content":{"role":"model","parts":[{"text":"hel"}]}}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":5,"totalTokenCount":1005},"modelVersion":"gemini-2.5-pro"}`
		final   = `{"candidates":[{"content":{"role":"model","parts":[{"text":"lo"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":40,"totalTokenCount":1040},"modelVersion":"gemini-2.5-pro"}`
	)
	sse := func(docs ...string) []byte {
		var b []byte
		for _, d := range docs {
			b = append(b, "data: "+d+"\n\n"...)
		}
		return b
	}
	f := facts()
	f.APIFamily, f.SelectedProvider, f.SelectedModel = FamilyGemini, "google", "gemini-2.5-pro"
	f.Streaming, f.ChargeKeys = true, []string{"user:u1"}
	run := func(body []byte, end error) {
		c := e.Begin(context.Background(), f)
		c.UpstreamHeader(200, nil)
		c.Chunk(body)
		c.End(end)
	}
	reset := errors.New("read tcp: connection reset by peer")
	run(sse(running), reset)                      // cut before the finishReason chunk
	run(sse(running), ErrClientGone)              // the agent went away before it
	run(sse(running, final), reset)               // cut after the final usage
	run(sse(running), nil)                        // a stream that ended (no cut) keeps its usage
	run([]byte("["+running+"\n"), reset)          // the JSON array stream (no alt=sse), cut
	run([]byte("["+running+",\n"+final+"]"), nil) // the JSON array stream, whole
	if want := []bool{false, false, true, true, false, true}; !slices.Equal(charges.known, want) {
		t.Fatalf("known %v, want %v (usd %v)", charges.known, want, charges.usd)
	}
	if charges.usd[2] <= 0 || charges.usd[5] != charges.usd[2] {
		t.Fatalf("a stream with its final usage keeps the computed cost: %v", charges.usd)
	}
}

// Allocation pin: a Gemini stream chunk without usage (the finishReason
// check included) is read with no allocation.
func TestGeminiStreamChunkAllocs(t *testing.T) {
	p := NewStreamParser(FamilyGemini)
	chunk := []byte(`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hel"}]},"finishReason":"STOP"}]}` + "\n\n")
	p.Write(chunk)
	if a := testing.AllocsPerRun(1000, func() { p.Write(chunk) }); a != 0 {
		t.Fatalf("allocs per chunk: %v", a)
	}
}
