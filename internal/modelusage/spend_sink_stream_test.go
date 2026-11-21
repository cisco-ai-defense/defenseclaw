// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An Anthropic stream cut after message_start (output_tokens 1) and before
// message_delta is charged as unknown, never as input + 1 output token: a
// client that drops the connection once the content arrived would otherwise
// get its answer billed as one output token (rel-1-0-10:GAP-1715). The same
// cut after message_delta, and a whole stream, keep their computed cost.
func TestChargeBudgetsStreamCutBeforeFinalUsageIsUnknown(t *testing.T) {
	e := NewEngine(newCapture())
	charges := &nativeChargeSink{}
	e.SetSpendSink(charges)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	full := fixture(t, "anthropic_stream.sse")
	cut := bytes.Index(full, []byte("event: message_delta"))
	if cut < 0 {
		t.Fatal("fixture has no message_delta")
	}
	f := facts()
	f.Streaming, f.ChargeKeys = true, []string{"user:u1"}
	run := func(body []byte, end error) {
		c := e.Begin(context.Background(), f)
		time.Sleep(2 * time.Millisecond) // a TTFB above 0 on a coarse clock
		c.UpstreamHeader(200, nil)
		c.Chunk(body)
		c.End(end)
	}
	for _, end := range []error{context.Canceled, ErrClientGone, errors.New("upstream reset")} {
		run(full[:cut], end)
	}
	run(full, context.Canceled)
	run(full, nil)
	if want := []bool{false, false, false, true, true}; !slices.Equal(charges.known, want) {
		t.Fatalf("known %v, want %v (usd %v)", charges.known, want, charges.usd)
	}
	if charges.usd[3] <= 0 || charges.usd[3] != charges.usd[4] {
		t.Fatalf("a stream with its final usage keeps the computed cost: %v", charges.usd)
	}
}
