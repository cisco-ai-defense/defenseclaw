// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// The black-box cases (recorded once, unrecorded counted, both orders,
// reload) are in internal/gateway/otel_ingest_native_usage_percall_v8_test.go.
// These cover the grace, the disable drain, the listener kinds and the bounds.

func reconcileEngine(t *testing.T) (*Engine, *captureSink, *nativeChargeSink) {
	t.Helper()
	sink, charges := newCapture(), &nativeChargeSink{}
	e := NewEngine(sink)
	e.SetSpendSink(charges)
	e.Apply(enabled(), testPricing())
	t.Cleanup(func() { e.Apply(config.TokenomicsConfig{}, config.PricingConfig{}) })
	return e, sink, charges
}

func routeOnlyCall(e *Engine) Call {
	f := facts()
	f.Listener, f.ChargeKeys = engine.ListenerRouteOnly, []string{"user:u1"}
	return e.Begin(context.Background(), f)
}

func endWithUsage(c Call, requestID string) Record {
	h := http.Header{}
	if requestID != "" {
		h.Set("Request-Id", requestID)
	}
	c.UpstreamHeader(200, h)
	c.Body([]byte(`{"usage":{"input_tokens":1000,"output_tokens":50,"cache_read_input_tokens":200,"cache_creation_input_tokens":100}}`))
	return c.End(nil)
}

func noRecord(t *testing.T, sink *captureSink) {
	t.Helper()
	select {
	case <-sink.ch:
		t.Fatalf("unexpected record %+v", sink.recs)
	case <-time.After(100 * time.Millisecond):
	}
}

// A native record parked behind a listener call that runs past the grace is
// counted; the listener record that then matches it keeps its budget charge
// but is not counted a second time.
func TestReconcileParkedNativeIsCountedAfterTheGrace(t *testing.T) {
	e, sink, charges := reconcileEngine(t)
	e.rc.grace = 20 * time.Millisecond
	c := routeOnlyCall(e)
	native := nativeRecord(nil)
	native.Facts.ModelResponseID = "req_1"
	if _, ok := e.RecordNative(native); !ok {
		t.Fatal("a parked native record may still be counted")
	}
	if recs := sink.wait(t, 1); recs[0].Facts.Listener != "native_otel" {
		t.Fatalf("the native record is counted after the grace: %+v", recs[0])
	}
	endWithUsage(c, "req_1")
	noRecord(t, sink)
	if len(charges.usd) != 1 {
		t.Fatalf("the listener budget charge stays: %v", charges.usd)
	}
}

// Turning tokenomics off counts the parked records before the queue closes.
func TestReconcileDisableCountsParkedNatives(t *testing.T) {
	e, sink, _ := reconcileEngine(t)
	c := routeOnlyCall(e)
	e.RecordNative(nativeRecord(nil))
	noRecord(t, sink)
	e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	if recs := sink.wait(t, 1); recs[0].Facts.Listener != "native_otel" {
		t.Fatalf("parked native record lost on disable: %+v", recs[0])
	}
	c.End(nil)
}

// Only route-only listener records pair with native records, a shared
// provider request id pairs even when the counts differ, and a panic while
// building a listener record still ends it in the ledger.
func TestReconcileMatchKinds(t *testing.T) {
	t.Run("guardrail listener", func(t *testing.T) {
		e, sink, _ := reconcileEngine(t)
		f := facts()
		f.Listener = "guardrail"
		endWithUsage(e.Begin(context.Background(), f), "")
		e.RecordNative(nativeRecord(nil))
		if recs := sink.wait(t, 2); len(recs) != 2 {
			t.Fatalf("records %d", len(recs))
		}
	})
	t.Run("request id", func(t *testing.T) {
		e, sink, _ := reconcileEngine(t)
		endWithUsage(routeOnlyCall(e), "req_9")
		native := nativeRecord(nil)
		native.Facts.ModelResponseID, native.Usage.Output = "req_9", 51
		if _, ok := e.RecordNative(native); ok {
			t.Fatal("the same request id is the same call")
		}
		sink.wait(t, 1)
		noRecord(t, sink)
	})
	t.Run("counts differ, no id", func(t *testing.T) {
		e, sink, _ := reconcileEngine(t)
		endWithUsage(routeOnlyCall(e), "")
		native := nativeRecord(nil)
		native.Usage.Output = 51
		e.RecordNative(native)
		sink.wait(t, 2)
	})
	t.Run("unbuilt listener record releases the parked native", func(t *testing.T) {
		e, sink, _ := reconcileEngine(t)
		c := routeOnlyCall(e).(*call)
		e.RecordNative(nativeRecord(nil))
		_ = c.settle(Record{}) // what End does when the record cannot be built
		if recs := sink.wait(t, 1); recs[0].Facts.Listener != "native_otel" {
			t.Fatalf("released native record: %+v", recs[0])
		}
		if e.rc.ledgers["claudecode"] != nil {
			t.Fatal("the ledger of an idle connector is dropped")
		}
	})
}

// A connector whose native usage is not imported is not tracked, a listener
// call in flight past reconcileTTL holds no native record back, and the
// queues keep their cap with O(1) trimming.
func TestReconcileBounds(t *testing.T) {
	t.Run("native import off", func(t *testing.T) {
		off := false
		sink := newCapture()
		e := NewEngine(sink)
		e.Apply(config.TokenomicsConfig{Enabled: true, NativeOTelImport: config.TokenomicsNativeImportConfig{ClaudeCode: &off}}, testPricing())
		defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
		endWithUsage(routeOnlyCall(e), "req_1")
		sink.wait(t, 1)
		if len(e.rc.ledgers) != 0 {
			t.Fatalf("no native record can arrive, nothing is tracked: %v", e.rc.ledgers)
		}
	})
	t.Run("stale call in flight", func(t *testing.T) {
		e, sink, _ := reconcileEngine(t)
		c := routeOnlyCall(e)
		e.rc.mu.Lock()
		for seq := range e.rc.ledgers["claudecode"].inflight {
			e.rc.ledgers["claudecode"].inflight[seq] = time.Now().Add(-reconcileTTL - time.Second)
		}
		e.rc.mu.Unlock()
		if _, ok := e.RecordNative(nativeRecord(nil)); !ok {
			t.Fatal("not recorded")
		}
		if recs := sink.wait(t, 1); recs[0].Facts.Listener != "native_otel" {
			t.Fatalf("counted at once: %+v", recs[0])
		}
		c.End(nil)
	})
	t.Run("queue cap", func(t *testing.T) {
		var q entryQueue
		u := Usage{Input: 1, Output: 1, Has: HasInput | HasOutput}
		for i := 0; i < 3*reconcileMaxEntries; i++ {
			u.Input = int64(i)
			q.push(reconcileEntry{usage: u, at: time.Now()})
		}
		if q.size() != reconcileMaxEntries || cap(q.items) > 4*reconcileMaxEntries {
			t.Fatalf("size %d cap %d", q.size(), cap(q.items))
		}
		u.Input = 3*reconcileMaxEntries - 1
		if !q.take(reconcileEntry{usage: u}) {
			t.Fatal("the newest entry pairs")
		}
		u.Input = 0
		if q.take(reconcileEntry{usage: u}) {
			t.Fatal("the oldest entries were evicted")
		}
		q.trim(time.Now().Add(time.Hour))
		if q.size() != 0 {
			t.Fatalf("trim left %d", q.size())
		}
	})
}
