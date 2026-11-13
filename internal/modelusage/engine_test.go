package modelusage

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type captureSink struct {
	mu   sync.Mutex
	recs []Record
	ch   chan struct{}
}

func newCapture() *captureSink { return &captureSink{ch: make(chan struct{}, 1024)} }

func (s *captureSink) Emit(_ context.Context, r Record) {
	s.mu.Lock()
	s.recs = append(s.recs, r)
	s.mu.Unlock()
	s.ch <- struct{}{}
}

func (s *captureSink) wait(t *testing.T, n int) []Record {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("sink got %d of %d records", i, n)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.recs...)
}

func enabled() config.TokenomicsConfig { return config.TokenomicsConfig{Enabled: true} }

func facts() CallFacts {
	return CallFacts{
		RequestID: "r1", Connector: "claudecode", APIFamily: FamilyMessages, CallRole: RoleAgent,
		RequestedProvider: "anthropic", RequestedModel: "claude-sonnet-4-5",
		SelectedProvider: "anthropic", SelectedModel: "claude-haiku-4-5-20251001",
		Route:       RouteFacts{Decision: DecisionApplied, Source: "rules", RuleID: "cheap"},
		ProfileName: "eng", Subject: "u1", Groups: []string{"g1"}, IdentityVerified: true,
	}
}

func TestDisabledEngineIsInert(t *testing.T) {
	before := runtime.NumGoroutine()
	e := NewEngine(newCapture())
	e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	c := e.Begin(context.Background(), facts())
	c.Body([]byte(`{"usage":{"input_tokens":1,"output_tokens":1}}`))
	if rec := c.End(nil); rec.Usage.Has != 0 || rec.Facts.RequestID != "" {
		t.Fatalf("disabled engine must record nothing: %+v", rec)
	}
	if e.Enabled() || runtime.NumGoroutine() > before {
		t.Fatalf("disabled engine started a goroutine (%d > %d)", runtime.NumGoroutine(), before)
	}
	var nilEngine *Engine
	nilEngine.Begin(context.Background(), facts()).End(nil)
}

func TestRecordFlowNonStreamWithCost(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	c := e.Begin(context.Background(), facts())
	c.UpstreamHeader(200, http.Header{})
	c.Body(fixture(t, "anthropic_messages.json"))
	rec := c.End(nil)
	if rec.Outcome != "completed" || rec.Usage.Input != 2112 || rec.Usage.Source != SourceProvider {
		t.Fatalf("%+v", rec)
	}
	if rec.Cost.Basis != BasisComputed || rec.Cost.USD == nil || rec.Cost.TableVersion != "t1" || rec.Cost.PriceEntry != "anthropic/claude-haiku-4-5*" {
		t.Fatalf("%+v", rec.Cost)
	}
	got := sink.wait(t, 1)
	if got[0].Facts.RequestID != "r1" || got[0].Facts.Route.RuleID != "cheap" || got[0].Facts.Subject != "u1" {
		t.Fatalf("%+v", got[0].Facts)
	}
	// End is idempotent: no second record
	if again := c.End(errors.New("late")); again.Outcome != "completed" {
		t.Fatalf("second End must return the first record: %+v", again)
	}
	select {
	case <-sink.ch:
		t.Fatal("a second End enqueued another record")
	case <-time.After(100 * time.Millisecond):
	}
	// labels are bounded and carry no identity
	for _, l := range rec.Labels {
		if l.Key == "user" || l.Value == "u1" || l.Value == "g1" {
			t.Fatalf("identity in label: %+v", l)
		}
	}
	if rec.Labels[2] != (Label{"model", "anthropic/claude-haiku-4-5*"}) {
		t.Fatalf("model label: %+v", rec.Labels)
	}
}

func TestStreamAndGivenUsagePrecedence(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})

	f := facts()
	f.Streaming = true
	c := e.Begin(context.Background(), f)
	c.UpstreamHeader(200, nil)
	data := fixture(t, "anthropic_stream.sse")
	for len(data) > 0 {
		n := 13
		if n > len(data) {
			n = len(data)
		}
		c.Chunk(data[:n])
		data = data[n:]
	}
	rec := c.End(nil)
	if rec.Usage.Input != 1025 || rec.Usage.Source != SourceStreamFinal {
		t.Fatalf("%+v", rec.Usage)
	}

	// usage the proxy already parsed (Bifrost) wins over the bytes
	c = e.Begin(context.Background(), f)
	c.Chunk(fixture(t, "anthropic_stream.sse"))
	c.Usage(ParsedUsage{Input: 7, Output: 3})
	rec = c.End(nil)
	if rec.Usage.Input != 7 || rec.Usage.Output != 3 || rec.Usage.Has != HasInput|HasOutput {
		t.Fatalf("%+v", rec.Usage)
	}
}

func TestFailureOutcomesAndAbsentCost(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	c := e.Begin(context.Background(), facts())
	c.UpstreamHeader(429, nil)
	rec := c.End(nil)
	if rec.Outcome != "failed" || rec.ErrorType != "http_429" || rec.Cost.USD != nil || rec.Cost.Basis != BasisNone {
		t.Fatalf("%+v", rec)
	}
	c = e.Begin(context.Background(), facts())
	if rec = c.End(context.Canceled); rec.Outcome != "cancelled" {
		t.Fatalf("%+v", rec)
	}
}

func TestRoleFilterAndProvenanceSwitch(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	off := false
	tok := enabled()
	tok.Roles = []string{"judge"}
	tok.RecordRoutingProvenance = &off
	e.Apply(tok, testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	if rec := e.Begin(context.Background(), facts()).End(nil); rec.Facts.RequestID != "" {
		t.Fatal("agent role is not enabled and must not be recorded")
	}
	f := facts()
	f.CallRole = RoleJudge
	rec := e.Begin(context.Background(), f).End(nil)
	if rec.Facts.RequestedModel != "" || rec.Facts.Route.RuleID != "" || rec.Facts.ProfileName != "" || rec.Facts.Route.Decision != DecisionApplied {
		t.Fatalf("provenance off keeps only the decision: %+v", rec.Facts)
	}
}

func TestAIDefenseFlatCost(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	f := facts()
	f.CallRole = RoleAIDefense
	c := e.Begin(context.Background(), f)
	c.UpstreamHeader(200, nil)
	rec := c.End(nil)
	if rec.Cost.USD == nil || *rec.Cost.USD != 0.002 || rec.Cost.Basis != BasisComputed {
		t.Fatalf("%+v", rec.Cost)
	}
	c = e.Begin(context.Background(), f)
	c.UpstreamHeader(500, nil)
	if rec = c.End(nil); rec.Cost.USD != nil {
		t.Fatalf("a failed inspection has no cost: %+v", rec.Cost)
	}
}

func TestToggleStartsAndStopsWorkerWithoutLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	e := NewEngine(newCapture())
	for i := 0; i < 20; i++ {
		e.Apply(enabled(), testPricing())
		e.Begin(context.Background(), facts()).End(nil)
		e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	}
	time.Sleep(50 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > base+1 {
		t.Fatalf("goroutines %d > %d after toggling", n, base)
	}
}

type panicSink struct{ n int }

func (p *panicSink) Emit(context.Context, Record) { p.n++; panic("sink bug") }

func TestPanickingSinkDoesNotKillWorker(t *testing.T) {
	ps := &panicSink{}
	good := newCapture()
	e := NewEngine(ps, good)
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	e.Begin(context.Background(), facts()).End(nil)
	e.Begin(context.Background(), facts()).End(nil)
	good.wait(t, 2)
}

type blockSink struct{ release chan struct{} }

func (b *blockSink) Emit(context.Context, Record) { <-b.release }

func TestFullQueueDropsAndNeverBlocks(t *testing.T) {
	b := &blockSink{release: make(chan struct{})}
	e := NewEngine(b)
	e.Apply(enabled(), testPricing())
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize+500; i++ {
			e.Begin(context.Background(), facts()).End(nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("End blocked on a stuck sink")
	}
	if e.Dropped() < 400 {
		t.Fatalf("dropped = %d", e.Dropped())
	}
	close(b.release)
	e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
}

func TestBedrockInvokeHeadersFallback(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	f := facts()
	f.APIFamily = FamilyInvoke
	c := e.Begin(context.Background(), f)
	h := http.Header{}
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "40")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "9")
	c.UpstreamHeader(200, h)
	c.Body([]byte(`{"content":[]}`))
	rec := c.End(nil)
	if rec.Usage.Input != 40 || rec.Usage.Output != 9 || rec.Usage.Source != SourceHeader {
		t.Fatalf("%+v", rec.Usage)
	}
}
