package modelusage

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestEmptyRoleDefaultsToAgentBeforeTheRoleFilter(t *testing.T) {
	e := NewEngine(newCapture())
	tok := enabled()
	tok.Roles = []string{"agent"}
	e.Apply(tok, testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	f := facts()
	f.CallRole = ""
	if rec := e.Begin(context.Background(), f).End(nil); rec.Facts.CallRole != RoleAgent {
		t.Fatalf("empty role must default to agent and be recorded: %+v", rec.Facts)
	}
}

func TestConcurrentApplyKeepsSnapshotAndWorkerConsistent(t *testing.T) {
	sink := newCapture()
	e := NewEngine(sink)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				if (i+j)%2 == 0 {
					e.Apply(enabled(), testPricing())
				} else {
					e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
				}
			}
		}(i)
	}
	wg.Wait()
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	e.Begin(context.Background(), facts()).End(nil)
	sink.wait(t, 1) // enabled means a worker exists and the record is delivered
}

func TestEndWhileChunksArrive(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	f := facts()
	f.Streaming = true
	c := e.Begin(context.Background(), f)
	data := fixture(t, "anthropic_stream.sse")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			c.Chunk(data[:7])
		}
	}()
	time.Sleep(time.Millisecond)
	c.End(context.Canceled) // client went away mid stream; run with -race
	<-done
}

func TestEmptyGivenUsageDoesNotHideParsedUsage(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	c := e.Begin(context.Background(), facts())
	c.Usage(ParsedUsage{}) // the Bifrost mapper had nothing
	c.Body(fixture(t, "anthropic_messages.json"))
	if rec := c.End(nil); rec.Usage.Input != 2112 {
		t.Fatalf("parsed usage must be used when the given usage is empty: %+v", rec.Usage)
	}
}

func TestMetadataStringContainingUsageKeyDoesNotHideRealUsage(t *testing.T) {
	big := strings.Repeat("x", 3*maxLineBytes)
	line := `data: {"type":"response.completed","response":{"output":"` + big +
		`","usage":{"input_tokens":5,"output_tokens":2},"metadata":{"note":"usage","usage":"team-a"}}}` + "\n"
	p := NewStreamParser(FamilyResponses)
	feed(p, []byte(line), 1<<20)
	if u := p.Usage(); u.Input != 5 || u.Output != 2 {
		t.Fatalf("%+v", u)
	}
	body := `{"output":"` + strings.Repeat("y", 2*maxFullDecodeBytes) + `","usage":{"input_tokens":3,"output_tokens":1},"metadata":{"usage":"x"}}`
	if u := ParseBody(FamilyResponses, []byte(body)); u.Input != 3 {
		t.Fatalf("%+v", u)
	}
}

func TestAnthropicWithoutInputTokensHasNoInput(t *testing.T) {
	u := ParseBody(FamilyMessages, []byte(`{"usage":{"cache_read_input_tokens":100,"output_tokens":5}}`))
	if u.Has&HasInput != 0 || u.Has&HasOutput == 0 {
		t.Fatalf("an absent input count must stay absent: %+v", u)
	}
	u = ParseBody(FamilyConverse, []byte(`{"usage":{"cacheReadInputTokens":100,"outputTokens":5}}`))
	if u.Has&HasInput != 0 {
		t.Fatalf("%+v", u)
	}
}

func TestHugeBodyKeepsOpenAIServiceTier(t *testing.T) {
	body := `{"service_tier":"flex","output":"` + strings.Repeat("z", 2*maxFullDecodeBytes) + `","usage":{"input_tokens":1,"output_tokens":1}}`
	if u := ParseBody(FamilyResponses, []byte(body)); u.Partial != "service_tier:flex" {
		t.Fatalf("%+v", u)
	}
}

func TestModelLabelFollowsTheEntryThatPricedTheCall(t *testing.T) {
	e := NewEngine(newCapture())
	e.Apply(enabled(), testPricing())
	defer e.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	f := facts()
	f.SelectedModel = "no-entry-for-this-alias"
	c := e.Begin(context.Background(), f)
	c.Body(fixture(t, "anthropic_messages.json")) // response model claude-haiku-4-5-20251001 has an entry
	rec := c.End(nil)
	if rec.Cost.USD == nil {
		t.Fatalf("response model should have priced the call: %+v", rec.Cost)
	}
	for _, l := range rec.Labels {
		if l.Key == "model" && l.Value != "anthropic/claude-haiku-4-5*" {
			t.Fatalf("model label disagrees with the price entry: %+v", rec.Labels)
		}
	}
}
