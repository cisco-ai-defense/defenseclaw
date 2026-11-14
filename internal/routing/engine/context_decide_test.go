// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// contextConfig adds a deploy signal, a shell-tool signal and a tool_loop
// decision to the engine fixture, with routing.context on.
func contextConfig(c config.RoutingContextConfig) *config.Config {
	cfg := testConfig()
	r := &cfg.Routing
	r.Signals.Keywords = append(r.Signals.Keywords,
		config.RoutingKeywordSignal{Name: "deploy", Keywords: []string{"deploy"}},
		config.RoutingKeywordSignal{Name: "shell", Keywords: []string{"bash"}})
	r.Decisions = append([]config.RoutingDecisionRule{
		{Name: "deploy", Priority: 30, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "deploy"}}, ModelRefs: []string{"claude"}},
		{Name: "shell", Priority: 25, Conditions: []config.RoutingCondition{{Type: "keyword", Name: "shell"}}, ModelRefs: []string{"fast"}},
	}, r.Decisions...)
	r.Context = c
	return cfg
}

func decided(d Decision) string {
	if d.Backend == nil {
		return d.Outcome + "/" + d.FailureCode
	}
	return d.Backend.Alias + "/" + d.RuleID
}

func TestDecideContextRoutesAToolLoop(t *testing.T) {
	ctx := context.Background()
	req := chat("yes, go ahead")
	req.ContextTurns = []string{"deploy the service to staging"}
	off := mustEngine(t, contextConfig(config.RoutingContextConfig{}), Options{})
	if got := decided(off.Decide(ctx, req)); got != "local/" {
		t.Fatalf("context off = %s, want the newest turn only (local)", got)
	}
	on := mustEngine(t, contextConfig(config.RoutingContextConfig{RecentUserTurns: 2}), Options{})
	if got := decided(on.Decide(ctx, req)); got != "claude/deploy" {
		t.Fatalf("context on = %s, want claude/deploy from the older turn", got)
	}

	tools := chat("continue")
	tools.ToolNames, tools.ToolLoop = []string{"Bash"}, true
	if got := decided(on.Decide(ctx, tools)); got != "local/" {
		t.Fatalf("include_tool_names off = %s, tool names must not count", got)
	}
	withTools := mustEngine(t, contextConfig(config.RoutingContextConfig{IncludeToolNames: true}), Options{})
	if got := decided(withTools.Decide(ctx, tools)); got != "fast/shell" {
		t.Fatalf("tool name signal = %s, want fast/shell", got)
	}
}

func TestDecideToolLoopCondition(t *testing.T) {
	cfg := contextConfig(config.RoutingContextConfig{IncludeToolNames: true})
	cfg.Routing.Decisions = append([]config.RoutingDecisionRule{{Name: "loop", Priority: 40,
		Conditions: []config.RoutingCondition{{Type: "request", Name: "tool_loop"}}, ModelRefs: []string{"fast"}}}, cfg.Routing.Decisions...)
	e := mustEngine(t, cfg, Options{})
	req := chat("continue")
	req.ToolLoop = true
	if got := decided(e.Decide(context.Background(), req)); got != "fast/loop" {
		t.Fatalf("tool_loop = %s, want fast/loop", got)
	}
}

// Truncation never lowers the base: per_turn_bytes does not cut the newest
// turn, its signal still matches, and the cut older turn is recorded.
func TestDecideContextTruncationKeepsTheBase(t *testing.T) {
	e := mustEngine(t, contextConfig(config.RoutingContextConfig{RecentUserTurns: 1, MaxBytes: 64, PerTurnBytes: 16}), Options{})
	req := chat(strings.Repeat("x", 40) + " refactor this")
	req.ContextTurns = []string{strings.Repeat("h", 40)}
	d := e.Decide(context.Background(), req)
	if decided(d) != "claude/code" || !slices.Contains(d.Warnings, "context_truncated:bytes") {
		t.Fatalf("decision = %s warnings %q", decided(d), d.Warnings)
	}
}

type textClassifier struct{ seen *ClassifyInput }

func (c textClassifier) Name() string { return "systemone" }
func (c textClassifier) Classify(_ context.Context, in ClassifyInput) (ClassifyResult, error) {
	*c.seen = in
	return ClassifyResult{Aliases: []string{"fast"}, Confidence: 0.9}, nil
}

func TestDecideContextTextForSystemOneIsBounded(t *testing.T) {
	cfg := contextConfig(config.RoutingContextConfig{RecentUserTurns: 8, MaxBytes: 65536, PerTurnBytes: 1024})
	cfg.Routing.Classifier = "systemone"
	var seen ClassifyInput
	e := mustEngine(t, cfg, Options{Classifier: textClassifier{seen: &seen}})
	newest := strings.Repeat("n", 3000)
	req := chat(newest)
	req.ContextTurns = []string{strings.Repeat("a", 6000), strings.Repeat("b", 6000)}
	d := e.Decide(context.Background(), req)
	if len(seen.Text) > ClassifierTextLimit || !strings.HasPrefix(seen.Text, newest+"\n\n"+strings.Repeat("a", 1024)+"\n\nbbb") {
		t.Fatalf("classifier text %d bytes, does not start with the whole newest turn and the cut older turns", len(seen.Text))
	}

	if !slices.Contains(d.Warnings, "context_truncated:bytes") {
		t.Fatalf("warnings %q, want the classifier cap recorded", d.Warnings)
	}
}

// Off is today's behaviour: the context fields are ignored, and an active
// context with nothing beyond the newest turn decides as off.
func TestDecideContextOffIsUnchanged(t *testing.T) {
	ctx := context.Background()
	off := mustEngine(t, testConfig(), Options{})
	on := mustEngine(t, contextConfig(config.RoutingContextConfig{RecentUserTurns: 2, IncludeToolNames: true}), Options{})
	plain := mustEngine(t, contextConfig(config.RoutingContextConfig{}), Options{})
	for _, req := range []Request{
		chat("please REFACTORING this"), chat("alpha beta refactor"), chat("hello"), chat(""),
		{APIFamily: "responses", Connector: "codex", HasTools: true, Caller: Caller{Key: "1"}},
	} {
		want := off.Decide(ctx, req)
		with := req
		with.ContextTurns, with.FirstTurn, with.ToolNames, with.ToolLoop = []string{"deploy now"}, "bash", []string{"Bash"}, true
		for name, d := range map[string]Decision{"off with context fields": off.Decide(ctx, with), "on, newest only": on.Decide(ctx, req), "plain off": plain.Decide(ctx, with)} {
			d.Latency, want.Latency = 0, 0
			// The two context-config engines have extra decisions, so only
			// their answer is compared; off with context fields must be equal.
			same := reflect.DeepEqual(d, want) ||
				(name != "off with context fields" && decided(d) == decided(want) && slices.Equal(d.Warnings, want.Warnings))
			if !same {
				t.Fatalf("%s: %q = %s %q, want %s %q", name, req.Text, decided(d), d.Warnings, decided(want), want.Warnings)
			}
		}
	}
	if off.ContextCollector() != nil || plain.ContextCollector() != nil {
		t.Fatal("routing.context off still hands out a collector")
	}
}

func TestContextIsOffForVLLMSR(t *testing.T) {
	cfg := testConfig()
	cfg.Routing.Classifier = "vllm_sr"
	cfg.Routing.Decisions = slices.DeleteFunc(cfg.Routing.Decisions, func(d config.RoutingDecisionRule) bool { return d.Name == "codex-tools" })
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	cfg.Routing.Context = config.RoutingContextConfig{RecentUserTurns: 2}
	if err := cfg.Routing.Validate(); err == nil || !strings.Contains(err.Error(), "context needs classifier rules or systemone") {
		t.Fatalf("validation of routing.context with vllm_sr = %v", err)
	}
	if contextOptionsOf(cfg.Routing).Active() {
		t.Fatal("vllm_sr compiled an active context")
	}
}
