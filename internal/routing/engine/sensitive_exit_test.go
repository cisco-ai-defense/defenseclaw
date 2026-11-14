// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0576: a request that routing.sensitive narrowed never leaves on the
// original (cloud) request or on an alias outside routing.sensitive.aliases,
// on OSS and on managed hosts alike.

func sensitiveSignalConfig() *config.Config {
	cfg := testConfig()
	cfg.Routing.Sensitive = &config.RoutingSensitiveConfig{Signals: []string{"secret"}, Aliases: []string{"local"}}
	return cfg
}

func TestSensitiveNarrowedOriginalIsNeverAnExit(t *testing.T) {
	for _, managed := range []bool{false, true} {
		e := mustEngine(t, sensitiveSignalConfig(), Options{Managed: managed})
		d := e.Decide(context.Background(), chat("my key is AKIA1234"))
		if d.Outcome != OutcomeApplied || d.Backend == nil || d.Backend.Alias != "local" || !d.SensitiveNarrowed() {
			t.Fatalf("managed=%v decision = %+v", managed, d)
		}
		deny := e.Gate(d, GateTarget{Provider: "openai", Model: "gpt-5"})
		if deny == nil || deny.Code != DenyCodeSensitiveLocal {
			t.Fatalf("managed=%v: the original request is an allowed exit of a sensitive decision: %+v", managed, deny)
		}
		if deny := e.Gate(d, GateTarget{Alias: "claude", Provider: "anthropic", Model: "claude-haiku-4-5"}); deny == nil {
			t.Fatalf("managed=%v: a cloud alias is an allowed exit of a sensitive decision", managed)
		}
		if deny := e.Gate(d, GateTarget{Alias: "local", Provider: "ollama", Model: "llama3.1"}); deny != nil {
			t.Fatalf("managed=%v: the sensitive alias is refused: %+v", managed, deny)
		}
		plain := e.Decide(context.Background(), chat("please refactor this"))
		if plain.SensitiveNarrowed() || e.Gate(plain, GateTarget{Provider: "openai", Model: "gpt-5"}) != nil {
			t.Fatalf("managed=%v: a plain request is gated: %+v", managed, plain.Sensitive)
		}
	}
}

func TestSensitiveNarrowedWithNoUsableLocalAliasIsDenied(t *testing.T) {
	for _, managed := range []bool{false, true} {
		e := mustEngine(t, sensitiveSignalConfig(), Options{Managed: managed, CredentialOK: func(b Backend, _ Request) bool { return b.Alias != "local" }})
		d := e.Decide(context.Background(), chat("refactor with AKIA1234"))
		if d.Outcome != OutcomeDenied || d.Deny == nil || d.Deny.Code != DenyCodeSensitiveLocal || d.Backend != nil {
			t.Fatalf("managed=%v: a sensitive request with no usable local alias = %+v", managed, d)
		}
		for _, want := range []string{"sensitive", "local", "credential"} {
			if !strings.Contains(d.Deny.Message, want) {
				t.Fatalf("managed=%v: deny message %q does not name %q", managed, d.Deny.Message, want)
			}
		}
	}
}

func TestSensitiveNarrowedTriesTheSensitiveAliases(t *testing.T) {
	cfg := sensitiveSignalConfig()
	// No unconditional default: only the classifier candidates (cloud).
	cfg.Routing.Decisions = slices.DeleteFunc(cfg.Routing.Decisions, func(r config.RoutingDecisionRule) bool { return len(r.Conditions) == 0 })
	e := mustEngine(t, cfg, Options{})
	d := e.Decide(context.Background(), chat("refactor this, key AKIA1234"))
	if d.Outcome != OutcomeApplied || d.Backend == nil || d.Backend.Alias != "local" || d.Source != SourceSensitive {
		t.Fatalf("a sensitive request whose candidates are all cloud = %+v", d)
	}
}

func TestSensitiveNarrowedWithNoAllowedLocalAliasIsDenied(t *testing.T) {
	cfg := sensitiveSignalConfig()
	cfg.Routing.Admin = &config.RoutingAdminConfig{AllowedAliases: []string{"claude", "fast"}}
	e := mustEngine(t, cfg, Options{})
	d := e.Decide(context.Background(), chat("AKIA1234"))
	if d.Outcome != OutcomeDenied || d.Deny == nil || d.Deny.Code != DenyCodeSensitiveLocal {
		t.Fatalf("a sensitive request with no allowed local alias = %+v", d)
	}
}

func TestSensitiveNarrowedIgnoresAUserOverrideToACloudAlias(t *testing.T) {
	e := mustEngine(t, sensitiveSignalConfig(), Options{})
	r := chat("AKIA1234 please")
	r.RequestedModel = "claude"
	d := e.Decide(context.Background(), r)
	if d.Outcome != OutcomeApplied || d.Backend == nil || d.Backend.Alias != "local" {
		t.Fatalf("user override to a cloud alias on a sensitive request = %+v", d)
	}
}

func TestSensitiveConversationStaysNarrowed(t *testing.T) {
	e := mustEngine(t, sensitiveSignalConfig(), Options{})
	first := chat("my key AKIA1234")
	first.ConversationID = "conv-1"
	if d := e.Decide(context.Background(), first); d.Sensitive.Source != SensitiveSourceSignal {
		t.Fatalf("first turn = %+v", d.Sensitive)
	}
	next := chat("please refactor this")
	next.ConversationID = "conv-1"
	d := e.Decide(context.Background(), next)
	if d.Sensitive.Source != SensitiveSourceSticky || d.Backend == nil || d.Backend.Alias != "local" {
		t.Fatalf("the next turn of a sensitive conversation = %+v %+v", d.Sensitive, d.Backend)
	}
	if e.SensitiveFloor(next) != SensitiveSourceSticky {
		t.Fatal("an unroutable request of the conversation is not marked")
	}
	other := chat("please refactor this")
	other.ConversationID = "conv-2"
	if d := e.Decide(context.Background(), other); d.SensitiveNarrowed() {
		t.Fatalf("another conversation is narrowed: %+v", d.Sensitive)
	}
	noID := chat("please refactor this")
	if d := e.Decide(context.Background(), noID); d.SensitiveNarrowed() {
		t.Fatalf("a request without a session id is narrowed: %+v", d.Sensitive)
	}
}

func TestSensitiveConversationMarkSlidesAndExpires(t *testing.T) {
	e := mustEngine(t, sensitiveSignalConfig(), Options{})
	now := time.Unix(1_800_000_000, 0)
	e.marks.now = func() time.Time { return now }
	turn := func(text string) Decision {
		r := chat(text)
		r.ConversationID = "conv-slide"
		return e.Decide(context.Background(), r)
	}
	turn("key AKIA1234")
	for i := 0; i < 3; i++ {
		now = now.Add(20 * time.Minute)
		if d := turn("keep refactoring"); d.Sensitive.Source != SensitiveSourceSticky {
			t.Fatalf("turn %d, 20 minutes after the last narrowed turn: %+v", i, d.Sensitive)
		}
	}
	now = now.Add(31 * time.Minute)
	if d := turn("keep refactoring"); d.SensitiveNarrowed() {
		t.Fatalf("31 minutes after the last narrowed turn: %+v", d.Sensitive)
	}
	if e.sticky != nil {
		t.Fatal("routing.sensitive alone must not cache classifier answers")
	}
}
