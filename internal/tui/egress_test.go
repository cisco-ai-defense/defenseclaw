// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadGatewayEgress_MissingFile(t *testing.T) {
	dir := t.TempDir()
	events, err := LoadGatewayEgress(filepath.Join(dir, "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil slice, got %+v", events)
	}
}

func TestLoadGatewayEgress_ParsesAndSorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	// Two egress rows at different timestamps plus a scan row the
	// parser must ignore. The loader returns newest-first, so the
	// "later" row is asserted at index 0.
	lines := []string{
		`{"ts":"2026-04-20T10:00:00Z","event_type":"egress","egress":{"target_host":"api.x.test","target_path":"/v1/messages","body_shape":"messages","looks_like_llm":true,"branch":"shape","decision":"allow","reason":"shape-match","source":"ts"}}`,
		`{"ts":"2026-04-20T10:05:00Z","event_type":"egress","egress":{"target_host":"api.y.test","target_path":"/v1/chat/completions","body_shape":"messages","looks_like_llm":true,"branch":"passthrough","decision":"allow","reason":"no-match","source":"ts"}}`,
		`{"ts":"2026-04-20T10:07:00Z","event_type":"scan","scan":{"scan_id":"s1","scanner":"rx","target":"x","verdict":"allow"}}`,
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := LoadGatewayEgress(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 egress rows, got %d", len(events))
	}
	if events[0].TargetHost != "api.y.test" {
		t.Fatalf("expected newest-first (api.y.test) at index 0, got %s", events[0].TargetHost)
	}
	if events[0].Branch != "passthrough" || !events[0].LooksLikeLLM {
		t.Fatalf("unexpected first event: %+v", events[0])
	}
	if events[1].TargetHost != "api.x.test" {
		t.Fatalf("expected api.x.test at index 1, got %s", events[1].TargetHost)
	}
}

func TestSyntheticEgressEvent_SeverityRules(t *testing.T) {
	base := EgressEvent{
		TS:         time.Now(),
		TargetHost: "api.x.test",
		TargetPath: "/v1/messages",
		BodyShape:  "messages",
		Branch:     "shape",
		Decision:   "allow",
		Source:     "ts",
	}

	t.Run("silent_bypass_shape_allow_is_warning", func(t *testing.T) {
		e := base
		e.LooksLikeLLM = true
		ev := SyntheticEgressEvent(e)
		if ev.Severity != "WARNING" {
			t.Fatalf("expected WARNING, got %q", ev.Severity)
		}
	})

	t.Run("block_is_always_warning", func(t *testing.T) {
		e := base
		e.Decision = "block"
		e.Branch = "passthrough"
		ev := SyntheticEgressEvent(e)
		if ev.Severity != "WARNING" {
			t.Fatalf("expected WARNING, got %q", ev.Severity)
		}
	})

	t.Run("known_provider_allow_is_info", func(t *testing.T) {
		e := base
		e.Branch = "known"
		e.LooksLikeLLM = true
		ev := SyntheticEgressEvent(e)
		if ev.Severity != "INFO" {
			t.Fatalf("expected INFO, got %q", ev.Severity)
		}
	})

	t.Run("action_is_egress", func(t *testing.T) {
		ev := SyntheticEgressEvent(base)
		if ev.Action != "egress" {
			t.Fatalf("expected action egress, got %q", ev.Action)
		}
	})
}

func TestCountRecentSilentBypass(t *testing.T) {
	now := time.Now()
	events := []EgressEvent{
		// Inside window, counts: passthrough + LLM-shaped + allow.
		{TS: now.Add(-5 * time.Second), Branch: "passthrough", LooksLikeLLM: true, Decision: "allow"},
		// Inside window, counts: shape + allow (operator opted in to unknown host).
		{TS: now.Add(-7 * time.Second), Branch: "shape", LooksLikeLLM: true, Decision: "allow"},
		// Blocked — proxy actually rejected, not a silent bypass.
		{TS: now.Add(-8 * time.Second), Branch: "shape", LooksLikeLLM: true, Decision: "block"},
		// Not LLM-shaped → not a silent-LLM-bypass.
		{TS: now.Add(-10 * time.Second), Branch: "passthrough", LooksLikeLLM: false, Decision: "allow"},
		// Known provider — goes through triage, not a silent bypass.
		{TS: now.Add(-20 * time.Second), Branch: "known", LooksLikeLLM: true, Decision: "allow"},
		// Too old.
		{TS: now.Add(-2 * time.Minute), Branch: "passthrough", LooksLikeLLM: true, Decision: "allow"},
	}
	got := CountRecentSilentBypass(events, time.Minute)
	if got != 2 {
		t.Fatalf("expected 2 silent-bypasses in last minute (1 passthrough-allow + 1 shape-allow), got %d", got)
	}
}
