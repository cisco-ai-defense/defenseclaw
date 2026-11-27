// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// gap0515Prose is n bytes of deterministic benign prose: words, numbers,
// punctuation, list items, short code spans with a path, and line breaks.
func gap0515Prose(n int, seed int64) string {
	words := strings.Fields(`the stream carries plain words about lists maps loops and the
	parser reads every line before it writes a summary of what changed in version
	release notes say config file values default to true when unset a function returns
	an error so the caller checks it then retries after a short wait with backoff we
	use tables for the results and charts for trends across weeks of data which shows
	how latency moved under load while memory stayed flat`)
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for b.Len() < n {
		switch k := r.Intn(40); {
		case k == 0:
			b.WriteString("\n\n- ")
		case k == 1:
			b.WriteString(".\n")
		case k == 2:
			fmt.Fprintf(&b, " %d.%d", r.Intn(10), r.Intn(20))
		case k == 3:
			b.WriteString(" `go test ./...`")
		case k < 7:
			b.WriteString(", ")
		default:
			b.WriteByte(' ')
		}
		b.WriteString(words[r.Intn(len(words))])
	}
	return b.String()[:n]
}

// gap0515TimedInspector is the local guardrail inspector with the time and
// text size of every mid-stream check recorded.
type gap0515TimedInspector struct {
	*GuardrailInspector
	mu     sync.Mutex
	checks []gap0515Check
}

type gap0515Check struct {
	size int
	took time.Duration
}

func (g *gap0515TimedInspector) note(size int, took time.Duration) {
	g.mu.Lock()
	g.checks = append(g.checks, gap0515Check{size: size, took: took})
	g.mu.Unlock()
}

func (g *gap0515TimedInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	t0 := time.Now()
	v := g.GuardrailInspector.InspectMidStream(ctx, direction, content, messages, model, mode)
	g.note(len(content), time.Since(t0))
	return v
}

func (g *gap0515TimedInspector) InspectMidStreamAgeDue(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) (*ScanVerdict, bool) {
	t0 := time.Now()
	v, full := g.GuardrailInspector.InspectMidStreamAgeDue(ctx, direction, content, messages, model, mode)
	g.note(len(content), time.Since(t0))
	return v, full
}

// gap0515Stream is one stream of text through the proxy: its mid-stream
// checks, the client body and the stream's wall time.
type gap0515Stream struct {
	checks []gap0515Check
	body   string
	wall   time.Duration
}

func (s gap0515Stream) checkTotal() time.Duration {
	var total time.Duration
	for _, c := range s.checks {
		total += c.took
	}
	return total
}

// gap0515Deltas cuts text into pieces of size bytes.
func gap0515Deltas(text string, size int) []string {
	var out []string
	for len(text) > 0 {
		k := min(size, len(text))
		out = append(out, text[:k])
		text = text[k:]
	}
	return out
}

// gap0515Serve streams text in deltas of size bytes through route
// ("anthropic": the passthrough; "chat": the /llm chat route) with the
// local inspector in action mode.
func gap0515Serve(t *testing.T, route, text string, size int) gap0515Stream {
	t.Helper()
	insp := &gap0515TimedInspector{GuardrailInspector: NewGuardrailInspector("local", nil, nil)}
	deltas := gap0515Deltas(text, size)
	var body string
	var t0 time.Time
	switch route {
	case "anthropic":
		var f streamTailFormat
		for _, x := range streamTailFormats {
			if x.name == "anthropic" {
				f = x
			}
		}
		// Paced, so each delta reaches the proxy alone, as on the chat route.
		up, _ := streamTailUpstream(t, f, deltas, time.Millisecond, nil)
		proxy := streamTailProxy(t, f.provider, insp, "action")
		t0 = time.Now()
		body, _ = streamTailServe(t, proxy, f, up.URL)
	case "chat":
		proxy := newTestProxy(t, &latencyStreamProvider{deltas: deltas}, insp, "action")
		front := httptest.NewServer(http.HandlerFunc(proxy.handleChatCompletion))
		defer front.Close()
		reqBody, _ := json.Marshal(map[string]any{"model": "m", "stream": true, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
		t0 = time.Now()
		resp, err := http.Post(front.URL+"/v1/chat/completions", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body = string(raw)
	default:
		t.Fatalf("unknown route %q", route)
	}
	wall := time.Since(t0)
	insp.mu.Lock()
	defer insp.mu.Unlock()
	return gap0515Stream{checks: append([]gap0515Check(nil), insp.checks...), body: body, wall: wall}
}

// gap0515WholeCheck is the median time of a mid-stream check of text read
// whole: the check of a stream with no memory of the checks before it.
func gap0515WholeCheck(text string, reps int) time.Duration {
	insp := NewGuardrailInspector("local", nil, nil)
	ds := make([]time.Duration, 0, reps)
	for i := 0; i < reps; i++ {
		t0 := time.Now()
		insp.InspectMidStream(context.Background(), "completion", text, []ChatMessage{{Role: "assistant", Content: text}}, "m", "action")
		ds = append(ds, time.Since(t0))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}

// gap0515CostBound is the most one mid-stream check of the 256 KiB stream
// may cost on average, as a fraction of a whole-text check of the full
// text. Every check of rel read the whole text so far: the mean check cost
// about half a whole check.
const gap0515CostBound = 0.125

// TestGAP0515MidStreamCheckCostBounded: a 256 KiB benign prose stream, in
// deltas of 512 bytes, through the passthrough and the /llm chat route with
// the local inspector: the mean mid-stream check costs at most
// gap0515CostBound of a whole-text check of the full text
// (rel-1-0-10:GAP-0515). The stream is not changed.
func TestGAP0515MidStreamCheckCostBounded(t *testing.T) {
	text := gap0515Prose(256<<10, 7)
	whole := gap0515WholeCheck(text, 5)
	for _, route := range []string{"anthropic", "chat"} {
		t.Run(route, func(t *testing.T) {
			s := gap0515Serve(t, route, text, 512)
			if strings.Contains(s.body, "blocked") {
				t.Fatalf("a benign stream was blocked")
			}
			if len(s.checks) < 50 {
				t.Fatalf("only %d mid-stream checks for %d bytes", len(s.checks), len(text))
			}
			total := s.checkTotal()
			mean := float64(total) / float64(len(s.checks)) / float64(whole)
			t.Logf("GAP0515 route=%s checks=%d total=%v whole_check=%v mean_check=%.3f wall=%v", route, len(s.checks), total, whole, mean, s.wall)
			if mean > gap0515CostBound {
				t.Fatalf("the %d mid-stream checks of a %d KiB stream cost %v: the mean check is %.3f of a whole-text check (%v); bound %.3f",
					len(s.checks), len(text)>>10, total, mean, whole, gap0515CostBound)
			}
		})
	}
}

// TestGAP0515MidStreamCostReport prints the before/after numbers of
// GAP-0515 (DC_GAP0515_REPORT=<file>, one JSON line per case): 200 KiB and
// 1 MiB of prose and 200 KiB with a private key at 190 KiB, in deltas of
// 512 bytes through the /llm chat route: mid-stream checks, their total,
// the mean check, the mean of the last 10% of checks, and the stream's
// wall time. The same file runs on rel for the before side.
func TestGAP0515MidStreamCostReport(t *testing.T) {
	out := os.Getenv("DC_GAP0515_REPORT")
	if out == "" {
		t.Skip("set DC_GAP0515_REPORT to run the GAP-0515 cost report")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	late := gap0515Prose(190<<10, 11) + "\n" + syntheticPrivateKeyPEM("RSA PRIVATE KEY") + "\n"
	late += gap0515Prose(200<<10-len(late), 12)
	cases := []struct {
		name, text string
		block      bool
	}{
		{"prose-200KiB", gap0515Prose(200<<10, 1), false},
		{"prose-1MiB", gap0515Prose(1<<20, 2), false},
		{"secret-late-200KiB", late, true},
	}
	for _, c := range cases {
		s := gap0515Serve(t, "chat", c.text, 512)
		blocked := strings.Contains(s.body, "blocked")
		if blocked != c.block {
			t.Errorf("%s: blocked=%v, want %v", c.name, blocked, c.block)
		}
		total := s.checkTotal()
		n := len(s.checks)
		var last time.Duration
		tail := s.checks[n-max(n/10, 1):]
		for _, x := range tail {
			last += x.took
		}
		row := map[string]any{
			"case": c.name, "bytes": len(c.text), "blocked": blocked, "checks": n,
			"checks_total_ms":     float64(total.Microseconds()) / 1000,
			"check_mean_ms":       float64(total.Microseconds()) / 1000 / float64(n),
			"check_last10_ms":     float64(last.Microseconds()) / 1000 / float64(len(tail)),
			"stream_wall_ms":      float64(s.wall.Microseconds()) / 1000,
			"last_check_size":     s.checks[n-1].size,
			"whole_check_last_ms": float64(gap0515WholeCheck(c.text[:s.checks[n-1].size], 3).Microseconds()) / 1000,
		}
		line, _ := json.Marshal(row)
		fmt.Fprintln(f, string(line))
		t.Log(string(line))
	}
}
