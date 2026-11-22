// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingeval

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// SensitiveCheck is one routing.sensitive.check answer for an item
// (rel-1-0-10 GAP-0003): the product checker, called as the gateway calls
// it. No prompt text is kept.
type SensitiveCheck struct {
	Positive  bool   `json:"positive"`
	Truncated bool   `json:"truncated,omitempty"`
	Failure   string `json:"failure,omitempty"`
	LatencyUS int64  `json:"latency_us"`
	InputB    int    `json:"input_bytes"`
}

// CheckAll runs the checker on every item with bounded concurrency.
func CheckAll(ctx context.Context, c *gateway.SensitiveEvalChecker, items []Item, conc int) map[string]SensitiveCheck {
	out := make(map[string]SensitiveCheck, len(items))
	var mu sync.Mutex
	sem := make(chan struct{}, max(conc, 1))
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it Item) {
			defer func() { <-sem; wg.Done() }()
			msgs := make([]gateway.ChatMessage, 0, len(it.Messages))
			size := 0
			for _, m := range it.Messages {
				msgs = append(msgs, gateway.ChatMessage{Role: m.Role, Content: m.Content})
				if m.Role != "system" && m.Role != "developer" {
					size += len(m.Content)
				}
			}
			start := time.Now()
			yes, trunc, err := c.Check(ctx, msgs)
			r := SensitiveCheck{Positive: yes, Truncated: trunc, LatencyUS: time.Since(start).Microseconds(), InputB: size}
			if err != nil {
				r.Positive, r.Failure = false, "error"
				var ce *engine.ClassifierError
				if errors.As(err, &ce) && ce.Code != "" {
					r.Failure = ce.Code
				}
			}
			mu.Lock()
			out[it.ID] = r
			mu.Unlock()
		}(it)
	}
	wg.Wait()
	return out
}

// SensitiveMode is one way to decide narrowing; an unavailable check
// routes local (the shipped on_unavailable: local).
type SensitiveMode struct {
	Name   string
	Narrow func(floor bool, c SensitiveCheck) bool
}

// SensitiveModes are the modes the GAP-0003 report compares.
var SensitiveModes = []SensitiveMode{
	{"regex floor only (no check)", func(f bool, _ SensitiveCheck) bool { return f }},
	{"floor OR decision-model check (routing.sensitive.check)", func(f bool, c SensitiveCheck) bool { return f || c.Positive || c.Failure != "" }},
	{"decision-model check alone", func(_ bool, c SensitiveCheck) bool { return c.Positive || c.Failure != "" }},
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// SensitiveReport renders the GAP-0003 table: per mode, sensitive leaks
// per profile (keyword route, then the narrowing, then the profile
// filter), the false-local rate on the other prompts, and the check
// latency, failures and an input-size cost estimate.
func SensitiveReport(eval []Item, floor map[string]bool, checks map[string]SensitiveCheck, preds map[string]Prediction, profs Profiles, checker string, usdPerMTokIn float64) string {
	var b strings.Builder
	sens, other := 0, 0
	for _, it := range eval {
		if it.ExpectedCategory == "sensitive" {
			sens++
		} else {
			other++
		}
	}
	local := map[string]bool{}
	for _, a := range profs.LocalAliases {
		local[a] = true
	}
	fmt.Fprintf(&b, "## Sensitive data stays local (GAP-0003)\n\nChecker: %s. Items: %d sensitive, %d other. A failed or timed-out check routes local (on_unavailable: local).\n\n", checker, sens, other)
	names := profs.Names()
	b.WriteString("| Mode | Recall on sensitive |")
	for _, n := range names {
		fmt.Fprintf(&b, " Leaks (%s) |", n)
	}
	b.WriteString(" False local (other) |\n|---|---|")
	for range names {
		b.WriteString("---|")
	}
	b.WriteString("---|\n")
	for _, m := range SensitiveModes {
		hit, falseLocal := 0, 0
		leaks := map[string]int{}
		for _, it := range eval {
			narrow := m.Narrow(floor[it.ID], checks[it.ID])
			if it.ExpectedCategory != "sensitive" {
				if narrow {
					falseLocal++
				}
				continue
			}
			if narrow {
				hit++
			}
			for _, n := range names {
				if fin := Route(preds[it.ID], narrow, profs.Profiles[n], profs); fin.Alias != "deny" && !local[fin.Alias] {
					leaks[n]++
				}
			}
		}
		fmt.Fprintf(&b, "| %s | %d/%d (%.0f%%) |", m.Name, hit, sens, pct(hit, sens))
		for _, n := range names {
			fmt.Fprintf(&b, " %d |", leaks[n])
		}
		fmt.Fprintf(&b, " %d/%d (%.1f%%) |\n", falseLocal, other, pct(falseLocal, other))
	}
	var lat []int64
	fails := map[string]int{}
	trunc, size := 0, 0
	for _, it := range eval {
		c := checks[it.ID]
		lat = append(lat, c.LatencyUS)
		if c.Failure != "" {
			fails[c.Failure]++
		}
		if c.Truncated {
			trunc++
		}
		size += c.InputB
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return float64(lat[min(len(lat)-1, int(p*float64(len(lat))))]) / 1000
	}
	fmt.Fprintf(&b, "\nCheck latency (runs in parallel with the classifier; the route waits for the slower): p50 %.0f ms, p95 %.0f ms, max %.0f ms. Failures: %v. Truncated inputs: %d.\n", q(0.5), q(0.95), q(1), fails, trunc)
	if len(eval) > 0 {
		tok := float64(size)/4/float64(len(eval)) + 180
		cost := ""
		if usdPerMTokIn > 0 {
			cost = fmt.Sprintf("; about $%.3f per 1,000 checks at $%.3f per million input tokens (the output is one short choice)", tok*1000*usdPerMTokIn/1e6, usdPerMTokIn)
		}
		fmt.Fprintf(&b, "Input per check: about %.0f tokens (bytes/4 estimate plus the question)%s.\n", tok, cost)
	}
	return b.String()
}
