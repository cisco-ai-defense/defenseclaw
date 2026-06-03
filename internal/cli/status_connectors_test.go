// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// captureStdout runs fn and returns everything it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// normalizeRosterShape collapses a rendered roster down to its
// count-agnostic skeleton so we can assert that a 1-connector and an
// N-connector roster use the SAME layout/wording. It strips ANSI styling,
// the per-connector names, and the numeric "N active" count, leaving only
// the structural labels (e.g. "Agents:", "since", "requests:"). If the two
// rosters share a layout, their skeletons are identical.
func rosterSkeleton(out string) []string {
	replacer := strings.NewReplacer(
		"antigravity", "X", "claudecode", "X", "codex", "X",
		"Antigravity", "X", "Claude Code", "X", "Codex", "X",
	)
	var lines []string
	for _, line := range strings.Split(stripANSI(out), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		t = replacer.Replace(t)
		// Drop the "N active" count and the RFC3339 "since" timestamp so
		// only the count-agnostic structure remains.
		if i := strings.Index(t, " active"); i >= 0 {
			t = "Agents: active"
		}
		if strings.HasPrefix(t, "since ") {
			t = "since"
		}
		lines = append(lines, t)
	}
	return lines
}

// stripANSI removes SGR escape sequences so structural comparisons are not
// thrown off by color codes.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// TestPrintConnectors_ListsAll pins the roster fix: the Agent view must
// list every active connector (with its own counters) under an
// "Agents: N active" header rather than rendering only the primary.
func TestPrintConnectors_ListsAll(t *testing.T) {
	now := time.Now()
	snap := &gateway.HealthSnapshot{
		Connector: &gateway.ConnectorHealth{Name: "antigravity", State: gateway.StateRunning, Since: now},
		Connectors: []gateway.ConnectorHealth{
			{Name: "antigravity", State: gateway.StateRunning, Since: now},
			{Name: "claudecode", State: gateway.StateRunning, Since: now},
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}

	out := captureStdout(t, func() { printConnectors(snap) })

	if !strings.Contains(out, "Agents") || !strings.Contains(out, "3 active") {
		t.Fatalf("expected roster header 'Agents: 3 active', got:\n%s", out)
	}
	for _, name := range []string{"antigravity", "claudecode", "codex"} {
		if !strings.Contains(out, "("+name+")") {
			t.Errorf("connector %q missing from Agents listing:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "Antigravity") || !strings.Contains(out, "Claude Code") || !strings.Contains(out, "Codex") {
		t.Errorf("friendly names missing from listing:\n%s", out)
	}
}

// TestPrintConnectors_SingleConnectorUsesRoster pins the uniform UX: a
// single active connector renders through the SAME "Agents: N active"
// roster as the multi-connector case — no special "Agent:" singular row,
// no "single vs multi" wording branch.
func TestPrintConnectors_SingleConnectorUsesRoster(t *testing.T) {
	now := time.Now()
	snap := &gateway.HealthSnapshot{
		Connector:  &gateway.ConnectorHealth{Name: "codex", State: gateway.StateRunning, Since: now},
		Connectors: []gateway.ConnectorHealth{{Name: "codex", State: gateway.StateRunning, Since: now}},
	}

	out := captureStdout(t, func() { printConnectors(snap) })

	if !strings.Contains(out, "Agents") || !strings.Contains(out, "1 active") {
		t.Errorf("single connector must use the uniform 'Agents: 1 active' header, got:\n%s", out)
	}
	if !strings.Contains(out, "(codex)") {
		t.Errorf("expected codex listed in roster, got:\n%s", out)
	}
}

// TestPrintConnectors_SingleAndMultiShareLayout is the core uniformity
// guarantee: the rendered layout/wording for a 1-connector roster and an
// N-connector roster must be IDENTICAL once connector names and the count
// are factored out. This is the regression guard against reintroducing a
// "single vs multi" presentation branch.
func TestPrintConnectors_SingleAndMultiShareLayout(t *testing.T) {
	now := time.Now()
	single := &gateway.HealthSnapshot{
		Connectors: []gateway.ConnectorHealth{
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}
	multi := &gateway.HealthSnapshot{
		Connectors: []gateway.ConnectorHealth{
			{Name: "antigravity", State: gateway.StateRunning, Since: now},
			{Name: "claudecode", State: gateway.StateRunning, Since: now},
			{Name: "codex", State: gateway.StateRunning, Since: now},
		},
	}

	singleOut := captureStdout(t, func() { printConnectors(single) })
	multiOut := captureStdout(t, func() { printConnectors(multi) })

	singleSkel := rosterSkeleton(singleOut)
	multiSkel := rosterSkeleton(multiOut)

	// The single roster is one connector entry; the multi roster repeats
	// the same entry shape N times. Compare the header + first entry block
	// (everything the single roster emits) against the multi roster prefix.
	if len(multiSkel) < len(singleSkel) {
		t.Fatalf("multi roster shorter than single roster\nsingle:\n%v\nmulti:\n%v", singleSkel, multiSkel)
	}
	for i := range singleSkel {
		if singleSkel[i] != multiSkel[i] {
			t.Errorf("layout diverges at line %d: single=%q multi=%q\nsingle:\n%v\nmulti:\n%v",
				i, singleSkel[i], multiSkel[i], singleSkel, multiSkel)
		}
	}
}

// TestPrintConnectors_NoConnector renders the empty state.
func TestPrintConnectors_NoConnector(t *testing.T) {
	out := captureStdout(t, func() { printConnectors(&gateway.HealthSnapshot{}) })
	if !strings.Contains(out, "no active connector") {
		t.Errorf("expected '(no active connector)', got:\n%s", out)
	}
}
