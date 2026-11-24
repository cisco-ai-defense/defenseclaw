// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1265 (P2, found by review r2 of GAP-0429): the open-secret
// hold reads a reply that ends a piece in a number (a version, a port, a
// count) as a digit run that can still become a card number or an SSN
// (GAP-1091). The run was given an idle bound: after streamHoldMaxPartialAge
// with no new text it took the TRUNCATED verdict of the unknown tier, so
// strict and managed-strict cut a benign reply whose upstream paused there,
// and the other tiers raised a false alert. A token or a digit run now has
// no idle clock and no TRUNCATED verdict: it stays held until the next text
// or the end of the stream decides it, so a benign reply goes out whole and
// a card number or a token the upstream pauses inside still never reaches
// the client in part (the GAP-1091 and GAP-0429 protection). Past
// streamSecretMaxHeld bytes held behind open runs (a long numeric table) the
// held bytes go out after the check, with no verdict.

// gap1265Pause is longer than the idle bound of the hold.
const gap1265Pause = streamHoldMaxPartialAge + 700*time.Millisecond

// gap1265Row is one stream of a GAP-1265 table: pieces, the upstream idle
// for pause before piece at (at == len(pieces): before the end of the
// stream; pause 0: none), in a tier.
type gap1265Row struct {
	name        string
	tier        string
	pack        string
	managed     bool
	pieces      []string
	at          int
	pause       time.Duration
	secret      gap0429Secret // a value that must not reach the client before its verdict; empty for a benign reply
	wantBlocked bool          // the secret's rule blocks it
}

// gap1265Result is what the client of one row got.
type gap1265Result struct {
	got     string // reply text the client got
	before  int    // secret bytes the client had at the first check that read it whole or found anything
	snapRaw string // the raw body the client had then (GAP-2154)
	bodyRaw string // the raw body the client got
	final   int    // secret bytes the client had at the end
	blocked bool
}

// gap1265Choice1 starts a piece that the GAP-1265 upstreams send in choice 1,
// a second lane of the reply (OpenAI chat shapes only; rel-1-0-10:GAP-1767).
const gap1265Choice1 = "\x00choice1:"

// gap1265Finish0 is a piece that finishes choice 0 (finish_reason; OpenAI
// chat shapes); gap1265Raw starts a piece a passthrough upstream writes as
// is (rel-1-0-10:GAP-2154).
const (
	gap1265Finish0 = "\x00finish0"
	gap1265Raw     = "\x00raw:"
)

// gap1265Piece is the choice and text of a row piece.
func gap1265Piece(p string) (int, string) {
	if text, ok := strings.CutPrefix(p, gap1265Choice1); ok {
		return 1, text
	}
	return 0, p
}

// gap1265Format is the passthrough stream format of a gap0429Path name.
func gap1265Format(t *testing.T, name string) streamTailFormat {
	t.Helper()
	f := strings.TrimPrefix(name, "passthrough/")
	if f == gap0429OpenAIChat.name {
		return gap0429OpenAIChat
	}
	return streamTailFormatNamed(t, f)
}

// gap1265Upstream serves pieces in format f (raw: OpenAI chat chunks), idle
// for pause before piece at.
func gap1265Upstream(t *testing.T, f streamTailFormat, raw bool, pieces []string, at int, pause time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", f.ctype)
		}
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		write := func(s string) {
			_, _ = io.WriteString(w, s)
			fl.Flush()
		}
		idle := func() bool {
			select {
			case <-time.After(pause):
				return true
			case <-r.Context().Done():
				return false
			}
		}
		if !raw {
			write(f.head)
		}
		for i, p := range pieces {
			if i == at && pause > 0 && !idle() {
				return
			}
			if ev, ok := strings.CutPrefix(p, gap1265Raw); ok && !raw {
				write(ev)
				continue
			}
			if p == gap1265Finish0 {
				if !raw && f.name != gap0429OpenAIChat.name {
					t.Errorf("gap1265Upstream: format %s has no finish_reason piece", f.name)
					return
				}
				write(`data: {"id":"r1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n")
				continue
			}
			choice, text := gap1265Piece(p)
			switch {
			case raw || (choice > 0 && f.name == gap0429OpenAIChat.name):
				write(fmt.Sprintf(`data: {"id":"r1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":%d,"delta":{"content":%s}}]}`, choice, streamTailJSON(text)) + "\n\n")
			case choice > 0:
				t.Errorf("gap1265Upstream: format %s has no choice %d", f.name, choice)
				return
			default:
				write(f.delta(text))
			}
		}
		if at == len(pieces) && pause > 0 && !idle() {
			return
		}
		if raw {
			write("data: [DONE]\n\n")
		} else {
			write(f.tail + f.terminal)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// gap1265Serve runs the rows of one path at the same time (each waits on
// its own idle upstream) and returns what each client got and the stderr of
// them all. The path's process-wide test settings (the provider of the
// loopback upstream, the private-target allowance) are set once for all.
func gap1265Serve(t *testing.T, path gap0429Path, rows []gap1265Row) ([]gap1265Result, string) {
	t.Helper()
	type run struct {
		rec   *httptest.ResponseRecorder
		watch *gap0429Watch
		serve func()
	}
	runs := make([]run, len(rows))
	chatReq := func(target string, row gap1265Row) *http.Request {
		body := mustJSON(t, map[string]interface{}{
			"model": "gpt-4", "stream": true,
			"messages": []map[string]interface{}{{"role": "user", "content": "go"}},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		if target != "" {
			req.Header.Set("X-DC-Target-URL", target)
			req.Header.Set("X-AI-Auth", "Bearer sk-test")
		}
		return streamTailWithTier(req, row.pack, row.managed)
	}
	var text func(string) string
	switch {
	case path.name == "llm":
		text = streamedContent
	case path.name == "raw-forward":
		text = streamedContent
		allowRawForwardPrivateTargets(t)
	case strings.HasPrefix(path.name, "passthrough/"):
		f := gap1265Format(t, path.name)
		text = path.text
		if f.name == gap0429OpenAIChat.name {
			allowRawForwardPrivateTargets(t)
		}
		orig := providerDomains
		providerDomains = append([]providerDomainEntry{{domain: "127.0.0.1", name: f.provider}}, orig...)
		t.Cleanup(func() { providerDomains = orig })
	default:
		t.Fatalf("no GAP-1265 runner for path %s", path.name)
	}
	registered := false
	for i, row := range rows {
		rec := httptest.NewRecorder()
		secret := row.secret.text
		if secret == "" {
			secret = "\x00never"
		}
		w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: secret, rec: rec}
		var serve func()
		switch path.name {
		case "llm":
			prov := &gap0429PausingProvider{chunks: gap0429Chunks(row.pieces), at: row.at, pause: row.pause}
			proxy, req := gap0429Proxy(t, prov, w), chatReq("", row)
			serve = func() { proxy.handleChatCompletion(rec, req) }
		case "raw-forward":
			up := gap1265Upstream(t, streamTailFormat{}, true, row.pieces, row.at, row.pause)
			if !registered {
				registerRawForwardProviderDomain(t, up.URL, "openai")
				registered = true
			}
			proxy, req := gap0429Proxy(t, &mockProvider{}, w), chatReq(up.URL, row)
			serve = func() { proxy.handleChatCompletion(rec, req) }
		default:
			f := gap1265Format(t, path.name)
			up := gap1265Upstream(t, f, false, row.pieces, row.at, row.pause)
			proxy, req := gap0429Proxy(t, &mockProvider{}, w), streamTailWithTier(streamTailRequest(t, f, "", up.URL), row.pack, row.managed)
			serve = func() { proxy.handlePassthrough(rec, req) }
		}
		runs[i] = run{rec: rec, watch: w, serve: serve}
	}
	log := captureStderr(t, func() {
		var wg sync.WaitGroup
		for _, r := range runs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.serve()
			}()
		}
		wg.Wait()
	})
	out := make([]gap1265Result, len(rows))
	for i, r := range runs {
		res := gap1265Result{got: text(r.rec.Body.String()), blocked: r.watch.blocked, bodyRaw: r.rec.Body.String()}
		if s := rows[i].secret; s.text != "" {
			snap := r.watch.snap
			if !r.watch.seen {
				snap = r.rec.Body.String()
			}
			res.snapRaw = snap
			res.before, res.final = gap0429Released(text(snap), s), gap0429Released(res.got, s)
		}
		out[i] = res
	}
	return out, log
}

// gap1265Check fails a row whose benign reply did not reach the client whole
// and unblocked, or whose secret reached it in part before its verdict.
func gap1265Check(t *testing.T, label string, row gap1265Row, res gap1265Result) {
	t.Helper()
	name := fmt.Sprintf("%s/%s/%s", label, row.tier, row.name)
	want := strings.Join(row.pieces, "")
	if row.secret.text == "" {
		if res.got != want || res.blocked {
			t.Errorf("%s: a benign reply was cut or blocked: the client got %d of %d bytes, blocked=%v", name, len(res.got), len(want), res.blocked)
		}
		return
	}
	n := row.secret.end - row.secret.body
	if res.before > 0 {
		t.Errorf("%s: %d of %d value bytes reached the client before the verdict", name, res.before, n)
	}
	if res.blocked && res.final > 0 {
		t.Errorf("%s: blocked, but %d of %d value bytes reached the client", name, res.final, n)
	}
	if row.wantBlocked && !res.blocked {
		t.Errorf("%s: the value is not blocked once whole", name)
	}
	if !res.blocked && res.got != want {
		t.Errorf("%s: not blocked, but the client got %d of %d bytes", name, len(res.got), len(want))
	}
}

// gap1265NoTruncated fails when a TRUNCATED verdict was logged for the rows.
func gap1265NoTruncated(t *testing.T, label, log string) {
	t.Helper()
	if n := strings.Count(log, "TRUNCATED"); n > 0 {
		t.Errorf("%s: %d TRUNCATED verdict line(s) logged; an open token or digit run takes none: %s", label, n, gap1265LogLine(log, "TRUNCATED"))
	}
}

func gap1265LogLine(log, mark string) string {
	i := strings.Index(log, mark)
	if i < 0 {
		return ""
	}
	line := log[strings.LastIndexByte(log[:i], '\n')+1:]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	return line[:min(len(line), 200)]
}

// gap1265Split is lead+value cut into 24-byte pieces with the upstream idle
// after the first cut bytes of the value.
func gap1265Split(lead string, v gap0429Secret, cut int, trailer string) ([]string, int) {
	first := gap0429Pieces(lead+v.text[:v.body+cut], 24, nil)
	return append(first, gap0429Pieces(v.text[v.body+cut:]+trailer, 24, nil)...), len(first)
}

// gap1265PauseRows are the idle rows of one tier: benign replies whose text
// ends a piece in a number, then the upstream is idle past the bound; and a
// card number and a token the upstream pauses inside.
func gap1265PauseRows(t *testing.T, tier string, pack string, managed bool) []gap1265Row {
	t.Helper()
	prose := gap0429Pieces(retestFiller(1500)[:1500], 24, nil)
	versionNL := append(append(append([]string(nil), prose...), "I bumped the release to version 1.0.10\n"), "Then the tests passed.\n")
	portEnd := append(append([]string(nil), prose...), "The service listens on port 8080")
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cardPieces, cardAt := gap1265Split(retestFiller(1100)[:1100], card, 9, " is the value. The build passed on the second run.\n")
	tok := gap0429Tokens(t)[0]
	tokPieces, tokAt := gap1265Split(retestFiller(1100)[:1100], tok, (tok.end-tok.body)/2, " is the value. The build passed on the second run.\n")
	return []gap1265Row{
		{name: "version-nl-then-text", tier: tier, pack: pack, managed: managed, pieces: versionNL, at: len(prose) + 1, pause: gap1265Pause},
		{name: "port-then-end", tier: tier, pack: pack, managed: managed, pieces: portEnd, at: len(portEnd), pause: gap1265Pause},
		{name: "card-paused-inside", tier: tier, pack: pack, managed: managed, pieces: cardPieces, at: cardAt, pause: gap1265Pause, secret: card, wantBlocked: true},
		{name: "token-paused-inside", tier: tier, pack: pack, managed: managed, pieces: tokPieces, at: tokAt, pause: gap1265Pause, secret: tok},
	}
}

// gap1265Paths are the routes of the GAP-1265 tables: the /llm proxy and the
// passthrough stream read on their own goroutine (an idle clock); the raw
// forward reads on the handler goroutine (none) and must not change.
func gap1265Paths(t *testing.T) []gap0429Path {
	return gap0429PathsNamed(t, "llm", "passthrough/anthropic", "raw-forward")
}

// TestGAP1265OpenRunIdleIsNotTruncated: in every tier, on the /llm,
// passthrough and raw forward routes, a benign reply that ends a piece in a
// number and then waits past the idle bound reaches the client whole with
// no block and no TRUNCATED alert, and a card number or a token the
// upstream pauses inside is still held whole until its verdict. Each route's
// rows run at the same time (one idle wait per route).
func TestGAP1265OpenRunIdleIsNotTruncated(t *testing.T) {
	for _, path := range gap1265Paths(t) {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				rows = append(rows, gap1265PauseRows(t, tier.name, tier.pack, tier.managed)...)
			}
			results, log := gap1265Serve(t, path, rows)
			for i, row := range rows {
				gap1265Check(t, path.name, row, results[i])
			}
			gap1265NoTruncated(t, path.name, log)
		})
	}
}

// gap1265Table is a numeric table streamed in pieces that each end in a
// digit, so the text ends in an open digit run at every piece end, with more
// stream bytes than streamSecretMaxHeld: no piece end ever closes the run.
func gap1265Table() []string {
	var pieces []string
	for i, n := 0, 0; n < streamSecretMaxHeld*5/4; i++ {
		// A short piece ending in a digit: the bound counts stream bytes
		// (the frame, at least 120 bytes), and every frame is checked over
		// the whole reply text, which costs more than linearly in its length,
		// so the least text per frame is the cheapest table (a long piece of
		// 8 KiB took 327 s under -race and cut the stream at the request
		// deadline; 16-byte pieces took 155 s).
		p := fmt.Sprintf(" k%d", i%97)
		pieces = append(pieces, p)
		n += len(p) + 120 // a piece is a frame of at least 120 bytes on these routes
	}
	return pieces
}

// TestGAP1265NumericTableIsNotCutAtHeldBound: a long numeric table keeps a
// digit run open at almost every piece end, so more than streamSecretMaxHeld
// bytes wait behind open runs; that is no secret that could not be read, and
// no tier cuts or alerts it (the /llm and passthrough routes; the raw forward
// checks the whole text at every frame, and 9k frames outlast the request
// deadline, as for the long-prose rows of TestGAP0429BenignStreamsAreNotHeld).
// Under -race the strict tiers run (the ones that cut).
func TestGAP1265NumericTableIsNotCutAtHeldBound(t *testing.T) {
	table := gap1265Table()
	for _, path := range gap0429PathsNamed(t, "llm", "passthrough/anthropic") {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				rows = append(rows, gap1265Row{name: "numeric-table", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: table})
			}
			results, log := gap1265Serve(t, path, rows)
			for i, row := range rows {
				gap1265Check(t, path.name, row, results[i])
			}
			gap1265NoTruncated(t, path.name, log)
		})
	}
}
