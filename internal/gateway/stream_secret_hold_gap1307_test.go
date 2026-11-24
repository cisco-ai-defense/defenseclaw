// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// rel-1-0-10:GAP-1307 (found by review r3 of GAP-0429/1265): since GAP-1265
// a reply whose text ends in an open token or digit run is held with no idle
// clock until the next text or the end of the stream. While the upstream is
// quiet there (a long server-tool phase, throttling, long thinking) the
// client got no byte at all and its stream-idle watchdog could end a session
// that works on rel, which sends those bytes at once. Now the client gets a
// keep-alive that carries no reply text about streamHoldMaxPartialAge after
// the last text (option a), or, where the framing has no content-free event
// (Bedrock ConverseStream), the held events with the open run masked (option
// b); no raw byte of the run goes out before its verdict.

// gap1307Pause is the upstream quiet time of the rows (the gate: 30 s or
// more); gap1307Slack is the scheduling slack over the hold's idle bound.
const (
	gap1307Pause = 30 * time.Second
	gap1307Slack = 2500 * time.Millisecond
)

// gap1307Converse is a Bedrock ConverseStream of a non-Anthropic model: an
// eventstream with no content-free event (option b).
var gap1307Converse = streamTailFormat{
	name: "bedrock-converse", provider: "bedrock", path: "/model/meta.llama3-test-v1:0/converse-stream", ctype: streamTailEventStream,
	head:     gap1307ConverseFrame("messageStart", map[string]any{"role": "assistant"}),
	tail:     gap1307ConverseFrame("contentBlockStop", map[string]any{"contentBlockIndex": 0}),
	terminal: gap1307ConverseFrame("messageStop", map[string]any{"stopReason": "end_turn"}),
	delta: func(text string) string {
		return gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": text}, "p": "abcdefgh"})
	},
}

func gap1307ConverseFrame(typ string, payload map[string]any) string {
	var buf bytes.Buffer
	_ = writeBedrockEventStreamFrame(&buf, typ, payload)
	return buf.String()
}

// gap1307ConverseText is the reply text of the ConverseStream frames in out.
func gap1307ConverseText(out string) string {
	var sb strings.Builder
	dec, r := eventstream.NewDecoder(), strings.NewReader(out)
	for {
		msg, err := dec.Decode(r, nil)
		if err != nil {
			return sb.String()
		}
		var d struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal(msg.Payload, &d) == nil {
			sb.WriteString(d.Delta.Text)
		}
	}
}

// gap1307Path is one route of the table; masked: the route's framing has no
// content-free event, so the held events go out with the run masked.
type gap1307Path struct {
	name   string
	format streamTailFormat // passthrough only
	text   func(string) string
	masked bool
}

func gap1307Paths() []gap1307Path {
	paths := []gap1307Path{{name: "llm", text: streamedContent}}
	for _, f := range append([]streamTailFormat{gap0429OpenAIChat}, streamTailFormats...) {
		paths = append(paths, gap1307Path{name: "passthrough/" + f.name, format: f, text: gap0429PassthroughPath(f).text})
	}
	paths = append(paths, gap1307Path{name: "passthrough/" + gap1307Converse.name, format: gap1307Converse, text: gap1307ConverseText, masked: true})
	return append(paths, gap1307Path{name: "raw-forward", text: streamedContent})
}

// gap1307Rec records when the proxy wrote to the client.
type gap1307Rec struct {
	*httptest.ResponseRecorder
	mu     sync.Mutex
	writes []time.Time
}

func (r *gap1307Rec) note() {
	r.mu.Lock()
	r.writes = append(r.writes, time.Now())
	r.mu.Unlock()
}

func (r *gap1307Rec) Write(b []byte) (int, error) {
	r.note()
	return r.ResponseRecorder.Write(b)
}

func (r *gap1307Rec) WriteString(s string) (int, error) {
	r.note()
	return r.ResponseRecorder.WriteString(s)
}

// gap1307Clock is when the upstream of one row went quiet.
type gap1307Clock struct {
	mu sync.Mutex
	at time.Time
}

func (c *gap1307Clock) mark() {
	c.mu.Lock()
	c.at = time.Now()
	c.mu.Unlock()
}

func (c *gap1307Clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// gap1307Provider is the /llm upstream: chunks, quiet for pause before
// chunk at.
type gap1307Provider struct {
	mockProvider
	chunks []StreamChunk
	at     int
	pause  time.Duration
	clock  *gap1307Clock
}

func (m *gap1307Provider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for i, c := range m.chunks {
		if i == m.at {
			m.clock.mark()
			select {
			case <-time.After(m.pause):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		cb(c)
	}
	return nil, nil
}

// gap1307Upstream serves pieces in format f (raw: OpenAI chat chunks),
// quiet for pause before piece at.
func gap1307Upstream(t *testing.T, f streamTailFormat, raw bool, pieces []string, at int, pause time.Duration, clock *gap1307Clock) *httptest.Server {
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
		if !raw {
			write(f.head)
		}
		for i, p := range pieces {
			if i == at {
				clock.mark()
				select {
				case <-time.After(pause):
				case <-r.Context().Done():
					return
				}
			}
			if raw {
				write(`data: {"id":"r1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":` + streamTailJSON(p) + `}}]}` + "\n\n")
			} else {
				write(f.delta(p))
			}
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

// gap1307Result is what the client of one row got, and when.
type gap1307Result struct {
	gap1265Result
	first  time.Duration // from the upstream going quiet to the client's first byte after it; -1: none while quiet
	maxGap time.Duration // the longest time with no byte to the client while the upstream was quiet
}

// gap1307Serve runs the rows of one path at the same time.
func gap1307Serve(t *testing.T, path gap1307Path, rows []gap1265Row) ([]gap1307Result, string) {
	t.Helper()
	type run struct {
		rec   *gap1307Rec
		watch *gap0429Watch
		clock *gap1307Clock
		serve func()
	}
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
	switch {
	case path.name == "raw-forward":
		allowRawForwardPrivateTargets(t)
	case strings.HasPrefix(path.name, "passthrough/"):
		if path.format.name == gap0429OpenAIChat.name {
			allowRawForwardPrivateTargets(t)
		}
		orig := providerDomains
		providerDomains = append([]providerDomainEntry{{domain: "127.0.0.1", name: path.format.provider}}, orig...)
		t.Cleanup(func() { providerDomains = orig })
	}
	runs := make([]run, len(rows))
	registered := false
	for i, row := range rows {
		rec := &gap1307Rec{ResponseRecorder: httptest.NewRecorder()}
		secret := row.secret.text
		if secret == "" {
			secret = "\x00never"
		}
		w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: secret, rec: rec.ResponseRecorder}
		clock := &gap1307Clock{}
		var serve func()
		switch path.name {
		case "llm":
			prov := &gap1307Provider{chunks: gap0429Chunks(row.pieces), at: row.at, pause: row.pause, clock: clock}
			proxy, req := newTestProxy(t, prov, w, "action"), chatReq("", row)
			serve = func() { proxy.handleChatCompletion(rec, req) }
		case "raw-forward":
			up := gap1307Upstream(t, streamTailFormat{}, true, row.pieces, row.at, row.pause, clock)
			if !registered {
				registerRawForwardProviderDomain(t, up.URL, "openai")
				registered = true
			}
			proxy, req := newTestProxy(t, &mockProvider{}, w, "action"), chatReq(up.URL, row)
			serve = func() { proxy.handleChatCompletion(rec, req) }
		default:
			up := gap1307Upstream(t, path.format, false, row.pieces, row.at, row.pause, clock)
			proxy, req := newTestProxy(t, &mockProvider{}, w, "action"), streamTailWithTier(streamTailRequest(t, path.format, "", up.URL), row.pack, row.managed)
			serve = func() { proxy.handlePassthrough(rec, req) }
		}
		runs[i] = run{rec: rec, watch: w, clock: clock, serve: serve}
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
	out := make([]gap1307Result, len(rows))
	for i, r := range runs {
		res := gap1307Result{gap1265Result: gap1265Result{got: path.text(r.rec.Body.String()), blocked: r.watch.blocked}, first: -1}
		if s := rows[i].secret; s.text != "" {
			snap := r.watch.snap
			if !r.watch.seen {
				snap = r.rec.Body.String()
			}
			res.before, res.final = gap0429Released(path.text(snap), s), gap0429Released(res.got, s)
		}
		quiet := r.clock.get()
		end := quiet.Add(rows[i].pause)
		last := quiet
		for _, at := range r.rec.writes {
			if !at.After(quiet) || !at.Before(end) {
				continue
			}
			if res.first < 0 {
				res.first = at.Sub(quiet)
			}
			res.maxGap = max(res.maxGap, at.Sub(last))
			last = at
		}
		res.maxGap = max(res.maxGap, end.Sub(last))
		out[i] = res
	}
	return out, log
}

// gap1307MaskedOnly reports that got is want with some letters and digits
// before the upstream's pause masked ('*').
func gap1307MaskedOnly(got, want string, pauseAt int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := 0; i < len(want); i++ {
		if got[i] == want[i] {
			continue
		}
		c := want[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if got[i] != '*' || i >= pauseAt || !alnum {
			return false
		}
	}
	return true
}

// TestGAP1307QuietOpenRunReachesClient: on every route (/llm, passthrough
// in every format, raw forward) and in every tier, a reply whose text ends
// in an open digit run or token while the upstream is quiet for 30 s gives
// the client bytes within the hold's idle bound plus slack (a keep-alive,
// again within each bound while the upstream stays quiet; or the held
// events with the run masked where the framing has no content-free event),
// and no raw byte of a card number or a token the upstream pauses inside
// reaches the client before its verdict. A benign reply reaches the client
// whole (masked only on the masked route), with no TRUNCATED verdict.
func TestGAP1307QuietOpenRunReachesClient(t *testing.T) {
	bound := streamHoldMaxPartialAge + gap1307Slack
	prose := gap0429Pieces(retestFiller(1500)[:1500], 24, nil)
	portThenText := append(append([]string(nil), prose...), "The service listens on port 8080", " and the tests passed.\n")
	card := gap1091Value("card-visa-spaced", gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4))
	cardPieces, cardAt := gap1265Split(retestFiller(1100)[:1100], card, 9, " is the value. The build passed on the second run.\n")
	tok := gap0429Tokens(t)[0]
	tokPieces, tokAt := gap1265Split(retestFiller(1100)[:1100], tok, (tok.end-tok.body)/2, " is the value. The build passed on the second run.\n")
	for _, path := range gap1307Paths() {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				rows = append(rows,
					gap1265Row{name: "port-then-quiet", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: portThenText, at: len(prose) + 1, pause: gap1307Pause},
					gap1265Row{name: "card-quiet-inside", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: cardPieces, at: cardAt, pause: gap1307Pause, secret: card, wantBlocked: true},
					gap1265Row{name: "token-quiet-inside", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: tokPieces, at: tokAt, pause: gap1307Pause, secret: tok},
				)
			}
			results, log := gap1307Serve(t, path, rows)
			for i, row := range rows {
				res := results[i]
				name := fmt.Sprintf("%s/%s/%s", path.name, row.tier, row.name)
				if res.first < 0 || res.first > bound {
					t.Errorf("%s: the client got no byte within %s of the upstream going quiet (first after %s)", name, bound, res.first)
				}
				// A route whose stream had no event out yet when the bound came
				// (an Anthropic invoke stream before message_start) masks too;
				// after a masked release nothing is held, as on rel.
				masked := path.masked || strings.Count(res.got, "*") > strings.Count(strings.Join(row.pieces, ""), "*")
				if !masked && res.maxGap > bound {
					t.Errorf("%s: the client got no byte for %s while the upstream was quiet (bound %s)", name, res.maxGap.Round(time.Millisecond), bound)
				}
				pauseAt := len(strings.Join(row.pieces[:row.at], ""))
				want := strings.Join(row.pieces, "")
				switch {
				case !masked:
					gap1265Check(t, path.name, row, res.gap1265Result)
				case row.secret.text == "":
					if res.blocked || !gap1307MaskedOnly(res.got, want, pauseAt) {
						t.Errorf("%s: a benign reply was cut, blocked or changed past the masked run: blocked=%v, got %d of %d bytes", name, res.blocked, len(res.got), len(want))
					}
				default:
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
					if !res.blocked && !gap1307MaskedOnly(res.got, want, pauseAt) {
						t.Errorf("%s: not blocked, but the client got other text than the reply with the run masked (%d of %d bytes)", name, len(res.got), len(want))
					}
				}
			}
			gap1265NoTruncated(t, path.name, log)
		})
	}
}

// TestGAP1320MaskedReleaseSendsNoRawRunStart: end to end through
// handlePassthrough, a Bedrock ConverseStream whose "p" padding (an
// alphabet prefix, as Bedrock sends it) ends with the last character of
// each text, so the frame holding the start of a card number or a token
// the upstream goes quiet inside carries a padding that ends like the run.
// In every tier the masked release (GAP-1307 option b) sends no raw byte of
// the value before its verdict, and the client gets the reply with only the
// run masked, or the block (review s7-rv1307, GAP-1320).
func TestGAP1320MaskedReleaseSendsNoRawRunStart(t *testing.T) {
	alpha := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	f := gap1307Converse
	f.name = "bedrock-converse-pad"
	f.delta = func(text string) string {
		pad := "abc"
		if n := len(text); n > 0 {
			if i := strings.IndexByte(alpha, text[n-1]); i >= 0 {
				pad = alpha[:i+1]
			}
		}
		return gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": text}, "p": pad})
	}
	path := gap1307Path{name: "passthrough/" + f.name, format: f, text: gap1307ConverseText, masked: true}
	prose := gap0429Pieces(retestFiller(1500)[:1500], 24, nil)
	card := gap1091Value("card-visa-spaced", "4111 1111 1111 1111")
	tok := gap0429Tokens(t)[0]
	split := func(s gap0429Secret) ([]string, int) {
		mid := s.body + (s.end-s.body)/2
		p := append(append([]string(nil), prose...), " "+s.text[:s.body+1], s.text[s.body+1:mid], s.text[mid:]+" and done.\n")
		return p, len(p) - 1
	}
	var rows []gap1265Row
	for _, tier := range streamTailTiers {
		cp, ca := split(card)
		tp, ta := split(tok)
		rows = append(rows,
			gap1265Row{name: "card", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: cp, at: ca, pause: gap1307Pause, secret: card},
			gap1265Row{name: "token", tier: tier.name, pack: tier.pack, managed: tier.managed, pieces: tp, at: ta, pause: gap1307Pause, secret: tok},
		)
	}
	bound := streamHoldMaxPartialAge + gap1307Slack
	results, _ := gap1307Serve(t, path, rows)
	for i, row := range rows {
		res := results[i]
		name := fmt.Sprintf("%s/%s/%s", path.name, row.tier, row.name)
		n := row.secret.end - row.secret.body
		if res.before > 0 {
			t.Errorf("%s: %d of %d raw value bytes reached the client before the verdict", name, res.before, n)
		}
		if res.blocked && res.final > 0 {
			t.Errorf("%s: blocked, but %d of %d value bytes reached the client", name, res.final, n)
		}
		if res.first < 0 || res.first > bound {
			t.Errorf("%s: the client got no byte within %s of the upstream going quiet (first after %s)", name, bound, res.first)
		}
		if !res.blocked && !gap1307MaskedOnly(res.got, strings.Join(row.pieces, ""), len(strings.Join(row.pieces[:row.at], ""))) {
			t.Errorf("%s: not blocked, but the client got other text than the reply with the run masked (%d bytes)", name, len(res.got))
		}
	}
}

// TestGAP2170BedrockUnsignedQuietHoldKeepsMaskedBytes keeps Converse clients
// active during an unsigned answer run. Signed reasoning remains queued intact.
func TestGAP2170BedrockUnsignedQuietHoldKeepsMaskedBytes(t *testing.T) {
	prose := gap0429Pieces(retestFiller(1500)[:1500], 24, nil)
	pieces := append(append([]string(nil), prose...), "Port 8080", " is open.\n")
	rows := []gap1265Row{}
	for _, pack := range []string{"default", "strict"} {
		rows = append(rows, gap1265Row{
			name: "answer-digit-run", tier: pack, pack: pack,
			pieces: pieces, at: len(pieces) - 1,
			pause: streamKeepAliveAfter + 400*time.Millisecond,
		})
	}
	results, _ := gap1307Serve(t, gap1307Path{
		name:   "passthrough/" + gap1307Converse.name,
		format: gap1307Converse, text: gap1307ConverseText, masked: true,
	}, rows)
	for i, res := range results {
		if res.first < 0 {
			t.Errorf("%s: no bytes reached client during quiet hold", rows[i].tier)
		}
		want := strings.Join(prose, "") + "Port **** is open.\n"
		if res.got != want {
			t.Errorf("%s: unsigned answer run was not masked during quiet hold (got %d, want %d bytes)", rows[i].tier, len(res.got), len(want))
		}
	}
}
