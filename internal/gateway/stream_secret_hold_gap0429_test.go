// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	privatekeyfixture "github.com/defenseclaw/defenseclaw/internal/secretshape/testfixture"
)

// rel-1-0-10:GAP-0429 (widened by the S7 lead): a secret whose match needs
// more bytes than one stream piece (a private-key PEM block, a token split
// across pieces) must not have any of its body reach the client before the
// verdict on it. Every secret here is generated at run time (no real key or
// token is in the repo); the token prefixes are joined at run time.
//
// The table streams each secret through every stream path that holds a reply
// (the /llm proxy, the passthrough stream in five wire formats, the raw
// forward stream), in pieces of 1, 7, 24 and 4096 bytes and whole, in the 3
// packs, and counts the body bytes the client had when the first check read
// the whole secret or decided on it (gap0429Watch). That count is 0.

// gap0429Watch is the rule inspector of a stream, which notes what the client
// had received at the first check that read the whole secret or found
// anything in the text.
type gap0429Watch struct {
	*GuardrailInspector
	secret  string
	rec     *httptest.ResponseRecorder
	snap    string
	seen    bool
	blocked bool
}

func (w *gap0429Watch) note(content string, v *ScanVerdict) *ScanVerdict {
	if v != nil && v.Action == "block" {
		w.blocked = true
	}
	if !w.seen && (strings.Contains(content, w.secret) || (v != nil && v.Action != "allow" && v.Severity != "NONE")) {
		w.seen, w.snap = true, w.rec.Body.String()
	}
	return v
}

func (w *gap0429Watch) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return w.note(content, w.GuardrailInspector.Inspect(ctx, direction, content, messages, model, mode))
}

func (w *gap0429Watch) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return w.note(content, w.GuardrailInspector.InspectMidStream(ctx, direction, content, messages, model, mode))
}

// InspectMidStreamAgeDue is the check of a hold due by age only (GAP-0625):
// it reads the held text before it is sent, as the other two do, so the
// watch notes it too. Unwatched, the embedded inspector's method decided
// without the watch seeing a block or the first read of the whole secret.
func (w *gap0429Watch) InspectMidStreamAgeDue(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) (*ScanVerdict, bool) {
	v, full := w.GuardrailInspector.InspectMidStreamAgeDue(ctx, direction, content, messages, model, mode)
	return w.note(content, v), full
}

// gap0429Secret is one secret of the table: secret[body:end] are the bytes
// that must not reach the client before the verdict.
type gap0429Secret struct {
	name, class string
	text        string
	body, end   int
}

const (
	gap0429Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	gap0429Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	gap0429Hex   = "0123456789abcdef"
)

func gap0429Random(t testing.TB, alphabet string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b)
}

// gap0429PEM is a private-key block of a PEM label made of parts.
func gap0429PEM(name string, block []byte) gap0429Secret {
	text := string(block)
	return gap0429Secret{name: name, class: "pem", text: text,
		body: strings.IndexByte(text, '\n') + 1, end: strings.LastIndex(text, "-----END ")}
}

func gap0429Token(name, prefix, body string) gap0429Secret {
	return gap0429Secret{name: name, class: "token", text: prefix + body, body: len(prefix), end: len(prefix) + len(body)}
}

func gap0429Label(parts ...string) string { return strings.Join(parts, "") }

// gap0429Keys are the private keys: run-time RSA, EC and Ed25519 keys in the
// PKCS#1, PKCS#8, SEC1 and OpenSSH forms, and the RFC 1423 encrypted, DSA and
// PGP fixtures of secretshape.
func gap0429Keys(t testing.TB) []gap0429Secret {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ossh, err := ssh.MarshalPrivateKey(ed, "")
	if err != nil {
		t.Fatal(err)
	}
	pk := gap0429Label("PRIVATE", " KEY")
	return []gap0429Secret{
		gap0429PEM("rsa2048-pkcs1", pem.EncodeToMemory(&pem.Block{Type: "RSA " + pk, Bytes: x509.MarshalPKCS1PrivateKey(rk)})),
		gap0429PEM("ec-pkcs8", pem.EncodeToMemory(&pem.Block{Type: pk, Bytes: pk8})),
		gap0429PEM("ec-sec1", pem.EncodeToMemory(&pem.Block{Type: "EC " + pk, Bytes: sec1})),
		gap0429PEM("openssh-ed25519", pem.EncodeToMemory(ossh)),
		gap0429PEM("rsa-rfc1423-encrypted", []byte(privatekeyfixture.MustLegacyEncryptedRSAPEM())),
		gap0429PEM("dsa", []byte(privatekeyfixture.MustPEM("DSA "+pk))),
		gap0429PEM("pgp", []byte(privatekeyfixture.MustPEM("PGP "+pk))),
	}
}

// gap0429Tokens are tokens of the token rules of the secret rules, with
// run-time bodies.
func gap0429Tokens(t testing.TB) []gap0429Secret {
	t.Helper()
	r := func(alphabet string, n int) string { return gap0429Random(t, alphabet, n) }
	return []gap0429Secret{
		gap0429Token("github-token", gap0429Label("gh", "p_"), r(gap0429Alnum, 36)),
		gap0429Token("github-pat", gap0429Label("github", "_pat_"), r(gap0429Alnum, 82)),
		gap0429Token("aws-access-key", gap0429Label("AK", "IA"), r(gap0429Upper, 16)),
		gap0429Token("aws-secret-key", gap0429Label("aws_secret", "_access_key = "), r(gap0429Alnum+"+/", 40)),
		gap0429Token("anthropic", gap0429Label("sk-", "ant-"), r(gap0429Alnum, 48)),
		gap0429Token("openai-project", gap0429Label("sk-", "proj-"), r(gap0429Alnum, 48)),
		gap0429Token("stripe", gap0429Label("sk_", "live_"), r(gap0429Alnum, 32)),
		gap0429Token("slack", gap0429Label("xo", "xb-"), r(gap0429Alnum, 40)),
		gap0429Token("google", gap0429Label("AI", "za"), r(gap0429Alnum, 35)),
		gap0429Token("gitlab", gap0429Label("gl", "pat-"), r(gap0429Alnum, 24)),
		gap0429Token("npm", gap0429Label("np", "m_"), r(gap0429Alnum, 36)),
		gap0429Token("pypi", gap0429Label("py", "pi-"), r(gap0429Alnum, 60)),
		gap0429Token("sendgrid", gap0429Label("S", "G."), r(gap0429Alnum, 22)+"."+r(gap0429Alnum, 43)),
		gap0429Token("twilio", gap0429Label("S", "K"), r(gap0429Hex, 32)),
		gap0429Token("jwt", gap0429Label("ey", "J"), r(gap0429Alnum, 20)+".eyJ"+r(gap0429Alnum, 30)+"."+r(gap0429Alnum, 43)),
		gap0429Token("connection-string", gap0429Label("postgres", "://svc:"), r(gap0429Alnum, 16)+"@db.internal"),
		gap0429Token("bearer", gap0429Label("Authorization: ", "Bearer "), r(gap0429Alnum, 40)),
		gap0429Token("hex-api-key", gap0429Label("api", "_key = "), r(gap0429Hex, 40)),
	}
}

// gap0429Shape places a secret in a reply: pre before it, and a piece
// boundary forced at the byte offsets cut (within pre).
type gap0429Shape struct {
	name string
	pre  func(filler string) string
	cut  func(filler string) []int
}

func gap0429Shapes(key gap0429Secret) []gap0429Shape {
	header := key.text[:key.body]
	plain := func(s string) func(string) string { return func(f string) string { return f + s } }
	return []gap0429Shape{
		{name: "mid", pre: plain("")},
		{name: "start", pre: func(string) string { return "" }},
		{name: "decoy-other-label", pre: plain("-----BEGIN X-----\n")},
		{name: "decoy-split-begin", pre: plain("-----BEGIN X-----\n"),
			cut: func(f string) []int { return []int{len(f), len(f) + len("-----BEGIN ")} }},
		{name: "decoy-certificate-line", pre: plain("-----BEGIN CERTIFICATE-----\n")},
		{name: "decoy-unclosed-same-label", pre: plain(header + "this line is no base64.\n")},
		{name: "decoy-end-line", pre: plain("-----END " + strings.TrimPrefix(header, "-----BEGIN "))},
	}
}

// gap0429Pieces cuts text into pieces of size bytes (whole when size is 0),
// with a boundary also at every offset of cut.
func gap0429Pieces(text string, size int, cut []int) []string {
	if size <= 0 {
		size = len(text)
	}
	bounds := map[int]bool{}
	for off := size; off < len(text); off += size {
		bounds[off] = true
	}
	for _, c := range cut {
		if c > 0 && c < len(text) {
			bounds[c] = true
		}
	}
	offs := make([]int, 0, len(bounds))
	for off := range bounds {
		offs = append(offs, off)
	}
	sort.Ints(offs)
	var out []string
	prev := 0
	for _, off := range offs {
		out = append(out, text[prev:off])
		prev = off
	}
	return append(out, text[prev:])
}

// gap0429Path is one stream path: run serves pieces as a streamed reply with
// insp, pack in action mode, and returns what the client got; text is the
// reply text a client reads from it.
type gap0429Path struct {
	name string
	run  func(t *testing.T, rec *httptest.ResponseRecorder, insp ContentInspector, pack string, pieces []string)
	text func(out string) string
}

var gap0429OpenAIChat = streamTailFormat{
	name: "openai-chat", provider: "openai", path: "/v1/chat/completions", ctype: streamTailSSE,
	terminal: "data: [DONE]\n\n", delta: retestOAIFrame,
}

// gap0429Stores is the one audit store and logger of each test that serves
// stream rows (gap0429Proxy), keyed by its *testing.T.
var gap0429Stores sync.Map

type gap0429Store struct {
	store  *audit.Store
	logger *audit.Logger
}

// gap0429Proxy is a new action-mode test proxy for one stream row, on the
// audit store of t made once for all its rows: a fresh store per row was
// 73% of the time of the /llm table (a copy of the migrated template, its
// Init and its read pool), and the stream paths only write audit rows, they
// never read them. Every row still gets a proxy of its own.
func gap0429Proxy(t *testing.T, prov LLMProvider, insp ContentInspector) *GuardrailProxy {
	t.Helper()
	v, ok := gap0429Stores.Load(t)
	if !ok {
		store, logger := testStoreAndLogger(t)
		v = gap0429Store{store: store, logger: logger}
		gap0429Stores.Store(t, v)
		t.Cleanup(func() { gap0429Stores.Delete(t) })
	}
	s := v.(gap0429Store)
	return newTestProxyOnStore(t, prov, insp, "action", s.store, s.logger)
}

func gap0429LLMRun(t *testing.T, rec *httptest.ResponseRecorder, insp ContentInspector, pack string, pieces []string) {
	t.Helper()
	gap0429LLMProvider(t, rec, &mockProvider{streamChunks: gap0429Chunks(pieces)}, insp, pack)
}

func gap0429Chunks(pieces []string) []StreamChunk {
	var chunks []StreamChunk
	for _, p := range pieces {
		if p == gap1265Finish0 {
			stop := "stop"
			chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &stop}}})
			continue
		}
		choice, text := gap1265Piece(p)
		chunks = append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: choice, Delta: &ChatMessage{Content: text}}}})
	}
	fin := "stop"
	return append(chunks, StreamChunk{ID: "c", Object: "chat.completion.chunk", Model: "gpt-4",
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fin}}})
}

func gap0429LLMProvider(t *testing.T, rec *httptest.ResponseRecorder, prov LLMProvider, insp ContentInspector, pack string) {
	t.Helper()
	gap0429LLMProxy(t, rec, gap0429Proxy(t, prov, insp), pack)
}

// gap0429LLMProxy is gap0429LLMProvider through proxy.
func gap0429LLMProxy(t *testing.T, rec *httptest.ResponseRecorder, proxy *GuardrailProxy, pack string) {
	t.Helper()
	body := mustJSON(t, map[string]interface{}{
		"model": "gpt-4", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "go"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	proxy.handleChatCompletion(rec, streamTailWithTier(req, pack, false))
}

func gap0429PassthroughPath(f streamTailFormat) gap0429Path {
	return gap0429Path{
		name: "passthrough/" + f.name,
		run: func(t *testing.T, rec *httptest.ResponseRecorder, insp ContentInspector, pack string, pieces []string) {
			t.Helper()
			up, _ := streamTailUpstream(t, f, pieces, 0, nil)
			gap0429Passthrough(t, f, rec, insp, streamTailWithTier(streamTailRequest(t, f, "", up.URL), pack, false))
		},
		text: func(out string) string {
			if f.name == gap0429OpenAIChat.name {
				return streamedContent(out) // chat chunks, not Responses events
			}
			return streamTailReceivedText(f, out)
		},
	}
}

// gap0429Passthrough serves req through the passthrough handler with the
// loopback upstream named f.provider for this run only. The first matching
// provider domain wins, so the per-run append of streamTailProxy would keep
// every later run of a test on the first run's provider (its reader), and
// the chat format forwards raw (X-DC-Target-URL), which needs the private
// target allowance.
func gap0429Passthrough(t *testing.T, f streamTailFormat, rec *httptest.ResponseRecorder, insp ContentInspector, req *http.Request) {
	t.Helper()
	if f.name == gap0429OpenAIChat.name {
		allowRawForwardPrivateTargets(t)
	}
	orig := providerDomains
	providerDomains = append([]providerDomainEntry{{domain: "127.0.0.1", name: f.provider}}, orig...)
	defer func() { providerDomains = orig }()
	gap0429Proxy(t, &mockProvider{}, insp).handlePassthrough(rec, req)
}

func gap0429RawForwardRun(t *testing.T, rec *httptest.ResponseRecorder, insp ContentInspector, pack string, pieces []string) {
	t.Helper()
	gap0429RawForward(t, rec, gap0429Proxy(t, &mockProvider{}, insp), pack, pieces)
}

// gap0429RawForward is gap0429RawForwardRun through proxy.
func gap0429RawForward(t *testing.T, rec *httptest.ResponseRecorder, proxy *GuardrailProxy, pack string, pieces []string) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for _, p := range pieces {
			_, _ = io.WriteString(w, `data: {"id":"r1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":`+streamTailJSON(p)+`}}]}`+"\n\n")
			fl.Flush()
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		fl.Flush()
	}))
	t.Cleanup(up.Close)
	registerRawForwardProviderDomain(t, up.URL, "openai")
	allowRawForwardPrivateTargets(t)
	body := mustJSON(t, map[string]interface{}{
		"model": "gpt-4", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "go"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", up.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-test")
	proxy.handleChatCompletion(rec, streamTailWithTier(req, pack, false))
}

func gap0429Paths() []gap0429Path {
	paths := []gap0429Path{
		{name: "llm", run: gap0429LLMRun, text: streamedContent},
		gap0429PassthroughPath(gap0429OpenAIChat),
	}
	for _, f := range streamTailFormats {
		paths = append(paths, gap0429PassthroughPath(f))
	}
	return append(paths, gap0429Path{name: "raw-forward", run: gap0429RawForwardRun, text: streamedContent})
}

// gap0429Released counts the body bytes of s in the reply text got: the
// bytes after the first copy of the text before the body that match the body.
func gap0429Released(got string, s gap0429Secret) int {
	i := strings.Index(got, s.text[:s.body])
	if i < 0 {
		return 0
	}
	rest, body := got[i+s.body:], s.text[s.body:s.end]
	n := 0
	for n < len(rest) && n < len(body) && rest[n] == body[n] {
		n++
	}
	return n
}

// gap0429Row is one run of the table.
type gap0429Row struct {
	path    gap0429Path
	pack    string
	secret  gap0429Secret
	shape   gap0429Shape
	size    int
	filler  int
	trailer string
}

// gap0429Result is what one run measured.
type gap0429Result struct {
	before, final int // body bytes the client had at the verdict and at the end
	blocked       bool
	text          string // reply text the client got
}

// gap0429Text is the reply text of row and the extra cut offsets of its shape.
func gap0429Text(row gap0429Row) (string, []int) {
	filler := retestFiller(row.filler)[:row.filler]
	pre := row.shape.pre(filler)
	text := pre + row.secret.text + row.trailer
	var cut []int
	if row.shape.cut != nil {
		cut = row.shape.cut(filler)
	}
	return text, cut
}

// gap0429IsWholeAgain reports a row of 4096-byte pieces whose whole reply
// text is no longer than 4096 bytes: gap0429Pieces cuts at 4096, 8192, ...
// only below len(text), so such a row serves exactly the pieces (one piece
// plus the shape's own cuts) of the whole (size 0) row of the same
// secret, shape, filler and pack. It is a duplicate of that row, so the
// tables skip it and say how many they skipped.
func gap0429IsWholeAgain(row gap0429Row) bool {
	if row.size != 4096 {
		return false
	}
	text, _ := gap0429Text(row)
	return len(text) <= 4096
}

func gap0429Serve(t *testing.T, row gap0429Row) gap0429Result {
	t.Helper()
	text, cut := gap0429Text(row)
	rec := httptest.NewRecorder()
	w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: row.secret.text, rec: rec}
	row.path.run(t, rec, w, row.pack, gap0429Pieces(text, row.size, cut))
	snap := w.snap
	if !w.seen {
		snap = rec.Body.String()
	}
	got := row.path.text(rec.Body.String())
	return gap0429Result{
		before:  gap0429Released(row.path.text(snap), row.secret),
		final:   gap0429Released(got, row.secret),
		blocked: w.blocked, text: got,
	}
}

// gap0429Tally sums the rows of one class of the table for the report.
type gap0429Tally struct {
	rows, leaking, maxBefore, bodyOfMax, sumBefore int
}

func gap0429Run(t *testing.T, paths []gap0429Path) {
	keys, tokens := gap0429Keys(t), gap0429Tokens(t)
	tallies := map[string]*gap0429Tally{}
	sizes := gap0429Sizes()
	dropped := 0
	for _, path := range paths {
		for _, pack := range gap0429Packs() {
			var rows []gap0429Row
			for _, size := range sizes {
				for i, k := range keys {
					shapes := gap0429Shapes(k)
					if i > 0 {
						shapes = shapes[:1] // the decoys run with the RSA key
					}
					for _, sh := range shapes {
						if size == 1 && i > 3 {
							continue // 1-byte pieces: the four run-time keys
						}
						rows = append(rows, gap0429Row{path: path, pack: pack, secret: k, shape: sh, size: size, filler: 1100,
							trailer: "\n\nThat key is a test fixture.\n"})
					}
				}
				// Tokens at three offsets: inside a scan window, and with the
				// /llm and passthrough 500-byte scan boundary (after the
				// 1024-byte initial buffer) falling inside the token.
				for _, tk := range tokens {
					for _, fill := range []int{1100, 1520 - tk.body - 3, 2020 - tk.body - 3} {
						rows = append(rows, gap0429Row{path: path, pack: pack, secret: tk, shape: gap0429Shape{name: fmt.Sprintf("at%d", fill), pre: func(f string) string { return f }},
							size: size, filler: fill, trailer: " is the value. The build passed on the second run.\n"})
					}
				}
			}
			for _, row := range rows {
				if gap0429IsWholeAgain(row) {
					dropped++
					continue
				}
				name := fmt.Sprintf("%s/%s/%s/%s/size=%d", path.name, pack, row.secret.name, row.shape.name, row.size)
				res := gap0429Serve(t, row)
				body := row.secret.end - row.secret.body
				key := path.name + "/" + row.secret.class
				tl := tallies[key]
				if tl == nil {
					tl = &gap0429Tally{}
					tallies[key] = tl
				}
				tl.rows++
				tl.sumBefore += res.before
				if res.before > 0 {
					tl.leaking++
					if res.before > tl.maxBefore {
						tl.maxBefore, tl.bodyOfMax = res.before, body
					}
					t.Errorf("%s: %d of %d body bytes reached the client before the verdict", name, res.before, body)
				}
				if res.blocked && res.final > 0 {
					t.Errorf("%s: blocked, but %d of %d body bytes reached the client", name, res.final, body)
				}
				if !res.blocked && !strings.Contains(res.text, row.secret.text[:row.secret.body]) {
					// Not blocked, so the client has the whole reply: a reply
					// text without it is a run the table did not measure.
					t.Errorf("%s: not blocked, and the reply text read from the client has no secret prefix (%d bytes): not measured", name, len(res.text))
				}
			}
		}
	}
	t.Logf("GAP0429-TALLY skipped %d rows of 4096-byte pieces whose reply text is at most 4096 bytes (the same pieces as their whole rows)", dropped)
	keysOut := make([]string, 0, len(tallies))
	for k := range tallies {
		keysOut = append(keysOut, k)
	}
	sort.Strings(keysOut)
	for _, k := range keysOut {
		tl := tallies[k]
		t.Logf("GAP0429-TALLY %s rows=%d rows_releasing=%d max_released=%d/%d sum_released=%d", k, tl.rows, tl.leaking, tl.maxBefore, tl.bodyOfMax, tl.sumBefore)
	}
}

func TestGAP0429StreamedSecretHeldLLM(t *testing.T) {
	gap0429Run(t, gap0429Paths()[:1])
}

// The passthrough table runs in three tests of two stream formats each, so
// each fits a CI shard (one test of all six ran 636 s plain).
func TestGAP0429StreamedSecretHeldPassthrough(t *testing.T) {
	gap0429Run(t, gap0429PathsNamed(t, "passthrough/"+gap0429OpenAIChat.name, "passthrough/anthropic"))
}

func TestGAP0429StreamedSecretHeldPassthroughResponsesGemini(t *testing.T) {
	gap0429Run(t, gap0429PathsNamed(t, "passthrough/openai-responses", "passthrough/gemini"))
}

func TestGAP0429StreamedSecretHeldPassthroughBedrockOllama(t *testing.T) {
	gap0429Run(t, gap0429PathsNamed(t, "passthrough/bedrock", "passthrough/ollama"))
}

// TestGAP0429PassthroughTestsCoverEveryFormat: the three passthrough tests
// above read every passthrough path of gap0429Paths, so a new stream format
// is not left out of the table.
func TestGAP0429PassthroughTestsCoverEveryFormat(t *testing.T) {
	covered := map[string]bool{"passthrough/" + gap0429OpenAIChat.name: true, "passthrough/anthropic": true,
		"passthrough/openai-responses": true, "passthrough/gemini": true, "passthrough/bedrock": true, "passthrough/ollama": true}
	for _, p := range gap0429Paths() {
		if strings.HasPrefix(p.name, "passthrough/") && !covered[p.name] {
			t.Errorf("%s is in no TestGAP0429StreamedSecretHeldPassthrough* test", p.name)
		}
	}
}

// gap0429PathsNamed returns the paths of gap0429Paths with these names, in
// that order; a name that is not a path fails the test.
func gap0429PathsNamed(t *testing.T, names ...string) []gap0429Path {
	t.Helper()
	all := gap0429Paths()
	out := make([]gap0429Path, 0, len(names))
	for _, n := range names {
		found := false
		for _, p := range all {
			if p.name == n {
				out, found = append(out, p), true
				break
			}
		}
		if !found {
			t.Fatalf("no stream path %q", n)
		}
	}
	return out
}

// gap0429Sizes are the piece sizes of the stream tables. Every frame is
// checked over the whole reply text (as on rel, not the hold), so a row of
// 1- or 7-byte pieces costs thousands of whole-text checks: under -race those
// rows run past the CI shard cap, and the plain build runs them.
func gap0429Sizes() []int {
	if hookAnswerRaceBuild {
		return []int{24, 4096, 0}
	}
	return []int{1, 7, 24, 4096, 0}
}

// gap0429Packs are the rule packs of the stream tables. Under -race each
// pack costs the same (the passthrough tests took 554-679 s with three, over
// the CI shard cap), so -race runs the default pack for the race check and
// the plain build runs all three.
func gap0429Packs() []string {
	if hookAnswerRaceBuild {
		return []string{"default"}
	}
	return []string{"default", "strict", "permissive"}
}

func TestGAP0429StreamedSecretHeldRawForward(t *testing.T) {
	paths := gap0429Paths()
	gap0429Run(t, paths[len(paths)-1:])
}

// TestGAP0429BenignStreamsAreNotHeld: ordinary replies with BEGIN words,
// public PEM blocks, a private-key header in prose, long prose and a reply
// whose upstream pauses after a number go out whole and unchanged on every
// path, with no block and no TRUNCATED alert.
func TestGAP0429BenignStreamsAreNotHeld(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ek.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	header := "-----BEGIN RSA " + gap0429Label("PRIVATE", " KEY") + "-----"
	benign := []struct{ name, text string }{
		{"sql-and-pascal-begin", "Run it in one transaction:\n\nBEGIN TRANSACTION;\nUPDATE jobs SET state = 'done' WHERE id = 7;\nCOMMIT;\n\nIn Pascal the body is begin writeln('ok'); end.\n"},
		{"certificate", "The server certificate:\n\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})) + "\nInstall it in the trust store.\n"},
		{"public-key", "The public key:\n" + string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})) + "Share it freely.\n"},
		{"key-header-in-prose", "A key file starts with the line " + header + " and ends with the matching END line.\n"},
		{"key-header-then-prose", "The file looks like this:\n\n" + header + "\n(the key body is omitted here)\n-----END RSA " + gap0429Label("PRIVATE", " KEY") + "-----\n"},
		{"code-words", "func (c *Client) Refresh() error {\n\ttoken, err := c.source.Token()\n\tif err != nil {\n\t\treturn err\n\t}\n\tc.task = \"desk-top\"\n\treturn c.store.Save(token)\n}\n"},
		{"long-prose", retestFiller(64 << 10)},
	}
	sizes := []int{7, 24, 4096}
	if hookAnswerRaceBuild {
		sizes = []int{24, 4096} // as gap0429Sizes: the 7-byte rows run in the plain build
	}
	for _, path := range gap0429Paths() {
		for _, b := range benign {
			for _, size := range sizes {
				if b.name == "long-prose" && size == 7 && (path.name == "raw-forward" || path.name == gap0429PassthroughPath(gap0429OpenAIChat).name) {
					// The raw forward checks the whole text at every frame:
					// 9k frames of 7 bytes outlast the request deadline, as on
					// rel 4269debe92 (not the hold).
					continue
				}
				if hookAnswerRaceBuild && b.name == "long-prose" && size != 4096 {
					// Under -race the whole-text check at every frame makes
					// 64 KiB in small frames outlast the request deadline on
					// every passthrough path (807 s, the client got part of
					// the text); the plain build runs those rows.
					continue
				}
				name := fmt.Sprintf("%s/%s/size=%d", path.name, b.name, size)
				rec := httptest.NewRecorder()
				w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: "\x00never", rec: rec}
				log := captureStderr(t, func() { path.run(t, rec, w, "default", gap0429Pieces(b.text, size, nil)) })
				if got := path.text(rec.Body.String()); got != b.text {
					t.Errorf("%s: the client got %d of %d bytes, or other text", name, len(got), len(b.text))
				}
				if w.blocked || strings.Contains(log, "TRUNCATED") || strings.Contains(log, "STREAM-BLOCK") {
					t.Errorf("%s: blocked=%v, or a TRUNCATED/BLOCK line was logged", name, w.blocked)
				}
			}
		}
	}
	// A reply that ends a piece in a number, then the upstream is idle past
	// the hold's idle bound (GAP-1265): whole, no block, no TRUNCATED alert.
	// One row per path; TestGAP1265OpenRunIdleIsNotTruncated runs the five
	// tiers.
	prose := gap0429Pieces(retestFiller(1500)[:1500], 24, nil)
	paused := append(append(append([]string(nil), prose...), "I bumped the release to version 1.0.10\n"), "Then the tests passed.\n")
	for _, path := range gap0429Paths() {
		t.Run("number-then-pause/"+path.name, func(t *testing.T) {
			row := gap1265Row{name: "number-then-pause", tier: "default", pack: "default", pieces: paused, at: len(prose) + 1, pause: gap1265Pause}
			results, log := gap1265Serve(t, path, []gap1265Row{row})
			gap1265Check(t, path.name, row, results[0])
			gap1265NoTruncated(t, path.name, log)
			if strings.Contains(log, "STREAM-BLOCK") {
				t.Errorf("%s: a BLOCK line was logged: %s", path.name, gap1265LogLine(log, "STREAM-BLOCK"))
			}
		})
	}
}
