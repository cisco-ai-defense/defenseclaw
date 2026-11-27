// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The bounds of the open-secret hold (rel-1-0-10:GAP-0429, the bound rule):
// a stream that ends inside a private-key block, an open block over
// streamSecretMaxPEM and an open secret with no new text for
// streamHoldMaxPartialAge are TRUNCATED. The unknown tier follows the pack:
// default and permissive alert and send, strict blocks and sends none of the
// body. Never a silent release.

// gap0429Tiers are the packs and what the unknown tier does in each.
var gap0429Tiers = []struct {
	pack   string
	blocks bool
}{{"default", false}, {"permissive", false}, {"strict", true}}

// gap0429BoundCase is a reply whose secret never ends inside the bounds.
type gap0429BoundCase struct {
	name   string
	secret gap0429Secret
	text   string
	piece  int // piece size; 0: gap0429BoundPieceSize
}

func gap0429BoundCases(t *testing.T) []gap0429BoundCase {
	key := gap0429Keys(t)[0]
	half := key.body + (key.end-key.body)/2
	half -= (half - key.body) % 65 // a whole number of 64-column lines
	cut := key
	cut.text, cut.end = key.text[:half], half
	// An open block with more body than secretshape reads: base64 lines past
	// streamSecretMaxPEM (by 32 KiB, so a frame of 4096 bytes ends inside
	// the open block past the cap, whichever frames a read batches), then
	// the END line.
	line := strings.Repeat("QUJD", 16) + "\n"
	big := key.text[:key.body] + strings.Repeat(line, streamSecretMaxPEM/len(line)+512)
	over := gap0429Secret{name: "over-cap", class: "pem", text: big + "-----END " + key.text[len("-----BEGIN "):key.body],
		body: key.body, end: len(big)}
	filler := retestFiller(1100)[:1100]
	return []gap0429BoundCase{
		{"ends-inside-key", cut, filler + cut.text, 0},
		// 4096-byte pieces: every frame is checked over the whole reply
		// text, so 64 KiB in 24-byte pieces (2700 frames) took 300 s plain
		// and in 512-byte pieces 295 s under -race, for a bound that is the
		// same at any piece size (it is crossed by the byte count).
		{"block-over-cap", over, filler + over.text + "\nDone.\n", 4096},
	}
}

// gap0429BoundPieceSize is the piece size of the hold-bound table: 24 bytes
// in the plain build; under -race 512, as a 64 KiB block in 24-byte pieces
// is thousands of whole-text checks (1301 s under -race) and the bound is
// the same at any piece size.
func gap0429BoundPieceSize() int {
	if hookAnswerRaceBuild {
		return 512
	}
	return 24
}

func TestGAP0429HoldBoundsAreTheUnknownTier(t *testing.T) {
	// The log names the bound only with reasons shown (a strict block line
	// shows the reason redacted otherwise); stderr is captured, not printed.
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	for _, path := range gap0429Paths() {
		for _, c := range gap0429BoundCases(t) {
			for _, tier := range gap0429Tiers {
				name := fmt.Sprintf("%s/%s/%s", path.name, c.name, tier.pack)
				rec := httptest.NewRecorder()
				w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: c.secret.text, rec: rec}
				size := c.piece
				if size == 0 {
					size = gap0429BoundPieceSize()
				}
				log := captureStderr(t, func() { path.run(t, rec, w, tier.pack, gap0429Pieces(c.text, size, nil)) })
				got := path.text(rec.Body.String())
				released := gap0429Released(got, c.secret)
				if !strings.Contains(log, "TRUNCATED") && !strings.Contains(log, boundedTruncatedTitle) {
					t.Errorf("%s: no TRUNCATED verdict was logged", name)
				}
				if tier.blocks {
					if released > 0 {
						t.Errorf("%s: strict, but %d body bytes reached the client", name, released)
					}
					continue
				}
				if got != c.text {
					t.Errorf("%s: %s alerts and sends the reply; the client got %d of %d bytes", name, tier.pack, len(got), len(c.text))
				}
			}
		}
	}
}

// gap0429PausingProvider streams chunks and waits pause before chunk at.
type gap0429PausingProvider struct {
	mockProvider
	chunks []StreamChunk
	at     int
	pause  time.Duration
}

func (m *gap0429PausingProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for i, c := range m.chunks {
		if i == m.at {
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

// TestGAP0429OpenSecretIdleBound: an upstream that goes quiet inside a key
// block holds the reply streamHoldMaxPartialAge, then the unknown tier
// decides: default alerts and sends, strict blocks with none of the body
// out. The paths with a reader goroutine (/llm and the passthrough stream;
// the raw forward reads on the handler goroutine and has no idle clock).
func TestGAP0429OpenSecretIdleBound(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1") // the bound's reason in the captured log
	key := gap0429Keys(t)[0]
	filler := retestFiller(1100)[:1100]
	text := filler + key.text + "\nDone.\n"
	pieces := gap0429Pieces(text, 24, nil)
	at := 0 // the first piece past half of the key body
	for n, i := 0, 0; i < len(pieces); i++ {
		n += len(pieces[i])
		if n > len(filler)+key.body+(key.end-key.body)/2 {
			at = i + 1
			break
		}
	}
	pause := streamHoldMaxPartialAge + 700*time.Millisecond
	for _, tier := range []struct {
		pack   string
		blocks bool
	}{{"default", false}, {"strict", true}} {
		t.Run("llm/"+tier.pack, func(t *testing.T) {
			rec := httptest.NewRecorder()
			w := &gap0429Watch{GuardrailInspector: retestInspector(), secret: key.text, rec: rec}
			prov := &gap0429PausingProvider{chunks: gap0429Chunks(pieces), at: at, pause: pause}
			log := captureStderr(t, func() { gap0429LLMProvider(t, rec, prov, w, tier.pack) })
			gap0429CheckIdle(t, log, streamedContent(rec.Body.String()), text, key, tier.blocks)
		})
		t.Run("passthrough/anthropic/"+tier.pack, func(t *testing.T) {
			stall := make(chan struct{})
			// A passthrough format read on the reader goroutine (the chat
			// format forwards raw, with no clock of its own).
			f := streamTailFormatNamed(t, "anthropic")
			up := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Header().Set("Content-Type", f.ctype)
				fl := rw.(http.Flusher)
				_, _ = io.WriteString(rw, f.head)
				for i, p := range pieces {
					if i == at {
						select {
						case <-stall:
						case <-time.After(pause):
						case <-r.Context().Done():
							return
						}
					}
					_, _ = io.WriteString(rw, f.delta(p))
					fl.Flush()
				}
				_, _ = io.WriteString(rw, f.tail+f.terminal)
				fl.Flush()
			}))
			defer up.Close()
			defer close(stall)
			rec := httptest.NewRecorder()
			log := captureStderr(t, func() {
				gap0429Passthrough(t, f, rec, retestInspector(), streamTailWithTier(streamTailRequest(t, f, "", up.URL), tier.pack, false))
			})
			gap0429CheckIdle(t, log, streamTailReceivedText(f, rec.Body.String()), text, key, tier.blocks)
		})
	}
}

func gap0429CheckIdle(t *testing.T, log, got, text string, key gap0429Secret, blocks bool) {
	t.Helper()
	if !strings.Contains(log, "no new text for") {
		t.Errorf("the idle bound was not decided (no TRUNCATED time verdict logged)")
	}
	// Default alerts and sends what it held; the key, once whole, is then
	// blocked by the secret rule as on rel. Strict blocks at the bound.
	released := gap0429Released(got, key)
	if blocks && released > 0 {
		t.Errorf("strict: %d of %d body bytes reached the client", released, key.end-key.body)
	}
	if !blocks && released == 0 {
		t.Errorf("default: the alert did not send the held text (the client got %d of %d bytes)", len(got), len(text))
	}
}

// TestStreamTokenOpenCoversSecretRules: every secret rule of every shipped
// pack has a token shape in streamTokenRules (or is exempt), so a new token
// rule is held while it streams too.
func TestStreamTokenOpenCoversSecretRules(t *testing.T) {
	covered := map[string]bool{}
	for _, r := range streamTokenRules {
		for _, id := range r.rules {
			covered[id] = true
		}
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "guardrail", "*", "rules", "secrets.yaml"))
	if err != nil || len(files) < 3 {
		t.Fatalf("secret rule files: %v (%d)", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID           string `yaml:"id"`
				ToolCallOnly bool   `yaml:"tool_call_only"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, r := range doc.Rules {
			if !strings.HasPrefix(r.ID, "SEC-") || r.ToolCallOnly || streamSecretExempt[r.ID] {
				continue
			}
			if !covered[r.ID] {
				t.Errorf("%s: secret rule %s has no token shape in streamTokenRules", f, r.ID)
			}
		}
	}
}

// TestSecretLaneOpenStates checks the open-secret reader on the text of one
// lane as it grows a byte at a time.
func TestSecretLaneOpenStates(t *testing.T) {
	key := gap0429Keys(t)[0]
	header := key.text[:key.body]
	ghp := gap0429Label("gh", "p_")
	cases := []struct {
		name string
		text string
		// open reports, for a prefix of text, whether it ends inside an
		// open secret.
		open func(prefix string) bool
	}{
		{"key", "ok " + key.text + "done.", func(p string) bool {
			i := strings.Index(p, "-----BEGIN ")
			return i >= 0 && !strings.Contains(p[i:], "-----END RSA "+gap0429Label("PRIVATE", " KEY")+"-----")
		}},
		{"certificate", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", func(p string) bool {
			return strings.HasPrefix(p, "-----BEGIN ") && !strings.Contains(p, "\n")
		}},
		{"other-end-line", header + "MIIB\n-----END CERTIFICATE-----\nafter", func(p string) bool {
			return strings.HasPrefix(p, "-----BEGIN ") && !strings.Contains(p, "-----END CERTIFICATE-----")
		}},
		{"prose-after-header", header + "this is prose.", func(p string) bool {
			return strings.HasPrefix(p, "-----BEGIN ") && !strings.Contains(p, "this ")
		}},
		{"token", "use " + ghp + "abc123 now", func(p string) bool {
			i := strings.LastIndex(p, ghp)
			return i >= 0 && len(p) > i+len(ghp) && !strings.Contains(p[i:], " ")
		}},
	}
	for _, c := range cases {
		var r responseText
		for i := 1; i <= len(c.text); i++ {
			r.Add(answerPiece(0, c.text[i-1:i]))
			got, want := r.OpenSecret().open, c.open(c.text[:i])
			if got != want {
				t.Fatalf("%s: after %d bytes (%q...) open=%v, want %v", c.name, i, c.text[max(0, i-20):i], got, want)
			}
		}
	}
	// A bound releases the open secret; it is not held again.
	var r responseText
	r.Add(answerPiece(0, header+"MIIB"))
	if !r.OpenSecret().pem {
		t.Fatal("open key block not reported")
	}
	r.ReleaseOpenSecret()
	r.Add(answerPiece(0, "MIIB"))
	if r.OpenSecret().open {
		t.Fatal("a released key block is held again")
	}
}

// TestStreamTokenOpenRegexpIsAnchored: the token check reads only the end.
func TestStreamTokenOpenRegexpIsAnchored(t *testing.T) {
	for _, re := range streamTokenOpenEach {
		if !strings.HasSuffix(re.String(), ")$") {
			t.Fatalf("%s: a token open expression must be anchored at the end", re)
		}
	}
	if !strings.HasSuffix(streamTokenOpen.String(), ")$") {
		t.Fatal("streamTokenOpen must be anchored at the end")
	}
	if _, err := regexp.Compile(streamTokenOpen.String()); err != nil {
		t.Fatal(err)
	}
}
