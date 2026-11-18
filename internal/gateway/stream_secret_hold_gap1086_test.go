// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1086: the passthrough stream reads an event shape no typed
// reader knows with the walker, which dropped every whitespace-only string,
// so a stream of 1-byte deltas lost the newlines and spaces of the reply: a
// private key or a bearer token split that way was never matched, and went
// out whole. The walker keeps a stream event's whitespace-only strings.

// gap1086Unknown is a stream whose events carry the text at a path no typed
// reader knows, and no other string.
var gap1086Unknown = streamTailFormat{
	name: "unknown-shape", provider: "anthropic", path: "/v1/messages", ctype: streamTailSSE,
	terminal: "data: {\"done\":true}\n\n",
	delta: func(text string) string {
		return "data: " + streamTailJSON(map[string]any{"seq": 1, "piece": map[string]any{"chunk": text}}) + "\n\n"
	},
}

// gap1086Text is the reply text a client reads from an unknown-shape stream.
func gap1086Text(out string) string {
	var sb strings.Builder
	for _, line := range strings.Split(out, "\n") {
		d, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Piece struct {
				Chunk string `json:"chunk"`
			} `json:"piece"`
		}
		if json.Unmarshal([]byte(d), &ev) == nil {
			sb.WriteString(ev.Piece.Chunk)
		}
	}
	return sb.String()
}

// gap1086Watch notes whether a check read the whole secret, whitespace and
// all, and whether one flagged it.
type gap1086Watch struct {
	*gap0429Watch
	whole, flagged bool
}

func (w *gap1086Watch) saw(content string, v *ScanVerdict) *ScanVerdict {
	w.whole = w.whole || strings.Contains(content, w.secret)
	w.flagged = w.flagged || (v != nil && v.Action != "allow" && v.Severity != "NONE")
	return v
}

func (w *gap1086Watch) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return w.saw(content, w.gap0429Watch.Inspect(ctx, direction, content, messages, model, mode))
}

func (w *gap1086Watch) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return w.saw(content, w.gap0429Watch.InspectMidStream(ctx, direction, content, messages, model, mode))
}

// TestGAP1086UnknownShapeStreamKeepsWhitespaceDeltas: two private keys and
// two tokens with spaces in them, in 1-byte and 7-byte deltas of an
// unknown-shape stream, in the default and strict packs. A check flags the
// secret, reads it whole (its newlines and spaces kept) unless it blocked on
// its first line, and no body byte reaches the client before the verdict.
func TestGAP1086UnknownShapeStreamKeepsWhitespaceDeltas(t *testing.T) {
	var secrets []gap0429Secret
	secrets = append(secrets, gap0429Keys(t)[:2]...)
	for _, tk := range gap0429Tokens(t) {
		if tk.name == "bearer" || tk.name == "aws-secret-key" {
			secrets = append(secrets, tk)
		}
	}
	path := gap0429Path{
		name: "passthrough/" + gap1086Unknown.name,
		run: func(t *testing.T, rec *httptest.ResponseRecorder, insp ContentInspector, pack string, pieces []string) {
			t.Helper()
			up, _ := streamTailUpstream(t, gap1086Unknown, pieces, 0, nil)
			gap0429Passthrough(t, gap1086Unknown, rec, insp, streamTailWithTier(streamTailRequest(t, gap1086Unknown, "", up.URL), pack, false))
		},
		text: gap1086Text,
	}
	for _, pack := range []string{"default", "strict"} {
		for _, s := range secrets {
			for _, size := range []int{1, 7} {
				name := fmt.Sprintf("%s/%s/%s/size=%d", path.name, pack, s.name, size)
				text := streamTailProse(200) + "\n" + s.text + "\n\nThat is a test fixture.\n"
				rec := httptest.NewRecorder()
				w := &gap1086Watch{gap0429Watch: &gap0429Watch{GuardrailInspector: retestInspector(), secret: s.text, rec: rec}}
				path.run(t, rec, w, pack, gap0429Pieces(text, size, nil))
				snap := w.snap
				if !w.seen {
					snap = rec.Body.String()
				}
				if !w.whole && !w.blocked {
					// A block before the whole key arrived read its header
					// line whole; any other run must read the secret whole.
					t.Errorf("%s: not blocked, and no check read the secret whole (its whitespace deltas were dropped)", name)
				}
				if !w.flagged {
					t.Errorf("%s: no check flagged the secret", name)
				}
				if n := gap0429Released(path.text(snap), s); n > 0 {
					t.Errorf("%s: %d of %d body bytes reached the client before the verdict", name, n, s.end-s.body)
				}
				if got := path.text(rec.Body.String()); !w.blocked && !strings.Contains(got, s.text[:s.body]) {
					t.Errorf("%s: not blocked, and the reply text read from the client has no secret prefix (%d bytes): not measured", name, len(got))
				}
			}
		}
	}
}
