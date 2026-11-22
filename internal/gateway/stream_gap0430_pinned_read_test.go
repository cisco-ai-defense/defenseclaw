// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGAP0430PinnedReadRuneSplit is the pinned-read probe of GAP-0430: the
// passthrough stream reads the upstream in reads whose boundaries fall
// inside a multi-byte rune, inside a long data line, and inside the secret
// itself. No byte may drop out of the text the checks read: the secret after
// the split runes is found and none of it reaches the client.
func TestGAP0430PinnedReadRuneSplit(t *testing.T) {
	secret := retestSecret()
	for _, long := range []bool{false, true} {
		for _, runeText := range []string{"é", "日本", "😀"} {
			for split := 1; split < len(runeText); split++ {
				name := fmt.Sprintf("long=%v/%q/split=%d", long, runeText, split)
				prose := "Here is the value " + strings.Repeat(runeText, 3)
				if long {
					prose = strings.Repeat("a line of text with runes "+runeText+" in it. ", 9000) + prose
				}
				content := prose + secret + " and more text after it."
				frame, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"index": 0, "delta": map[string]string{"content": content}}}})
				stream := "data: " + string(frame) + "\n\ndata: [DONE]\n\n"
				// Read boundaries: every 4096-split bytes of the long line,
				// inside the last rune before the secret, and in the middle
				// of the secret.
				runeAt := strings.Index(stream, secret) - len(runeText)
				var cuts []int
				for off := 4096 - split; off < runeAt; off += 4096 {
					cuts = append(cuts, off)
				}
				cuts = append(cuts, runeAt+split, strings.Index(stream, secret)+len(secret)/2)
				got := gap0430Run(t, stream, cuts)
				if strings.Contains(got, secret[len(secret)/2:]) || strings.Contains(got, secret) {
					t.Errorf("%s: the secret reached the client across pinned reads", name)
				}
				if !strings.Contains(got, "blocked") && strings.Contains(got, "more text after") {
					t.Errorf("%s: the reply was not blocked", name)
				}
			}
		}
	}
}

// gap0430Reader returns stream in reads that end exactly at cuts.
type gap0430Reader struct {
	stream string
	cuts   []int
	off    int
}

func (r *gap0430Reader) Read(b []byte) (int, error) {
	if r.off >= len(r.stream) {
		return 0, io.EOF
	}
	end := len(r.stream)
	for _, c := range r.cuts {
		if c > r.off {
			end = min(end, c)
			break
		}
	}
	end = min(end, r.off+len(b))
	n := copy(b, r.stream[r.off:end])
	r.off += n
	return n, nil
}

func gap0430Run(t *testing.T, stream string, cuts []int) string {
	t.Helper()
	proxy := gap0429Proxy(t, &mockProvider{}, retestInspector())
	req := streamTailWithTier(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true}`)), "default", false)
	rec := httptest.NewRecorder()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(&gap0430Reader{stream: stream, cuts: cuts})}
	(&passthroughStream{p: proxy, w: rec, r: req, resp: resp, mode: "action", label: "m", provider: "openai",
		path: "/v1/chat/completions", model: "m"}).run()
	return rec.Body.String()
}
