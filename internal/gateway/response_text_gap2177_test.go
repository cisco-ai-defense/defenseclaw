// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestGAP2177BoundaryRunClosesAfterFirstAnswerLine(t *testing.T) {
	var r responseText
	r.Add(reasoningPiece(0, "analysis."))
	r.Add(answerPiece(0, "Total: 42"))
	if !r.OpenSecret().open {
		t.Fatal("digit run was not held while the first answer line was open")
	}
	r.Add(answerPiece(0, "\n"+strings.Repeat("more ", 32)))
	if r.OpenSecret().open {
		t.Fatal("completed first answer line kept the boundary run open")
	}
	if !strings.Contains(r.CheckText(), "analysis.Total: 42") {
		t.Fatal("the completed check line was lost")
	}

	var long responseText
	long.Add(reasoningPiece(0, "analysis."))
	long.Add(answerPiece(0, "Total: 42 "+strings.Repeat("x", 600)))
	if long.OpenSecret().open {
		t.Fatal("the bounded first answer line kept the boundary run open")
	}
}

func TestGAP2166BoundaryWindowKeepsUnbrokenSides(t *testing.T) {
	token := gap0429Label("gh", "p_") + gap0429Random(t, gap0429Alnum, 36)
	var left responseText
	left.Add(reasoningPiece(0, strings.Repeat("é", 300)+token[:7]))
	left.Add(answerPiece(0, token[7:]))
	check := left.CheckText()
	if !utf8.ValidString(check) || !strings.Contains(check, token) {
		t.Fatal("the last 512 reasoning bytes lost a split token")
	}

	var right responseText
	right.Add(reasoningPiece(0, "gh"))
	right.Add(answerPiece(0, "p_"+strings.Repeat("a", 600)))
	check = right.CheckText()
	if !utf8.ValidString(check) || !strings.Contains(check, "ghp_"+strings.Repeat("a", 24)) {
		t.Fatal("the first 512 answer bytes were dropped")
	}
}

func TestGAP2170LongAnswerKeepsReasoningRun(t *testing.T) {
	card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
	var r responseText
	r.Add(reasoningPiece(0, "VALUE: "+card[:10]))
	if !r.OpenSecret().open {
		t.Fatal("split card prefix was not held")
	}
	r.Add(answerPiece(0, strings.Repeat("safe ", 130)))
	if !r.OpenSecret().open {
		t.Fatal("answer longer than 512 bytes released the reasoning prefix")
	}
	r.Add(reasoningPiece(0, card[10:]+" done"))
	if !strings.Contains(r.CheckText(), card) {
		t.Fatal("the resumed reasoning lane lost the card")
	}
}

func gap2177LiveFrames(t *testing.T, shape, lead, tail string) (streamTailFormat, []string, string) {
	t.Helper()
	answer := "Total: 42\n"
	switch shape {
	case "openai-chat":
		f := gap0429OpenAIChat
		frames := []string{
			strings.TrimPrefix(gap2166ChatDelta(0, "reasoning_content", lead), gap1265Raw),
			strings.TrimPrefix(gap2166ChatDelta(0, "content", answer), gap1265Raw),
			strings.TrimPrefix(gap2166ChatDelta(0, "content", tail), gap1265Raw),
		}
		return f, frames, "data: [DONE]\n\n"
	case "anthropic":
		f := streamTailFormatNamed(t, "anthropic")
		frames := []string{
			strings.TrimPrefix(gap2162AnthropicDelta(0, "thinking_delta", lead), gap1265Raw),
			strings.TrimPrefix(gap2162AnthropicStop(0), gap1265Raw),
			strings.TrimPrefix(gap2162AnthropicStart(1, map[string]any{"type": "text", "text": ""}), gap1265Raw),
			strings.TrimPrefix(gap2162AnthropicDelta(1, "text_delta", answer), gap1265Raw),
			strings.TrimPrefix(gap2162AnthropicDelta(1, "text_delta", tail), gap1265Raw),
		}
		return f, frames, strings.TrimPrefix(gap2162Event("message_stop", map[string]any{}), gap1265Raw)
	case "bedrock-converse":
		f := streamTailFormat{name: "bedrock-converse", provider: "bedrock", path: "/model/m/converse-stream", ctype: ctEvents}
		frames := []string{
			eventStreamBody(t, "contentBlockDelta", streamTailJSON(map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"reasoningContent": map[string]any{"text": lead}}})),
			eventStreamBody(t, "contentBlockDelta", streamTailJSON(map[string]any{"contentBlockIndex": 1, "delta": map[string]any{"text": answer}})),
			eventStreamBody(t, "contentBlockDelta", streamTailJSON(map[string]any{"contentBlockIndex": 1, "delta": map[string]any{"text": tail}})),
		}
		return f, frames, eventStreamBody(t, "messageStop", "{}")
	default:
		t.Fatalf("unknown live boundary shape %q", shape)
		return streamTailFormat{}, nil, ""
	}
}

func TestGAP2177FirstAnswerLineStreamsLive(t *testing.T) {
	lead := retestFiller(2048)[:2048] + " analysis."
	marker := "LIVE-AFTER-NEWLINE"
	tail := strings.Repeat("more ", 830) + marker
	for _, shape := range []string{"openai-chat", "anthropic", "bedrock-converse"} {
		for _, pack := range []string{"default", "strict"} {
			t.Run(shape+"/"+pack, func(t *testing.T) {
				f, frames, terminal := gap2177LiveFrames(t, shape, lead, tail)
				entered := make(chan struct{})
				resume := make(chan struct{})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", f.ctype)
					flusher := w.(http.Flusher)
					for _, frame := range frames {
						_, _ = io.WriteString(w, frame)
						flusher.Flush()
					}
					close(entered)
					select {
					case <-resume:
					case <-r.Context().Done():
						return
					}
					_, _ = io.WriteString(w, terminal)
					flusher.Flush()
				}))
				defer upstream.Close()
				registerRawForwardProviderDomain(t, upstream.URL, f.provider)
				allowRawForwardPrivateTargets(t)
				proxy := gap0429Proxy(t, &mockProvider{}, retestInspector())
				req := streamTailWithTier(streamTailRequest(t, f, "", upstream.URL), pack, false)
				rec := &covSyncRecorder{}
				done := make(chan struct{})
				go func() {
					proxy.handlePassthrough(rec, req)
					close(done)
				}()
				defer func() {
					close(resume)
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("stream handler did not finish")
					}
				}()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream did not reach the pause")
				}
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				for !bytes.Contains(rec.bytes(), []byte(tail)) {
					select {
					case <-deadline.C:
						t.Fatal("answer bytes after the newline remained held")
					case <-done:
						t.Fatal("stream ended before the upstream resumed")
					case <-tick.C:
					}
				}
			})
		}
	}
}
