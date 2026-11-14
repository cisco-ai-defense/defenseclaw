// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Streamed equals non-streamed (rel-1-0-10:GAP-0212, GAP-0629): in action
// mode a stream is blocked exactly when the check over its whole text
// blocks, and the client never receives the text that completes a match,
// whatever the chunking. The cases the property has to be able to fail on:
//   - a match longer than any window: a stub "validated block" finding that
//     needs both of its ends in one read, with 4.6 to 20 KiB between them
//     (the shape of a full PEM block, GAP-0622);
//   - lanes: the second end arrives in an earlier lane (choice or candidate
//     0) after a later lane has grown past 4 KiB (GAP-0623).
// A check that reads less than the whole text, or one lane's tail, lets the
// closing end through and fails here.

const (
	streamSpanBegin = "zq-span-open-41c2"
	streamSpanEnd   = "zq-span-close-41c2"
)

// streamSpanMatch reports a complete span: an opening end with a closing
// end after it.
func streamSpanMatch(text string) bool {
	i := strings.Index(text, streamSpanBegin)
	return i >= 0 && strings.Contains(text[i+len(streamSpanBegin):], streamSpanEnd)
}

// streamSpanInspector blocks a completion whose text holds a complete span,
// in the mid-stream and the final check.
type streamSpanInspector struct {
	*mockInspector
	mu        sync.Mutex
	midChecks int
}

func (i *streamSpanInspector) verdict(direction, content string) *ScanVerdict {
	if direction == "completion" && streamSpanMatch(content) {
		return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "stream span", Findings: []string{"test:stream-span"}}
	}
	return &ScanVerdict{Action: "allow", Severity: "NONE"}
}

func (i *streamSpanInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	return i.verdict(direction, content)
}

func (i *streamSpanInspector) InspectMidStream(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	i.mu.Lock()
	i.midChecks++
	i.mu.Unlock()
	return i.verdict(direction, content)
}

// streamSpanChunkings cut text into deltas: tiny, the 500-byte scan
// interval exactly, and seeded random sizes from 1 to 600.
func streamSpanChunkings(text string, seed int64) map[string][]string {
	cut := func(size func() int) []string {
		var out []string
		for rest := text; len(rest) > 0; {
			k := min(size(), len(rest))
			out = append(out, rest[:k])
			rest = rest[k:]
		}
		return out
	}
	rng := mrand.New(mrand.NewSource(seed))
	return map[string][]string{
		"7":      cut(func() int { return 7 }),
		"500":    cut(func() int { return 500 }),
		"random": cut(func() int { return 1 + rng.Intn(600) }),
	}
}

// streamSpanTexts are the cases: complete spans of every length around and
// past the 4 KiB overlap the reverted window used, at several offsets, and
// benign twins (an opening end alone, the ends in the wrong order).
func streamSpanTexts() map[string]string {
	out := map[string]string{}
	for _, before := range []int{0, 1100, 3000} {
		for _, span := range []int{60, 4600, 9000, 20000} {
			out[fmt.Sprintf("match/before=%d/span=%d", before, span)] = streamTailProse(before) + streamSpanBegin +
				streamTailProse(span) + streamSpanEnd + streamTailProse(3000)
		}
	}
	out["benign/open-only"] = streamTailProse(1100) + streamSpanBegin + streamTailProse(12000)
	out["benign/reversed"] = streamTailProse(1100) + streamSpanEnd + streamTailProse(9000) + streamSpanBegin + streamTailProse(2000)
	return out
}

func TestStreamTailMatchesWholeTextCheck(t *testing.T) {
	texts := streamSpanTexts()
	seed := int64(0)
	for _, f := range streamTailFormats {
		for name, text := range texts {
			seed++
			for cut, deltas := range streamSpanChunkings(text, seed) {
				t.Run(f.name+"/"+name+"/"+cut, func(t *testing.T) {
					insp := &streamSpanInspector{mockInspector: newMockInspector()}
					up, whole := streamTailUpstream(t, f, deltas, 0, nil)
					proxy := streamTailProxy(t, f.provider, insp, "action")
					out, _ := streamTailServe(t, proxy, f, up.URL)
					got := streamTailReceivedText(f, out)
					if !strings.HasPrefix(text, got) {
						t.Fatalf("the client text is not a prefix of the reply (%d of %d bytes)", len(got), len(text))
					}
					if !streamSpanMatch(text) {
						if out != whole {
							t.Fatalf("a benign stream changed: got %d bytes, want %d", len(out), len(whole))
						}
						return
					}
					if streamSpanMatch(got) || strings.Contains(got, streamSpanEnd) {
						t.Fatalf("the client received the end of a match the whole-text check blocks (%d of %d text bytes, %d mid-stream checks)",
							len(got), len(text), insp.midChecks)
					}
					// Blocked mid-stream, or before any output when the match
					// completes in the initial buffer: no terminal event either way.
					if strings.Contains(out, f.terminal) {
						t.Fatalf("a matching stream was not blocked (%d bytes)", len(out))
					}
				})
			}
		}
	}
}

// Lanes: the closing end arrives in lane 0 after lane 1 has grown past
// 4 KiB, and a hold release falls between the two (the provider pauses).
// /llm with two choices, and Gemini with two candidates.
func TestStreamTailMatchesWholeTextCheckAcrossLanes(t *testing.T) {
	type step struct {
		lane  int
		text  string
		pause time.Duration
	}
	var steps []step
	steps = append(steps, step{lane: 0, text: streamTailProse(1100) + streamSpanBegin})
	for _, d := range streamTailDeltas(5000, 500) {
		steps = append(steps, step{lane: 1, text: d})
	}
	steps = append(steps, step{lane: 1, text: " lane one goes on", pause: 3 * streamHoldMaxAge})
	steps = append(steps, step{lane: 0, text: " then " + streamSpanEnd, pause: 3 * streamHoldMaxAge})
	steps = append(steps, step{lane: 1, text: streamTailProse(600)})

	t.Run("llm/choices", func(t *testing.T) {
		var paced []streamTailPacedChunk
		for _, s := range steps {
			paced = append(paced, streamTailPacedChunk{pause: s.pause, chunk: StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: s.lane, Delta: &ChatMessage{Content: s.text}}}}})
		}
		stop := "stop"
		paced = append(paced, streamTailPacedChunk{chunk: StreamChunk{ID: "c1", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &stop}}}})
		body := mustJSON(t, map[string]any{"model": "gpt-4", "stream": true, "n": 2, "messages": []map[string]any{{"role": "user", "content": "hello"}}})
		insp := &streamSpanInspector{mockInspector: newMockInspector()}
		proxy := newTestProxy(t, &streamTailPacedProvider{chunks: paced}, insp, "action")
		out := postChat(t, proxy, body).Body.String()
		lanes := map[int]string{}
		for _, line := range strings.Split(out, "\n") {
			d, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
			if !ok || d == "[DONE]" {
				continue
			}
			var c StreamChunk
			if json.Unmarshal([]byte(d), &c) != nil {
				continue
			}
			for _, ch := range c.Choices {
				if ch.Delta != nil {
					lanes[ch.Index] += ch.Delta.Content
				}
			}
		}
		if strings.Contains(lanes[0], streamSpanEnd) || streamSpanMatch(lanes[0]) {
			t.Fatalf("the client received the end of a match in choice 0 (%d mid-stream checks)", insp.midChecks)
		}
		if !strings.Contains(out, "content blocked mid-stream by guardrail") {
			t.Fatalf("the stream was not blocked")
		}
	})

	t.Run("gemini/candidates", func(t *testing.T) {
		f := streamTailFormatNamed(t, "gemini")
		up := streamTailPacedUpstream(t, f, len(steps), func(i int) string {
			return streamTailGeminiEvent(steps[i].lane, []any{map[string]any{"text": steps[i].text}}, nil)
		}, func(i int) time.Duration { return steps[i].pause })
		insp := &streamSpanInspector{mockInspector: newMockInspector()}
		proxy := streamTailProxy(t, f.provider, insp, "action")
		out, _ := streamTailServe(t, proxy, f, up.URL)
		if strings.Contains(out, streamSpanEnd) {
			t.Fatalf("the client received the end of a match in candidate 0 (%d mid-stream checks)", insp.midChecks)
		}
		if strings.Contains(out, f.terminal) {
			t.Fatalf("a matching stream was not blocked (%d bytes)", len(out))
		}
	})
}

// streamTailPacedChunk is one provider chunk and the pause after it.
type streamTailPacedChunk struct {
	chunk StreamChunk
	pause time.Duration
}

// streamTailPacedProvider sends its chunks with their pauses.
type streamTailPacedProvider struct {
	mockProvider
	chunks []streamTailPacedChunk
}

func (s *streamTailPacedProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, cb func(StreamChunk)) (*ChatUsage, error) {
	for _, c := range s.chunks {
		cb(c.chunk)
		if c.pause > 0 {
			select {
			case <-time.After(c.pause):
			case <-ctx.Done():
				return &ChatUsage{}, ctx.Err()
			}
		}
	}
	return &ChatUsage{}, nil
}

// streamTailPacedUpstream serves event(i) for each of n steps, pausing
// pause(i) after it, then the format's terminal event.
func streamTailPacedUpstream(t *testing.T, f streamTailFormat, n int, event func(int) string, pause func(int) time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ctype)
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		for i := 0; i < n; i++ {
			_, _ = io.WriteString(w, event(i))
			fl.Flush()
			if d := pause(i); d > 0 {
				select {
				case <-time.After(d):
				case <-r.Context().Done():
					return
				}
			}
		}
		_, _ = io.WriteString(w, f.terminal)
	}))
	t.Cleanup(srv.Close)
	return srv
}
