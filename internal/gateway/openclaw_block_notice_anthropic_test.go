// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Anthropic Messages route of OpenClaw (provider bedrock-anthropic,
// POST /anthropic/v1/messages): the tool call keeps its provider id, the replay
// carries it back on a tool_result part of a user message, and the reply is
// text/event-stream.
const (
	anthropicBlockedID  = "toolu_bdrk_01FmS74KfD5ay8upYF6m64Qo"
	anthropicReplyText  = "I could not run that."
	anthropicNoticeRule = noticeTestRule
)

func anthropicReplayBody(resultID string) string {
	return `{"model":"us.anthropic.claude-haiku-4-5-20251001-v1:0","stream":true,"max_tokens":4096,"messages":[` +
		`{"role":"user","content":[{"type":"text","text":"run the command"}]},` +
		`{"role":"assistant","content":[{"type":"text","text":"Running it."},{"type":"tool_use","id":"` + anthropicBlockedID + `","name":"exec","input":{"command":"x"}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + resultID + `","content":[{"type":"text","text":"DefenseClaw: blocked"}],"is_error":true}]}]}`
}

// anthropicReplyStream is the reply of a Claude model over the
// Anthropic wire: start, one text block, then the closing events.
func anthropicReplyStream() string {
	frame := func(typ, data string) string { return "event: " + typ + "\ndata: " + data + "\n\n" }
	return frame("message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}`) +
		frame("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		frame("ping", `{"type":"ping"}`) +
		frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I could not "}}`) +
		frame("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"run that."}}`) +
		frame("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		frame("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":6}}`) +
		frame("message_stop", `{"type":"message_stop"}`)
}

func anthropicReplyJSON() string {
	return `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"` + anthropicReplyText + `"}],"stop_reason":"end_turn"}`
}

func gzipNoticeBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := io.WriteString(zw, s); err != nil || zw.Close() != nil {
		t.Fatal("gzip failed")
	}
	return b.Bytes()
}

// anthropicRoundTrip sends one replay through the notice middleware and the real
// passthrough handler, as the OpenClaw fetch interceptor does: the model client
// asks for a compressed reply (undici adds accept-encoding), and the upstream
// compresses when asked. The reply the client reads is returned decoded.
func anthropicRoundTrip(t *testing.T, resultID string, stream, upstreamGzip bool) (body string, header http.Header) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply, ctype := anthropicReplyJSON(), "application/json"
		if stream {
			reply, ctype = anthropicReplyStream(), "text/event-stream"
		}
		w.Header().Set("Content-Type", ctype)
		out := []byte(reply)
		if upstreamGzip && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			out = gzipNoticeBytes(t, reply)
		}
		_, _ = w.Write(out)
	}))
	defer upstream.Close()
	proxy := newForwardingProxy(t, upstream.URL)
	notice := openClawBlockNoticeMiddleware(http.HandlerFunc(proxy.handlePassthrough), func(*http.Request) bool { return true })
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notice.ServeHTTP(w, r.WithContext(withThresholdConnector(r.Context(), "openclaw")))
	}))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/anthropic/v1/messages", strings.NewReader(anthropicReplayBody(resultID)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "br, gzip, deflate")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer sk-upstream")
	req.Header.Set(SessionIDHeader, noticeTestSession)
	req.Header.Set(SessionBoundHeader, "1")
	// A transport that decodes nothing, so what the proxy sent is what is read.
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = io.ReadAll(zr)
	}
	return string(raw), resp.Header
}

// A blocked call on the Anthropic route shows its line once on the first text of
// the reply, stream and not, whether or not the upstream compresses the reply.
func TestGAP0644AnthropicBlockLeadsTheReplyThroughThePassthroughHandler(t *testing.T) {
	line := openClawBlockNoticeLine("exec", []string{anthropicNoticeRule}, "matched: ssh authorized_keys write")
	for _, tc := range []struct {
		name         string
		stream, gzip bool
	}{
		{"sse", true, false},
		{"sse compressed upstream", true, true},
		{"json", false, false},
		{"json compressed upstream", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", anthropicBlockedID, noticeTestSession, []string{anthropicNoticeRule}, "matched: ssh authorized_keys write")
			out, _ := anthropicRoundTrip(t, anthropicBlockedID, tc.stream, tc.gzip)
			if tc.stream {
				if got, want := streamText(sseData(t, out), "anthropic"), line+"\n\n"+anthropicReplyText; got != want {
					t.Fatalf("streamed text = %q, want %q", got, want)
				}
			} else if !strings.Contains(out, `\n\n`+anthropicReplyText) || strings.Count(out, openClawBlockNoticeMark) != 1 {
				t.Fatalf("reply = %s", out)
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the notice stayed pending after it was shown")
			}
			if again, _ := anthropicRoundTrip(t, anthropicBlockedID, tc.stream, tc.gzip); strings.Contains(again, openClawBlockNoticeMark) {
				t.Fatalf("the line was shown twice:\n%s", again)
			}
		})
	}
}

// An allowed call, and a result of another call, leave the reply as it was and
// the block pending for its own result.
func TestGAP0644AnthropicAllowedCallAndOtherResultShowNothing(t *testing.T) {
	for _, stream := range []bool{true, false} {
		resetOpenClawBlockNotices(t)
		observeOpenClawToolCall("toolu_bdrk_01AllowedAllowedAllowed")
		out, _ := anthropicRoundTrip(t, "toolu_bdrk_01AllowedAllowedAllowed", stream, false)
		if strings.Contains(out, openClawBlockNoticeMark) {
			t.Fatalf("an allowed call got a line: %s", out)
		}
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", anthropicBlockedID, noticeTestSession, []string{anthropicNoticeRule}, "r")
		out, _ = anthropicRoundTrip(t, "toolu_bdrk_01SomeoneElseSomeoneElse", stream, false)
		if strings.Contains(out, openClawBlockNoticeMark) || !openClawBlockNoticesPending() {
			t.Fatalf("a result of another call took the block: %s", out)
		}
	}
}

// Only a request that took a notice loses its accept-encoding; every other
// request reaches the provider exactly as the client sent it.
func TestGAP0644AcceptEncodingIsDroppedOnlyForAClaimedRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resultID string
		want     string
	}{
		{"claimed request", anthropicBlockedID, ""},
		{"result of another call", "toolu_bdrk_01SomeoneElseSomeoneElse", "br, gzip, deflate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", anthropicBlockedID, noticeTestSession, []string{anthropicNoticeRule}, "r")
			var got string
			h := openClawBlockNoticeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Accept-Encoding")
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, anthropicReplyJSON())
			}), func(*http.Request) bool { return true })
			req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(anthropicReplayBody(tc.resultID)))
			req = req.WithContext(withThresholdConnector(req.Context(), "openclaw"))
			req.Header.Set("Accept-Encoding", "br, gzip, deflate")
			req.Header.Set(SessionIDHeader, noticeTestSession)
			req.Header.Set(SessionBoundHeader, "1")
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got != tc.want {
				t.Fatalf("accept-encoding seen upstream = %q, want %q", got, tc.want)
			}
		})
	}
}
