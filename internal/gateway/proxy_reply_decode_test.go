// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// encodeReply applies the encodings of a Content-Encoding value in order.
func encodeReply(t *testing.T, encodings string, plain []byte) []byte {
	t.Helper()
	out := plain
	for _, enc := range strings.Split(encodings, ",") {
		var buf bytes.Buffer
		switch strings.TrimSpace(enc) {
		case "gzip", "x-gzip":
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(out)
			_ = zw.Close()
		case "deflate":
			zw := zlib.NewWriter(&buf)
			_, _ = zw.Write(out)
			_ = zw.Close()
		case "raw-deflate":
			fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
			_, _ = fw.Write(out)
			_ = fw.Close()
		case "br":
			bw := brotli.NewWriter(&buf)
			_, _ = bw.Write(out)
			_ = bw.Close()
		case "zstd":
			zw, err := zstd.NewWriter(nil)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(zw.EncodeAll(out, nil))
			_ = zw.Close()
		default:
			t.Fatalf("encoding %q", enc)
		}
		out = buf.Bytes()
	}
	return out
}

func TestDecodeReplyBodyEncodings(t *testing.T) {
	plain := []byte(`{"type":"message","content":[{"type":"text","text":"hello"}]}`)
	for _, tc := range []struct{ header, applied string }{
		{"gzip", "gzip"}, {"x-gzip", "gzip"}, {"deflate", "deflate"}, {"deflate", "raw-deflate"},
		{"br", "br"}, {"zstd", "zstd"}, {"gzip, br", "gzip, br"}, {"deflate, zstd", "deflate, zstd"}, {"BR", "br"},
	} {
		h := http.Header{"Content-Encoding": {tc.header}, "Content-Length": {"9"}}
		got, ok := decodeReplyBody(h, encodeReply(t, tc.applied, plain))
		if !ok || !bytes.Equal(got, plain) || h.Get("Content-Encoding") != "" || h.Get("Content-Length") != "" {
			t.Errorf("%s (%s): ok=%t body=%q header=%v", tc.header, tc.applied, ok, got, h)
		}
	}
	h := http.Header{"Content-Encoding": {"gzip", "br"}}
	if got, ok := decodeReplyBody(h, encodeReply(t, "gzip, br", plain)); !ok || !bytes.Equal(got, plain) {
		t.Errorf("two header lines: ok=%t %q", ok, got)
	}
	for _, tc := range []struct {
		name, header string
		body         []byte
	}{
		{"unknown token", "compress", plain},
		{"unknown layer in a stack", "gzip, x-foo", encodeReply(t, "gzip", plain)},
		{"corrupt br", "br", []byte("\x1b\x07\x00\xf8\xa5opaque-br-bytes")},
		{"corrupt gzip", "gzip", []byte("not gzip")},
		{"wrong order", "br, gzip", encodeReply(t, "gzip, br", plain)},
	} {
		h := http.Header{"Content-Encoding": {tc.header}}
		got, ok := decodeReplyBody(h, tc.body)
		if ok || !bytes.Equal(got, tc.body) || h.Get("Content-Encoding") != tc.header {
			t.Errorf("%s: decoded or changed: ok=%t header=%v", tc.name, ok, h)
		}
	}
	if got, ok := decodeReplyBody(http.Header{"Content-Encoding": {"identity"}}, plain); ok || !bytes.Equal(got, plain) {
		t.Error("identity is not a decode")
	}
	big := bytes.Repeat([]byte("a"), replyDecodeCap+1)
	if _, ok := decodeReplyBody(http.Header{"Content-Encoding": {"zstd"}}, encodeReply(t, "zstd", big)); ok {
		t.Error("a reply over the cap was decoded")
	}
}

// The client asks for every encoding; the provider answers with one the
// proxy did not ask for. The reply is decoded, inspected and sent plain.
func TestPassthroughDecodesProviderEncodings(t *testing.T) {
	const invoke = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke"
	plain := []byte(`{"type":"message","role":"assistant","content":[{"type":"text","text":"` + bedrockSecretText + `"}]}`)
	for _, enc := range []string{"gzip", "br", "zstd", "deflate", "gzip, br", "deflate, zstd"} {
		t.Run(enc, func(t *testing.T) {
			var asked string
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = r.Header.Get("Accept-Encoding")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", enc)
				_, _ = w.Write(encodeReply(t, enc, plain))
			}))
			defer up.Close()
			req := func() *http.Request {
				return bedrockRequest(up.URL, invoke, "Accept-Encoding", "br, zstd, gzip, deflate")
			}
			proxy, insp := bedrockPassthroughProxy(t, up)
			insp.setVerdict("completion", allowVerdict("mock"))
			rec := httptest.NewRecorder()
			proxy.handlePassthrough(rec, req())
			if asked != "gzip" {
				t.Fatalf("upstream asked for %q, want the transport gzip", asked)
			}
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), plain) || rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("allowed reply: %d %q %v", rec.Code, rec.Body.Bytes(), rec.Header())
			}
			proxy, insp = bedrockPassthroughProxy(t, up)
			insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
			rec = httptest.NewRecorder()
			proxy.handlePassthrough(rec, req())
			if strings.Contains(rec.Body.String(), "4242") || rec.Header().Get("Content-Encoding") != "" {
				t.Fatalf("blocked reply forwarded: %d %v %q", rec.Code, rec.Header(), rec.Body.Bytes())
			}
		})
	}
}

// A reply the proxy cannot read (an undecodable encoding, a broken Bedrock
// eventstream) is refused in action mode on a managed install and in the
// strict tier, and forwarded with an alert (log line and telemetry) in
// every other case (GAP-0128).
func TestPassthroughUnreadableReplyPerMode(t *testing.T) {
	const invoke = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke"
	const stream = "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream"
	opaque := []byte("opaque-bytes-" + bedrockSecretText)
	encodedWith := func(enc string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", enc)
			_, _ = w.Write(opaque)
		}))
	}
	badFrame := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(bedrockInvokeStreamFrames(t, "a"))
		_, _ = w.Write(badFrame)
	}))
	defer broken.Close()
	strict := func(r *http.Request) *http.Request {
		cfg := &config.Config{}
		cfg.Guardrail.RulePack = "strict"
		return r.WithContext(withPinnedGeneration(r.Context(), &Generation{N: 1, Config: cfg}))
	}
	for _, tc := range []struct {
		name, enc, mode string
		stream, managed bool
		edit            func(*http.Request) *http.Request
		refused         bool
	}{
		{name: "unknown encoding, default tier", enc: "compress", mode: "action"},
		{name: "unknown layer in a stack, default tier", enc: "gzip, x-foo", mode: "action"},
		{name: "corrupt br, observe on a managed install", enc: "br", mode: "observe", managed: true},
		{name: "unknown encoding, strict tier observe", enc: "compress", mode: "observe", edit: strict},
		{name: "unknown encoding, strict tier action", enc: "compress", mode: "action", edit: strict, refused: true},
		{name: "unknown layer, managed action", enc: "gzip, x-foo", mode: "action", managed: true, refused: true},
		{name: "broken frame, default tier", stream: true, mode: "action"},
		{name: "broken frame, strict tier action", stream: true, mode: "action", edit: strict, refused: true},
		{name: "broken frame, managed action", stream: true, mode: "action", managed: true, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withManagedEnterprise(t, tc.managed)
			up, path := broken, stream
			if !tc.stream {
				up, path = encodedWith(tc.enc), invoke
				defer up.Close()
			}
			proxy, insp := bedrockPassthroughProxy(t, up)
			proxy.mode, proxy.cfg.Mode = tc.mode, tc.mode
			insp.setVerdict("completion", allowVerdict("mock"))
			req := bedrockRequest(up.URL, path)
			if tc.edit != nil {
				req = tc.edit(req)
			}
			rec := httptest.NewRecorder()
			log := captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
			want := "forwarded with an alert"
			if tc.refused {
				want = "refused"
			}
			if !strings.Contains(log, "[guardrail] reply not inspectable") || !strings.Contains(log, want) {
				t.Fatalf("log line missing (want %q): %s", want, log)
			}
			alerts, err := proxy.store.ListAlerts(50)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(fmt.Sprintf("%+v", alerts), uninspectableReplyFinding) {
				t.Fatalf("no %s telemetry row: %+v", uninspectableReplyFinding, alerts)
			}
			switch {
			case tc.stream && tc.refused:
				if bytes.Contains(rec.Body.Bytes(), badFrame) {
					t.Fatalf("refused stream reached the caller whole: %d bytes", rec.Body.Len())
				}
			case tc.stream:
				if !bytes.HasSuffix(rec.Body.Bytes(), badFrame) {
					t.Fatalf("stream not forwarded whole: %d bytes", rec.Body.Len())
				}
			case tc.refused:
				if bytes.Contains(rec.Body.Bytes(), opaque) || rec.Header().Get("Content-Encoding") != "" {
					t.Fatalf("refused reply forwarded: %d %v", rec.Code, rec.Header())
				}
			default:
				if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), opaque) || rec.Header().Get("Content-Encoding") != tc.enc {
					t.Fatalf("reply not forwarded as it came: %d %v %q", rec.Code, rec.Header(), rec.Body.Bytes())
				}
			}
		})
	}
}

// The S10 usage record reads the decoded reply on the passthrough.
func TestPassthroughUsageReadsDecodedReply(t *testing.T) {
	ch := installUsageEngine(t)
	plain := []byte(`{"id":"resp_1","object":"response","model":"gpt-4.1","usage":{"input_tokens":5,"output_tokens":2}}`)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(encodeReply(t, "br", plain))
	}))
	defer up.Close()
	proxy := newForwardingProxy(t, up.URL)
	rec := postPassthrough(t, proxy, up.URL, "/v1/responses", map[string]string{"Accept-Encoding": "br"}, mustJSON(t, map[string]any{"model": "gpt-4.1", "input": "hi"}))
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), plain) {
		t.Fatalf("reply %d %q", rec.Code, rec.Body.Bytes())
	}
	if got := nextUsage(t, ch); got.Usage.Input != 5 || got.Usage.Output != 2 {
		t.Fatalf("usage = %+v", got.Usage)
	}
}

// Route-only (S1): the client Accept-Encoding is not forwarded on either
// side of the credential boundary, streams stay streams, and the usage
// record reads a reply decoded when the transport left an encoding. The caller gets
// the bytes as they came (route-only does not inspect replies; the hooks
// decide every tool call).
func TestRouteOnlyAcceptEncodingAndDecodedUsage(t *testing.T) {
	ch := installUsageEngine(t)
	f := newRouteOnlyFixture(t)
	reply := []byte(`{"type":"message","model":"claude-haiku-4-5","usage":{"input_tokens":12,"output_tokens":3}}`)
	asks := func(r *http.Request) { r.Header.Set("Accept-Encoding", "br, gzip, zstd") }
	for _, enc := range []string{"gzip", "br", "zstd", "gzip, br"} {
		t.Run(enc, func(t *testing.T) {
			var asked string
			f.alt.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				asked = r.Header.Get("Accept-Encoding")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", enc)
				_, _ = w.Write(encodeReply(t, enc, reply))
			})
			body := messagesBody("quick question")
			body["stream"] = false
			rec := f.post(t, "/r/claudecode/v1/messages", body, asks)
			if rec.Code != 200 || asked != "gzip" {
				t.Fatalf("status %d, upstream asked for %q", rec.Code, asked)
			}
			got, ok := decodeReplyBody(rec.Header().Clone(), rec.Body.Bytes())
			if enc == "gzip" {
				got, ok = rec.Body.Bytes(), rec.Header().Get("Content-Encoding") == ""
			}
			if !ok || !bytes.Equal(got, reply) {
				t.Fatalf("caller reply %v %q", rec.Header(), rec.Body.Bytes())
			}
			if u := nextUsage(t, ch); u.Usage.Input != 12 || u.Usage.Output != 3 {
				t.Fatalf("usage = %+v", u.Usage)
			}
		})
	}
	// The agent own provider (no boundary) does not get it either, and the
	// stream arrives whole.
	rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), asks)
	if got := f.origHdr.Get("Accept-Encoding"); got != "gzip" || !strings.Contains(rec.Body.String(), "message_stop") {
		t.Fatalf("same-provider: upstream asked for %q, body %q", got, rec.Body.String())
	}
	_ = nextUsage(t, ch)
}

func TestDecodeReplyBodyRefusesTooManyLayers(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Encoding", "gzip, gzip, gzip, gzip, gzip")
	if out, ok := decodeReplyBody(h, []byte("x")); ok || string(out) != "x" || h.Get("Content-Encoding") == "" {
		t.Fatalf("five layers decoded: ok=%v", ok)
	}
}
