// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"strings"
	"testing"
	"unicode/utf16"
)

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zl(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// TestBodyDecodingGAP0044 is GAP-0044: a tools/call body the origin can
// read (gzip, deflate, a UTF-8 BOM) is judged; one the callout can't read
// (another encoding, a non-UTF-8 charset, UTF-16, NaN, not JSON) is refused
// when closed and an alert when open, never a silent allow.
func TestBodyDecodingGAP0044(t *testing.T) {
	ctx := context.Background()
	call := mcpCall("drop_tables")
	secret := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"` + fakeAWSKey + `"}}}`)
	nan := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"n":NaN}}}`)
	bomb := gz(t, make([]byte, 2<<20))
	cases := []struct {
		name, host, encoding, ctype string
		body                        []byte
		// closed is the closed-mode category ("" = allowed), judged whether
		// the judge saw the call.
		closed string
		judged bool
	}{
		{"gzip tools/call", "mcp.example.com", "gzip", "application/json", gz(t, call), CategoryMCPToolBlocked, true},
		{"x-gzip tools/call", "mcp.example.com", "x-gzip", "application/json", gz(t, call), CategoryMCPToolBlocked, true},
		{"deflate tools/call", "mcp.example.com", "deflate", "application/json", zl(t, call), CategoryMCPToolBlocked, true},
		{"gzip, identity", "mcp.example.com", "gzip, identity", "application/json", gz(t, call), CategoryMCPToolBlocked, true},
		{"bom tools/call", "mcp.example.com", "", "application/json", append([]byte("\xef\xbb\xbf"), call...), CategoryMCPToolBlocked, true},
		{"gzip secret", "mcp.example.com", "gzip", "application/json", gz(t, secret), findSecretInBody, false},
		{"gzip secret, listed host", "upload.example.org", "gzip", "application/octet-stream", gz(t, secret), findSecretInBody, false},
		{"binary, listed host", "upload.example.org", "", "application/octet-stream", []byte{0x00, 0xff, 0x10}, "", false},
		{"brotli", "mcp.example.com", "br", "application/json", call, CategoryBodyUninspected, false},
		{"three encodings", "mcp.example.com", "gzip, gzip, gzip", "application/json", call, CategoryBodyUninspected, false},
		{"corrupt gzip", "mcp.example.com", "gzip", "application/json", []byte("not gzip"), CategoryBodyUninspected, false},
		{"utf-16 charset", "mcp.example.com", "", "application/json; charset=utf-16", utf16le(string(call)), CategoryBodyUninspected, false},
		{"utf-16 without charset", "mcp.example.com", "", "application/json", utf16le(string(call)), CategoryBodyUninspected, false},
		{"NaN argument", "mcp.example.com", "", "application/json", nan, CategoryBodyUninspected, false},
		{"not json", "mcp.example.com", "", "text/plain", []byte("tools/call drop_tables"), CategoryBodyUninspected, false},
	}
	for _, mode := range []string{FailureClosed, FailureOpen} {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				h := newHarness(t, func(cfg *Config, _ *Options) { cfg.FailureMode = mode })
				h.judge.block = true
				r := req("eng-web", "POST", c.host, "/mcp", "content-type", c.ctype)
				r.ContentType = c.ctype
				if c.encoding != "" {
					r.Headers = append(r.Headers, Header{"content-encoding", c.encoding})
				}
				v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, c.body)
				if got := len(h.judge.calls) > 0; got != c.judged {
					t.Fatalf("judged %v, want %v: %+v", got, c.judged, v)
				}
				want := c.closed
				if mode == FailureOpen && want == CategoryBodyUninspected {
					// Open: allowed, with the alert.
					if !v.Allow || !v.Alert || !strings.Contains(strings.Join(v.Findings, ","), "body_unreadable:") {
						t.Fatalf("open: %+v", v)
					}
					return
				}
				if want == "" {
					if !v.Allow {
						t.Fatalf("refused: %+v", v)
					}
					return
				}
				if v.Allow || v.Category != want || v.Reason == "" {
					t.Fatalf("got %+v, want refusal %s", v, want)
				}
			})
		}
	}
	// A gzip bomb is over the cap, not decoded to the end.
	h := newHarness(t, nil)
	r := req("eng-web", "POST", "mcp.example.com", "/mcp")
	r.Headers = append(r.Headers, Header{"content-encoding", "gzip"})
	if v := h.eng.DecideBody(ctx, r, Verdict{Allow: true}, bomb); v.Allow || !v.BodyOverCap {
		t.Fatalf("gzip bomb: %+v", v)
	}
}
