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
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// jsonEscape writes every character of s as a \u escape.
func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "\\u%04x", r)
	}
	return b.String()
}

// percentAll percent-encodes every byte of s.
func percentAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// TestDLPOneDecodeSet is GAP-0064: URL, headers and bodies are scanned in
// the same forms, so a percent-encoded secret in a plain header and a
// \u-escaped one in a body are found.
func TestDLPOneDecodeSet(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	enc := percentAll(fakeGitHubToken)
	enc2 := url.QueryEscape(enc)
	for _, hv := range []string{enc, enc2} {
		v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/", "x-data", "v="+hv))
		if v.Allow || v.Category != findSecretInHeader {
			t.Errorf("encoded secret in a header: %+v", v)
		}
	}
	r := req("eng-web", "POST", "mcp.example.com", "/mcp")
	for name, body := range map[string]string{
		"u-escaped shape":         `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"` + jsonEscape(fakeAWSKey) + `"}}}`,
		"u-escaped actor secret":  `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"` + jsonEscape("s3cret-db-value-123") + `"}}}`,
		"percent-encoded in json": `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"u":"https://x/?t=` + enc + `"}}}`,
		"form body":               "k=" + enc,
	} {
		v := h.eng.DecideBody(ctx, r, Verdict{Allow: true, Profile: "eng"}, []byte(body))
		if v.Allow || (v.Category != findSecretInBody && v.Category != findActorSecret) {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// Benign escapes stay allowed.
	if v := h.eng.DecideBody(ctx, r, Verdict{Allow: true}, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":{"k":"café 100%"}}}`)); !v.Allow {
		t.Errorf("benign body: %+v", v)
	}
}
