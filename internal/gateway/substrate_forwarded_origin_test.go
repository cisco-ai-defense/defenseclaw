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

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// T-PF6 (B3.2): `substrate port` serves the agent's app at
// http://127.0.0.1:LOCAL, a localhost Origin the laptop gateway trusts. Such
// a page must still not change anything on the laptop gateway: a mutating
// request needs X-DefenseClaw-Client, which a page can set cross-origin only
// after a CORS preflight the gateway never allows, and a same-site fetch is
// refused by Sec-Fetch-Site. The same holds for the substrate attach route.
func TestForwardedOriginCannotPostLocalAPI(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	for name, h := range map[string]http.Handler{"api": csrfProtect(next), "attach": substrateAttachCSRF(next)} {
		for _, tc := range []struct {
			what string
			hdr  map[string]string
		}{
			{"form post, no client tag", map[string]string{"Origin": "http://localhost:3000", "Content-Type": "text/plain"}},
			{"json post, no client tag", map[string]string{"Origin": "http://127.0.0.1:3000", "Content-Type": "application/json"}},
		} {
			reached = false
			req := httptest.NewRequest(http.MethodPost, "/api/v1/policy/reload", strings.NewReader(`{}`))
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if reached || rec.Code != http.StatusForbidden {
				t.Errorf("%s, %s: status %d reached=%v; want 403 before the handler", name, tc.what, rec.Code, reached)
			}
		}
	}
	// A same-site browser fetch from the forwarded page (Sec-Fetch-Site:
	// same-site) is refused on the API even with a client tag.
	reached = false
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy/reload", strings.NewReader(`{}`))
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("X-DefenseClaw-Client", "page")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	csrfProtect(next).ServeHTTP(rec, req)
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("same-site fetch: status %d reached=%v", rec.Code, reached)
	}
}
