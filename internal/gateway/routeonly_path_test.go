// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http/httptest"
	"testing"
)

func TestRouteOnlyPathRules(t *testing.T) {
	for _, tc := range []struct {
		target    string
		claimed   bool
		ok        bool
		connector string
		native    string
	}{
		{"/r/claudecode/v1/messages", true, true, "claudecode", "/v1/messages"},
		{"/r/codex/v1/responses", true, true, "codex", "/v1/responses"},
		{"/r/claudecode/bedrock/model/arn%3Aaws%3Ax%2Fy/invoke", true, true, "claudecode", "/bedrock/model/arn%3Aaws%3Ax%2Fy/invoke"},
		{"/r/../api/v1/inspect", true, false, "", ""},
		{"/r/%2e%2e/api/v1/inspect", true, false, "", ""},
		{"/r/claudecode/../../api/v1/inspect", true, false, "", ""},
		{"/r/claudecode%2f..%2fapi", true, false, "", ""},
		{"/R/claudecode/v1/messages", true, false, "", ""},
		{"/r/Claude/v1/messages", true, false, "", ""},
		{"/r", true, false, "", ""},
		{"/r/claudecode", true, false, "", ""},
		{"//r/claudecode/v1/messages", false, false, "", ""},
		{"/api/v1/inspect", false, false, "", ""},
		{"/readiness", false, false, "", ""},
	} {
		r := httptest.NewRequest("POST", "http://127.0.0.1"+tc.target, nil)
		if got := routeOnlyClaim(r); got != tc.claimed {
			t.Errorf("%s: claim = %v, want %v", tc.target, got, tc.claimed)
			continue
		}
		c, n, ok := routeOnlyParse(r)
		if ok != tc.ok || c != tc.connector || n != tc.native {
			t.Errorf("%s: parse = %q %q %v, want %q %q %v", tc.target, c, n, ok, tc.connector, tc.native, tc.ok)
		}
	}
}
