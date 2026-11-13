// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package refusalpipe

import "testing"

func TestRoutingReadPaths(t *testing.T) {
	for _, ok := range []string{"/api/v1/routing/effective", "/api/v1/routing/effective?recent=20", "/api/v1/routing/budgets", "/api/v1/routing/explain/req-123"} {
		msg, err := RoutingRequest(ok)
		if err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
		if path, valid := ParseRoutingRequest(msg); !valid || path != ok {
			t.Fatalf("%s round trip: %q %v", ok, path, valid)
		}
	}
	for _, bad := range []string{"/api/v1/routing/test", "/api/v1/usage", "/api/v1/routing/effective?user=x", "/api/v1/routing/explain/../x", "/api/v1/routing/explain/..",
		"/api/v1/routing/explain/a%2Fb", "http://h/api/v1/routing/budgets", "/api/v1/routing/budgets?x=1", "/api/v1/routing/"} {
		if _, err := RoutingRequest(bad); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	if _, ok := ParseRoutingRequest([]byte(`{"request":"own-status"}`)); ok {
		t.Fatal("another request kind is not a routing read")
	}
	status, body, err := ParseRoutingAnswer(EncodeRoutingAnswer(403, []byte("not json")))
	if err != nil || status != 403 || string(body) != "{}" {
		t.Fatalf("answer: %d %s %v", status, body, err)
	}
}
