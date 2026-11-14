// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"strings"
	"testing"
)

// GAP-0262: status and doctor --cluster show the gateway's own sign-in
// server check: a failing cause is a fail line, a healthy one passes, no
// OIDC issuer skips, and an unreadable gateway warns.
func TestCheckSignInServerReachGAP0262(t *testing.T) {
	base := Observed{SignInIssuer: "https://kc.example/realms/dc", SignInRead: true}
	if c := CheckSignInServerReach(base); c.Status != Pass {
		t.Fatalf("healthy %+v", c)
	}
	for _, cause := range []string{"issuer_unreachable", "issuer_tls_name", "issuer_tls_untrusted", "issuer_http", "issuer_mismatch", "issuer_keys"} {
		o := base
		o.SignInCause, o.SignInSince = cause, "2026-11-14T14:00:00Z"
		if c := CheckSignInServerReach(o); c.Status != Fail || !strings.Contains(c.Message, cause) || !strings.Contains(c.Message, "nobody can sign in") {
			t.Errorf("%s: %+v", cause, c)
		}
	}
	if c := CheckSignInServerReach(Observed{}); c.Status != Skip {
		t.Errorf("no OIDC issuer %+v", c)
	}
	o := base
	o.SignInRead, o.SignInNote = false, "no port-forward"
	if c := CheckSignInServerReach(o); c.Status != Warn {
		t.Errorf("unread %+v", c)
	}
}
