// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"strings"
	"testing"
)

// GAP-0279: the server-error class has its own words in status and verify.
func TestCheckSignInServerUnavailableGAP0279(t *testing.T) {
	o := Observed{SignInIssuer: "https://kc.example/realms/dc", SignInRead: true, SignInCause: "issuer_unavailable", SignInSince: "2026-11-14T17:00:00Z"}
	if c := CheckSignInServerReach(o); c.Status != Fail || !strings.Contains(c.Message, "server errors") {
		t.Fatalf("%+v", c)
	}
}
