// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0262: a sign-in the gateway cannot check names the cause class and
// points at the administrator's doctor; other reasons keep their words.
func TestSignInServerCauseMessageGAP0262(t *testing.T) {
	for reason, want := range map[string]string{
		identity.IssuerUnreachable:  "cannot reach the sign-in server",
		identity.IssuerTLSName:      "certificate does not name",
		identity.IssuerTLSUntrusted: "not trusted",
		identity.IssuerMismatch:     "another issuer",
	} {
		msg := substrateAPIMessage(&api.Error{Status: 503, Reason: reason})
		if !strings.Contains(msg, want) || !strings.Contains(msg, reason) || !strings.Contains(msg, "doctor --cluster") {
			t.Errorf("%s: %q", reason, msg)
		}
	}
	if msg := substrateAPIMessage(&api.Error{Status: 403, Reason: "profile_not_allowed"}); strings.Contains(msg, "sign-in server") {
		t.Errorf("other reason: %q", msg)
	}
}
