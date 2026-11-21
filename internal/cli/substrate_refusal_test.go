// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0182: a refused create says why and gives the agent id, never only
// "the cluster refused this (actor refused)".
func TestGAP0182RefusedCreateMessageNamesTheCause(t *testing.T) {
	const uid = "91883e85-25b8-42f8-8f05-118879ec3270"
	msg := substrateAPIMessage(&api.Error{Status: 403, Reason: "actor_refused", Refusal: "sandbox.template_unverified",
		Detail: "template dc-eng/claude is not attested", Actor: "dc-eng/claude-ef3c8916", ActorUID: uid})
	for _, want := range []string{"template dc-eng/claude is not attested", "template unverified", uid, "dc-eng/claude-ef3c8916", "Nothing was started"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "(actor refused)") {
		t.Errorf("message %q is still the generic one", msg)
	}
	// An older gateway sends only the closed reason: still a clear sentence.
	if old := substrateAPIMessage(&api.Error{Status: 403, Reason: "actor_refused"}); !strings.Contains(old, "refused to start this agent") {
		t.Errorf("old gateway answer %q", old)
	}
}
