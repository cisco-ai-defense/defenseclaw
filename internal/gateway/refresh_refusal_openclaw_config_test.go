// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0907: an openclaw.json that is not valid JSON5 is fixed in the file and
// the gateway restarted. No agent holds it open and an upgrade does not change
// it, so the next step must not say so.
func TestRefreshRefusalForAnUnreadableOpenClawConfigNamesTheFileFixNotAnOpenAgent(t *testing.T) {
	err := fmt.Errorf("connector openclaw setup failed: %w",
		fmt.Errorf("openclaw extension install: %w", fmt.Errorf("patch openclaw.json: %w", connector.ErrOpenClawConfigSyntax)))
	got := refreshRefusalNextStep(err)
	if !strings.Contains(got, "defenseclaw-gateway restart") {
		t.Fatalf("next step %q does not name the restart", got)
	}
	for _, unwanted := range []string{"close the agent", "defenseclaw upgrade"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("next step %q wrongly says %q", got, unwanted)
		}
	}
	if other := refreshRefusalNextStep(fmt.Errorf("settings busy")); !strings.Contains(other, "close the agent holding its settings") {
		t.Fatalf("an unrelated refusal lost its default next step: %q", other)
	}
}
