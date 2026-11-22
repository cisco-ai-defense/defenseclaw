// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-1745: the two connector-switch errors carry the cause of
// each connector that kept the switch from finishing.
func TestConnectorSwitchErrorsCarryTheCauses(t *testing.T) {
	why := map[string]string{"kiro": "kiro cleanup incomplete: /home/u/.kiro/agents/mine.json is not a JSON object"}

	refusal := connectorSwitchRefusal("kiro", "codex", []string{"kiro"}, why).Error()
	for _, want := range []string{"refuse connector switch kiro to codex", "without complete prior-registration rollback authority: kiro (", "mine.json"} {
		if !strings.Contains(refusal, want) {
			t.Errorf("refusal %q lacks %q", refusal, want)
		}
	}
	if bare := connectorSwitchRefusal("kiro", "codex", nil, nil).Error(); strings.HasSuffix(bare, ":") || strings.Contains(bare, "(") {
		t.Errorf("a refusal with no named connector carries a cause suffix: %q", bare)
	}

	restored := connectorSwitchTeardownFailure("kiro", "codex", []string{"kiro"}, why, nil).Error()
	if !strings.Contains(restored, "teardown failed: kiro (kiro cleanup incomplete") || !strings.HasSuffix(restored, "restored the prior connector registration") {
		t.Errorf("restored: %q", restored)
	}

	rollback := errors.New("reapply the hook lock: access denied")
	incomplete := connectorSwitchTeardownFailure("kiro", "codex", []string{"kiro"}, why, rollback)
	if !strings.Contains(incomplete.Error(), "teardown failed: kiro (kiro cleanup incomplete") ||
		!strings.Contains(incomplete.Error(), "prior-registration rollback incomplete: reapply the hook lock: access denied") ||
		!errors.Is(incomplete, rollback) {
		t.Errorf("rollback incomplete: %q", incomplete)
	}
}
