// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestGAP0429BlockReasonCarriesNoMatchedValue: the reason of a local-pattern
// verdict is the text of the block message the agent and the user read. A
// secret or PII value the legacy detectors matched is named there by its
// finding, never quoted, or a blocked reply carries the secret it withheld
// (rel-1-0-10:GAP-0429: a raw-forward block showed the assignment it
// blocked). The findings keep the match for the audit boundary.
func TestGAP0429BlockReasonCarriesNoMatchedValue(t *testing.T) {
	r := func(alphabet string, n int) string { return gap0429Random(t, alphabet, n) }
	cases := []struct{ name, value, text string }{
		{"aws", "", gap0429Label("aws_secret", "_access_key = ")},
		{"token", "", gap0429Label("tok", "en: ")},
		{"api-key", "", gap0429Label("api", "_key = ")},
		{"bearer", "", gap0429Label("Authorization: ", "Bearer ")},
		{"password", "", gap0429Label("pass", "word = ")},
	}
	for _, c := range cases {
		value := r(gap0429Alnum, 40)
		text := "The build passed on the second run.\n" + c.text + value + " is the value.\n"
		v := scanLocalPatterns("completion", text)
		if v == nil || v.Action == "allow" {
			t.Errorf("%s: no verdict (the probe needs a match): %+v", c.name, v)
			continue
		}
		if strings.Contains(v.Reason, value[:16]) || strings.Contains(blockMessage("", "completion", v.Reason), value[:16]) {
			t.Errorf("%s: the reason quotes the matched value (%d bytes of reason)", c.name, len(v.Reason))
		}
		found := false
		for _, f := range v.Findings {
			found = found || strings.Contains(f, value[:16])
		}
		if !found && !strings.Contains(strings.Join(v.Findings, ","), "SEC-") {
			t.Errorf("%s: the findings lost the match: %d findings", c.name, len(v.Findings))
		}
	}
}
