// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// GAP-0758: a standard user of a standalone enterprise Windows computer was
// told to run `defenseclaw skill info <name>`, a command that computer does
// not give them, both in the agent's block text and in the notification.
// The flags are the ones a running gateway sets (sidecar.go): a standalone
// enterprise gateway sets standaloneEnterpriseActive and not
// managedEnterpriseActive (Secure Client only), and the test reads the text
// through the two production callers, not agentAssetPolicySubject itself.
// A standalone Linux gateway and a per-user Windows gateway keep the hint.
func TestReasonDisabledSkillHintFitsTheManagedWindowsUser(t *testing.T) {
	previousGOOS := reasonDisplayGOOS
	previousManaged, previousStandalone := managedEnterpriseActive.Load(), standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		managedEnterpriseActive.Store(previousManaged)
		standaloneEnterpriseActive.Store(previousStandalone)
	})
	const reason = "ASSET-POLICY reason_code=runtime-disable source=runtime-disable asset_type=skill asset_name=epa-high-c"
	for _, tc := range []struct {
		name       string
		goos       string
		standalone bool
		info       bool
	}{
		{"standalone enterprise windows", "windows", true, false},
		{"standalone enterprise linux", "linux", true, true},
		{"per-user windows", "windows", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reasonDisplayGOOS = tc.goos
			managedEnterpriseActive.Store(false)
			standaloneEnterpriseActive.Store(tc.standalone)
			block := agentVerdictReason("block", reason, reason, redaction.SinkPolicyDefault)
			note := notificationDisplayReason(reason, redaction.SinkPolicyDefault)
			for _, got := range []string{block, note} {
				if !strings.Contains(got, "skill epa-high-c is disabled by security policy") {
					t.Fatalf("text does not name the disabled skill: %q", got)
				}
				if strings.Contains(got, "defenseclaw skill info") != tc.info {
					t.Fatalf("%q: want skill info hint %v", got, tc.info)
				}
			}
			if !tc.info && !strings.Contains(block, "your administrator can tell you why") {
				t.Fatalf("block text does not point at the administrator: %q", block)
			}
		})
	}
}
