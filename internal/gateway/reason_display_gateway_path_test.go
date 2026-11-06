// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// The administrator the user is told to ask runs the gateway by its absolute
// path: the standalone packages put it on no PATH (cowork-1-0-8 GAP-0081).
func TestProjectSkillPendingHintNamesTheManagedGatewayByItsFullPath(t *testing.T) {
	previousGOOS, previousStandalone := reasonDisplayGOOS, standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		standaloneEnterpriseActive.Store(previousStandalone)
	})
	standaloneEnterpriseActive.Store(true)
	const reason = "ASSET-POLICY reason_code=project-skill-pending source=project asset_type=skill asset_name=demo"
	for goos, gateway := range map[string]string{
		"linux":  "/opt/defenseclaw/bin/defenseclaw-gateway",
		"darwin": "/opt/cisco/defenseclaw/bin/defenseclaw-gateway",
	} {
		reasonDisplayGOOS = goos
		got := agentProjectSkillPendingSentence(reason)
		if !strings.Contains(got, "run `"+gateway+" scan skill PATH`") || strings.Contains(got, "`defenseclaw-gateway") {
			t.Errorf("%s: %q", goos, got)
		}
	}
}
