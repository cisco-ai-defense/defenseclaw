// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestProjectSkillPendingReasonNamesTheScanStep(t *testing.T) {
	previousGOOS := reasonDisplayGOOS
	previousManaged, previousStandalone := managedEnterpriseActive.Load(), standaloneEnterpriseActive.Load()
	t.Cleanup(func() {
		reasonDisplayGOOS = previousGOOS
		managedEnterpriseActive.Store(previousManaged)
		standaloneEnterpriseActive.Store(previousStandalone)
	})
	const reason = "ASSET-POLICY reason_code=project-skill-pending source=project-skill-pending asset_type=skill asset_name=daily-log-review connector=claudecode registry_status=disabled registry_configured=false surface=hook"
	for _, tc := range []struct {
		name, goos, command string
		standalone          bool
	}{
		{name: "per-user Linux", goos: "linux", command: "defenseclaw skill scan --path"},
		{name: "standalone Linux", goos: "linux", standalone: true, command: "defenseclaw-gateway scan skill"},
		{name: "standalone Windows", goos: "windows", standalone: true, command: "managed skill watcher"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reasonDisplayGOOS = tc.goos
			standaloneEnterpriseActive.Store(tc.standalone)
			managedEnterpriseActive.Store(false)
			got := agentVerdictReason("block", reason, redaction.ReasonForAgent(reason), redaction.SinkPolicyDefault)
			for _, want := range []string{"daily-log-review", "scan", tc.command, "retry"} {
				if !strings.Contains(got, want) {
					t.Fatalf("pending skill reason %q does not name %q", got, want)
				}
			}
			if strings.Contains(got, "Do not retry") || strings.Contains(got, "registry") {
				t.Fatalf("pending scan is worded as a permanent refusal: %q", got)
			}
		})
	}
	managedEnterpriseActive.Store(true)
	if got := agentVerdictReason("block", reason, redaction.ReasonForAgent(reason), redaction.SinkPolicyDefault); strings.Contains(got, "scan --path") || strings.Contains(got, "scan skill") {
		t.Fatalf("Secure Client received a standalone scan hint: %q", got)
	}
	managedEnterpriseActive.Store(false)
	if got := agentVerdictReason("block", reason, redaction.ReasonForSink(reason, redaction.SinkPolicyRedact), redaction.SinkPolicyRedact); strings.Contains(got, "scan --path") || strings.Contains(got, "scan skill") {
		t.Fatalf("explicit redaction was bypassed by a scan hint: %q", got)
	}
}
