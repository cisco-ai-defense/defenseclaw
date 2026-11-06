// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6 GAP-0380, as on the 14-account managed RHEL host (dc-float2):
// a machine-wide OpenCode V1 under /opt/dc-agents is one
// opencode_v1_unprotected line, and the accounts whose own run of
// /opt/dc-agents/bin/opencode printed no version add no
// hook_contract_unverified line each; the machine-wide line counts them. A
// different per-account problem still has its own line, and coverage and
// security stay incomplete for both codes.
func TestMachineWideOpenCodeV1FoldsTheLaunchersUnversionedAccounts(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			machine := "/opt/dc-agents/lib/node_modules/opencode-ai"
			launcher := "/opt/dc-agents/bin/opencode"
			var agents []enterprisehooks.UnprotectedAgent
			for i := 0; i < 14; i++ {
				uid := 2001 + i
				user := fmt.Sprintf("os%04d", 1200+i)
				agents = append(agents, enterprisehooks.UnprotectedAgent{User: user, UID: &uid, Connector: "opencode", Version: "1.18.34",
					InstallPath: machine, Code: enterprisehooks.UnprotectedCodeHookContractUnverified,
					Reason: "version 1.18.34 is not verified against a known hook contract"})
				if i < 11 {
					agents = append(agents, enterprisehooks.UnprotectedAgent{User: user, UID: &uid, Connector: "opencode",
						Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
						Reason: enterprisehooks.UnixAgentUnversionedReasonPrefix + launcher + enterprisehooks.UnixAgentUnversionedContractSuffix})
				}
			}
			uid := 3001
			agents = append(agents, enterprisehooks.UnprotectedAgent{User: "realproblem", UID: &uid, Connector: "opencode",
				Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
				Reason: enterprisehooks.UnixAgentUnversionedReasonPrefix + "/home/realproblem/.local/bin/opencode" + enterprisehooks.UnixAgentUnversionedContractSuffix})
			data, err := h.marshalCompletedScan(agents)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
				t.Fatal(err)
			}
			writeFreshLedger(t, h)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				v1 := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeOpenCodeV1)
				var unverified []string
				for _, w := range result.Warnings {
					if w.Code == enterprisehooks.UnprotectedCodeHookContractUnverified && strings.Contains(w.Message, "opencode") {
						unverified = append(unverified, w.Message)
					}
				}
				if strings.Count(v1, "machine-wide copy") != 1 || !strings.Contains(v1, "not protected for 14 users") ||
					!strings.Contains(v1, "For 11 of these users the version check of "+launcher) {
					t.Fatalf("%s %s: want one machine-wide line counting 14 users and the 11 unversioned ones: %q", platform, action, v1)
				}
				if len(unverified) != 1 || !strings.Contains(unverified[0], "realproblem") {
					t.Fatalf("%s %s: want only the private copy's hook_contract_unverified line, got %d: %q", platform, action, len(unverified), unverified)
				}
				roll := messagesOf(result.Warnings, "security_incomplete")
				for _, code := range []string{enterprisehooks.UnprotectedCodeOpenCodeV1, enterprisehooks.UnprotectedCodeHookContractUnverified} {
					if !strings.Contains(roll, code) {
						t.Fatalf("%s %s: the roll-up no longer names %s: %q", platform, action, code, roll)
					}
				}
				if result.CoverageComplete || result.SecurityComplete {
					t.Fatalf("%s %s: coverage=%v security=%v", platform, action, result.CoverageComplete, result.SecurityComplete)
				}
			}
			// The administrator's record keeps every per-account entry.
			kept, err := enterprisehooks.ParseUnprotectedAgents([]byte(h.read(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))))
			if err != nil || len(kept) != len(agents) {
				t.Fatalf("the unprotected-agents record changed: %d entries, want %d (%v)", len(kept), len(agents), err)
			}
		})
	}
}
