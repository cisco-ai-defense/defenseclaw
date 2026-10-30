// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-6 GAP-0037: OpenCode V1 loads the V2 plugin the managed install
// puts in machine policy and runs every call unchecked. While the enumerator
// finds it, ensure, status and verify warn that OpenCode is NOT protected,
// with the remedy, and coverage_complete is false because of it; nothing is
// blocked or removed (balanced defaults), so verify still exits 0.
func TestOpenCodeV1MakesManagedStatusVerifyAndEnsureIncomplete(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			uid := 1001
			install := "/opt/dc-agents/lib/node_modules/opencode-ai"
			// As the enumerator writes it: the separate-copy scan names the V1
			// package with the generic contract reason.
			data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
				User: "alice", UID: &uid, Connector: "opencode", Version: "1.18.34", InstallPath: install,
				Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
				Reason: "version 1.18.34 is not verified against a known hook contract",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
				t.Fatal(err)
			}
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			writeFreshLedger(t, h)
			for _, action := range []string{ActionStatus, ActionVerify, ActionEnsure} {
				result := h.run(Options{Action: action})
				requireOK(t, result)
				message := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeOpenCodeV1)
				for _, want := range []string{"opencode 1.18.34 at " + install + " for user alice is not protected: it is OpenCode V1",
					"OpenCode is NOT protected until OpenCode V2 (@opencode/cli 2.x) is installed", "npm install -g @opencode/cli@2"} {
					if !strings.Contains(message, want) {
						t.Fatalf("%s %s: warning %q lacks %q (warnings %+v)", platform, action, message, want, result.Warnings)
					}
				}
				if result.CoverageComplete || result.SecurityComplete {
					t.Fatalf("%s %s: coverage=%v security=%v with OpenCode V1 installed", platform, action, result.CoverageComplete, result.SecurityComplete)
				}
				if roll := messagesOf(result.Warnings, "security_incomplete"); !strings.Contains(roll, "coverage_complete is false because of: ") ||
					!strings.Contains(roll[strings.Index(roll, "coverage_complete is false"):], enterprisehooks.UnprotectedCodeOpenCodeV1) {
					t.Fatalf("%s %s: the roll-up does not name OpenCode V1 for coverage: %q", platform, action, roll)
				}
				if len(result.Errors) != 0 || result.ExitCode != 0 {
					t.Fatalf("%s %s: OpenCode V1 must warn, not fail: %+v", platform, action, result.Errors)
				}
			}
			if len(audited) != 2 || audited[0].Connector != "opencode" || audited[0].InstallPath != install || audited[0].Version != "1.18.34" {
				t.Fatalf("status and verify must audit the V1 copy once each: %+v", audited)
			}

			// OpenCode V2 installed and V1 removed: the next scan publishes an
			// empty record, and coverage is complete again for OpenCode.
			empty, _ := enterprisehooks.MarshalUnprotectedAgents(nil)
			if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), empty, 0o600); err != nil {
				t.Fatal(err)
			}
			status := h.run(Options{Action: ActionStatus})
			if messagesOf(status.Warnings, enterprisehooks.UnprotectedCodeOpenCodeV1) != "" ||
				strings.Contains(messagesOf(status.Warnings, "security_incomplete"), enterprisehooks.UnprotectedCodeOpenCodeV1) {
				t.Fatalf("%s: OpenCode V1 is still reported after it was removed: %+v", platform, status.Warnings)
			}
		})
	}
}
