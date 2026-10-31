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

// GAP-0071: a machine-wide OpenCode V1 gives one warning with the count of
// users, not one per account; a copy under one account's home keeps its own
// line; coverage_complete stays false and every account is still audited.
func TestMachineWideOpenCodeV1IsOneWarningWithTheUserCount(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	machine := "/opt/dc-agents/lib/node_modules/opencode-ai"
	var agents []enterprisehooks.UnprotectedAgent
	for i, user := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
		uid := 1001 + i
		agents = append(agents, enterprisehooks.UnprotectedAgent{User: user, UID: &uid, Connector: "opencode", Version: "1.18.34", InstallPath: machine,
			Code: enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is not verified against a known hook contract"})
	}
	uid := 1100
	agents = append(agents, enterprisehooks.UnprotectedAgent{User: "gina", UID: &uid, Connector: "opencode", Version: "1.18.34",
		InstallPath: "/home/gina/.npm-global/lib/node_modules/opencode-ai",
		Code:        enterprisehooks.UnprotectedCodeHookContractUnverified, Reason: "version 1.18.34 is not verified against a known hook contract"})
	data, err := enterprisehooks.MarshalUnprotectedAgents(agents)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	audited := 0
	h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { audited++; return nil }
	writeFreshLedger(t, h)

	result := h.run(Options{Action: ActionStatus})
	requireOK(t, result)
	var lines []string
	for _, m := range result.Warnings {
		if m.Code == enterprisehooks.UnprotectedCodeOpenCodeV1 {
			lines = append(lines, m.Message)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("want one machine-wide line and one per-user line, got %d: %q", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"machine-wide copy and is not protected for 6 users", machine, "for user gina is not protected"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings lack %q: %q", want, lines)
		}
	}
	// status-v2 GAP-0005: the machine-wide line counts the accounts and names
	// none of them; the per-account line of a copy in one home is unchanged.
	for _, line := range lines {
		if !strings.Contains(line, "machine-wide copy") {
			continue
		}
		for _, user := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
			if strings.Contains(line, user) {
				t.Fatalf("the machine-wide line names account %s: %q", user, line)
			}
		}
		if !strings.Contains(line, "`enterprise policy show --json` lists them") {
			t.Fatalf("the machine-wide line does not say where the accounts are listed: %q", line)
		}
	}
	if result.CoverageComplete || result.SecurityComplete {
		t.Fatalf("coverage=%v security=%v with OpenCode V1 installed", result.CoverageComplete, result.SecurityComplete)
	}
	if audited != 7 {
		t.Fatalf("every account must still be audited: %d of 7", audited)
	}
}
