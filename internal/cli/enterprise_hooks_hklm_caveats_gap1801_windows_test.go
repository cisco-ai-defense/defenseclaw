// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1801 (b), (c): enterprise hooks status names the caveats of a merging
// HKLM Claude Code value as warnings; a shadowing value keeps its own
// warning, and a non-merging value adds no caveat.
func TestGAP1801StatusWarnsOnHKLMMergeCaveats(t *testing.T) {
	previousStatus, previousCaveats := enterpriseHookClaudeOSAdminPolicyStatus, enterpriseHookClaudeOSAdminMergeCaveats
	t.Cleanup(func() {
		enterpriseHookClaudeOSAdminPolicyStatus, enterpriseHookClaudeOSAdminMergeCaveats = previousStatus, previousCaveats
	})
	merges := true
	enterpriseHookClaudeOSAdminPolicyStatus = func(connector.SetupOpts) (bool, bool, string) { return false, merges, "merge" }
	enterpriseHookClaudeOSAdminMergeCaveats = func(connector.SetupOpts) []string { return []string{"no client floor"} }
	rows := []enterpriseHookReconcileRow{{Connector: "claudecode", SID: "S-1-5-21-1-2-3-1001"}}
	var report enterpriseHookStatusReport
	enterpriseHooksReportClaudeHKLMPolicy(&report, rows)
	if len(report.Warnings) != 1 || !strings.HasPrefix(report.Warnings[0], "claude_policy_hklm_merge_caveat: no client floor") {
		t.Fatalf("warnings %q", report.Warnings)
	}
	merges = false
	report = enterpriseHookStatusReport{}
	enterpriseHooksReportClaudeHKLMPolicy(&report, rows)
	if len(report.Warnings) != 0 {
		t.Fatalf("a non-merging value got caveats: %q", report.Warnings)
	}
}
