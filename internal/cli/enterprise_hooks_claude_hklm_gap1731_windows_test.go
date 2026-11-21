//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestGAP1731StatusReportsClaudeHKLMShadowing: status names an HKLM Claude
// Code policy that shadows the DefenseClaw drop-in (a warning naming the fix)
// and one that merges managed sources, only when Claude Code is enrolled.
func TestGAP1731StatusReportsClaudeHKLMShadowing(t *testing.T) {
	previous := enterpriseHookClaudeOSAdminPolicyStatus
	t.Cleanup(func() { enterpriseHookClaudeOSAdminPolicyStatus = previous })
	var gotVersion string
	verdict := struct {
		shadowed, merges bool
		detail           string
	}{true, false, `Claude Code HKLM has higher precedence; add "managedSourcesBehavior": "merge"`}
	enterpriseHookClaudeOSAdminPolicyStatus = func(opts connector.SetupOpts) (bool, bool, string) {
		gotVersion = opts.AgentVersion
		return verdict.shadowed, verdict.merges, verdict.detail
	}
	claudeRows := []enterpriseHookReconcileRow{
		{Connector: "codex", OK: true},
		{Connector: "claudecode", OK: false, Result: &enterprisehooks.InstallResult{AgentVersion: "2.1.250 (Claude Code)"}},
	}

	report := enterpriseHookStatusReport{}
	enterpriseHooksReportClaudeHKLMPolicy(&report, claudeRows)
	if !report.ClaudePolicyShadowedByHKLM || report.ClaudePolicyHKLMDetail != verdict.detail || gotVersion != "2.1.250 (Claude Code)" {
		t.Fatalf("shadowed report = %+v (version %q)", report, gotVersion)
	}
	if len(report.Warnings) != 1 || !strings.HasPrefix(report.Warnings[0], "claude_policy_shadowed_by_hklm: ") {
		t.Fatalf("warnings = %q", report.Warnings)
	}

	verdict.shadowed, verdict.merges, verdict.detail = false, true, "merge"
	report = enterpriseHookStatusReport{}
	enterpriseHooksReportClaudeHKLMPolicy(&report, claudeRows)
	if report.ClaudePolicyShadowedByHKLM || !report.ClaudePolicyHKLMManagedSourcesMerge || len(report.Warnings) != 0 {
		t.Fatalf("merge report = %+v", report)
	}

	verdict.shadowed = true
	report = enterpriseHookStatusReport{}
	enterpriseHooksReportClaudeHKLMPolicy(&report, claudeRows[:1])
	if report.ClaudePolicyShadowedByHKLM || len(report.Warnings) != 0 {
		t.Fatalf("report without an enrolled Claude Code target = %+v", report)
	}
}
