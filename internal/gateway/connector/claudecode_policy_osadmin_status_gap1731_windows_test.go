//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// TestGAP1731HKLMRawGateAndStatus covers the raw-string gate the enterprise
// installer calls after it authenticates the HKLM key, and the status view.
func TestGAP1731HKLMRawGateAndStatus(t *testing.T) {
	opts, _, setHKLM, _ := gap1731Fixture(t)
	opts.AgentVersion = "2.1.250"
	label := `HKLM Settings policy (HKLM\SOFTWARE\Policies\ClaudeCode\Settings)`
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"managedSourcesBehavior":"merge","permissions":{"deny":["Bash(curl:*)"]}}`, label, opts); err != nil {
		t.Fatalf("raw merge policy refused: %v", err)
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`  `, label, opts); err != nil {
		t.Fatalf("blank policy refused: %v", err)
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"model":"x"}`, label, opts); err == nil || !strings.Contains(err.Error(), "managedSourcesBehavior") {
		t.Fatalf("raw shadowing policy = %v, want the merge fix", err)
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"model":`, label, opts); err == nil {
		t.Fatal("malformed raw policy admitted")
	}

	setHKLM(map[string]interface{}{"model": "x"})
	if shadowed, merges, detail := ClaudeCodeOSAdminPolicyStatus(opts); !shadowed || merges || !strings.Contains(detail, "managedSourcesBehavior") {
		t.Fatalf("shadowing status = (%v, %v, %q)", shadowed, merges, detail)
	}
	setHKLM(map[string]interface{}{"managedSourcesBehavior": "merge", "model": "x"})
	if shadowed, merges, detail := ClaudeCodeOSAdminPolicyStatus(opts); shadowed || !merges || !strings.Contains(detail, "merge") {
		t.Fatalf("merge status = (%v, %v, %q)", shadowed, merges, detail)
	}
	setHKLM(nil)
	if shadowed, merges, detail := ClaudeCodeOSAdminPolicyStatus(opts); shadowed || merges || detail != "" {
		t.Fatalf("no-HKLM status = (%v, %v, %q)", shadowed, merges, detail)
	}
	statusOpts := SetupOpts{ManagedEnterprise: true}
	ours := map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{
		"matcher": "*",
		"hooks": []interface{}{map[string]interface{}{
			"type":    "command",
			"command": `"C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe" claudecode`,
		}},
	}}}
	setHKLM(map[string]interface{}{"hooks": ours, "model": "x"})
	if shadowed, _, detail := ClaudeCodeOSAdminPolicyStatus(statusOpts); shadowed || !strings.Contains(detail, "own hooks") {
		t.Fatalf("status of a hooks table naming the DefenseClaw hook, without an executable = (%v, %q), want deferred to the guardian rows", shadowed, detail)
	}
	// A hooks table that names no DefenseClaw hook cannot be the matrix, so it
	// is not deferred: status reports it as shadowing (GAP-1801 (a)).
	setHKLM(map[string]interface{}{"hooks": map[string]interface{}{}, "model": "x"})
	if shadowed, _, detail := ClaudeCodeOSAdminPolicyStatus(statusOpts); !shadowed || !strings.Contains(detail, "managedSourcesBehavior") {
		t.Fatalf("status of a hooks table naming no DefenseClaw hook = (%v, %q), want shadowed with the merge fix", shadowed, detail)
	}
}
