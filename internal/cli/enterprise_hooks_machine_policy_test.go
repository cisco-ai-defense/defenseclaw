// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestApplyEnterpriseHookMachinePolicyPreferencesFollowsConfig(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })

	cfg = &config.Config{}
	opts := enterprisehooks.InstallOptions{ConnectorName: "cursor"}
	if err := applyEnterpriseHookMachinePolicyPreferences(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.ClaudeCodeAllowUnmanagedHooks {
		t.Fatal("default config opted out of the Claude managed-hooks-only lock")
	}
	if opts.CursorApprovedForeignHooks == nil || len(opts.CursorApprovedForeignHooks) != 0 {
		t.Fatalf("default allowlist = %#v, want authoritative empty list", opts.CursorApprovedForeignHooks)
	}

	digest := strings.Repeat("c", 64)
	cfg = &config.Config{
		ClaudeCode: config.AgentHookConfig{AllowUnmanagedHooks: true},
		ConnectorHooks: map[string]config.AgentHookConfig{
			"cursor": {ApprovedForeignHooks: []string{"sha256:" + strings.ToUpper(digest)}},
		},
	}
	opts = enterprisehooks.InstallOptions{ConnectorName: "cursor"}
	if err := applyEnterpriseHookMachinePolicyPreferences(&opts); err != nil {
		t.Fatal(err)
	}
	if !opts.ClaudeCodeAllowUnmanagedHooks {
		t.Fatal("claude_code.allow_unmanaged_hooks was not applied")
	}
	if len(opts.CursorApprovedForeignHooks) != 1 || opts.CursorApprovedForeignHooks[0] != digest {
		t.Fatalf("allowlist = %v", opts.CursorApprovedForeignHooks)
	}

	cfg = &config.Config{ConnectorHooks: map[string]config.AgentHookConfig{
		"cursor": {ApprovedForeignHooks: []string{"nope"}},
	}}
	if err := applyEnterpriseHookMachinePolicyPreferences(&enterprisehooks.InstallOptions{ConnectorName: "cursor"}); err == nil {
		t.Fatal("malformed allowlist accepted")
	}
}

// The Cursor allowlist belongs to Cursor targets only: a malformed Cursor
// entry must not stop install, verify or guardian repair of any other
// managed connector, and other connectors never carry the list.
func TestApplyEnterpriseHookMachinePolicyPreferencesScopesCursorAllowlist(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })

	cfg = &config.Config{
		ClaudeCode: config.AgentHookConfig{AllowUnmanagedHooks: true},
		ConnectorHooks: map[string]config.AgentHookConfig{
			"cursor": {ApprovedForeignHooks: []string{strings.Repeat("a", 63)}},
		},
	}
	for _, connector := range []string{"claudecode", "codex", "copilot", ""} {
		opts := enterprisehooks.InstallOptions{
			ConnectorName:              connector,
			CursorApprovedForeignHooks: []string{strings.Repeat("b", 64)},
		}
		if err := applyEnterpriseHookMachinePolicyPreferences(&opts); err != nil {
			t.Fatalf("%q target failed on a malformed Cursor allowlist: %v", connector, err)
		}
		if opts.CursorApprovedForeignHooks != nil {
			t.Fatalf("%q target carries the Cursor allowlist: %v", connector, opts.CursorApprovedForeignHooks)
		}
		if !opts.ClaudeCodeAllowUnmanagedHooks {
			t.Fatalf("%q target lost the Claude Code opt-out", connector)
		}
	}
	for _, connector := range []string{"cursor", " Cursor "} {
		err := applyEnterpriseHookMachinePolicyPreferences(&enterprisehooks.InstallOptions{ConnectorName: connector})
		if err == nil || !strings.Contains(err.Error(), "connector_hooks.cursor.approved_foreign_hooks") {
			t.Fatalf("%q target error = %v, want the malformed allowlist entry reported", connector, err)
		}
	}
}

func TestEnterpriseHookMachinePolicyWarningsReportClaudeOptOut(t *testing.T) {
	if warnings := enterpriseHookMachinePolicyWarnings(&config.Config{}, nil); len(warnings) != 0 {
		t.Fatalf("default warnings = %v", warnings)
	}
	optOut := &config.Config{ClaudeCode: config.AgentHookConfig{AllowUnmanagedHooks: true}}
	warnings := enterpriseHookMachinePolicyWarnings(optOut, nil)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "claude_code.allow_unmanaged_hooks") {
		t.Fatalf("opt-out warnings = %v", warnings)
	}
	// A published opt-out is reported even if the local config was changed
	// back and the guardian has not reconciled yet.
	rows := []enterpriseHookReconcileRow{{
		Connector: "claudecode",
		OK:        true,
		Result: &enterprisehooks.InstallResult{
			ClaudeManagedHooksOnly: enterprisehooks.ClaudeManagedHooksOnlyDisabledByAdmin,
		},
	}}
	if warnings := enterpriseHookMachinePolicyWarnings(&config.Config{}, rows); len(warnings) != 1 {
		t.Fatalf("published opt-out warnings = %v", warnings)
	}
	if warnings := enterpriseHookMachinePolicyWarnings(nil, nil); len(warnings) != 0 {
		t.Fatalf("nil config warnings = %v", warnings)
	}
}
