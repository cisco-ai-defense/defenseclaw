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
	var opts enterprisehooks.InstallOptions
	if err := applyEnterpriseHookMachinePolicyPreferences(&opts); err != nil {
		t.Fatal(err)
	}
	if opts.ClaudeCodeAllowUnmanagedHooks {
		t.Fatal("default config opted out of the Claude managed-hooks-only lock")
	}
	cfg = &config.Config{
		ClaudeCode: config.AgentHookConfig{AllowUnmanagedHooks: true},
	}
	opts = enterprisehooks.InstallOptions{}
	if err := applyEnterpriseHookMachinePolicyPreferences(&opts); err != nil {
		t.Fatal(err)
	}
	if !opts.ClaudeCodeAllowUnmanagedHooks {
		t.Fatal("claude_code.allow_unmanaged_hooks was not applied")
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
