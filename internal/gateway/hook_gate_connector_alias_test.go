// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestHookGatesReadAnAliasedPrimaryAsTheConnector pins GAP-1971 and
// GAP-1972: activeConnector folds guardrail.connector (claude-code,
// claude_code, any case) and installs that connector's hooks, so the hook
// gates must fold it the same way. Before, they compared the raw value and
// answered every Claude Code hook call allow without a scan.
func TestHookGatesReadAnAliasedPrimaryAsTheConnector(t *testing.T) {
	cases := []struct {
		primary, canonical string
	}{
		{"claude-code", "claudecode"},
		{"claude_code", "claudecode"},
		{"Claude-Code", "claudecode"},
		{" CLAUDECODE ", "claudecode"},
		{"Codex", "codex"},
		{" codex ", "codex"},
	}
	for _, tc := range cases {
		t.Run(tc.primary, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Connector = tc.primary
			api := &APIServer{scannerCfg: cfg}
			if got := api.claudeCodeEnabled(); got != (tc.canonical == "claudecode") {
				t.Errorf("claudeCodeEnabled() = %v for guardrail.connector %q", got, tc.primary)
			}
			if got := api.codexEnabled(); got != (tc.canonical == "codex") {
				t.Errorf("codexEnabled() = %v for guardrail.connector %q", got, tc.primary)
			}
			if !api.agentHookEnabled(t.Context(), tc.canonical) {
				t.Errorf("agentHookEnabled(%q) = false for guardrail.connector %q", tc.canonical, tc.primary)
			}
			if api.agentHookEnabled(t.Context(), "cursor") {
				t.Errorf("agentHookEnabled(cursor) = true for guardrail.connector %q", tc.primary)
			}
		})
	}
}
