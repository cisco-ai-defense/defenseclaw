// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0696: a literal assignment can name the link program. The link and the
// later write must be judged by their resolved destinations on every route.
func TestR104GAP0696BoundProgramOrdinaryAndProtectedLinks(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	ordinary := filepath.Join(cwd, "ordinary.txt")
	if err := os.WriteFile(ordinary, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"ordinary bound ln", `L=/bin/ln; "$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"ordinary direct ln", `ln -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"protected bound ln", `L=/bin/ln; "$L" -sf ../.ssh/authorized_keys protected.link; echo marker >> protected.link`, true},
		{"protected direct ln", `ln -sf ../.ssh/authorized_keys protected.link; echo marker >> protected.link`, true},
		{"unknown ln program", `"$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, true},
		{"computed ln program", `L=$(printf ln); "$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Errorf("proof route %d blocked=%t, want %t", i, blocked, tc.block)
				}
			}
			installToolCallCorpusProfileConnector(t, "codex", "default")
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			cfg.Guardrail.BlockAt = "CRITICAL"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			args, err := json.Marshal(map[string]string{"command": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(),
				&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: "codex"},
				trustedActionRequest{Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true})
			if got := verdict.Action == guardrailActionBlock; got != tc.block {
				t.Errorf("native Codex action=%q findings=%v, want block=%t", verdict.Action, verdict.Findings, tc.block)
			}
		})
	}
}
