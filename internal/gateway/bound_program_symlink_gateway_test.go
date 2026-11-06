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
		{"unknown ln program", `"$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"computed ln program", `L=$(printf ln); "$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if blocked != tc.block {
					t.Errorf("proof route %d blocked=%t, want %t", i, blocked, tc.block)
				}
			}
			// rel-1-0-6:GAP-0675: the default pack alerts on the protected
			// write and strict blocks it; the ordinary rows are allowed in both.
			for _, posture := range []string{"default", "strict"} {
				installToolCallCorpusProfileConnector(t, "codex", posture)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "codex"
				cfg.Guardrail.BlockAt = "CRITICAL"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
				args, err := json.Marshal(map[string]string{"command": tc.command})
				if err != nil {
					t.Fatal(err)
				}
				input := actionfacts.Input{Tool: "Bash", Args: args, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(),
					&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: "codex"},
					trustedActionRequest{Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true})
				want := guardrailActionAllow
				if tc.block {
					want = map[string]string{"default": guardrailActionAlert, "strict": guardrailActionBlock}[posture]
				}
				if verdict.Action != want {
					t.Errorf("%s native Codex action=%q findings=%v, want %q", posture, verdict.Action, verdict.Findings, want)
				}
			}
		})
	}
}
