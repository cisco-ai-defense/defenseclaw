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
	// Route 2 is the protected-home Codex hook. Its client link proof cannot
	// tell whether a computed program makes a link, so it keeps the later
	// write unproved. That is the link proof's own class, filed separately.
	codexHookLinkClosed := map[string]bool{"unknown ln program": true, "computed ln program": true}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"ordinary bound ln", `L=/bin/ln; "$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"ordinary direct ln", `ln -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"protected bound ln", `L=/bin/ln; "$L" -sf ../.ssh/authorized_keys protected.link; echo marker >> protected.link`, true},
		{"protected direct ln", `ln -sf ../.ssh/authorized_keys protected.link; echo marker >> protected.link`, true},
		// A computed program is uncertainty (W24 loop round 2): it blocks
		// only with a protected target in the text.
		{"unknown ln program", `"$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"computed ln program", `L=$(printf ln); "$L" -sf ordinary.txt ordinary.link; echo marker >> ordinary.link`, false},
		{"unknown ln program to the protected file", `"$L" -sf ../.ssh/authorized_keys x.link; echo marker >> x.link`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, blocked := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				want := tc.block
				if i == 2 && codexHookLinkClosed[tc.name] {
					want = true
				}
				if blocked != want {
					t.Errorf("proof route %d blocked=%t, want %t", i, blocked, want)
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
