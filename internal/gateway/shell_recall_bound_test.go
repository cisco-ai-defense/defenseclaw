// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A call past the operand bound (more than actionfacts.MaxOperandsPerCall words)
// is read only up to the bound, so a push at its end is never parsed. The shared bound rule decides such a call by the pack, not
// by what the five shell-recall rules can see: it alerts in the default and
// permissive packs and blocks in strict. The five rules add nothing here and
// must not turn the verdict into a pass. A single word over the byte cap of the
// parser (GAP-0281..0285, s7/parselimits) is outside this bound and not pinned here.
func TestShellRecallPushPastTheOperandBoundFollowsTheBoundRule(t *testing.T) {
	const connector = "shell-recall-bound-test"
	installDefaultProfileConnector(t, connector)
	push := shellRecallEffectsFixtureCommand(t, "shell-recall-effects-v1/adhoc-ssh-push")
	shapes := map[string]string{
		// more operands than actionfacts.MaxOperandsPerCall, then the push
		"operands": "echo " + strings.Repeat("a ", actionfacts.MaxOperandsPerCall+100) + "\n" + push,
	}
	for shape, command := range shapes {
		for pack, want := range map[string]string{
			"default":    guardrailActionAlert,
			"permissive": guardrailActionAlert,
			"strict":     guardrailActionBlock,
		} {
			t.Run(shape+"/"+pack, func(t *testing.T) { testShellRecallBound(t, connector, command, pack, want) })
		}
	}
}

func testShellRecallBound(t *testing.T, connector, command, pack, want string) {
	{
		{
			args, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(
				t.Context(),
				&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector},
				trustedActionRequest{
					Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: "/repo"},
					LegacyText: string(args), Connector: connector, EnforcementCapable: true,
				},
			)
			if verdict.Action != want {
				t.Fatalf("%s: action %q, want %q; verdict=%+v", pack, verdict.Action, want, verdict)
			}
		}
	}
}
