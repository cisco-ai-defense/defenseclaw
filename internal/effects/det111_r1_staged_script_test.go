// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func TestDET111R1WrittenScriptBodyLowersStagedMutations(t *testing.T) {
	const target = "/home/alice/.defenseclaw/config.yaml"
	for _, tc := range []struct {
		name, command string
	}{
		{"shell", "cat > x <<'EOF'\n: >> ~/.defenseclaw/config.yaml\nEOF\nsh x"},
		{"direct", "cat > x <<'EOF'\n: >> ~/.defenseclaw/config.yaml\nEOF\n./x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := effects.Call{Surface: effects.SurfaceShell, Tool: "Bash", Command: tc.command}
			res := effects.Extract(call, effects.Options{
				Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX,
				Home: "/home/alice", CWD: "/home/alice/proj",
				Env: map[string]string{"HOME": "/home/alice"},
			})
			for _, e := range res.Effects {
				if e.Target.Path == target && e.Kind == effects.KindAppend && e.TargetState == effects.TargetStateKnown && e.RoleState == effects.RoleStateKnown && e.Origin.Depth > 0 {
					return
				}
			}
			t.Fatalf("staged script body did not produce a mutation of %s: %+v", target, res.Effects)
		})
	}
}
