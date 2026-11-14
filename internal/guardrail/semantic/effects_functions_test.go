// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func effectTarget(matches ...*semanticpb.ProtectedMatch) *semanticpb.EffectTarget {
	return &semanticpb.EffectTarget{Type: "path", Path: "/x", Protected: matches}
}

func match(set, state string) *semanticpb.ProtectedMatch {
	return &semanticpb.ProtectedMatch{Set: set, State: state}
}

func TestProtectedState(t *testing.T) {
	cases := []struct {
		name   string
		target *semanticpb.EffectTarget
		set    string
		want   string
	}{
		{"nil target is unknown, never no", nil, "", ProtectedUnknown},
		{"no matches is no", effectTarget(), "", ProtectedNo},
		{"known match", effectTarget(match("ssh_authorized_keys", ProtectedKnown)), "", ProtectedKnown},
		{"unknown match", effectTarget(match("ssh_authorized_keys", ProtectedUnknown)), "", ProtectedUnknown},
		{"known wins over unknown", effectTarget(
			match("shell_rc", ProtectedUnknown), match("credentials", ProtectedKnown)), "", ProtectedKnown},
		{"set filter selects the named set", effectTarget(
			match("shell_rc", ProtectedKnown), match("credentials", ProtectedUnknown)), "credentials", ProtectedUnknown},
		{"set filter: no member of the set is no", effectTarget(
			match("shell_rc", ProtectedKnown)), "credentials", ProtectedNo},
		{"explicit no match does not raise the state", effectTarget(match("shell_rc", ProtectedNo)), "", ProtectedNo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProtectedState(tc.target, tc.set); got != tc.want {
				t.Fatalf("ProtectedState = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProtectedFunctionInCEL(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		expr string
		want bool
	}{
		{"protected-set case 1: known unary match blocks", "f.effects.exists(e, protected(e.target) == 'known')", true},
		{"protected-set case 2: unknown unary match", "f.effects.exists(e, protected(e.target) == 'unknown')", true},
		{"protected-set case 3: named set match", "f.effects.exists(e, protected(e.target, 'credentials') == 'known')", true},
		{"protected-set case 4: a set with no member is no", "f.effects.exists(e, protected(e.target, 'shell_rc') == 'no')", true},
	}
	facts := &semanticpb.Facts{Effects: []*semanticpb.EffectFact{
		{Index: 1, Kind: "write", TargetState: "known", RoleState: "known",
			Target: effectTarget(match("credentials", ProtectedKnown))},
		{Index: 2, Kind: "delete", TargetState: "unknown", RoleState: "known",
			Target: effectTarget(match("ssh_authorized_keys", ProtectedUnknown))},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program, code := compiler.Compile(tc.expr)
			if code != CompileOK {
				t.Fatalf("compile %q: %v", tc.expr, code)
			}
			result, evalCode := program.EvalBool(context.Background(), facts)
			if evalCode != EvalOK {
				t.Fatalf("eval %q: %v", tc.expr, evalCode)
			}
			if result.Matched != tc.want {
				t.Fatalf("expr %q matched=%v, want %v", tc.expr, result.Matched, tc.want)
			}
		})
	}
}
