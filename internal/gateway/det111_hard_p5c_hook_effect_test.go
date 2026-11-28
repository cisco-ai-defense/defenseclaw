// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// TestGAP1478MixedPurposeHookConfigNeedsProvenDisable pins the class boundary
// for at/codex/5c0f76c2745bc515/406 in all five profiles. The trace writes
// ordinary Codex settings; an exact hook file deletion, truncation, known
// overwrite dropping registered hooks, and opaque overwrite remain raised.
func TestGAP1478MixedPurposeHookConfigNeedsProvenDisable(t *testing.T) {
	home := t.TempDir()
	// The fixture is a file of this host: its path is a Windows path on a
	// Windows host, read with that flavor as the hook reads it there.
	flavor := effects.FlavorPOSIX
	if runtime.GOOS == "windows" {
		flavor = effects.FlavorWindows
	}
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	registered := "[hooks]\n[[hooks.PreToolUse]]\ncommand = \"defenseclaw-hook\"\n"
	registeredNotify := "notify = [\"defenseclaw-hook\", \"notify\"]\n"
	ordinary := "model = \"gpt-5\"\n"
	ordinaryAppend := "[model]\nname = \"gpt-5\"\n"
	tests := []struct {
		name      string
		kind      effects.Kind
		data      *effects.Data
		before    string
		wantRaise bool
	}{
		{"ordinary known write", effects.KindWrite, &effects.Data{Kind: effects.DataLiteral, Text: ordinary, Bytes: len(ordinary)}, "", false},
		{"known write keeps hooks", effects.KindWrite, &effects.Data{Kind: effects.DataLiteral, Text: ordinary + registered, Bytes: len(ordinary + registered)}, registered, false},
		{"known append keeps hooks", effects.KindAppend, &effects.Data{Kind: effects.DataLiteral, Text: ordinaryAppend, Bytes: len(ordinaryAppend)}, registered, false},
		{"delete", effects.KindDelete, nil, registered, true},
		{"truncate", effects.KindWrite, &effects.Data{Kind: effects.DataLiteral, Text: "", Bytes: 0}, registered, true},
		{"known write drops hooks", effects.KindWrite, &effects.Data{Kind: effects.DataLiteral, Text: ordinary, Bytes: len(ordinary)}, registered, true},
		{"known write drops notify", effects.KindWrite, &effects.Data{Kind: effects.DataLiteral, Text: ordinary, Bytes: len(ordinary)}, registeredNotify, true},
		{"opaque overwrite", effects.KindWrite, &effects.Data{Kind: effects.DataFile}, registered, true},
	}
	profiles := []struct {
		name   string
		strict bool
	}{
		{"default", false}, {"strict", true}, {"permissive", false},
		{"managed", false}, {"managed-strict", true},
	}
	for _, profile := range profiles {
		for _, tc := range tests {
			t.Run(profile.name+"/"+tc.name, func(t *testing.T) {
				if tc.before == "" {
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
					t.Fatal(err)
				}
				f := &semanticpb.EffectFact{
					Index: 1, Kind: string(tc.kind), TargetState: "known", RoleState: "known",
					Origin: &semanticpb.EffectOrigin{Program: "", Surface: string(effects.SurfaceShell)},
					Target: &semanticpb.EffectTarget{Type: "path", Path: path,
						Protected: []*semanticpb.ProtectedMatch{{Set: effectrules.SetAgentHookConfig, State: "known", Reason: "exact"}}},
				}
				res := effects.Result{Effects: []effects.Effect{{
					Kind: tc.kind, Target: effects.Target{Type: effects.TargetPath, Path: path},
					TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown, Data: tc.data,
				}}}
				paths := effectPreservedHookConfigPaths(res, []*semanticpb.EffectFact{f}, home)
				handoff := &effectKnownHookConfigTargets{paths: paths}
				if got := handoff.preserves(path); got == tc.wantRaise {
					t.Fatalf("safe-target handoff=%v, want %v", got, !tc.wantRaise)
				}
				if handoff.preserves(path+".other") || (*effectKnownHookConfigTargets)(nil).preserves(path) {
					t.Fatal("handoff widened beyond the exact, present target")
				}
				c := classifyEffects(res, []*semanticpb.EffectFact{f}, flavor, tierRestricted, effectReachEnv{Home: home, preservedHookConfigPaths: paths})
				if c.touches != tc.wantRaise {
					t.Fatalf("touches=%v, want %v", c.touches, tc.wantRaise)
				}
				if tc.wantRaise && !c.restricted {
					t.Fatal("proven or opaque hook config mutation lost restricted tier")
				}
				wantAction := guardrailActionAllow
				if tc.wantRaise {
					wantAction = guardrailActionAlert
					if profile.strict {
						wantAction = guardrailActionBlock
					}
				}
				if action := effectAction(c.touches, c.restrictedRuling, profile.strict); action != wantAction {
					t.Fatalf("action=%s, want %s", action, wantAction)
				}
			})
		}
	}
}

func TestGAP1478PreservingWriteBesideDeleteNeverEntersHandoff(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	text := "model = \"gpt-5\"\n"
	result := effects.Result{Effects: []effects.Effect{
		{Kind: effects.KindWrite, Target: effects.Target{Type: effects.TargetPath, Path: path}, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown, Data: &effects.Data{Kind: effects.DataLiteral, Text: text, Bytes: len(text)}},
		{Kind: effects.KindDelete, Target: effects.Target{Type: effects.TargetPath, Path: path}, TargetState: effects.TargetStateKnown, RoleState: effects.RoleStateKnown},
	}}
	facts := []*semanticpb.EffectFact{}
	for i, kind := range []effects.Kind{effects.KindWrite, effects.KindDelete} {
		facts = append(facts, &semanticpb.EffectFact{Index: int64(i + 1), Kind: string(kind), TargetState: "known", RoleState: "known", Target: &semanticpb.EffectTarget{Type: "path", Path: path, Protected: []*semanticpb.ProtectedMatch{{Set: effectrules.SetAgentHookConfig, State: "known", Reason: "exact"}}}})
	}
	if (&effectKnownHookConfigTargets{paths: effectPreservedHookConfigPaths(result, facts, home)}).preserves(path) {
		t.Fatal("a delete of the same target entered the safe-target handoff")
	}
}
