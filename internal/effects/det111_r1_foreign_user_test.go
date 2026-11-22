// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func extractDET111ForeignUserCommand(t *testing.T, command string) effects.Result {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	call := effects.Normalize("det111", "Bash", args)
	call.Workdir = "/home/alice/proj"
	return effects.Extract(call, effects.Options{
		CWD: "/home/alice/proj", Home: "/home/alice",
		Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX,
	})
}

func foreignContext(effect effects.Effect) bool {
	for _, reason := range effect.Reasons {
		if reason.Code == effects.ReasonForeignContext {
			return true
		}
	}
	return false
}

func effectPath(effect effects.Effect) string {
	if effect.Target.Path != "" {
		return effect.Target.Path
	}
	return effect.Target.Spelling
}

// A known non-root account wrapper cannot prove that absolute paths belong to
// the hook account. Its writes stay foreign-context MAYBE effects. A root
// wrapper and plain sudo retain their exact, stronger path facts.
func TestDET111NamedForeignUserWrappersKeepEffectsMaybe(t *testing.T) {
	const state = "/home/alice/.defenseclaw/.ci-helper.lock"
	const token = "/home/alice/.defenseclaw/hooks/.ci-helper.token"
	rows := []struct {
		name, command string
	}{
		{"sudo login option", "sudo -iu buildrunner rm -f -- " + state + " " + token},
		{"sudo user option", "sudo -u buildrunner rm -f -- " + state + " " + token},
		{"sudo long user option", "sudo --user buildrunner rm -f -- " + state + " " + token},
		{"su command body", "su buildrunner -c 'rm -f -- " + state + " " + token + "'"},
		{"runuser option", "runuser -u buildrunner -- rm -f -- " + state + " " + token},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			res := extractDET111ForeignUserCommand(t, row.command)
			var sawDelete bool
			for _, effect := range res.Effects {
				path := effectPath(effect)
				if effect.Kind != effects.KindDelete || path != state && path != token {
					continue
				}
				sawDelete = true
				if !foreignContext(effect) {
					t.Errorf("delete %q is not graded in a foreign account context: %+v", path, effect.Origin)
				}
			}
			if !sawDelete {
				t.Fatalf("wrapper did not lower the state deletes: %+v", res.Effects)
			}
		})
	}

	for _, row := range []struct {
		name, command string
	}{
		{"sudo dynamic account stays unaccounted", `sudo -u "$BUILD_USER" rm -f -- ` + state},
		{"runuser dynamic account stays unaccounted", `runuser -u "$BUILD_USER" -- rm -f -- ` + state},
	} {
		t.Run(row.name, func(t *testing.T) {
			res := extractDET111ForeignUserCommand(t, row.command)
			for _, effect := range res.Effects {
				if effect.Kind != effects.KindDelete || effectPath(effect) != state {
					continue
				}
				if foreignContext(effect) || effect.RoleState != effects.RoleStateUnknown {
					t.Errorf("dynamic account delete was treated as a named foreign account: %+v", effect)
				}
			}
		})
	}

	controls := []struct {
		name, command, target string
		kind                  effects.Kind
	}{
		{"plain sudo state delete", "sudo rm -f -- " + state, state, effects.KindDelete},
		{"sudo root user preserves local effects", "sudo -u root rm -f -- " + state, state, effects.KindDelete},
		{"sudo authorized keys append", "sudo tee -a /root/.ssh/authorized_keys", "/root/.ssh/authorized_keys", effects.KindAppend},
	}
	for _, control := range controls {
		t.Run(control.name, func(t *testing.T) {
			res := extractDET111ForeignUserCommand(t, control.command)
			var found bool
			for _, effect := range res.Effects {
				if effect.Kind != control.kind || effectPath(effect) != control.target {
					continue
				}
				found = true
				if foreignContext(effect) || effect.TargetState != effects.TargetStateKnown {
					t.Errorf("control target %q lost its Known local grade: %+v", control.target, effect)
				}
			}
			if !found {
				t.Errorf("control target %q was not lowered: %+v", control.target, res.Effects)
			}
		})
	}
}
