// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

func TestDET111IcaclsDisplayIsReadOnlyButGrantChangesPermissions(t *testing.T) {
	const target = `c:\users\alice\.defenseclaw\hooks\.hookcfg`
	opts := Options{Flavor: FlavorWindows, Dialect: DialectCMD, Home: `C:\Users\alice`, CWD: `C:\Users\alice\proj`, CaseInsensitive: true}
	display := Extract(Call{Surface: SurfaceShell, Command: `icacls "` + target + `"`}, opts)
	for _, effect := range display.Effects {
		if effect.Kind == KindPermissionChange {
			t.Fatalf("display-only icacls lowered to a permission change: %+v", effect)
		}
	}
	if _, ok := findEffect(display, KindRead, target); !ok {
		t.Fatalf("display-only icacls did not retain its read operand: %+v", display.Effects)
	}

	mutate := Extract(Call{Surface: SurfaceShell, Command: `icacls "` + target + `" /grant Everyone:F`}, opts)
	if effect, ok := findEffect(mutate, KindPermissionChange, target); !ok || effect.TargetState != TargetStateKnown || effect.RoleState == RoleStateKnown {
		t.Fatalf("icacls /grant did not retain a conservative permission change: %+v", mutate.Effects)
	}
}
