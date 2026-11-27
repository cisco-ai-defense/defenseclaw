// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

func TestDET111R1GitBashWindowsHostTargets(t *testing.T) {
	const target = `c:\users\alice\.defenseclaw\config.yaml`
	opts := Options{
		Flavor: FlavorWindows, Dialect: DialectPOSIX,
		Home: `C:\Users\alice`, CWD: `C:\Users\alice\proj`, Drive: "C", CaseInsensitive: true,
		Env: map[string]string{"HOME": `C:\Users\alice`, "USERPROFILE": `C:\Users\alice`},
	}
	cases := []struct {
		name, command string
		kind          Kind
	}{
		{"tar extract at tilde destination", "tar -xf b.tar -C ~ .defenseclaw/config.yaml", KindWrite},
		{"python argv append", `python3 -c "import sys; open(sys.argv[1],'a').write('x')" ~/.defenseclaw/config.yaml`, KindAppend},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Extract(Call{Surface: SurfaceShell, Tool: "Bash", Command: tc.command}, opts)
			for _, effect := range got.Effects {
				if effect.Kind == tc.kind && effect.TargetState == TargetStateKnown &&
					effect.RoleState == RoleStateKnown && strings.EqualFold(effect.Target.Path, target) {
					return
				}
			}
			t.Fatalf("Git Bash effect did not resolve to %s with known %v: %+v", target, tc.kind, got.Effects)
		})
	}
}

func TestDET111R1TarMemberTransformStaysUnknown(t *testing.T) {
	opts := Options{
		Flavor: FlavorWindows, Dialect: DialectPOSIX,
		Home: `C:\Users\alice`, CWD: `C:\Users\alice\proj`, Drive: "C", CaseInsensitive: true,
		Env: map[string]string{"HOME": `C:\Users\alice`, "USERPROFILE": `C:\Users\alice`},
	}
	for _, transform := range []string{"--strip-components=1", "--strip-c=1", "--transform=s@x@y@"} {
		t.Run(transform, func(t *testing.T) {
			command := "tar " + transform + " -xf b.tar -C ~ .defenseclaw/config.yaml"
			got := Extract(Call{Surface: SurfaceShell, Tool: "Bash", Command: command}, opts)
			for _, effect := range got.Effects {
				if effect.Kind == KindWrite && effect.TargetState == TargetStateKnown &&
					strings.EqualFold(effect.Target.Path, `c:\users\alice\.defenseclaw\config.yaml`) {
					t.Fatalf("transformed tar member was incorrectly resolved: %+v", got.Effects)
				}
			}
		})
	}
}
