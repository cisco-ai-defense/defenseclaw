// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package effects

import "testing"

func TestDET111R1PythonInlineOpenReadIsKnownRead(t *testing.T) {
	cases := []struct {
		name, command, target string
	}{
		{"argv path", `python3 -c "import sys; print(open(sys.argv[1]).read())" /home/u/.ssh/id_rsa`, "/home/u/.ssh/id_rsa"},
		{"literal path", `python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`, "/home/u/.ssh/id_rsa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Extract(Call{Surface: SurfaceShell, Command: tc.command}, Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"})
			for _, effect := range got.Effects {
				if effect.Kind == KindRead && effect.Target.Path == tc.target && effect.TargetState == TargetStateKnown && effect.RoleState == RoleStateKnown {
					return
				}
			}
			t.Fatalf("Python inline open/read did not produce a known read: %+v", got)
		})
	}
}
