// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP2290ShellDashSReadsCodeFromStdin: with -s (alone or in a cluster such
// as -xs) and no -c, every operand of an sh-style shell is a positional
// parameter and the shell reads its code from standard input. So `bash -s -- a
// <&3` and `bash -s a < f` run code we cannot see, exactly like the same shell
// with the same stdin and no -s, and a here-document fed to `bash -s a` is
// unwrapped like one fed to `bash`. -c wins over -s, and -s after the first
// operand is itself a positional, so those keep reading their -c text or
// script. The values of -o / -O / +o / --rcfile are not scripts. Red at
// 0978301022 (CHK-RF-EFFECTS3): every -s form with an operand gave no
// opaque-code exec.
func TestGAP2290ShellDashSReadsCodeFromStdin(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	// sig is the stdin-code part of the effects: the opaque-code exec and a
	// write of out.txt by unwrapped here-document text.
	type sig struct{ opaque, write bool }
	get := func(command string) sig {
		var s sig
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
		for _, e := range r.Effects {
			if e.Kind == KindExec {
				for _, reason := range e.Reasons {
					if reason.Code == ReasonOpaqueCode {
						s.opaque = true
					}
				}
			}
			if e.Kind == KindWrite && e.Target.Path == "/home/u/proj/out.txt" {
				s.write = true
			}
		}
		return s
	}
	for _, tc := range []struct {
		command, twin string // twin: the same shell and stdin with no -s
		want          sig
	}{
		{"bash -s -- a <&3", "bash <&3", sig{opaque: true}},
		{"bash -s a < in.txt", "bash < in.txt", sig{opaque: true}},
		{"sh -s a b 0<&3", "sh 0<&3", sig{opaque: true}},
		{"dash -s a <&3", "dash <&3", sig{opaque: true}},
		{"zsh -s a < in.txt", "zsh < in.txt", sig{opaque: true}},
		{"ksh -s a < in.txt", "ksh < in.txt", sig{opaque: true}},
		{"bash -xs a < in.txt", "bash -x < in.txt", sig{opaque: true}},
		{"sh -es -- a <> in.txt", "sh -e <> in.txt", sig{opaque: true}},
		{"bash --norc -s a < in.txt", "bash --norc < in.txt", sig{opaque: true}},
		{"bash -o posix -s a < in.txt", "bash -o posix < in.txt", sig{opaque: true}},
		{"bash -s -O extglob a < in.txt", "bash -O extglob < in.txt", sig{opaque: true}},
		{"bash +x -s a < in.txt", "bash +x < in.txt", sig{opaque: true}},
		{"bash -s a -c true < in.txt", "bash < in.txt", sig{opaque: true}}, // after an operand, -c is a positional
		{"bash -s a <<'EOF'\ntouch out.txt\nEOF", "bash <<'EOF'\ntouch out.txt\nEOF", sig{write: true}},
		{"bash -s < in.txt", "bash < in.txt", sig{opaque: true}}, // benign twin, unchanged
		// -c wins over -s; a script operand ahead of -s makes -s a positional.
		{"bash -s -c true a < in.txt", "bash -c true a < in.txt", sig{}},
		{"bash -sc true a < in.txt", "bash -c true a < in.txt", sig{}},
		{"bash -c true -s < in.txt", "bash -c true < in.txt", sig{}},
		{"bash run.sh -s a < in.txt", "bash run.sh a < in.txt", sig{}},
		{"bash -- -s a < in.txt", "bash -- -s a < in.txt", sig{}}, // after --, -s is the script name
		{"bash -o posix run.sh < in.txt", "bash run.sh < in.txt", sig{}},
		{"python3 -s run.py < in.txt", "python3 run.py < in.txt", sig{}}, // python -s is no-user-site, not stdin
	} {
		got, twin := get(tc.command), get(tc.twin)
		if got != tc.want {
			t.Errorf("%q: stdin code = %+v, want %+v", tc.command, got, tc.want)
		}
		if got != twin {
			t.Errorf("%q: stdin code = %+v, its no -s twin %q gives %+v", tc.command, got, tc.twin, twin)
		}
	}
}
