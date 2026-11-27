// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"fmt"
	"slices"
	"testing"
)

func gap2214Known(r Result) []string {
	var out []string
	for _, e := range r.Effects {
		if (e.Kind == KindLink || e.Kind == KindWrite || e.Kind == KindRead) &&
			e.TargetState == TargetStateKnown && e.RoleState == RoleStateKnown {
			out = append(out, fmt.Sprintf("%s %s %t", e.Kind, e.Target.Path, e.LinkTarget))
		}
	}
	slices.Sort(out)
	return out
}

// TestGAP2214BareXargsFeedsEveryLiteralWord: a bare xargs (no option) runs
// its command once with the blank-separated words of its input, so
// echo SRC DST | xargs ln -s (or cp) reads as the plain call: the
// same Known link or copy effects, and no unknown. Red at
// det111/t23e6-merge f6e151801a: only one piped word was fed, and only to a
// copier, so the link of two words had an unknown target.
func TestGAP2214BareXargsFeedsEveryLiteralWord(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	const key = "/home/u/.ssh/id_ed25519"
	extract := func(command string) Result {
		return Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
	}
	for _, tc := range []struct{ xargs, plain string }{
		{"echo " + key + " /tmp/k | xargs ln -s", "ln -s " + key + " /tmp/k"},
		{"echo /tmp/k | xargs ln -s " + key, "ln -s " + key + " /tmp/k"},
		{"echo " + key + " /tmp/k | xargs cp", "cp " + key + " /tmp/k"},
		{"echo /home/u/proj/a /home/u/proj/b | xargs ln -s", "ln -s /home/u/proj/a /home/u/proj/b"},
	} {
		got, want := extract(tc.xargs), extract(tc.plain)
		if len(got.Unknowns) != 0 {
			t.Errorf("%q: %d unknowns, want none", tc.xargs, len(got.Unknowns))
		}
		if g, w := gap2214Known(got), gap2214Known(want); !slices.Equal(g, w) {
			t.Errorf("%q: known effects %v, want the plain call's %v", tc.xargs, g, w)
		}
	}
	// xargs reads these its own way (an option, a quote, a backslash, an
	// end-of-file word): the operands stay the dynamic ones they were.
	for _, command := range []string{
		"echo " + key + " /tmp/k | xargs -n1 ln -s",
		"echo " + key + " /tmp/k | xargs -0 ln -s",
		"echo \"'" + key + "' /tmp/k\" | xargs ln -s",
		"echo " + key + "\\\\ /tmp/k | xargs ln -s",
		"echo " + key + " _ /tmp/k | xargs ln -s",
	} {
		for _, e := range extract(command).Effects {
			if e.Kind == KindLink && e.Target.Path == key && e.TargetState == TargetStateKnown {
				t.Errorf("%q: a Known link of the key, want the operands from input left dynamic", command)
			}
		}
	}
}
