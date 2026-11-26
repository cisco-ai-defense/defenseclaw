// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"strings"
	"testing"
)

// TestGAP2214XargsOwnStdinRedirectReplacesThePipe: a redirect of xargs's own
// standard input replaces the pipe, so its operands come from the file, the
// here-string or the descriptor, never from the words the stage before it
// printed. The last stdin redirect wins (walker.stdinText); a file the call
// did not write and a descriptor duplicate are input the call does not show,
// so the operands stay dynamic. Red at bea636bca1: the echo words were fed
// and read Known.
func TestGAP2214XargsOwnStdinRedirectReplacesThePipe(t *testing.T) {
	o := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	extract := func(command string) Result {
		return Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: command, Workdir: o.CWD}, o)
	}
	const pipe = "echo /home/u/proj/a /home/u/proj/b | "
	echoWord := func(known []string) bool {
		for _, k := range known {
			if strings.Contains(k, "/home/u/proj/a ") || strings.Contains(k, "/home/u/proj/b ") {
				return true
			}
		}
		return false
	}
	// Input the call does not show: no Known effect of the echo words.
	for _, command := range []string{
		pipe + "xargs cp < /home/u/proj/list",
		pipe + "xargs ln -s < /home/u/proj/list",
		pipe + "xargs ln -s 0</home/u/proj/list",
		pipe + "xargs cp 0<&3",
		pipe + "xargs ln -s <&3",
		pipe + "xargs ln -s <> /home/u/proj/list",
		pipe + "xargs cp <<< \"/home/u/proj/c /home/u/proj/d\" < /home/u/proj/list",
		// The one-word copier path (GAP-1317) reads the same input.
		"echo /home/u/proj/b | xargs cp /home/u/proj/a < /home/u/proj/list",
	} {
		r := extract(command)
		if k := gap2214Known(r); echoWord(k) {
			t.Errorf("%q: known effects %v name an echo word, want the operands from the redirect left dynamic", command, k)
		}
		for _, e := range r.Effects {
			if (e.Kind == KindWrite || e.Kind == KindLink) && e.Target.Path == "/home/u/proj/b" {
				t.Errorf("%q: a %s of an echo word, want the operands from the redirect", command, e.Kind)
			}
		}
	}
	// Input the call shows exactly (a here-string or a literal heredoc, the
	// last stdin redirect): the call reads as the plain command on its words
	// (an earlier redirect still opens its file).
	for _, tc := range []struct{ xargs, plain string }{
		{pipe + "xargs cp <<< \"/home/u/proj/c /home/u/proj/d\"", "cp /home/u/proj/c /home/u/proj/d"},
		{pipe + "xargs ln -s < /home/u/proj/list <<< \"/home/u/proj/c /home/u/proj/d\"", "ln -s /home/u/proj/c /home/u/proj/d < /home/u/proj/list"},
		{pipe + "xargs ln -s <<'EOF'\n/home/u/proj/c\n/home/u/proj/d\nEOF", "ln -s /home/u/proj/c /home/u/proj/d"},
	} {
		got, want := extract(tc.xargs), extract(tc.plain)
		if g, w := gap2214Known(got), gap2214Known(want); !slices.Equal(g, w) || len(w) == 0 {
			t.Errorf("%q: known effects %v, want the plain call's %v", tc.xargs, g, w)
		}
	}
}
