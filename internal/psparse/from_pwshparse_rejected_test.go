// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "testing"

// GAP-1915: the adapter attaches a redirection pwshparse rejected
// (StreamAlreadyRedirected) to its command, in source order, as Parse keeps it.
func TestFromPwshparseKeepsARejectedRedirection(t *testing.T) {
	for _, src := range []string{"echo k 1>&2 >> C:\\t\\out.txt", "& { echo k 1>&2 >> C:\\t\\out.txt }"} {
		sc, ok := FromPwshparse(src, Options{Dialect: DialectUnknown})
		if !ok {
			t.Fatalf("%q: port declined", src)
		}
		var cmd *Command
		WalkCommands(sc, func(c *Command) {
			if name, _ := LiteralString(c.Name); name == "echo" {
				cmd = c
			}
		})
		if cmd == nil || len(cmd.Redirs) != 2 {
			t.Fatalf("%q: echo redirections = %+v, want 1>&2 and >> file", src, cmd)
		}
		if cmd.Redirs[0].Merge != "2" || cmd.Redirs[1].Op != ">>" {
			t.Fatalf("%q: redirections %+v %+v, want 1>&2 then >>", src, cmd.Redirs[0], cmd.Redirs[1])
		}
		if v, _ := LiteralString(cmd.Redirs[1].Target); v != "C:\\t\\out.txt" {
			t.Fatalf("%q: >> target %q", src, v)
		}
	}
}
