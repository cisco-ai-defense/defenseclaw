// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import "testing"

// GAP-1915: a second redirection of a stream that is already redirected is a
// parse error (StreamAlreadyRedirected) and is not part of the CommandAst, as in
// pwsh; Result.Rejected still holds it, so a reader can see the target it names.
func TestRejectedRedirectionIsKeptOutsideTheTree(t *testing.T) {
	for _, src := range []string{"echo k 1>&2 >> C:\\t\\out.txt", "(1) 1>&2 >> C:\\t\\out.txt"} {
		res := ParseTree(src)
		if len(res.Rejected) != 1 || res.Rejected[0].Type != "FileRedirectionAst" {
			t.Fatalf("%q: Rejected = %v, want the >> file redirection", src, res.Rejected)
		}
		var walk func(n *Node) bool
		walk = func(n *Node) bool {
			if n == res.Rejected[0] {
				return true
			}
			for _, k := range n.Kids {
				if walk(k) {
					return true
				}
			}
			return false
		}
		if walk(res.Root) {
			t.Fatalf("%q: the rejected redirection is in the tree (pwsh drops it from the AST)", src)
		}
	}
	if res := ParseTree("echo k 2>&1 >> C:\\t\\out.txt"); len(res.Rejected) != 0 {
		t.Fatalf("two streams: Rejected = %v, want none", res.Rejected)
	}
}
