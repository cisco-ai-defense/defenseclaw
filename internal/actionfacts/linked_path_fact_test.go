// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// The file a link reaches is one more spelling of the operand, written the
// way every other path fact is: a Windows physical path in its slash form
// with an upper-case drive letter, a POSIX path as it is.
func TestLinkedPathFactSpellsAPhysicalPathLikeAnyPathFact(t *testing.T) {
	operand := PathFact{
		CommandID: 7, Access: PathAccessWrite, Flavor: PathFlavorWindows,
		Value: `C:\Users\acct\proj\jn\.netrc`, Normalized: "C:/Users/acct/proj/jn/.netrc",
		Absolute: true, Resolved: "C:/Users/acct/proj/jn/.netrc",
	}
	for _, tc := range []struct{ name, physical, want string }{
		{"drive path", `C:\ProgramData\fx\Users\fixture\.netrc`, "C:/ProgramData/fx/Users/fixture/.netrc"},
		{"lower-case drive", `c:\ProgramData\fx\Users\fixture\.netrc`, "C:/ProgramData/fx/Users/fixture/.netrc"},
		{"slash drive path", "D:/data/Users/fixture/.netrc", "D:/data/Users/fixture/.netrc"},
		{"extended prefix", `\\?\C:\ProgramData\fx\Users\fixture\.netrc`, "C:/ProgramData/fx/Users/fixture/.netrc"},
		{"share path", `\\srv\share\Users\fixture\.netrc`, "//srv/share/Users/fixture/.netrc"},
		{"dot segments", `C:\ProgramData\fx\..\fx\Users\fixture\.netrc`, "C:/ProgramData/fx/Users/fixture/.netrc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := LinkedPathFact(operand, tc.physical)
			if got.Resolved != tc.want || got.Normalized != tc.want || got.Value != tc.want {
				t.Fatalf("spelling = %q / %q / %q, want %q", got.Value, got.Normalized, got.Resolved, tc.want)
			}
			if !got.Linked || !got.Absolute || got.CommandID != 7 || got.Access != PathAccessWrite || got.Flavor != PathFlavorWindows {
				t.Fatalf("operand fields changed: %+v", got)
			}
		})
	}
}

func TestLinkedPathFactKeepsAPOSIXPathAsItIs(t *testing.T) {
	operand := PathFact{
		CommandID: 3, Access: PathAccessRead, Flavor: PathFlavorPOSIX,
		Value: "link.txt", Normalized: "link.txt", Resolved: "/home/u/proj/link.txt",
	}
	for _, physical := range []string{
		"/home/u/Users/fixture/.netrc",
		`/home/u/odd\name/.netrc`,
		`/tmp/C:\not-a-drive`,
	} {
		got := LinkedPathFact(operand, physical)
		if got.Resolved != physical || got.Normalized != physical || got.Value != physical {
			t.Fatalf("POSIX physical path %q was rewritten to %q", physical, got.Resolved)
		}
		if got.Flavor != PathFlavorPOSIX || !got.Linked || !got.Absolute {
			t.Fatalf("operand fields changed: %+v", got)
		}
		if got.LinkedFrom != operand.Resolved {
			t.Fatalf("the fact names operand %q, want %q", got.LinkedFrom, operand.Resolved)
		}
	}
}
