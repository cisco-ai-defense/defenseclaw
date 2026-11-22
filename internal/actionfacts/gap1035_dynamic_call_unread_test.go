// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// A PowerShell dynamic call target whose arguments hold a construct with no
// balanced end skips the rest of the call unread, so it sets Unread as the
// same construct does outside a dynamic call. An ordinary dynamic call, or one
// whose values balance, stays read (rel-1-0-10:GAP-1035).
func TestPowerShellDynamicCallWithNoBalancedEndIsUnread(t *testing.T) {
	// plain is the same text behind an ordinary command word. Only the opaque
	// value without an end is unread there; the comment and the stray close
	// are skipped by the dynamic call's own scan, which must not hide them.
	for _, row := range []struct {
		name, plain, dynamic string
		unread, plainUnread  bool
	}{
		{"opaque value", `foo $(Get-Date`, `& $x $(Get-Date`, true, true},
		{"block comment", `foo <# open`, `& $x <# open`, true, false},
		{"stray close", `foo )`, `& $x )`, true, false},
		{"balanced value", `foo $(Get-Date)`, `& $x $(Get-Date)`, false, false},
		{"plain arguments", `foo a b`, `& $x a b`, false, false},
		{"next statement", `foo a; id`, `& $x a; id`, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			plain := Analyze(Input{Tool: "powershell", Command: row.plain, DialectHint: DialectPowerShell})
			dynamic := Analyze(Input{Tool: "powershell", Command: row.dynamic, DialectHint: DialectPowerShell})
			if plain.Parse.Unread != row.plainUnread {
				t.Fatalf("control %q Unread = %v, want %v", row.plain, plain.Parse.Unread, row.plainUnread)
			}
			if dynamic.Parse.Unread != row.unread {
				t.Errorf("%q Unread = %v, want %v", row.dynamic, dynamic.Parse.Unread, row.unread)
			}
		})
	}
}
