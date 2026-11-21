// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP1627PlainValueOnlyForBackslashSpellings: on a Windows host the plain
// value of a word the resolver reads is judged only when it holds a
// backslash, the Windows home spelling the resolver loses (GAP-1624). Before
// the fix it was judged for every resolver word there, so
// 'authorized_key[s]'* was read as the glob authorized_key[s]* again
// (rel-1-0-10:GAP-1627). A word the resolver does not read keeps its plain
// reading on every host.
func TestGAP1627PlainValueOnlyForBackslashSpellings(t *testing.T) {
	for _, row := range []struct {
		resolver, windows bool
		value             string
		want              bool
	}{
		{false, false, "authorized_key[s]*", true},
		{false, true, "authorized_key[s]*", true},
		{true, false, `C:\Users\me\.ssh\authorized_keys`, false},
		{true, true, `C:\Users\me\.ssh\authorized_keys`, true},
		{true, true, "authorized_key[s]*", false},
		{true, true, "/c/Users/me/.ssh/authorized_key[s]*", false},
		{true, false, "authorized_key[s]*", false},
	} {
		if got := actionPlainValueJudged(row.resolver, row.windows, row.value); got != row.want {
			t.Errorf("resolver=%v windows=%v %q: plain value judged %v, want %v", row.resolver, row.windows, row.value, got, row.want)
		}
	}
}
