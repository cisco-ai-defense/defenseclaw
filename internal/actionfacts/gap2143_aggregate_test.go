// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-2143: bash and zsh write the file of an all-output redirect, which
// POSIX sh reads as a background command and a separate redirect.
func TestBashAggregateRedirectsAsPOSIX(t *testing.T) {
	for _, tc := range []struct {
		command, want string
		ok            bool
	}{
		{"true &> ~/f", "true > ~/f 2>~/f", true},
		{"echo x &>> ~/f", "echo x >> ~/f 2>>~/f", true},
		{"true >& ~/f", "true > ~/f 2>~/f", true},
		{"true >&/tmp/f", "true >/tmp/f 2>/tmp/f", true},
		{`echo x &> "$HOME"/f`, `echo x > "$HOME"/f 2>"$HOME"/f`, true},
		{"make &>/dev/null", "make >/dev/null 2>/dev/null", true},
		{"echo x >&2", "", false},
		{"echo x 2>&1", "", false},
		{"echo x >&-", "", false},
		{"echo x >& $fd", "", false},
		{"echo x &> $(mktemp)", "", false},
		{"echo x > f", "", false},
		{"true 1>& ~/f", "true 1> ~/f 2>~/f", true},
		{"echo x 1>&$HOME/f", "echo x 1>$HOME/f 2>$HOME/f", true},
		{`true >& "$HOME/f"`, `true > "$HOME/f" 2>"$HOME/f"`, true},
		{"echo x 1>&2", "", false},
		{"echo x >&\"$fd\"", "", false},
		{"exec 3>&-", "", false},
	} {
		got, ok := BashAggregateRedirectsAsPOSIX(tc.command)
		if ok != tc.ok || got != tc.want {
			t.Errorf("BashAggregateRedirectsAsPOSIX(%q) = %q, %t; want %q, %t", tc.command, got, ok, tc.want, tc.ok)
		}
	}
}
