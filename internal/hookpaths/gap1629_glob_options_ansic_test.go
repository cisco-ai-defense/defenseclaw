// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP1629GlobOptionsReadANSICEscapes pins rel-1-0-10:GAP-1629: an ANSI-C
// quote with an escape names a word as the shell decodes it, so
// $'\x65val' is eval and $'sh\x6fpt' is shopt. The text gate removed the
// quote characters only, and globOptionLiteral gave up on any escape, so such
// a program word returned the options unchanged with no unknown.
func TestGAP1629GlobOptionsReadANSICEscapes(t *testing.T) {
	for _, c := range []struct {
		command string
		want    func(shellGlobOptions) bool
	}{
		{`$'\x65val' x; touch -h *`, func(o shellGlobOptions) bool { return o.unknown }},
		{`$'\145val' "$X"; touch -h *`, func(o shellGlobOptions) bool { return o.unknown }},
		{`$'sh\x6fpt' -s dotglob; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayDot != 0 }},
		{`$'se\x74' -f; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayNoGlob != 0 }},
		{`shopt -s $'null\x67lob'; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayNull != 0 }},
		{`$'\x47LOBIGNORE'=x; touch -h *`, func(o shellGlobOptions) bool { return true }}, // not an assignment: a command word
	} {
		if got := globOptionsInCall(c.command, shellGlobOptions{}); !c.want(got) {
			t.Errorf("globOptionsInCall(%q) = %+v", c.command, got)
		}
	}
	// ANSI-C text that names no option change changes nothing.
	for _, command := range []string{
		`echo $'a\nb'; touch -h *`,
		`$'ech\x6f' shopt -s dotglob; touch -h *`,
		`printf $'%s\x0a' 'set -f'; touch -h *`,
		`echo $'sh\x6fpt -s dotglob'; touch -h *`,
	} {
		if got := globOptionsInCall(command, shellGlobOptions{}); got != (shellGlobOptions{}) {
			t.Errorf("globOptionsInCall(%q) = %+v; want no change", command, got)
		}
	}
}
