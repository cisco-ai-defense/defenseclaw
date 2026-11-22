// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP1614GlobOptionsReadAfterQuoteRemoval pins rel-1-0-10:GAP-1614: the
// glob options a call may change are read from its words as the shell reads
// them, after line-continuation and quote removal. A quoted or escaped
// spelling of shopt, set, eval or GLOBIGNORE changes the options as the plain
// one does; the text gate saw only the raw spelling and returned the options
// unchanged, with no parse.
func TestGAP1614GlobOptionsReadAfterQuoteRemoval(t *testing.T) {
	for _, c := range []struct {
		command string
		want    func(shellGlobOptions) bool
	}{
		{"GLOB\\\nIGNORE=x; touch -h *", func(o shellGlobOptions) bool { return o.globIgnore }},
		{`"shopt" -s dotglob; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayDot != 0 }},
		{`s\hopt -s dotglob; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayDot != 0 }},
		{`sh'opt' -s nullglob; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayNull != 0 }},
		{`'set' -f; touch -h *`, func(o shellGlobOptions) bool { return o.may&globMayNoGlob != 0 }},
		{"set \\\n-f; touch -h *", func(o shellGlobOptions) bool { return o.may&globMayNoGlob != 0 }},
		{`$'eval' "$X"; touch -h *`, func(o shellGlobOptions) bool { return o.unknown }},
		{`ev\al "$X"; touch -h *`, func(o shellGlobOptions) bool { return o.unknown }},
		{`shopt -s "dot\glob"; touch -h *`, func(o shellGlobOptions) bool { return o.may == 0 && !o.unknown }},
	} {
		if got := globOptionsInCall(c.command, shellGlobOptions{}); !c.want(got) {
			t.Errorf("globOptionsInCall(%q) = %+v", c.command, got)
		}
	}
	// Words that only print or quote a name change nothing.
	for _, command := range []string{`echo "shopt -s dotglob"; touch -h *`, `printf '%s\n' 'set -f'; touch -h *`, `"se\t" -f; touch -h *`, `touch -h *`} {
		if got := globOptionsInCall(command, shellGlobOptions{}); got != (shellGlobOptions{}) {
			t.Errorf("globOptionsInCall(%q) = %+v; want no change", command, got)
		}
	}
}
