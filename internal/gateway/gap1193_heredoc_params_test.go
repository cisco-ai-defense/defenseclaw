// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestGAP1193UnquotedHeredocParametersAreNotReadAsWritten: the shell that
// holds an unquoted here-document expands its parameters before the shell it
// feeds runs the text, so a parameter inside single quotes, after an escaped
// backslash, or named by an assignment of the body is not what the text as
// written says. The hook does not read such a body as written; it judges the
// call at least at the unknown tier: alert in default, block in strict
// (rel-1-0-10:GAP-1193). A quoted body stays literal and a body whose
// parameters both shells expand alike stays read, with no unread finding.
// Scripts are the GAP-1148 rows (TestGAP1148UnquotedHeredocEscapesAreUndone)
// with $HOME respelled; rows from the g1137 round-2 review (s7-g1137rev2).
func TestGAP1193UnquotedHeredocParametersAreNotReadAsWritten(t *testing.T) {
	scripts := []string{
		"rm -rf $HOME/*",
		"echo x >> $HOME/.bashrc",
	}
	respell := []func(string) string{
		// inside single quotes
		func(script string) string { return strings.ReplaceAll(script, "$HOME", "'$HOME'") },
		// after an escaped backslash
		func(script string) string { return strings.ReplaceAll(script, "$HOME", "\\\\$HOME") },
		// a name the body binds, which the holding shell expands unset
		func(script string) string { return "D=/tmp/build\n" + strings.ReplaceAll(script, "$HOME", "$D") },
	}
	forms := []string{
		"cat <<EOF | sh\nBODY\nEOF",
		"sh <<EOF\nBODY\nEOF",
		"tee run.sh <<EOF | bash\nBODY\nEOF",
	}
	data := []string{
		"cat <<'EOF' | sh\nD=/tmp/build\nrm -rf $D/*\nEOF",
		"sh <<EOF\nmake -C $HOME/src\nEOF",
		"cat <<EOF | sh\n# build in $HOME\nmake\nEOF",
	}
	shellTextTiers(t, func(tier string, decide func(string) (string, []string), _ func(string, bool) (string, []string)) {
		least := "allow"
		switch {
		case strings.HasSuffix(tier, "/strict"):
			least = "block"
		case strings.HasSuffix(tier, "/default"):
			least = "alert"
		}
		for _, script := range scripts {
			for _, spell := range respell {
				for _, form := range forms {
					command := strings.ReplaceAll(form, "BODY", spell(script))
					if got, findings := decide(command); gap1137Rank[got] < gap1137Rank[least] {
						t.Errorf("%s: %q is %s (%q), want at least the unknown tier %s", tier, command, got, findings, least)
					}
				}
			}
		}
		for _, command := range data {
			got, findings := decide(command)
			if got == "block" || strings.Contains(strings.Join(findings, "|"), gap1147UnreadReason) {
				t.Errorf("%s: %q is %s (%q), want no block and no unread-text finding", tier, command, got, findings)
			}
		}
	})
}
