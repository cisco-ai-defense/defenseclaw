// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// A filename pattern, brace or tilde word that is a source of cp, mv, install
// or ln is read as one plain name like a runtime-expanded word: what it
// expands to never changes which operand is the destination
// (rel-1-0-6:GAP-1053). A pattern in a destination or option-value position
// has no twin, and a call with nothing to replace has none either.
func TestDynamicOperandTwinsReadPatternSourcesOnly(t *testing.T) {
	const home = "/home/u"
	rows := []struct {
		name, command string
		want          []string
	}{
		{"cp-glob-source", "cp /tmp/*.cfg ~/.defenseclaw/config.yaml", []string{"cp /dev/null '/home/u/.defenseclaw/config.yaml'"}},
		{"cp-glob-source-absolute", "cp /tmp/*.cfg /home/u/.defenseclaw/config.yaml", []string{"cp /dev/null /home/u/.defenseclaw/config.yaml"}},
		{"cp-glob-source-login", "cp /tmp/*.cfg /home/$USER/.defenseclaw/config.yaml", []string{"cp /dev/null /home/u/.defenseclaw/config.yaml"}},
		{"cp-glob-source-login-braced", "cp ./*.yaml /home/${USER}/.defenseclaw/config.yaml", []string{"cp /dev/null /home/u/.defenseclaw/config.yaml"}},
		{"cp-force-glob-source", "cp -f * /d/f", []string{"cp -f /dev/null /d/f"}},
		{"mv-glob-source", "mv a* /d/f", []string{"mv /dev/null /d/f"}},
		{"install-glob-source", "install -m 600 /tmp/[ab].cfg /d/f", []string{"install -m 600 /dev/null /d/f"}},
		{"cp-several-sources", "cp /tmp/*.cfg /tmp/other /d/f", []string{"cp /dev/null /tmp/other /d/f"}},
		{"cp-target-directory-glob-source", "cp -t /d *.txt", []string{"cp -t /d /dev/null"}},
		{"cp-target-directory-long-glob-source", "cp --target-directory=/d *.txt", []string{"cp --target-directory=/d /dev/null"}},
		{"cp-pattern-and-runtime-sources", "cp *.txt $SRC /d/f", []string{"cp /dev/null /dev/null /d/f"}},
		{"cp-glob-destination", "cp a.txt /d/*.bak", nil},
		{"cp-glob-destination-with-glob-source", "cp *.txt /d/*.bak", nil},
		{"cp-glob-target-directory-value", "cp -t *.d a.txt", nil},
		{"cp-glob-target-directory-attached", "cp --target-directory=/d/* a.txt", nil},
		{"cp-glob-after-value-option", "cp -S *.x a.txt /d/f", nil},
		{"tee-glob-operand", "tee *.log", nil},
		{"ordinary-listing", "ls *.txt", nil},
		{"login-destination-alone", "cp a.txt /home/$USER/f", nil},
		{"no-pattern", "cp a.txt /d/f", nil},
	}
	for _, row := range rows {
		got := DynamicOperandTwins(row.command, home)
		if !slices.Equal(got, row.want) {
			t.Errorf("%s: DynamicOperandTwins(%q) = %q, want %q", row.name, row.command, got, row.want)
		}
	}
}
