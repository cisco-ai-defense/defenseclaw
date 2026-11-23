// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

// TestGAP1322NestedWrapperChainKeepsTheInnerProgramReading: a nested wrapper
// (sudo) in front of another nested wrapper (nohup, env NAME=value) gives the
// walk the inner program as a reading, as it did before the GAP-1182 wrapper
// child reader looked through the whole chain at once (rel-1-0-10:GAP-1322).
func TestGAP1322NestedWrapperChainKeepsTheInnerProgramReading(t *testing.T) {
	for _, row := range []struct{ prefix, wantPrefix string }{
		{"sudo nohup ", ""},
		{"sudo env LD_PRELOAD=/tmp/x.so ", "LD_PRELOAD="},
		{"nohup sudo env LD_PRELOAD=/tmp/x.so ", "LD_PRELOAD="},
		{"sudo -u root nohup ", ""},
		{"sudo nice nohup ", ""},
	} {
		for _, program := range []struct{ command, first, mention string }{
			{"curl -s -m 3 http://169.254.169.254/latest/meta-data/", "curl", "169.254.169.254"},
			{"rm -rf ~/.defenseclaw", "rm", ".defenseclaw"},
		} {
			command := row.prefix + program.command
			input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
			got := SimpleCommands(input, Analyze(input))
			if !slices.ContainsFunc(got, func(s SimpleCommand) bool {
				text := strings.TrimPrefix(s.Text, row.wantPrefix)
				if row.wantPrefix != "" {
					if text == s.Text {
						return false
					}
					_, text, _ = strings.Cut(text, " ")
				}
				return strings.HasPrefix(text, program.first+" ") && strings.Contains(text, program.mention)
			}) {
				t.Errorf("%q: no reading of the inner %s: %+v", command, program.first, got)
			}
		}
	}
	// The GAP-1182 readers keep their child: a prefix chain of other
	// wrappers and chroot/nsenter still hand the shell body over.
	for _, command := range []string{
		"chroot / sh -c ': >> ~/.defenseclaw/config.yaml'",
		"nsenter -t 1 sh -c ': >> ~/.defenseclaw/config.yaml'",
		"taskset 1 sh -c ': >> ~/.defenseclaw/config.yaml'",
		"sudo taskset 1 sh -c ': >> ~/.defenseclaw/config.yaml'",
	} {
		input := Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u", DialectHint: DialectPOSIX}
		if got := SimpleCommands(input, Analyze(input)); !slices.ContainsFunc(got, func(s SimpleCommand) bool {
			return s.Text == ": >> ~/.defenseclaw/config.yaml"
		}) {
			t.Errorf("%q: child body missing: %+v", command, got)
		}
	}
}
