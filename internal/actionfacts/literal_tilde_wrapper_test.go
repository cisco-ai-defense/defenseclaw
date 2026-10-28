// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// Round m (1b7708e7 review) and GAP-1455: a quoted or escaped tilde, also
// after a wrapper that passes argv on as written, is a literal directory
// "~" below the cwd. An unquoted tilde is still the active home.
func TestR104RoundMStaticTildeIsLiteralThroughWrappers(t *testing.T) {
	const home = "/sandbox"
	resolvedInHome := func(command string) []string {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/work/app", ActiveHome: home, DialectHint: DialectPOSIX})
		var hits []string
		for _, path := range facts.Paths {
			if path.Access != PathAccessRead && strings.HasPrefix(path.Resolved, home+"/.ssh/") {
				hits = append(hits, path.Resolved)
			}
		}
		return hits
	}
	for _, command := range []string{
		`mv payload \~/.ssh/authorized_keys`,
		`cp payload \~/.ssh/authorized_keys`,
		`command cp payload '~/.ssh/authorized_keys'`,
		`command -p cp payload "~/.ssh/authorized_keys"`,
		`env cp payload '~/.ssh/authorized_keys'`,
		`env -i cp payload '~/.ssh/authorized_keys'`,
		`exec cp payload '~/.ssh/authorized_keys'`,
		`sudo cp payload '~/.ssh/authorized_keys'`,
		`sudo -n -u root cp payload "~/.ssh/authorized_keys"`,
		`sudo -- mv payload \~/.ssh/authorized_keys`,
		`command env sudo cp payload '~/.ssh/authorized_keys'`,
	} {
		if hits := resolvedInHome(command); len(hits) != 0 {
			t.Errorf("%s: write facts in the home %v, want the literal ./~ name", command, hits)
		}
	}
	for _, command := range []string{
		`cp payload ~/.ssh/authorized_keys`,
		`mv payload ~/.ssh/authorized_keys`,
		`cat payload >> ~/.ssh/authorized_keys`,
	} {
		if hits := resolvedInHome(command); len(hits) == 0 {
			t.Errorf("%s: no write fact in the home, want %s/.ssh/authorized_keys", command, home)
		}
	}
}
