// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// set -e, set -u, set -x and set -o pipefail change no glob option, so a call
// that begins with them keeps the resolver's reading of its glob words; set -f,
// set -B, set -o noglob and set -o posix may change them (rel-1-0-10:GAP-0350,
// GAP-0018: the aidev owner traces begin many commands with set -e).
func TestSetThatChangesNoGlobOptionIsNotAnOptionChange(t *testing.T) {
	for _, test := range []struct {
		command string
		change  bool
	}{
		{"set -e; cp a.txt b/*.sh", false},
		{"set -eu; cp a b/*", false},
		{"set -euo pipefail\ncp a b/*", false},
		{"set -x && cp a b/*", false},
		{"set +e; cp a b/*", false},
		{"set -f; cp a b/*", true},
		{"set +f; cp a b/*", true},
		{"set -euf; cp a b/*", true},
		{"set -o noglob; cp a b/*", true},
		{"set +B; cp a b/*", true},
		{"set -o posix; cp a b/*", true},
		{"shopt -s extglob; cp a b/*", true},
		{"source ./env.sh; cp a b/*", true},
		{"eval \"$X\"; cp a b/*", true},
	} {
		if got := globOptionsMayChange(test.command); got != test.change {
			t.Errorf("%q: globOptionsMayChange = %t, want %t", test.command, got, test.change)
		}
	}
}
