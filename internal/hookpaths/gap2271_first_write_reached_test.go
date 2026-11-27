// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestGAP2271FirstWriteReachedIsTheFullReadingsFirst: the guard's reader
// (RegistrationFirstWriteReached) stops narrowing at the first member and
// reads the set-free write operands once (registrationWrites); it names the
// member the full reading (RegistrationWriteReached) names first, for every
// order of the names, and nothing where the full reading names nothing
// (rel-1-0-10:GAP-2271).
func TestGAP2271FirstWriteReachedIsTheFullReadingsFirst(t *testing.T) {
	const home = "/home/alice"
	names := []string{home + "/.a", home + "/.b", home + "/.c", home + "/p/.d", "relative/.e", home + "/p/q/.f"}
	var long strings.Builder
	long.WriteString("cd p\n$CMD\n")
	for i := range 300 {
		fmt.Fprintf(&long, ":%d\n", i)
	}
	long.WriteString("echo x > ../.c")
	commands := []string{
		"echo x > /home/alice/.b; echo y > /home/alice/.a",
		"cd /home/alice && cp f .b",
		"cd p; $CMD; echo x > ../.c",
		"cat f | while read l; do echo $l > /home/alice/.c; done",
		"sed -i s/a/b/ /home/alice/.b",
		"tee /home/alice/.a < f",
		"mv f /home/alice/.c && rm /home/alice/.a",
		"cd p && touch .d && cd q && touch .f",
		"echo x > /tmp/other",
		"for f in .a .b; do : > $f; done",
		"x=.c; echo y > $x",
		"ls",
		"",
		long.String(),
	}
	orders := [][]string{names, slices.Clone(names)}
	slices.Reverse(orders[1])
	for _, command := range commands {
		for _, cwd := range []string{home, home + "/p"} {
			for _, order := range orders {
				want := ""
				if full := RegistrationWriteReached(command, cwd, home, order); len(full) != 0 {
					want = full[0]
				}
				if got := RegistrationFirstWriteReached(command, cwd, home, order); got != want {
					t.Errorf("%.40q in %s: first %q, the full reading %q", command, cwd, got, want)
				}
			}
		}
	}
}
