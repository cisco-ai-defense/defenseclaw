// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path"
	"strings"
	"testing"
)

// pairs is every reading of readings, by text and folder.
func (readings *guestShellReadings) pairs() map[guestShellReading]bool {
	if readings == nil {
		return nil
	}
	out := map[guestShellReading]bool{}
	for text, lists := range readings.texts {
		for _, at := range lists {
			for _, dir := range readings.lists[at] {
				out[guestShellReading{text, dir}] = true
			}
		}
	}
	return out
}

// TestGAP2226OwnShellReadingsHasEveryPair pins that has answers exactly the
// pairs the walk read (rel-1-0-10:GAP-2226), short lists and set-backed
// long ones alike, and no other text or folder.
func TestGAP2226OwnShellReadingsHasEveryPair(t *testing.T) {
	home := "/home/alice"
	var long strings.Builder
	long.WriteString("cd .cache\n$CMD\n")
	for i := range 40 {
		fmt.Fprintf(&long, "cd d%d\ntouch f%d\n", i, i%7)
	}
	long.WriteString("ls\ncd ../.ssh || exit\necho k >> authorized_keys")
	for _, command := range []string{
		long.String(),
		"cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ntouch f0\nls",
		"$CMD\ncd ../.ssh || exit\necho k >> authorized_keys",
		"cd a && $CMD && cd b; ls; ls",
	} {
		readings := guestOwnShellFolders(command, home, home)
		pairs := readings.pairs()
		if len(pairs) == 0 {
			t.Fatalf("%q: no readings", command)
		}
		texts := map[string]bool{"nope": true}
		dirs := map[string]bool{"/nope": true, home + "/.cache/x": true}
		for pair := range pairs {
			texts[pair.text], dirs[pair.dir] = true, true
		}
		for text := range texts {
			for dir := range dirs {
				if got, want := readings.has(text, dir), pairs[guestShellReading{text, dir}]; got != want {
					t.Errorf("%q: has(%q, %q) = %v, want %v", command, text, dir, got, want)
				}
			}
		}
	}
	var none *guestShellReadings
	if none.has("ls", home) {
		t.Error("a nil reading has a pair")
	}
}

// TestGAP2226CDJoinCleanIsCDJoin pins guestCDJoinClean to guestCDJoin over
// clean bases, and its targets to clean folders, the walks' invariant.
func TestGAP2226CDJoinCleanIsCDJoin(t *testing.T) {
	var bases []string
	for _, base := range []string{"/", "/a", "/a/b.c/.d", "/a/...", "/.ssh", "/home/alice/.cache/s0/s1", "/x y", "rel"} {
		if base != "rel" && path.Clean(base) != base {
			t.Fatalf("base %q is not clean", base)
		}
		bases = append(bases, base)
	}
	for _, operand := range []string{"d5", ".ssh", "..x", "...", "a b", "x/y", "./x", "../x", ".", "..", "x/", "/abs", "/a/../b", "~", "~/d", "~/../x", ""} {
		for _, home := range []string{"/home/alice", "rel"} {
			got := guestCDJoinClean(operand, bases, home)
			if want := guestCDJoin(operand, bases, home); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("guestCDJoinClean(%q, home %q) = %q, guestCDJoin %q", operand, home, got, want)
			}
			for _, target := range got {
				if path.Clean(target) != target {
					t.Errorf("guestCDJoinClean(%q) made %q, not clean", operand, target)
				}
			}
		}
	}
}
