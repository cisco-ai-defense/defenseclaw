// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestPatchEnvelopeRepeatedTargetIsReadBlockByBlock pins that a file an
// envelope names in more than one block is a complete patch whose blocks are
// all read: each block is a change of its own, however the name is spelled,
// and the loader-preload proof holds when either block holds the library.
func TestPatchEnvelopeRepeatedTargetIsReadBlockByBlock(t *testing.T) {
	const (
		library = "+/usr/local/lib/liblogger.so\n"
		comment = "+# no libraries are preloaded\n"
	)
	add := func(path, body string) string { return "*** Add File: " + path + "\n" + body }
	for _, c := range []struct {
		name, text string
		proof      bool
	}{
		{"add twice, library second", add("/etc/ld.so.preload", comment) + add("/etc/ld.so.preload", library), true},
		{"add twice, library first", add("/etc/ld.so.preload", library) + add("/etc/ld.so.preload", comment), true},
		{"add twice, dot spelling", add("/etc/ld.so.preload", comment) + add("/etc/./ld.so.preload", library), true},
		{"add twice, backslash spelling", add("/etc/ld.so.preload", comment) + add("\\etc\\ld.so.preload", library), true},
		{"update twice", "*** Update File: /etc/ld.so.preload\n@@\n" + comment + "*** Update File: /etc/ld.so.preload\n@@\n" + library, true},
		{"add then delete (no file left to prove)", add("/etc/ld.so.preload", library) + "*** Delete File: /etc/ld.so.preload\n", false},
		{"ordinary file twice", add("/srv/app/a.txt", "+one\n") + add("/srv/app/a.txt", "+two\n"), false},
		{"ordinary add then delete", add("/srv/app/a.txt", "+one\n") + "*** Delete File: /srv/app/a.txt\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := "*** Begin Patch\n" + c.text + "*** End Patch"
			input, facts := paddedPatchCall(t, "apply_patch", "command", text)
			if facts.Parse.Status != StatusComplete {
				t.Fatalf("status %s, want complete", facts.Parse.Status)
			}
			if len(facts.Paths) == 0 {
				t.Fatalf("no path facts")
			}
			if got := ExactGlobalLDPreloadFileWrite(input, facts); got != c.proof {
				t.Fatalf("loader-preload proof = %v, want %v", got, c.proof)
			}
		})
	}
}

// TestPatchEnvelopeRepeatedTargetOverProofBoundIsStrictOnly pins that blocks
// of one content-rule file that are each read, but make a text past the proof
// bound together, are no unread block of the default reading
// (OverLimitWriteElidedContentTarget) and are reported by the combined reading
// alone; a block that is itself past the bound stays unread, and an ordinary
// file is never a target.
func TestPatchEnvelopeRepeatedTargetOverProofBoundIsStrictOnly(t *testing.T) {
	line := "+# no libraries are preloaded on this host\n"
	half := strings.Repeat(line, (maxCommandBytes*5/8)/len(line))
	whole := strings.Repeat(line, (maxCommandBytes*5/4)/len(line))
	add := func(path, body string) string { return "*** Add File: " + path + "\n" + body }
	for _, c := range []struct {
		name, text       string
		unread, combined bool
	}{
		{"two readable blocks", add("/etc/ld.so.preload", half) + add("/etc/ld.so.preload", half), false, true},
		{"two readable blocks, dot spelling", add("/etc/ld.so.preload", half) + add("/etc/./ld.so.preload", half), false, true},
		{"two readable blocks of daemon.json", add("/etc/docker/daemon.json", half) + add("/etc/docker/daemon.json", half), false, true},
		{"one readable block", add("/etc/ld.so.preload", half), false, false},
		{"two small blocks", add("/etc/ld.so.preload", "+# a\n") + add("/etc/ld.so.preload", "+# b\n"), false, false},
		{"one block past the bound", add("/etc/ld.so.preload", whole), true, false},
		{"two readable blocks of an ordinary file", add("/srv/app/a.txt", half) + add("/srv/app/a.txt", half), false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := "*** Begin Patch\n" + c.text + "*** End Patch"
			input, facts := paddedPatchCall(t, "apply_patch", "command", text)
			if _, got := OverLimitWriteElidedContentTarget(input, facts, nil); got != c.unread {
				t.Fatalf("unread block = %v, want %v", got, c.unread)
			}
			if _, got := OverLimitCombinedPatchContentTarget(input, facts, nil); got != c.combined {
				t.Fatalf("combined text unread = %v, want %v", got, c.combined)
			}
		})
	}
}
