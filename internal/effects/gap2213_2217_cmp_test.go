// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestGAP2213CmpPrintOptionsShowTheRead: cmp is a summary reader (it names
// the first differing byte) unless -l / --verbose, -b / --print-bytes or
// BSD -x makes it print the bytes it compares; then the read reaches the
// call's output. Red at det111/t23e6-merge f6e151801a: Program.Summary hid
// every cmp read whatever its options.
func TestGAP2213CmpPrintOptionsShowTheRead(t *testing.T) {
	const key = "/home/u/.ssh/id_rsa"
	for _, bsd := range []bool{false, true} {
		opts := Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u/proj",
			Env: map[string]string{"HOME": "/home/u"}, BSDUserland: bsd}
		for _, tc := range []struct {
			command string
			shown   bool
		}{
			{"cmp -l " + key + " /dev/zero", true},
			{"cmp -b " + key + " /dev/zero", true},
			{"cmp -bl " + key + " /dev/zero", true},
			{"cmp -x " + key + " /dev/zero", true},
			{"cmp --verbose " + key + " /dev/zero", true},
			{"cmp --print-bytes " + key + " /dev/zero", true},
			{"cmp --verb " + key + " /dev/zero", true},
			{"cmp -n 64 -l " + key + " /dev/zero", true},
			{"cmp " + key + " /dev/zero -l", true},
			// The benign twins: the summary forms print no byte of the file.
			{"cmp " + key + " /dev/zero", false},
			{"cmp -s " + key + " /dev/zero", false},
			{"cmp --quiet " + key + " /dev/zero", false},
			{"cmp -n 64 " + key + " /dev/zero", false},
		} {
			result := Extract(Call{Surface: SurfaceShell, Command: tc.command}, opts)
			found := false
			for _, e := range result.Effects {
				if e.Kind != KindRead || e.Target.Path != key {
					continue
				}
				found = true
				if e.Shown != tc.shown {
					t.Errorf("bsd=%t %q: read shown=%t, want %t", bsd, tc.command, e.Shown, tc.shown)
				}
			}
			if !found {
				t.Errorf("bsd=%t %q: the read was not extracted", bsd, tc.command)
			}
		}
	}
	if SummaryReader("cmp") {
		t.Error("SummaryReader(cmp) = true: its print options show the bytes")
	}
	for _, digest := range []string{"sha256sum", "md5sum", "cksum", "wc"} {
		if !SummaryReader(digest) {
			t.Errorf("SummaryReader(%s) = false, want true", digest)
		}
	}
}

// TestGAP2217CmpLongOptionsKeepTheReadKnown: the cmp row lists its long
// options with their value arity, so a long spelling reads as Known as its
// short twin does. Red at det111/t23e6-merge f6e151801a: every long option
// was an unknown flag and the reads lost their Known role.
func TestGAP2217CmpLongOptionsKeepTheReadKnown(t *testing.T) {
	const key = "/home/bob/.ssh/id_ed25519"
	opts := Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	for _, command := range []string{
		"cmp --verbose " + key + " /dev/zero",
		"cmp --print-bytes " + key + " /dev/zero",
		"cmp -l --bytes=64 " + key + " /dev/zero",
		"cmp -l --bytes 64 " + key + " /dev/zero",
		"cmp --ignore-initial=8 -b " + key + " /dev/zero",
		"cmp -i 8 -l " + key + " /dev/zero",
		"cmp --silent " + key + " /dev/zero",
		"cmp -l " + key + " /dev/zero",
	} {
		result := Extract(Call{Surface: SurfaceShell, Command: command}, opts)
		reads := 0
		for _, e := range result.Effects {
			if e.Kind != KindRead {
				continue
			}
			reads++
			if e.Target.Path == key && (e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown) {
				t.Errorf("%q: read target=%s role=%s, want known/known", command, e.TargetState, e.RoleState)
			}
		}
		// The key and /dev/zero; a flag value (64, 8) is never a file read.
		if reads != 2 {
			t.Errorf("%q: %d reads, want 2 (the two operands)", command, reads)
		}
		if len(result.Unknowns) != 0 {
			t.Errorf("%q: %d unknowns, want none", command, len(result.Unknowns))
		}
	}
}
