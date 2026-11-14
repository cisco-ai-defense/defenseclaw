// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"
	"testing"
)

// TestSedInPlaceNameRule pins the paths a sed -i call writes: the edited
// file and the backup its suffix names, under GNU sed 4.9 and under BSD sed
// (macOS 15). Every row was run against the real programs in a scratch tree
// (evidence/rel-1-0-10/s7/sfx: gnu-sed-4.9-probe1.txt and -probe2.txt, and
// bsd-sed-macos-probe.txt; the id of the probe is in the "real" column). A
// reading that makes sed fail (BSD sed has no long options) writes nothing.
// rel-1-0-10:GAP-0414.
func TestSedInPlaceNameRule(t *testing.T) {
	for _, tc := range []struct {
		real, command string
		gnu, bsd      []string
	}{
		{"g1 b3", "sed -i.bak s/x/y/ f", []string{"f", "f.bak"}, []string{"f", "f.bak"}},
		{"g2 b3", "sed -i.bak s/x/y/ sub/f", []string{"sub/f", "sub/f.bak"}, []string{"sub/f", "sub/f.bak"}},
		{"g3 b14", "sed --in-place=.bak s/x/y/ sub/f", []string{"sub/f", "sub/f.bak"}, nil},
		{"g4", "sed --in=.bak s/x/y/ sub/f", []string{"sub/f", "sub/f.bak"}, nil},
		{"g5", "sed --i=.bak s/x/y/ sub/f", []string{"sub/f", "sub/f.bak"}, nil},
		{"h15", "sed --in-pl=.bak s/x/y/ f", []string{"f", "f.bak"}, nil},
		{"g6 b12", "sed -ni.bak s/x/y/ f", []string{"f", "f.bak"}, []string{"f", "f.bak"}},
		{"h7 b23", "sed -E -i.bak s/x/y/ f", []string{"f", "f.bak"}, []string{"f", "f.bak"}},
		{"h10", "sed -si.bak s/x/y/ f sub/f", []string{"f", "f.bak", "sub/f", "sub/f.bak"}, []string{"f", "f.bak", "sub/f", "sub/f.bak"}},
		{"g16", "sed -i.bak s/x/y/ f sub/f", []string{"f", "f.bak", "sub/f", "sub/f.bak"}, []string{"f", "f.bak", "sub/f", "sub/f.bak"}},
		{"h6", "sed -i.bak -e s/x/y/ f", []string{"f", "f.bak"}, []string{"f", "f.bak"}},
		{"h9", "sed --in-place=.bak --expression=s/x/y/ f", []string{"f", "f.bak"}, nil},
		{"h8 b31", "sed -i.bak -- s/x/y/ f", []string{"f", "f.bak"}, []string{"f", "f.bak"}},
		{"b22 g6", "sed -iE s/x/y/ f", []string{"f", "fE"}, []string{"f", "fE"}},

		// GNU: "*" becomes the operand as typed, directory included.
		{"g7 b7", "sed -ibak_* s/x/y/ f", []string{"f", "bak_f"}, []string{"f", "fbak_*"}},
		{"g8", "sed -ibak_* s/x/y/ sub/f", []string{"sub/f", "bak_sub/f"}, []string{"sub/f", "sub/fbak_*"}},
		{"g9 b8", "sed -ibak/* s/x/y/ f", []string{"f", "bak/f"}, []string{"f", "fbak/*"}},
		{"g11", "sed -i../other/bak/* s/x/y/ f", []string{"f", "../other/bak/f"}, []string{"f", "f../other/bak/*"}},
		{"g12 b16", "sed -i../other/* s/x/y/ f", []string{"f", "../other/f"}, []string{"f", "f../other/*"}},
		{"h1", "sed -i*_*.b s/x/y/ f", []string{"f", "f_f.b"}, []string{"f", "f*_*.b"}},
		{"h2", "sed -ibak/*_* s/x/y/ f", []string{"f", "bak/f_f"}, []string{"f", "fbak/*_*"}},
		{"g14", "sed -ibak/*.old s/x/y/ f", []string{"f", "bak/f.old"}, []string{"f", "fbak/*.old"}},
		{"g18 b15", "sed -i* s/x/y/ f", []string{"f", "f"}, []string{"f", "f*"}},
		{"g19", "sed -isub/* s/x/y/ f", []string{"f", "sub/f"}, []string{"f", "fsub/*"}},
		{"g20", "sed -i./* s/x/y/ sub/f", []string{"sub/f", "./sub/f"}, []string{"sub/f", "sub/f./*"}},
		{"h17", "sed -i/tmp/x_* s/x/y/ /abs/f", []string{"/abs/f", "/tmp/x_/abs/f"}, []string{"/abs/f", "/abs/f/tmp/x_*"}},
		{"h13", "sed --in-place=x/y/* s/x/y/ f", []string{"f", "x/y/f"}, nil},

		// GAP-0496 (cases HLR4-SFX-pfx-attached, -cluster, -long of the s7-hlrev4
		// review; real GNU sed 4.9 changed the keys file in each): the operand
		// is typed with a directory part, so "*" becomes "ssh/authorized_keys"
		// and the suffix "/home/u/.*" names /home/u/.ssh/authorized_keys. BSD
		// keeps "*" literal.
		{"HLR4-SFX-pfx-attached", "sed -i/home/u/.* s/x/y/ ssh/authorized_keys", []string{"ssh/authorized_keys", "/home/u/.ssh/authorized_keys"}, []string{"ssh/authorized_keys", "ssh/authorized_keys/home/u/.*"}},
		{"HLR4-SFX-pfx-cluster", "sed -ni/home/u/.* s/x/y/ ssh/authorized_keys", []string{"ssh/authorized_keys", "/home/u/.ssh/authorized_keys"}, []string{"ssh/authorized_keys", "ssh/authorized_keys/home/u/.*"}},
		{"HLR4-SFX-pfx-long", "sed --in-place=/home/u/.* s/x/y/ ssh/authorized_keys", []string{"ssh/authorized_keys", "/home/u/.ssh/authorized_keys"}, nil},
		{"HLR4-SFX-ctl", "sed -i s/x/y/ ssh/authorized_keys", []string{"ssh/authorized_keys"}, nil},

		// GNU: no suffix, no backup.
		{"g17", "sed -i s/x/y/ f", []string{"f"}, nil},
		{"h3", "sed --in-place s/x/y/ f", []string{"f"}, nil},
		{"h4", "sed --in-place= s/x/y/ f", []string{"f"}, nil},
		{"h5", "sed -i -e s/x/y/ f", []string{"f"}, []string{"f", "f-e"}},
		{"b28", "sed -i -- s/x/y/ f", []string{"f"}, []string{"f", "f--"}},

		// BSD: the suffix is the next word.
		{"b1", "sed -i .bak s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f", "f.bak"}},
		{"b2", "sed -i .bak s/x/y/ sub/f", []string{"s/x/y/", "sub/f"}, []string{"sub/f", "sub/f.bak"}},
		{"b4", "sed -i '' s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f"}},
		{"b29", "sed -i '' -e s/x/y/ f", []string{"f"}, []string{"f"}},
		{"b5", "sed -i -e s/x/y/ sub/f", []string{"sub/f"}, []string{"sub/f", "sub/f-e"}},
		{"b6", "sed -i -E s/x/y/ f", []string{"f"}, []string{"f", "f-E"}},
		{"b11", "sed -I .bak s/x/y/ f", nil, []string{"f", "f.bak"}},
		{"b12", "sed -ni .bak s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f", "f.bak"}},
		{"b24", "sed -Ei .bak s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f", "f.bak"}},
		{"b30", "sed -l -i .bak s/x/y/ f", nil, []string{"f", "f.bak"}},
		{"b20", "sed -i .bak -e s/x/y/ f sub/f", []string{"f", "sub/f"}, []string{"f", "f.bak", "sub/f", "sub/f.bak"}},
		{"b7", "sed -i bak_* s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f", "fbak_*"}},
		{"b10", "sed -i ../other/bak/ s/x/y/ f", []string{"s/x/y/", "f"}, []string{"f", "f../other/bak/"}},
		{"b13", "sed -in .bak s/x/y/ f", []string{"s/x/y/", "s/x/y/n", "f", "fn"}, []string{"s/x/y/", "s/x/y/n", "f", "fn"}},

		// Not in place, or no file operand.
		{"-", "sed -n s/x/y/p f", nil, nil},
		{"b21", "sed -i.bak s/x/y/", nil, nil},
		{"-", "sed -e s/x/y/ f", nil, nil},
	} {
		words := strings.Fields(tc.command)
		for i, word := range words {
			if word == "''" {
				words[i] = ""
			}
		}
		if got := sedGNUWrites(words); !slices.Equal(got, tc.gnu) {
			t.Errorf("%s (%s) GNU writes = %q, want %q", tc.command, tc.real, got, tc.gnu)
		}
		if got := sedBSDWrites(words); !slices.Equal(got, tc.bsd) {
			t.Errorf("%s (%s) BSD writes = %q, want %q", tc.command, tc.real, got, tc.bsd)
		}
		want := append(slices.Clone(tc.gnu), tc.bsd...)
		if got := sedInPlaceWrites(words); !slices.Equal(got, want) {
			t.Errorf("%s (%s) union writes = %q, want %q", tc.command, tc.real, got, want)
		}
	}
}
