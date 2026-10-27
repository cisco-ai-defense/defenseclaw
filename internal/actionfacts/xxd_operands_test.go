// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// GAP-2302: xxd's second operand is its output file.
func TestXxdOperandsNameTheOutputFile(t *testing.T) {
	for _, row := range []struct {
		args   []string
		want   []string
		writes bool
	}{
		{[]string{"/dev/null", "hook.sh"}, []string{"/dev/null", "hook.sh"}, true},
		{[]string{"-r", "in.hex", "out.bin"}, []string{"in.hex", "out.bin"}, true},
		{[]string{"-c", "8", "-s", "-16", "in", "out"}, []string{"in", "out"}, true},
		{[]string{"-cols", "8", "{}"}, []string{"{}"}, false},
		{[]string{"-c8", "-l64", "in"}, []string{"in"}, false},
		{[]string{"in"}, []string{"in"}, false},
		{[]string{"in", "-"}, []string{"in", "-"}, true},
		{[]string{"-s"}, nil, true},
		// xxd matches options by prefix (pod check10): these take the
		// next word as the value, so /dev/null is INFILE.
		{[]string{"-skip", "0", "/dev/null", "hook.sh"}, []string{"/dev/null", "hook.sh"}, true},
		{[]string{"-length", "4", "/dev/null", "hook.sh"}, []string{"/dev/null", "hook.sh"}, true},
		{[]string{"-colsx", "4", "/dev/null", "config.yaml"}, []string{"/dev/null", "config.yaml"}, true},
		{[]string{"-namex", "foo", "/dev/null", "config.yaml"}, []string{"/dev/null", "config.yaml"}, true},
		{[]string{"-groupsizex", "2", "-offsetx", "0", "/dev/null", "t"}, []string{"/dev/null", "t"}, true},
		{[]string{"--seek", "0", "--", "/dev/null", "t"}, []string{"/dev/null", "t"}, true},
		{[]string{"-skip", "0", "in"}, []string{"in"}, false},
		{[]string{"-cx", "in"}, []string{"in"}, false},
	} {
		got, _ := xxdPositionals(row.args)
		if !slices.Equal(got, row.want) || xxdWritesOutput(row.args) != row.writes {
			t.Errorf("xxd %q: positionals %q writes %v, want %q %v", row.args, got, xxdWritesOutput(row.args), row.want, row.writes)
		}
	}
}
