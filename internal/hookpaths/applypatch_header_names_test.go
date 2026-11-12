// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"reflect"
	"testing"
)

// ApplyPatchCommandHeaderNames lists the headers of the envelopes a shell
// command holds, in a function body as at the top level, and none for a
// command that holds no envelope or a name with no raw spelling to walk.
func TestApplyPatchCommandHeaderNamesReadsFunctionBodies(t *testing.T) {
	patch := func(name string) string {
		return "apply_patch <<\"EOF\"\n*** Begin Patch\n*** Add File: " + name + "\n+x\n*** End Patch\nEOF\n"
	}
	for _, row := range []struct {
		name    string
		command string
		want    []string
	}{
		{"top level", patch("a/../b"), []string{"a/../b"}},
		{"function body", "f() {\n" + patch("a/../b") + "}\nf\n", []string{"a/../b"}},
		{"uncalled function body", "f() {\n" + patch("a/../b") + "}\ntrue\n", []string{"a/../b"}},
		{"home form", patch("~/a/../b"), nil},
		{"variable form", patch("$X/a"), nil},
		{"no envelope", "echo a/../b\n", nil},
		{"empty", "", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := ApplyPatchCommandHeaderNames(row.command); !reflect.DeepEqual(got, row.want) {
				t.Fatalf("names = %q, want %q", got, row.want)
			}
		})
	}
}
