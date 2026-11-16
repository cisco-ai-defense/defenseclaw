// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

func TestR104CopyProgramAndLinkOptionsShareOperandProof(t *testing.T) {
	cwd := t.TempDir()
	for _, test := range []struct {
		name string
		argv []string
		want string
	}{
		{"direct", []string{"cp", "source", "copy"}, filepath.Join(cwd, "copy")},
		{"multicall", []string{"busybox", "cp", "source", "copy"}, filepath.Join(cwd, "copy")},
		{"other multicall", []string{"toybox", "cp", "-t", "copies", "source"}, filepath.Join(cwd, "copies")},
		{"unrelated applet", []string{"busybox", "echo", "source", "copy"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsCopyProgram(test.argv); got != (test.want != "") {
				t.Fatalf("copy program = %v, want %v", got, test.want != "")
			}
			if got := CopyDestination(test.argv, cwd); got != test.want {
				t.Fatalf("copy destination = %q, want %q", got, test.want)
			}
		})
	}

	links := shellLinks{known: true}
	if !links.add("cp", []string{"--symbolic-link", "--target-directory", "copies", "source"}, cwd) {
		t.Fatal("valid copy link options were not parsed")
	}
	wantAlias := filepath.Join(cwd, "copies", "source")
	if len(links.aliases) != 1 || links.aliases[0].name != wantAlias {
		t.Fatalf("link aliases = %+v, want %q", links.aliases, wantAlias)
	}
	if links.add("cp", []string{"--link", "--unrecognized", "source", "copy"}, cwd) {
		t.Fatal("unknown copy option was treated as a proved link")
	}
	if links.add("cp", []string{"--link=value", "source", "copy"}, cwd) {
		t.Fatal("copy flag with an operand was treated as a proved link")
	}
}
