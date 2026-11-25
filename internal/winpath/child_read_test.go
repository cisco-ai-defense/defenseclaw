// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"io/fs"
	"testing"
)

func TestReadChildNameIsOneDirectoryEntry(t *testing.T) {
	for _, name := range []string{"SKILL.md", "scripts", "my file.txt", "日本語.md"} {
		if err := validateReadChildName(name); err != nil {
			t.Errorf("ordinary name %q: %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "dir/file", `dir\file`, "file:stream", "name\x00suffix"} {
		if err := validateReadChildName(name); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("non-component %q: %v", name, err)
		}
	}
}

func TestReadChildLinkUsesGoWindowsTargetSpelling(t *testing.T) {
	for _, tc := range []struct {
		name string
		link reparseLink
		want string
	}{
		{"relative", reparseLink{target: `..\shared\SKILL.md`, relative: true}, `..\shared\SKILL.md`},
		{"drive", reparseLink{target: `\??\C:\skills`}, `C:\skills`},
		{"share", reparseLink{target: `\??\UNC\server\share\skills`}, `\\server\share\skills`},
		{"volume", reparseLink{target: `\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\skills`}, `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\skills`},
		{"unchanged", reparseLink{target: `C:\skills`}, `C:\skills`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizedReadLinkTarget(tc.link); got != tc.want {
				t.Fatalf("target = %q, want %q", got, tc.want)
			}
		})
	}
}
