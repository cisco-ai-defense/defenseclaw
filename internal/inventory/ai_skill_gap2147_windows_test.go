// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2147: a managed skill folder is one only administrators can change and
// so is everything in it that the walk opens: a subfolder or file that kept a
// user's access entry (an administrator copy from a user's location) makes it
// user content.
func TestGAP2147WindowsManagedNeedsEveryEntryAdminOnly(t *testing.T) {
	admins := gap2008Administrators(t)
	base := t.TempDir()
	adminList := gap2008AdminOnly + gap2008UsersRead
	for _, tc := range []struct {
		name    string
		child   string // access list of the child folder
		file    string // access list of the file in it
		managed bool
	}{
		{"every entry admin only", adminList, adminList, true},
		{"a file users may write", adminList, adminList + "(A;;0x2;;;BU)", false},
		{"a folder users may add to", adminList + "(A;;0x6;;;BU)", adminList, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skill := filepath.Join(base, filepath.Base(t.Name()))
			child := filepath.Join(skill, "scripts")
			file := filepath.Join(child, "run.txt")
			if err := os.MkdirAll(child, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: s\n---\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			gap2008Secure(t, filepath.Join(skill, "SKILL.md"), admins, adminList)
			gap2008Secure(t, file, admins, tc.file)
			gap2008Secure(t, child, admins, tc.child)
			gap2008Secure(t, skill, admins, adminList)
			s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: t.TempDir()}}
			facts := s.skillFacts(skill, false)
			if facts == nil || facts.ContentStatus != SkillContentOK || (facts.Scope == SkillScopeManaged) != tc.managed {
				t.Fatalf("facts %+v, want content ok and managed %t", facts, tc.managed)
			}
		})
	}
}
