// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A publication over a file whose access list inherits from its folder keeps
// the access list it gave the new file. The replaced file, once renamed out
// of the folder, reads back with its inherited entries as explicit ones; that
// is not an administrator's change at the swap and must not be put on the
// published file (it took a Users read entry that a publication added away).
func TestPublishSharedFileKeepsTheAccessListOverAnInheritingFile(t *testing.T) {
	for _, test := range []struct {
		name      string
		grant     bool
		wantUsers bool
	}{
		{name: "kept access list"},
		{name: "kept access list with a Users read entry added", grant: true, wantUsers: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "requirements.toml")
			if err := os.WriteFile(path, []byte("a = 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			metadata, err := ReadPathMetadata(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(metadata.SecurityDescriptor, ";ID;") {
				t.Fatalf("fixture: %s inherits no entries: %s", path, metadata.SecurityDescriptor)
			}
			base := SharedFile{Path: path, Exists: true, Data: []byte("a = 1\n"), Metadata: metadata}
			var want FileMetadata
			_, swapped, err := PublishSharedFile(SharedPublish{
				Base: base, CompareMetadata: true, Data: []byte("b = 1\n"), Limit: 1 << 20,
				TempPattern: ".swap-inherit-*",
				Protect: func(temp string) error {
					if err := ApplyFileMetadata(temp, metadata); err != nil {
						return err
					}
					if test.grant {
						if err := GrantUsersRead(temp); err != nil {
							return err
						}
					}
					want, err = ReadPathMetadata(temp)
					return err
				},
			})
			if err != nil || !swapped {
				t.Fatalf("publish: swapped=%t err=%v", swapped, err)
			}
			got, err := ReadPathMetadata(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("published file metadata = %+v, want what the publication gave it: %+v", got, want)
			}
			if test.wantUsers != (UsersCanRead(got) == nil) {
				t.Fatalf("Users read on the published file = %v, want %t", UsersCanRead(got), test.wantUsers)
			}
		})
	}
}
