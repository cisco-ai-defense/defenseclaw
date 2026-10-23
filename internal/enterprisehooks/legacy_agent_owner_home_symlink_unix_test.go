// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// GAP-0939: the owner token of a symlinked home took the device and inode
// of the home the symlink points at, but the creation time of the symlink
// itself. A home recreated behind the symlink with a reused inode then kept
// the token, and the account given the uid next inherited the earlier
// account's agent rows. The token now proves one object: the followed
// home, through the home's symlink or a symlinked parent alike.
func TestLegacyAgentOwnerTokenOfASymlinkedHomeIsItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-alice")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	want := LegacyAgentOwnerToken("", target)
	if strings.Count(want, ":") < 3 {
		t.Skipf("the file system of %s keeps no creation time (token %q)", root, want)
	}
	// The symlinks are created later, so their own creation times differ.
	time.Sleep(20 * time.Millisecond)
	link := filepath.Join(root, "alice")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "homes")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{link, filepath.Join(parent, "alice"), filepath.Join(parent, "real-alice")} {
		if got := LegacyAgentOwnerToken("", home); got != want {
			t.Errorf("token of %s = %q; want the token of the home it names, %q", home, got, want)
		}
	}
	// A symlink to something that is not a directory proves nothing.
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "file-home")
	if err := os.Symlink(file, fileLink); err != nil {
		t.Fatal(err)
	}
	if got := LegacyAgentOwnerToken("", fileLink); got != "" {
		t.Errorf("token of a symlink to a file = %q; want none", got)
	}
}

// Review of r104 Q-identity (continuation 3, loop round 2): the 1.0.4
// builds before the GAP-0939 fix (r104 trains t7 to t10) wrote the owner
// token of a symlinked home with the symlink's own creation time. This
// build writes the creation time of the directory the symlink names, so
// after the guardian rewrote the account's identity record the immutable
// map no longer matched it, and its 1.0.x agents entry was unbound for
// good. The guardian now gives the record the token the map holds while it
// is the earlier proof of this same home, and the directory it names was
// created before the map: a directory created again behind the symlink
// after the map, on the freed inode, is another account's.
func TestMapWithTheSymlinkProofBeforeTheFixKeepsItsAccount(t *testing.T) {
	for _, tc := range []struct {
		name string
		// symlink: the home is a symlink to the directory.
		symlink bool
		// after: the directory is created after the map was written.
		after bool
		// user is the account the map records for the uid ("alice" when
		// unset).
		user string
		// current: the map holds the token of this build.
		current bool
		// migrated: the record carries the token of the map.
		migrated bool
	}{
		{name: "a map written before the fix", symlink: true, migrated: true},
		{name: "the directory was created again after the map", symlink: true, after: true},
		{name: "the map records another account for the uid", symlink: true, user: "bob"},
		{name: "a map written by this build", symlink: true, current: true},
		{name: "a home that is not a symlink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, root := t.TempDir(), t.TempDir()
			at := time.Now()
			if tc.after {
				time.Sleep(50 * time.Millisecond)
			}
			home := filepath.Join(root, "real-alice")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.symlink {
				// The symlink is created later, so its own creation time
				// differs from the directory's.
				time.Sleep(20 * time.Millisecond)
				link := filepath.Join(root, "alice")
				if err := os.Symlink(home, link); err != nil {
					t.Fatal(err)
				}
				home = link
			}
			if !tc.after {
				at = time.Now()
			}
			before, now := ownerTokenBeforeSymlinkFix(t, home), LegacyAgentOwnerToken("files", home)
			if strings.Count(now, ":") < 3 || strings.Count(before, ":") < 3 {
				t.Skipf("the file system of %s keeps no creation time (tokens %q, %q)", root, before, now)
			}
			if tc.symlink == (before == now) {
				t.Fatalf("token before the fix %q, now %q; want them to differ only for a symlinked home", before, now)
			}
			recorded, user := before, "alice"
			if tc.current {
				recorded = now
			}
			if tc.user != "" {
				user = tc.user
			}
			if _, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{501: {User: user, Token: recorded}}, at, nil); err != nil {
				t.Fatal(err)
			}
			previousCollect, previousHome := identitySpoolCollect, identitySpoolAccountHome
			t.Cleanup(func() { identitySpoolCollect, identitySpoolAccountHome = previousCollect, previousHome })
			identitySpoolAccountHome = func(int) string { return home }
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
				return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: "alice", UpdatedAt: now, AccountIncarnation: "files"}, nil
			}
			if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: 501, User: "alice"}}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			record, err := ReadIdentitySpoolRecord(dir, "501", nil)
			if err != nil {
				t.Fatal(err)
			}
			want := now
			if tc.migrated {
				want = recorded
			}
			if record.LegacyOwnerToken != want {
				t.Fatalf("record token %q; want %q (the map holds %q)", record.LegacyOwnerToken, want, recorded)
			}
		})
	}
}
