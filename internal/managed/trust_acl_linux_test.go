//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"
)

func posixACL(entries ...[3]uint32) []byte {
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, posixACLXattrVersion)
	for index, e := range entries {
		offset := 4 + 8*index
		binary.LittleEndian.PutUint16(data[offset:], uint16(e[0]))
		binary.LittleEndian.PutUint16(data[offset+2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(data[offset+4:], e[2])
	}
	return data
}

func TestCheckPOSIXAccessACL(t *testing.T) {
	const userObj, groupObj, other = 0x01, 0x04, 0x20
	cases := []struct {
		name    string
		acl     []byte
		wantErr string
	}{
		{"read-only named user", posixACL([3]uint32{userObj, 7, 0}, [3]uint32{posixACLUser, 4, 1000}, [3]uint32{groupObj, 5, 0}, [3]uint32{posixACLMask, 5, 0}, [3]uint32{other, 5, 0}), ""},
		{"write masked off", posixACL([3]uint32{userObj, 7, 0}, [3]uint32{posixACLUser, 7, 1000}, [3]uint32{posixACLMask, 5, 0}, [3]uint32{other, 5, 0}), ""},
		{"named user write", posixACL([3]uint32{userObj, 7, 0}, [3]uint32{posixACLUser, 7, 1000}, [3]uint32{posixACLMask, 7, 0}, [3]uint32{other, 5, 0}), "user 1000"},
		{"named group write", posixACL([3]uint32{userObj, 7, 0}, [3]uint32{posixACLGroup, 6, 988}, [3]uint32{posixACLMask, 7, 0}, [3]uint32{other, 5, 0}), "group 988"},
		{"malformed", []byte{2, 0, 0}, "malformed"},
	}
	for _, tc := range cases {
		err := checkPOSIXAccessACL("/x", tc.acl)
		if tc.wantErr == "" && err != nil {
			t.Fatalf("%s: unexpected %v", tc.name, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Fatalf("%s: error %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

// The account rule skips a named entry for root or the account, not for
// another account or a group (GAP-0053 REVIEW-7 MF1).
func TestPOSIXAccessACLForAccountSkipsOnlyRootAndTheAccount(t *testing.T) {
	const userObj, other = 0x01, 0x20
	skip := func(tag uint16, id uint32) bool { return tag == posixACLUser && (id == 0 || id == 1000) }
	acl := func(kind uint32, id uint32) []byte {
		return posixACL([3]uint32{userObj, 7, 0}, [3]uint32{kind, 7, id}, [3]uint32{posixACLMask, 7, 0}, [3]uint32{other, 5, 0})
	}
	for _, tc := range []struct {
		name    string
		acl     []byte
		wantErr bool
	}{
		{"root", acl(posixACLUser, 0), false},
		{"the account", acl(posixACLUser, 1000), false},
		{"another account", acl(posixACLUser, 1001), true},
		{"a group of the same number", acl(posixACLGroup, 1000), true},
	} {
		if err := checkPOSIXAccessACLFor("/x", tc.acl, skip); (err != nil) != tc.wantErr {
			t.Fatalf("%s: error %v, want refusal=%v", tc.name, err, tc.wantErr)
		}
		if err := checkPOSIXAccessACL("/x", tc.acl); err == nil {
			t.Fatalf("%s: the strict rule accepted a named writer", tc.name)
		}
	}
}

// Linux reports the POSIX ACL mask as the group bits. A named entry for root
// raises the mask, so the group bits must come from the group object entry
// (the root-only ACL case of GAP-0053 round 9).
func TestModeWithGroupObjectReadsTheGroupEntryNotTheMask(t *testing.T) {
	const userObj, groupObj, other = 0x01, 0x04, 0x20
	acl := func(group, mask uint32) []byte {
		return posixACL([3]uint32{userObj, 6, 0}, [3]uint32{posixACLUser, 6, 0}, [3]uint32{groupObj, group, 0}, [3]uint32{posixACLMask, mask, 0}, [3]uint32{other, 0, 0})
	}
	for _, tc := range []struct {
		name string
		acl  []byte
		mode fs.FileMode
		want fs.FileMode
	}{
		{"root entry only, group has nothing", acl(0, 6), 0o660, 0o600},
		{"group object writes, mask allows", acl(6, 6), 0o660, 0o660},
		{"group object writes, mask removes it", acl(6, 4), 0o640, 0o640},
		{"group object reads, mask writes", acl(4, 6), 0o660, 0o640},
		{"other bits stay", acl(0, 6), 0o662, 0o602},
		{"no mask entry keeps the mode", posixACL([3]uint32{userObj, 6, 0}, [3]uint32{groupObj, 6, 0}, [3]uint32{other, 0, 0}), 0o660, 0o660},
		{"malformed keeps the mode", []byte{2, 0, 0}, 0o660, 0o660},
	} {
		if got := modeWithGroupObject(tc.mode, tc.acl); got != tc.want {
			t.Fatalf("%s: mode %o, want %o", tc.name, got, tc.want)
		}
	}
}
