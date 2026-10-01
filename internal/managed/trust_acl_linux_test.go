//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/binary"
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
