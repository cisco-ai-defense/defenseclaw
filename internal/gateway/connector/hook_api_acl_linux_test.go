// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestHookAPILinuxPOSIXACLRejectsUntrustedNamedWriter(t *testing.T) {
	data := validLinuxACLFixture(hookAPILinuxACLWrite, 0x7)
	if err := hookAPIValidateLinuxPOSIXACL("test", data); err == nil || !strings.Contains(err.Error(), "untrusted uid") {
		t.Fatalf("hookAPIValidateLinuxPOSIXACL error = %v, want untrusted uid rejection", err)
	}
}

func TestHookAPILinuxPOSIXACLIgnoresMaskedWrite(t *testing.T) {
	data := validLinuxACLFixture(hookAPILinuxACLWrite, 0x5)
	if err := hookAPIValidateLinuxPOSIXACL("test", data); err != nil {
		t.Fatalf("masked write permission was treated as effective: %v", err)
	}
}

func TestHookAPILinuxPOSIXACLRejectsUnknownReadOnlyTag(t *testing.T) {
	data := make([]byte, 4+6*8)
	copy(data, validLinuxACLFixture(hookAPILinuxACLWrite, 0x5))
	putLinuxACLEntry(data[44:52], 0x40, 0x4, ^uint32(0))
	if err := hookAPIValidateLinuxPOSIXACL("test", data); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("hookAPIValidateLinuxPOSIXACL error = %v, want unsupported tag rejection", err)
	}
}

func validLinuxACLFixture(namedPermissions, maskPermissions uint16) []byte {
	data := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(data[:4], hookAPILinuxACLXattrVersion)
	putLinuxACLEntry(data[4:12], hookAPILinuxACLUserObj, 0x7, ^uint32(0))
	putLinuxACLEntry(data[12:20], hookAPILinuxACLUser, namedPermissions, 4_294_967_000)
	putLinuxACLEntry(data[20:28], hookAPILinuxACLGroupObj, 0x5, ^uint32(0))
	putLinuxACLEntry(data[28:36], hookAPILinuxACLMask, maskPermissions, ^uint32(0))
	putLinuxACLEntry(data[36:44], hookAPILinuxACLOther, 0x5, ^uint32(0))
	return data
}

func putLinuxACLEntry(dst []byte, tag, permissions uint16, id uint32) {
	binary.LittleEndian.PutUint16(dst[:2], tag)
	binary.LittleEndian.PutUint16(dst[2:4], permissions)
	binary.LittleEndian.PutUint32(dst[4:8], id)
}
