//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// aclEntry is one POSIX ACL entry: tag, rwx bits and the uid or gid.
type aclEntry struct {
	tag, perm uint16
	id        uint32
}

const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20
)

// setKernelACL writes a real access ACL (the kernel checks it and reports the
// mask as the group mode bits). The entries must be in tag order.
func setKernelACL(t *testing.T, path string, entries ...aclEntry) {
	t.Helper()
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, 2)
	for i, e := range entries {
		binary.LittleEndian.PutUint16(data[4+8*i:], e.tag)
		binary.LittleEndian.PutUint16(data[6+8*i:], e.perm)
		binary.LittleEndian.PutUint32(data[8+8*i:], e.id)
	}
	if err := unix.Setxattr(path, "system.posix_acl_access", data, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("this file system has no POSIX ACLs: %v", err)
		}
		t.Fatalf("set POSIX ACL on %s: %v", path, err)
	}
}

// accountACL grants the named user (root, or another account) rwx and the
// group object nothing; the mask is rwx, so the group mode bits read rwx.
func accountACL(named uint32, group uint16) []aclEntry {
	return []aclEntry{
		{aclUserObj, 7, 0}, {aclUser, 7, named}, {aclGroupObj, group, 0}, {aclMask, 7, 0}, {aclOther, 0, 0},
	}
}

func assertGroupModeReadsRWX(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o070 != 0o070 {
		t.Fatalf("the ACL mask is not in the group bits of %s: %v %v", path, info, err)
	}
}

// A root-only POSIX ACL on the account folder leaves the group mode bits at
// the mask but adds no authority: root has the access anyway. Balanced work
// must go on, with the port imported and a matching port left alone
// (GAP-0053 round 9 MF1).
func TestOpenCodeServicePortKeepsAFolderWithARootOnlyPOSIXACL(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	setKernelACL(t, filepath.Dir(path), accountACL(0, 0)...)
	assertGroupModeReadsRWX(t, filepath.Dir(path))
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("a folder with a root-only ACL was refused: port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("a folder with a root-only ACL was refused by the setter: %+v %v", result, err)
	}
}

// The same entry on service.json: the file belongs to the account, it is not shared.
func TestOpenCodeServicePortKeepsAFileWithARootOnlyPOSIXACL(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	setKernelACL(t, path, accountACL(0, 0)...)
	assertGroupModeReadsRWX(t, path)
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 25001 {
		t.Fatalf("a file with a root-only ACL was not imported: port=%d err=%v", port, err)
	}
	result, err := SetOpenCodeServicePort(home, 25001)
	if err != nil || result.Changed || result.Port != 25001 {
		t.Fatalf("a file with a root-only ACL was rewritten: %+v %v", result, err)
	}
}

// Security twin: a named entry for another account stays refused, on the
// folder and on the file, by the read and by the setter.
func TestOpenCodeServicePortRefusesAnotherAccountPOSIXACL(t *testing.T) {
	const other = 4242
	t.Run("folder", func(t *testing.T) {
		home := t.TempDir()
		path := writeACLTestService(t, home, "25001")
		setKernelACL(t, filepath.Dir(path), accountACL(other, 0)...)
		if port, err := ReadOpenCodeServicePortAsUser(home); err == nil || port != 0 {
			t.Fatalf("a folder with another account ACL was read: port=%d err=%v", port, err)
		}
		if _, err := SetOpenCodeServicePort(home, 25001); err == nil {
			t.Fatal("a folder with another account ACL was accepted by the setter")
		}
	})
	t.Run("file", func(t *testing.T) {
		home := t.TempDir()
		path := writeACLTestService(t, home, "25001")
		setKernelACL(t, path, accountACL(other, 0)...)
		if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 0 {
			t.Fatalf("a file with another account ACL was imported: port=%d err=%v", port, err)
		}
		if result, err := SetOpenCodeServicePort(home, 25001); err != nil || !result.Changed {
			t.Fatalf("a file with another account ACL was accepted as it stands: %+v %v", result, err)
		}
	})
}

// Security twin: a group object that can write the file is real group access
// even beside a root entry, so the file is shared and not imported.
func TestOpenCodeServicePortRefusesAFileTheGroupObjectCanWrite(t *testing.T) {
	home := t.TempDir()
	path := writeACLTestService(t, home, "25001")
	setKernelACL(t, path, accountACL(0, 6)...)
	if port, err := ReadOpenCodeServicePortAsUser(home); err != nil || port != 0 {
		t.Fatalf("a file the group can write was imported: port=%d err=%v", port, err)
	}
}
