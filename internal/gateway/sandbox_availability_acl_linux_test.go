// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxKVMNamedUserACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kvm-device")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid() + 10001 // no group lookup is needed for a named user
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	entries := [][3]uint32{
		{0x01, 6, ^uint32(0)},  // owner
		{0x02, 6, uint32(uid)}, // named account
		{0x04, 0, ^uint32(0)},  // owning group
		{0x10, 6, ^uint32(0)},  // effective mask
		{0x20, 0, ^uint32(0)},  // other
	}
	for i, entry := range entries {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(acl[off:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(acl[off+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(acl[off+4:], entry[2])
	}
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("test filesystem has no POSIX ACLs")
		}
		t.Fatal(err)
	}
	if got := sandboxDevicePathAccess(path, uid, true); got.State != sandboxDeviceUsable {
		t.Fatalf("named user with read-write ACL: %+v", got)
	}
	if got := sandboxDevicePathAccess(path, uid, false); got.State == sandboxDeviceUsable {
		t.Fatalf("mode-only probe incorrectly accepted named user: %+v", got)
	}
	// A named entry with no write permission must override even permissive
	// group and other bits. The mask also limits a named entry.
	binary.LittleEndian.PutUint16(acl[4+1*8+2:], 4)
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal(err)
	}
	if got := sandboxDevicePathAccess(path, uid, true); got.State != sandboxDeviceDenied {
		t.Fatalf("read-only ACL accepted: %+v", got)
	}
	binary.LittleEndian.PutUint16(acl[4+1*8+2:], 6)
	binary.LittleEndian.PutUint16(acl[4+3*8+2:], 4)
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal(err)
	}
	if got := sandboxDevicePathAccess(path, uid, true); got.State != sandboxDeviceDenied {
		t.Fatalf("ACL mask without write accepted: %+v", got)
	}
}
