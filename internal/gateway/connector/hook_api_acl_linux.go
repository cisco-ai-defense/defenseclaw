// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	hookAPILinuxACLXattrVersion = 2
	hookAPILinuxACLUserObj      = 0x01
	hookAPILinuxACLUser         = 0x02
	hookAPILinuxACLGroupObj     = 0x04
	hookAPILinuxACLGroup        = 0x08
	hookAPILinuxACLMask         = 0x10
	hookAPILinuxACLOther        = 0x20
	hookAPILinuxACLWrite        = 0x02
)

func hookAPIValidateDirectoryACL(path string) error {
	for _, name := range []string{"system.nfs4_acl", "system.nfs4acl"} {
		if data, present, err := hookAPIReadLinuxXattr(path, name); err != nil {
			return err
		} else if present {
			return fmt.Errorf("cannot verify NFSv4 ACL %s on %s (%d bytes)", name, path, len(data))
		}
	}
	data, present, err := hookAPIReadLinuxXattr(path, "system.posix_acl_access")
	if err != nil || !present {
		return err
	}
	return hookAPIValidateLinuxPOSIXACL(path, data)
}

func hookAPIReadLinuxXattr(path, name string) ([]byte, bool, error) {
	size, err := unix.Getxattr(path, name, nil)
	if err != nil {
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect ACL attribute %s on %s: %w", name, path, err)
	}
	if size <= 0 {
		return nil, true, fmt.Errorf("ACL attribute %s on %s is empty", name, path)
	}
	data := make([]byte, size)
	n, err := unix.Getxattr(path, name, data)
	if err != nil {
		return nil, false, fmt.Errorf("read ACL attribute %s on %s: %w", name, path, err)
	}
	return data[:n], true, nil
}

func hookAPIValidateLinuxPOSIXACL(path string, data []byte) error {
	if len(data) < 4 || binary.LittleEndian.Uint32(data[:4]) != hookAPILinuxACLXattrVersion || (len(data)-4)%8 != 0 {
		return fmt.Errorf("invalid POSIX ACL on %s", path)
	}
	mask := uint16(0x7)
	var userObjCount, groupObjCount, otherCount, maskCount int
	hasNamedEntry := false
	for offset := 4; offset < len(data); offset += 8 {
		switch binary.LittleEndian.Uint16(data[offset : offset+2]) {
		case hookAPILinuxACLUserObj:
			userObjCount++
		case hookAPILinuxACLUser, hookAPILinuxACLGroup:
			hasNamedEntry = true
		case hookAPILinuxACLGroupObj:
			groupObjCount++
		case hookAPILinuxACLOther:
			otherCount++
		case hookAPILinuxACLMask:
			maskCount++
			mask = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		}
	}
	if userObjCount != 1 || groupObjCount != 1 || otherCount != 1 || maskCount > 1 || (hasNamedEntry && maskCount != 1) {
		return fmt.Errorf("incomplete POSIX ACL on %s", path)
	}
	for offset := 4; offset < len(data); offset += 8 {
		tag := binary.LittleEndian.Uint16(data[offset : offset+2])
		permissions := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		id := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		switch tag {
		case hookAPILinuxACLUser, hookAPILinuxACLGroupObj, hookAPILinuxACLGroup:
			permissions &= mask
		case hookAPILinuxACLUserObj, hookAPILinuxACLOther, hookAPILinuxACLMask:
		default:
			return fmt.Errorf("unsupported POSIX ACL tag 0x%x on %s", tag, path)
		}
		if permissions&hookAPILinuxACLWrite == 0 {
			continue
		}
		switch tag {
		case hookAPILinuxACLUserObj:
			continue
		case hookAPILinuxACLUser:
			if hookAPITrustedOwner(id) {
				continue
			}
			return fmt.Errorf("untrusted uid %d has write access in POSIX ACL on %s", id, path)
		case hookAPILinuxACLGroupObj, hookAPILinuxACLGroup:
			return fmt.Errorf("group has write access in POSIX ACL on %s", path)
		case hookAPILinuxACLOther:
			return fmt.Errorf("other has write access in POSIX ACL on %s", path)
		case hookAPILinuxACLMask:
			continue
		}
	}
	return nil
}
