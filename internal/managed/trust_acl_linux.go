//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

const posixACLAccessXattr = "system.posix_acl_access"

// POSIX ACL xattr layout (linux/posix_acl_xattr.h): a little-endian
// version header followed by {tag uint16, perm uint16, id uint32} entries.
const (
	posixACLXattrVersion = 0x0002
	posixACLUser         = 0x02
	posixACLGroupObj     = 0x04
	posixACLGroup        = 0x08
	posixACLMask         = 0x10
	posixACLWrite        = 0x02
)

// validateTrustedPathACL rejects a POSIX access ACL whose named user or
// group entries can effectively write the path. The group mode bits
// already reflect the ACL mask, so this is mostly belt and braces, but it
// names the entry instead of reporting a bare mode.
func validateTrustedPathACL(path string) error { return inspectPOSIXAccessACL(path, nil) }

// inspectPOSIXAccessACL reads the access ACL of path and judges every named
// entry except those skip accepts.
func inspectPOSIXAccessACL(path string, skip func(tag uint16, id uint32) bool) error {
	buf := make([]byte, 4096)
	size, err := unix.Lgetxattr(path, posixACLAccessXattr, buf)
	if err != nil {
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil
		}
		if errors.Is(err, unix.ERANGE) {
			return fmt.Errorf("%s: POSIX ACL is too large to inspect", path)
		}
		return fmt.Errorf("%s: read POSIX ACL: %w", path, err)
	}
	return checkPOSIXAccessACLFor(path, buf[:size], skip)
}

// validateStrictPathACL is validateTrustedPathACL on Linux: the POSIX rule
// has no administrator principals to treat differently.
func validateStrictPathACL(path string) error { return validateTrustedPathACL(path) }

// validateAccountPathACL is ValidatePathACLForAccount on Linux: a named entry
// for root or for the account itself adds no authority, so it is not judged.
func validateAccountPathACL(path string, uid int, _ string) error {
	return inspectPOSIXAccessACL(path, func(tag uint16, id uint32) bool {
		return tag == posixACLUser && (id == 0 || (uid >= 0 && int(id) == uid))
	})
}

func checkPOSIXAccessACL(path string, data []byte) error {
	return checkPOSIXAccessACLFor(path, data, nil)
}

// checkPOSIXAccessACLFor judges every named entry except those skip accepts.
func checkPOSIXAccessACLFor(path string, data []byte, skip func(tag uint16, id uint32) bool) error {
	if len(data) < 4 || (len(data)-4)%8 != 0 {
		return fmt.Errorf("%s: malformed POSIX ACL", path)
	}
	if version := binary.LittleEndian.Uint32(data[:4]); version != posixACLXattrVersion {
		return fmt.Errorf("%s: unsupported POSIX ACL version %d", path, version)
	}
	maskWrite := true
	type entry struct {
		tag, perm uint16
		id        uint32
	}
	var named []entry
	for offset := 4; offset < len(data); offset += 8 {
		e := entry{
			tag:  binary.LittleEndian.Uint16(data[offset:]),
			perm: binary.LittleEndian.Uint16(data[offset+2:]),
			id:   binary.LittleEndian.Uint32(data[offset+4:]),
		}
		switch e.tag {
		case posixACLMask:
			maskWrite = e.perm&posixACLWrite != 0
		case posixACLUser, posixACLGroup:
			named = append(named, e)
		}
	}
	for _, e := range named {
		if e.perm&posixACLWrite == 0 || !maskWrite || (skip != nil && skip(e.tag, e.id)) {
			continue
		}
		kind := "user"
		if e.tag == posixACLGroup {
			kind = "group"
		}
		return fmt.Errorf("%s: POSIX ACL grants write to %s %d; remove it (setfacl -b)", path, kind, e.id)
	}
	return nil
}

// modeWithoutACLMask replaces the group bits of mode, which Linux reports as
// the POSIX ACL mask when path has an access ACL, with what the group object
// itself can do (its entry limited by the mask). A named entry for root or
// for the owner raises the mask without giving the group anything, so the
// mask alone would make an ordinary account folder or file look group
// writable. Named entries are judged by validateAccountPathACL, not here.
// A path without an ACL, or with an ACL that cannot be read, keeps its mode.
func modeWithoutACLMask(path string, mode fs.FileMode) fs.FileMode {
	buf := make([]byte, 4096)
	size, err := unix.Lgetxattr(path, posixACLAccessXattr, buf)
	if err != nil {
		return mode
	}
	return modeWithGroupObject(mode, buf[:size])
}

func modeWithGroupObject(mode fs.FileMode, data []byte) fs.FileMode {
	if len(data) < 4 || (len(data)-4)%8 != 0 || binary.LittleEndian.Uint32(data[:4]) != posixACLXattrVersion {
		return mode
	}
	groupObj, mask := -1, -1
	for offset := 4; offset < len(data); offset += 8 {
		perm := int(binary.LittleEndian.Uint16(data[offset+2:]) & 7)
		switch binary.LittleEndian.Uint16(data[offset:]) {
		case posixACLGroupObj:
			groupObj = perm
		case posixACLMask:
			mask = perm
		}
	}
	if groupObj < 0 || mask < 0 {
		return mode
	}
	return mode&^0o070 | fs.FileMode(groupObj&mask)<<3
}
