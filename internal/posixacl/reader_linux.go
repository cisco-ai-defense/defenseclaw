//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package posixacl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

type systemReader struct{}

var System Reader = systemReader{}

func (systemReader) Read(path string, mode os.FileMode) (View, error) {
	output, err := exec.Command("getfacl", "-cpn", "--", path).Output()
	if err == nil {
		return ParseGetfacl(string(output))
	}
	if !errors.Is(err, exec.ErrNotFound) {
		return View{}, fmt.Errorf("getfacl %s: %w", path, err)
	}
	// Minimal Linux installations need not have the acl command. The kernel's
	// access ACL xattr carries the same entries, so retain the check there.
	for {
		size, err := unix.Getxattr(path, "system.posix_acl_access", nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return View{}, nil
		}
		if err != nil {
			return View{}, err
		}
		data := make([]byte, size)
		n, err := unix.Getxattr(path, "system.posix_acl_access", data)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if errors.Is(err, unix.ENODATA) {
			return View{}, nil
		}
		if err != nil {
			return View{}, err
		}
		return parseXattr(data[:n])
	}
}

func parseXattr(data []byte) (View, error) {
	if len(data) < 4 || (len(data)-4)%8 != 0 || binary.LittleEndian.Uint32(data) != 2 {
		return View{}, fmt.Errorf("unrecognised POSIX ACL (%d bytes)", len(data))
	}
	v := View{Present: true, Mask: 7}
	for off := 4; off < len(data); off += 8 {
		tag := binary.LittleEndian.Uint16(data[off:])
		perm := binary.LittleEndian.Uint16(data[off+2:])
		id := int(binary.LittleEndian.Uint32(data[off+4:]))
		switch tag {
		case 0x01:
			v.Owner = perm
		case 0x02:
			v.Users = append(v.Users, Entry{Kind: "user", ID: id, Perm: perm})
		case 0x04:
			v.Group = perm
		case 0x08:
			v.Groups = append(v.Groups, Entry{Kind: "group", ID: id, Perm: perm})
		case 0x10:
			v.Mask = perm
		case 0x20:
			v.Other = perm
		default:
			return View{}, fmt.Errorf("unrecognised POSIX ACL tag %d", tag)
		}
	}
	return v, nil
}
