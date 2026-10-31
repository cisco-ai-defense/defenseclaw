// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package posixacl evaluates Linux access ACLs. Reader is replaceable so
// callers can test permission decisions without changing the host's ACLs.
package posixacl

import (
	"fmt"
	"os"
	"strings"
)

type Entry struct {
	Kind string
	ID   int
	Perm uint16
}

type View struct {
	Present bool
	Owner   uint16
	Group   uint16
	Other   uint16
	Mask    uint16
	Users   []Entry
	Groups  []Entry
}

// NamedUserAllows reports the effective permission of a named user entry.
// Such an entry takes precedence over the owning group and other classes.
func (v View) NamedUserAllows(uid int, want uint16) (found, allowed bool) {
	if !v.Present {
		return false, false
	}
	for _, entry := range v.Users {
		if entry.ID == uid {
			return true, entry.Perm&v.Mask&want == want
		}
	}
	return false, false
}

type Reader interface {
	Read(path string, mode os.FileMode) (View, error)
}

// Allows follows the POSIX ACL precedence: owner, named user, all matching
// groups, then other. The service account has no supplementary groups.
func (v View) Allows(ownerUID, ownerGID int, mode os.FileMode, uid, gid int, want uint16) bool {
	if !v.Present {
		perm := uint16(mode.Perm())
		switch {
		case uid == ownerUID:
			perm >>= 6
		case gid == ownerGID:
			perm >>= 3
		}
		return perm&want == want
	}
	if uid == ownerUID {
		return v.Owner&want == want
	}
	for _, e := range v.Users {
		if e.ID == uid {
			return e.Perm&v.Mask&want == want
		}
	}
	var groupPerm uint16
	matched := false
	if gid == ownerGID {
		groupPerm, matched = v.Group, true
	}
	for _, e := range v.Groups {
		if e.ID == gid {
			groupPerm |= e.Perm
			matched = true
		}
	}
	if matched {
		return groupPerm&v.Mask&want == want
	}
	return v.Other&want == want
}

// Denied names ACL entries that can prevent a policy consumer from getting
// want even when the file's mode appears readable or traversable.
func (v View) Denied(want uint16) string {
	if !v.Present {
		return ""
	}
	var denied []string
	if v.Group&v.Mask&want != want {
		denied = append(denied, "group::"+RWX(v.Group&v.Mask))
	}
	for _, e := range append(append([]Entry(nil), v.Users...), v.Groups...) {
		if e.Perm&v.Mask&want != want {
			denied = append(denied, fmt.Sprintf("%s:%d:%s", e.Kind, e.ID, RWX(e.Perm&v.Mask)))
		}
	}
	return strings.Join(denied, ", ")
}

// RWX spells perm the way getfacl does (r-x).
func RWX(perm uint16) string {
	out := []byte("---")
	for i, c := range "rwx" {
		if perm&(4>>i) != 0 {
			out[i] = byte(c)
		}
	}
	return string(out)
}
