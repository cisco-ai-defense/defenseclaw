// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package posixacl evaluates Linux access ACLs. Reader is replaceable so
// callers can test permission decisions without changing the host's ACLs.
package posixacl

import (
	"fmt"
	"os"
	"strconv"
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

type Reader interface {
	Read(path string, mode os.FileMode) (View, error)
}

// ParseGetfacl parses the numeric, comment-free output of getfacl -cpn.
func ParseGetfacl(output string) (View, error) {
	v := View{Present: true, Mask: 7}
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "default:") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || len(parts[2]) != 3 {
			return View{}, fmt.Errorf("invalid getfacl entry %q", line)
		}
		var perm uint16
		for i, c := range parts[2] {
			if c == rune("rwx"[i]) {
				perm |= 4 >> i
			} else if c != '-' {
				return View{}, fmt.Errorf("invalid getfacl permission %q", line)
			}
		}
		if parts[1] == "" {
			if seen[parts[0]] {
				return View{}, fmt.Errorf("duplicate getfacl entry %q", line)
			}
			seen[parts[0]] = true
			switch parts[0] {
			case "user":
				v.Owner = perm
			case "group":
				v.Group = perm
			case "other":
				v.Other = perm
			case "mask":
				v.Mask = perm
			default:
				return View{}, fmt.Errorf("invalid getfacl entry %q", line)
			}
			continue
		}
		id, err := strconv.Atoi(parts[1])
		if err != nil || id < 0 {
			return View{}, fmt.Errorf("invalid getfacl identity %q", line)
		}
		e := Entry{Kind: parts[0], ID: id, Perm: perm}
		switch parts[0] {
		case "user":
			v.Users = append(v.Users, e)
		case "group":
			v.Groups = append(v.Groups, e)
		default:
			return View{}, fmt.Errorf("invalid getfacl entry %q", line)
		}
	}
	if !seen["user"] || !seen["group"] || !seen["other"] {
		return View{}, fmt.Errorf("incomplete getfacl output")
	}
	return v, nil
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
		denied = append(denied, "group::"+rwx(v.Group&v.Mask))
	}
	for _, e := range append(append([]Entry(nil), v.Users...), v.Groups...) {
		if e.Perm&v.Mask&want != want {
			denied = append(denied, fmt.Sprintf("%s:%d:%s", e.Kind, e.ID, rwx(e.Perm&v.Mask)))
		}
	}
	return strings.Join(denied, ", ")
}

func rwx(perm uint16) string {
	out := []byte("---")
	for i, c := range "rwx" {
		if perm&(4>>i) != 0 {
			out[i] = byte(c)
		}
	}
	return string(out)
}
