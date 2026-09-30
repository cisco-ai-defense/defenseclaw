//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrNotFound is the definitive "no such account or group" answer.
var ErrNotFound = errors.New("unixidentity: not found")

// Account is one resolved user account.
type Account struct {
	Name  string
	UID   int
	GID   int // primary group
	Gecos string
	Home  string
	Shell string
}

// Group is one resolved group.
type Group struct {
	Name    string
	GID     int
	Members []string
}

// Resolver resolves accounts and group membership.
type Resolver interface {
	LookupUser(name string) (Account, error)
	LookupUID(uid int) (Account, error)
	LookupGroupID(gid int) (Group, error)
	LookupGroup(name string) (Group, error)
	// GroupIDs returns the account's primary and supplementary group ids.
	GroupIDs(account Account) ([]int, error)
	// ListUsers enumerates accounts. complete is false when the backend
	// cannot enumerate everything (SSSD enumerate=false, directory-only
	// macOS accounts), so callers must add other candidate sources.
	ListUsers() (accounts []Account, complete bool, err error)
}

// IsNotFound reports a definitive absence.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

const (
	maxNameLength  = 256
	maxFieldLength = 4096
)

// ParsePasswdLine strictly parses one passwd(5) entry
// (name:passwd:uid:gid:gecos:home:shell).
func ParsePasswdLine(line string) (Account, error) {
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return Account{}, fmt.Errorf("unixidentity: passwd entry has %d fields, want 7", len(fields))
	}
	name := fields[0]
	if err := validName(name); err != nil {
		return Account{}, err
	}
	uid, err := parseID(fields[2], "uid")
	if err != nil {
		return Account{}, err
	}
	gid, err := parseID(fields[3], "gid")
	if err != nil {
		return Account{}, err
	}
	for _, value := range fields[4:] {
		if len(value) > maxFieldLength || strings.ContainsRune(value, 0) {
			return Account{}, fmt.Errorf("unixidentity: passwd entry for %q has an oversized or malformed field", name)
		}
	}
	return Account{Name: name, UID: uid, GID: gid, Gecos: fields[4], Home: fields[5], Shell: fields[6]}, nil
}

// ParseGroupLine strictly parses one group(5) entry (name:passwd:gid:members).
func ParseGroupLine(line string) (Group, error) {
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Split(line, ":")
	if len(fields) != 4 {
		return Group{}, fmt.Errorf("unixidentity: group entry has %d fields, want 4", len(fields))
	}
	if err := validName(fields[0]); err != nil {
		return Group{}, err
	}
	gid, err := parseID(fields[2], "gid")
	if err != nil {
		return Group{}, err
	}
	group := Group{Name: fields[0], GID: gid}
	if fields[3] != "" {
		for _, member := range strings.Split(fields[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			if err := validName(member); err != nil {
				return Group{}, err
			}
			group.Members = append(group.Members, member)
		}
	}
	return group, nil
}

// ParseInitgroups parses `getent initgroups <user>` output: the user name
// followed by whitespace-separated group ids.
func ParseInitgroups(output, user string) ([]int, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 {
		return nil, fmt.Errorf("unixidentity: empty initgroups output")
	}
	if fields[0] != user {
		return nil, fmt.Errorf("unixidentity: initgroups output names %q, want %q", fields[0], user)
	}
	seen := map[int]bool{}
	var ids []int
	for _, raw := range fields[1:] {
		gid, err := parseID(raw, "gid")
		if err != nil {
			return nil, err
		}
		if !seen[gid] {
			seen[gid] = true
			ids = append(ids, gid)
		}
	}
	sort.Ints(ids)
	return ids, nil
}

// ParseLoginDefsUIDRange reads UID_MIN and UID_MAX from login.defs content.
// Missing values keep the supplied defaults.
func ParseLoginDefsUIDRange(content string, defaultMin, defaultMax int) (int, int) {
	minUID, maxUID := defaultMin, defaultMax
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.Atoi(fields[1])
		if err != nil || value < 0 {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			minUID = value
		case "UID_MAX":
			maxUID = value
		}
	}
	if maxUID < minUID {
		return defaultMin, defaultMax
	}
	return minUID, maxUID
}

func validName(name string) error {
	if name == "" || len(name) > maxNameLength {
		return fmt.Errorf("unixidentity: account or group name has invalid length")
	}
	for _, r := range name {
		if r < 0x21 || r == 0x7f || r == ':' || r == ',' || r == '/' {
			return fmt.Errorf("unixidentity: account or group name %q contains a forbidden character", name)
		}
	}
	return nil
}

func parseID(raw, label string) (int, error) {
	if raw == "" || len(raw) > 10 {
		return 0, fmt.Errorf("unixidentity: invalid %s %q", label, raw)
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("unixidentity: invalid %s %q", label, raw)
		}
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value > 4294967294 {
		return 0, fmt.Errorf("unixidentity: %s %q is out of range", label, raw)
	}
	return int(value), nil
}
