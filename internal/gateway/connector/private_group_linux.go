// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"bufio"
	"bytes"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// The account and group files the private-group rule reads (tests point them
// elsewhere). The CLI preflight reads the same two
// (cli/defenseclaw/connector_paths.py owner_private_group).
var (
	privateGroupPasswdFile  = "/etc/passwd"
	privateGroupGroupFile   = "/etc/group"
	privateGroupLookupUser  = user.LookupId
	privateGroupLookupGroup = user.LookupGroupId
)

// ownerPrivateGroup reports whether the group of path is its owner's own
// private group (GAP-0053). Ubuntu and Debian give each account a group of
// its own name with no other member, and a umask of 002, so the folders
// OpenCode creates (~/.config, ~/.config/opencode) are 0775. Group write there
// lets nobody but the owner write. True only when this process's effective
// account owns path, its group is that account's primary group and carries
// the account's name, no other account is a member or has it as primary
// group (in /etc/passwd and /etc/group, and as os/user answers), and path
// has no access ACL (then the group bits are the ACL mask). Anything
// unreadable, duplicated or ambiguous answers false, so a shared group stays
// refused.
func ownerPrivateGroup(path string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if _, present, err := hookAPIReadLinuxXattr(path, "system.posix_acl_access"); err != nil || present {
		return false
	}
	passwd, ok := privateGroupRecords(privateGroupPasswdFile)
	if !ok {
		return false
	}
	groups, ok := privateGroupRecords(privateGroupGroupFile)
	if !ok {
		return false
	}
	uid, gid := strconv.FormatUint(uint64(stat.Uid), 10), strconv.FormatUint(uint64(stat.Gid), 10)
	name := ""
	for _, rec := range passwd {
		if len(rec) < 4 {
			return false
		}
		if rec[2] == uid {
			if name != "" && name != rec[0] {
				return false
			}
			name = rec[0]
		}
	}
	if name == "" {
		return false
	}
	for _, rec := range passwd {
		if (rec[3] == gid) != (rec[0] == name) {
			return false
		}
	}
	matched := false
	for _, rec := range groups {
		if len(rec) < 4 {
			return false
		}
		if strings.TrimSpace(rec[2]) != gid {
			continue
		}
		matched = true
		if rec[0] != name {
			return false
		}
		for _, member := range strings.Split(rec[3], ",") {
			if member = strings.TrimSpace(member); member != "" && member != name {
				return false
			}
		}
	}
	if !matched {
		return false
	}
	account, err := privateGroupLookupUser(uid)
	if err != nil || account.Username != name || account.Gid != gid {
		return false
	}
	group, err := privateGroupLookupGroup(gid)
	return err == nil && group.Name == name
}

// privateGroupRecords splits a passwd or group file into its colon fields.
// false when it cannot be read or holds NIS compat (+/-) lines, whose
// members this check cannot see.
func privateGroupRecords(path string) ([][]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var records [][]string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			return nil, false
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, scanner.Err() == nil
}
