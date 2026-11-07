// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The account and group files the private-group rule reads (tests point them
// elsewhere). The CLI preflight reads the same two through
// file_permissions.owner_private_group.
var (
	privateGroupPasswdFile  = "/etc/passwd"
	privateGroupGroupFile   = "/etc/group"
	privateGroupLookupUser  = user.LookupId
	privateGroupLookupGroup = user.LookupGroupId
	privateGroupGetent      = getentOutput
)

const privateGroupGetentTimeout = 5 * time.Second

// ownerPrivateGroup reports whether the group of path is its owner's own
// private group (GAP-0657). Ubuntu and Debian give each account a group of
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
	_, ok := ownerPrivateGroupName(path, info)
	return ok
}

// ownerPrivateGroupStrict is ownerPrivateGroup plus the name service: the
// group and the account are read again through getent, which asks every source
// nsswitch lists (SSSD, LDAP, NIS, winbind), and the group may list no member
// but its owner. The local files cannot show a member a directory service adds
// (the CLI preflight asks the same through grp.getgrgid(gid).gr_mem). It starts
// a process, so only the managed setter, which runs once per ensure, asks it;
// the hook paths keep the local proof. Where getent is missing, times out or
// answers anything unexpected, the folder is not private (REVIEW-3 MF1).
func ownerPrivateGroupStrict(path string, info os.FileInfo) bool {
	name, ok := ownerPrivateGroupName(path, info)
	if !ok {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid, gid := strconv.FormatUint(uint64(stat.Uid), 10), strconv.FormatUint(uint64(stat.Gid), 10)
	group, ok := privateGroupEntry("group", gid)
	if !ok || len(group) != 4 || group[0] != name || group[2] != gid {
		return false
	}
	for _, member := range strings.Split(group[3], ",") {
		if member = strings.TrimSpace(member); member != "" && member != name {
			return false
		}
	}
	account, ok := privateGroupEntry("passwd", name)
	return ok && len(account) >= 4 && account[0] == name && account[2] == uid && account[3] == gid
}

// privateGroupEntry returns the colon fields of the one record getent finds.
func privateGroupEntry(database, key string) ([]string, bool) {
	line, ok := privateGroupGetent(database, key)
	line = strings.TrimSuffix(line, "\n")
	if !ok || line == "" || strings.Contains(line, "\n") {
		return nil, false
	}
	return strings.Split(line, ":"), true
}

// getentOutput asks the name service switch, with a fixed program path and
// environment, so nothing from the caller steers the lookup.
func getentOutput(database, key string) (string, bool) {
	for _, program := range []string{"/usr/bin/getent", "/bin/getent"} {
		if _, err := os.Stat(program); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), privateGroupGetentTimeout)
		cmd := exec.CommandContext(ctx, program, database, key)
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
		out, err := cmd.Output()
		cancel()
		return string(out), err == nil
	}
	return "", false
}

// ownerPrivateGroupName is the local proof ownerPrivateGroup answers, with the
// account name it found.
func ownerPrivateGroupName(path string, info os.FileInfo) (string, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", false
	}
	if _, present, err := hookAPIReadLinuxXattr(path, "system.posix_acl_access"); err != nil || present {
		return "", false
	}
	passwd, ok := privateGroupRecords(privateGroupPasswdFile)
	if !ok {
		return "", false
	}
	groups, ok := privateGroupRecords(privateGroupGroupFile)
	if !ok {
		return "", false
	}
	uid, gid := strconv.FormatUint(uint64(stat.Uid), 10), strconv.FormatUint(uint64(stat.Gid), 10)
	name := ""
	ownerRecords := 0
	for _, rec := range passwd {
		if len(rec) < 4 {
			return "", false
		}
		recordUID, uidErr := strconv.ParseUint(rec[2], 10, 32)
		if _, gidErr := strconv.ParseUint(rec[3], 10, 32); uidErr != nil || gidErr != nil {
			return "", false
		}
		if recordUID == uint64(stat.Uid) {
			ownerRecords++
			if ownerRecords > 1 {
				return "", false
			}
			name = rec[0]
		}
	}
	if name == "" {
		return "", false
	}
	for _, rec := range passwd {
		recordUID, _ := strconv.ParseUint(rec[2], 10, 32)
		recordGID, _ := strconv.ParseUint(rec[3], 10, 32)
		if recordGID == uint64(stat.Gid) && recordUID != uint64(stat.Uid) {
			return "", false
		}
		if rec[0] == name && (recordUID != uint64(stat.Uid) || recordGID != uint64(stat.Gid)) {
			return "", false
		}
	}
	matched := false
	for _, rec := range groups {
		if len(rec) < 4 {
			return "", false
		}
		recordGID, err := strconv.ParseUint(strings.TrimSpace(rec[2]), 10, 32)
		if err != nil {
			return "", false
		}
		if recordGID != uint64(stat.Gid) {
			continue
		}
		matched = true
		if rec[0] != name {
			return "", false
		}
		for _, member := range strings.Split(rec[3], ",") {
			if member = strings.TrimSpace(member); member != "" && member != name {
				return "", false
			}
		}
	}
	if !matched {
		return "", false
	}
	account, err := privateGroupLookupUser(uid)
	if err != nil || account.Username != name || account.Gid != gid {
		return "", false
	}
	group, err := privateGroupLookupGroup(gid)
	return name, err == nil && group.Name == name
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
		if strings.HasPrefix(strings.TrimSpace(line), "+") || strings.HasPrefix(strings.TrimSpace(line), "-") {
			return nil, false
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, scanner.Err() == nil
}
