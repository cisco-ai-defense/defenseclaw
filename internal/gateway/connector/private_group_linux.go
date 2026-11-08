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
	"path/filepath"
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
	_, ok := ownerPrivateGroupName(path, info, false)
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
	return ownerPrivateGroupStrictFor(path, info, false)
}

// ownerPrivateGroupStrictAfterACL is ownerPrivateGroupStrict for a caller that
// has already judged every named entry of the access ACL of path and reads
// the group bits as the group object (managed.ModeWithoutACLMask). An ACL then
// does not by itself rule the private group out: a named entry for root or
// for the owner adds no member to the group.
func ownerPrivateGroupStrictAfterACL(path string, info os.FileInfo) bool {
	return ownerPrivateGroupStrictFor(path, info, true)
}

func ownerPrivateGroupStrictFor(path string, info os.FileInfo, aclJudged bool) bool {
	name, ok := ownerPrivateGroupName(path, info, aclJudged)
	if !ok {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && privateGroupNameServiceAgrees(name, stat)
}

// privateGroupNameServiceAgrees is the name-service half of the strict proof:
// getent finds the group under the account's name and gid with no member but
// its owner, and the account with the same uid and primary group.
func privateGroupNameServiceAgrees(name string, stat *syscall.Stat_t) bool {
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

// The files that say where this host gets its accounts and groups from
// (tests point them elsewhere).
var (
	privateGroupNsswitchFile = "/etc/nsswitch.conf"
	privateGroupSSSDDir      = "/etc/sssd"
	privateGroupUserdbDirs   = []string{"/etc/userdb", "/run/userdb", "/run/host/userdb", "/var/lib/userdb", "/usr/lib/userdb", "/var/lib/systemd/home"}
	privateGroupUserdbSocks  = "/run/systemd/userdb"
	// Where pam_group reads its rules from. The local directory is read first:
	// the module falls back to the vendor group.conf only where the local
	// group.conf does not exist (Linux-PAM vendordir; /usr/share/pam is its
	// default, /usr/etc and /usr/lib are common distribution choices). The
	// vendor list is a floor, not the answer: the build-time directory is also
	// read out of the installed module (privateGroupPAMModuleDirs). Each
	// directory holds group.conf and group.d/*.conf.
	privateGroupPAMLocalDir   = "/etc/security"
	privateGroupPAMVendorDirs = []string{
		"/usr/share/pam/security", "/usr/etc/security", "/usr/lib/security", "/usr/share/security",
		"/usr/share/defaults/etc/security",
	}
	// Where the pam_group module itself lives (glob patterns).
	privateGroupPAMModuleDirs = []string{
		"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security",
		"/lib/*/security", "/usr/lib/*/security",
	}
)

const privateGroupPAMModuleMaxBytes = 8 << 20

// The Varlink services in privateGroupUserdbSocks that cannot add an account
// or a group membership of their own: the dynamic service users of units (ids
// in the dynamic range, group equal to user), the multiplexer that fans a
// lookup out to the other services, the glibc bridge, whose answers come from
// the nsswitch sources this check reads, and the drop-in service, which only
// serves the record files in privateGroupUserdbDirs (checked below). Any other service (homed,
// machined, a vendor provider) is a source of accounts this check cannot list.
var privateGroupBuiltinUserdbServices = map[string]bool{
	"io.systemd.DropIn":            true,
	"io.systemd.DynamicUser":       true,
	"io.systemd.Multiplexer":       true,
	"io.systemd.NameServiceSwitch": true,
}

// ownerPrivateGroupLocalSources is the proof for a check that runs on every
// watcher event (GAP-0905). A private group lets nobody else in only when no
// other account can have it as its primary group or as a supplementary group,
// and the name service cannot be asked that: getent lists a directory service
// accounts only when the service enumerates, and an account that is not a listed
// member still writes through its primary gid. So the folder is private only
// when the local files are the whole answer: ownerPrivateGroup holds, and
// nothing else can add an account or a membership (privateGroupSourcesAreLocal).
// Nothing is remembered between calls, so a source added later refuses on the
// next call. False off Linux, and for anything unreadable or ambiguous.
func ownerPrivateGroupLocalSources(path string, info os.FileInfo) bool {
	return ownerPrivateGroup(path, info) && privateGroupSourcesAreLocal()
}

// privateGroupSourcesAreLocal reports whether /etc/passwd and /etc/group are
// everything that decides who holds a group. The passwd and group databases
// (primary gid, listed members) and the initgroups database (the supplementary
// groups glibc hands a login; a separate nsswitch line that falls back to group
// only where it is absent) are each listed once in nsswitch.conf with sources
// that serve only this host. sss counts only where no sssd configuration is
// readable (it has no domain then). systemd counts only where no userdb or homed
// record file exists and no userdb service but the built-in ones is running.
// Where pam_group has a rule, the group is not private either. Any other source
// (ldap, nis, winbind, extrausers, db, ...), a missing line or an unreadable
// file is not local.
func privateGroupSourcesAreLocal() bool {
	data, err := os.ReadFile(privateGroupNsswitchFile)
	if err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		database, sources, found := strings.Cut(line, ":")
		database = strings.TrimSpace(database)
		if !found || (database != "passwd" && database != "group" && database != "initgroups") {
			continue
		}
		if seen[database] {
			return false
		}
		seen[database] = true
		listed := 0
		for _, source := range strings.Fields(sources) {
			if strings.HasPrefix(source, "[") && strings.HasSuffix(source, "]") {
				continue
			}
			// An initgroups line of its own exists to treat supplementary groups
			// differently from group, and sss is the source that does it; an
			// sssd without a configuration is not taken as local there.
			if !privateGroupSourceIsLocal(source) || (database == "initgroups" && source == "sss") {
				return false
			}
			listed++
		}
		if listed == 0 {
			return false
		}
	}
	return seen["passwd"] && seen["group"] && !privateGroupPAMAddsGroups()
}

// privateGroupPAMAddsGroups reports whether pam_group has a rule to read: any
// line in a group.conf or group.d/*.conf it reads that is not blank or a
// comment. Whether the PAM stack loads the module is not asked; a rule file in
// any place the module reads is reason enough to refuse. A file or directory
// that cannot be read counts as a rule. The module reads the vendor group.conf
// only where the local one does not exist, so a local group.conf, even an empty
// or commented one, shadows the vendor file; group.d is read in every
// directory. The directories are the vendor floor plus those compiled into the
// installed module; a module that is there but names no group.conf cannot be
// told apart from one that reads somewhere unlisted, so it counts as a rule.
func privateGroupPAMAddsGroups() bool {
	hasRule := func(path string) bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return !os.IsNotExist(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				return true
			}
		}
		return false
	}
	vendorDirs, ok := privateGroupPAMVendorSources()
	if !ok {
		return true
	}
	localConf := filepath.Join(privateGroupPAMLocalDir, "group.conf")
	_, err := os.Lstat(localConf)
	if err != nil && !os.IsNotExist(err) {
		return true
	}
	vendorConfRead := err != nil
	if !vendorConfRead && hasRule(localConf) {
		return true
	}
	for i, dir := range append([]string{privateGroupPAMLocalDir}, vendorDirs...) {
		if i > 0 && vendorConfRead && hasRule(filepath.Join(dir, "group.conf")) {
			return true
		}
		groupDir := filepath.Join(dir, "group.d")
		if privateGroupDirHasEntry(groupDir, func(name string) bool {
			return strings.HasSuffix(name, ".conf") && hasRule(filepath.Join(groupDir, name))
		}) {
			return true
		}
	}
	return false
}

// privateGroupPAMVendorSources returns the vendor directories pam_group may
// read: privateGroupPAMVendorDirs plus every directory the installed module
// names for group.conf or group.d. false when a module is there that cannot be
// read or names no group.conf path.
func privateGroupPAMVendorSources() ([]string, bool) {
	seen := map[string]bool{filepath.Clean(privateGroupPAMLocalDir): true}
	var dirs []string
	add := func(dir string) {
		if dir = filepath.Clean(dir); !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	for _, dir := range privateGroupPAMVendorDirs {
		add(dir)
	}
	for _, pattern := range privateGroupPAMModuleDirs {
		matches, err := filepath.Glob(filepath.Join(pattern, "pam_group.so"))
		if err != nil {
			return nil, false
		}
		for _, module := range matches {
			info, err := os.Stat(module)
			if err != nil || info.Size() > privateGroupPAMModuleMaxBytes {
				return nil, false
			}
			data, err := os.ReadFile(module)
			if err != nil {
				return nil, false
			}
			named := false
			for _, text := range bytes.Split(data, []byte{0}) {
				path := string(text)
				if !strings.HasPrefix(path, "/") {
					continue
				}
				if strings.HasSuffix(path, "/group.conf") {
					named = true
					add(filepath.Dir(path))
				} else if i := strings.Index(path, "/group.d"); i > 0 && (path[i:] == "/group.d" || strings.HasPrefix(path[i:], "/group.d/")) {
					add(path[:i])
				}
			}
			if !named {
				return nil, false
			}
		}
	}
	return dirs, true
}

func privateGroupSourceIsLocal(source string) bool {
	switch source {
	case "files", "compat":
		return true
	case "sss":
		return !privateGroupDirHasEntry(privateGroupSSSDDir, func(name string) bool {
			return name == "sssd.conf"
		}) && !privateGroupDirHasEntry(filepath.Join(privateGroupSSSDDir, "conf.d"), func(name string) bool {
			return strings.HasSuffix(name, ".conf")
		})
	case "systemd":
		if privateGroupDirHasEntry(privateGroupUserdbSocks, func(name string) bool {
			return !privateGroupBuiltinUserdbServices[name]
		}) {
			return false
		}
		for _, dir := range privateGroupUserdbDirs {
			if privateGroupDirHasEntry(dir, func(name string) bool {
				for _, suffix := range []string{".user", ".group", ".membership", ".identity"} {
					if strings.HasSuffix(name, suffix) {
						return true
					}
				}
				return false
			}) {
				return false
			}
		}
		return true
	}
	return false
}

// privateGroupDirHasEntry reports whether dir holds an entry the match accepts.
// A directory that is not there holds none; one that cannot be read counts as
// holding one, so the answer stays on the refusing side.
func privateGroupDirHasEntry(dir string, match func(name string) bool) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, entry := range entries {
		if match(entry.Name()) {
			return true
		}
	}
	return false
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
// account name it found. A path with an access ACL fails it unless the caller
// has judged the ACL (aclJudged).
func ownerPrivateGroupName(path string, info os.FileInfo, aclJudged bool) (string, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", false
	}
	if !aclJudged {
		if _, present, err := hookAPIReadLinuxXattr(path, "system.posix_acl_access"); err != nil || present {
			return "", false
		}
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
