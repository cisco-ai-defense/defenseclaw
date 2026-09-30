//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// enokey is fscrypt's "key not available" error for a locked home.
const enokey = syscall.ENOKEY

// ecryptfsSupported: ecryptfs private homes exist only on Linux.
const ecryptfsSupported = true

var (
	unixMountInfoPath          = "/proc/self/mountinfo"
	unixLogindUsersDir         = "/run/systemd/users"
	unixMountInfoMaxSize int64 = 16 << 20
)

// platformMountAt reads the kernel mount table, not the filesystem at
// path, so a hung or hostile mount cannot block or answer it. Stacked
// mounts are listed bottom-up; the last one at path is the visible one.
func platformMountAt(path string) (unixMount, bool, error) {
	file, err := os.Open(unixMountInfoPath)
	if err != nil {
		return unixMount{}, false, err
	}
	defer file.Close()
	return parseMountInfoAt(bufio.NewScanner(io.LimitReader(file, unixMountInfoMaxSize)), filepath.Clean(path))
}

func parseMountInfoAt(scanner *bufio.Scanner, path string) (unixMount, bool, error) {
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var found unixMount
	ok := false
	for scanner.Scan() {
		// id parent major:minor root mountpoint options [optional...] - fstype source superoptions
		fields := strings.Fields(scanner.Text())
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) {
			continue
		}
		if filepath.Clean(unescapeMountInfo(fields[4])) != path {
			continue
		}
		mount := unixMount{FSType: fields[sep+1], Owner: -1}
		if sep+3 < len(fields) {
			for _, option := range strings.Split(fields[sep+3], ",") {
				if value, has := strings.CutPrefix(option, "user_id="); has {
					if uid, err := strconv.Atoi(value); err == nil && uid >= 0 {
						mount.Owner = uid
					}
				}
			}
		}
		found, ok = mount, true
	}
	if err := scanner.Err(); err != nil {
		return unixMount{}, false, err
	}
	return found, ok, nil
}

// unescapeMountInfo decodes the kernel's octal escapes (\040 for a space).
func unescapeMountInfo(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

// platformLiveSession reports a logind user record: a login session or a
// lingering user manager, either of which can run the user's agents.
func platformLiveSession(uid int) bool {
	if uid <= 0 {
		return false
	}
	_, err := os.Lstat(filepath.Join(unixLogindUsersDir, strconv.Itoa(uid)))
	return err == nil
}
