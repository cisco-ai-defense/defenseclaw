// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterprisehooks

import (
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// LocalAccountsStamp is the size, modification time and inode of
// /etc/passwd, which useradd, userdel and usermod replace, followed by those
// of the other local account databases NSS reads that exist on the host
// (LocalAccountDatabases) (Linux); "" when /etc/passwd cannot be read and on
// other systems. The guardian writes the stamp it read before a pass into
// the identity records with a home proof (IdentitySpoolRecord.AccountsStamp),
// and the gateway takes such a proof for the uid's holder only while the
// stamp is still the current one (GAP-0422, GAP-2025). Tests replace it.
var LocalAccountsStamp = func() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	stamp := localAccountDatabaseStamp("/etc/passwd")
	if stamp == "" {
		return ""
	}
	for _, path := range LocalAccountDatabases {
		if other := localAccountDatabaseStamp(path); other != "" {
			stamp += "+" + other
		}
	}
	return stamp
}

// LocalAccountDatabases are the local account databases besides /etc/passwd
// that NSS reads on Linux: the systemd-userdb drop-in record directories
// (nss-systemd), which change when a record is removed or added, and
// nss-altfiles. An account deleted and created again there under the same
// name, uid and home path left /etc/passwd as it was, so the gateway took the
// earlier holder's home proof as current until the guardian's next pass
// (GAP-2028). A path that does not exist adds nothing, so the stamp stays the
// /etc/passwd one where none of them is used. Tests replace it.
var LocalAccountDatabases = append(append([]string{}, unixidentity.UserdbRecordDirs...), unixidentity.AltfilesPasswdFiles...)

// localAccountDatabaseStamp is the modification time, size and inode of
// path; "" when it cannot be read.
func localAccountDatabaseStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += "/" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}
