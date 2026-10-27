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
)

// LocalAccountsStamp is the size, modification time and inode of
// /etc/passwd, which useradd, userdel and usermod replace (Linux); "" when it
// cannot be read and on other systems. The guardian writes the stamp it read
// before a pass into the identity records with a home proof
// (IdentitySpoolRecord.AccountsStamp), and the gateway takes such a proof
// for the uid's holder only while the stamp is still the current one
// (GAP-0422, GAP-2025). Tests replace it.
var LocalAccountsStamp = func() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		return ""
	}
	stamp := strconv.FormatInt(info.ModTime().UnixNano(), 10) + "/" + strconv.FormatInt(info.Size(), 10)
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp += "/" + strconv.FormatUint(uint64(st.Ino), 10)
	}
	return stamp
}
