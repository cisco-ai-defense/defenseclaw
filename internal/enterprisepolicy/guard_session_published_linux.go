//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// grantPublishedSessionReader sets the POSIX access ACL of the per-user
// folder: the owner (the gateway service account) rwx, the account uid
// r-x, nobody else (mask r-x, so the folder's mode reads 0750 and the
// group class can never write).
func grantPublishedSessionReader(dir string, uid uint32) error {
	acl := posixacl.View{
		Present: true,
		Owner:   7,
		Mask:    5,
		Users:   []posixacl.Entry{{Kind: "user", ID: int(uid), Perm: 5}},
	}
	return unix.Setxattr(dir, linuxAccessACLXattr, linuxAccessACLData(acl), 0)
}
