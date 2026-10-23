//go:build darwin

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
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// grantPublishedSessionReader adds one macOS ACL entry to the per-user
// folder (mode 0700, owned by the gateway service account) that lets the
// account read and search it and read its metadata, nothing else. Every
// macOS user's primary group is staff, so the mode bits alone cannot give
// one user access. The records in the folder are 0644.
func grantPublishedSessionReader(dir string, uid uint32) error {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return err
	}
	name := strings.TrimSpace(account.Username)
	if name == "" || strings.ContainsAny(name, " \t\n,:") {
		return fmt.Errorf("account name %q cannot be named in an ACL entry", name)
	}
	entry := "user:" + name + " allow list,search,readattr,readextattr,readsecurity"
	cmd := exec.Command("/bin/chmod", "+a", entry, dir)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chmod +a: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
