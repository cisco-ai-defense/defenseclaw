//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// openClawInstallPolicyPathTrusted applies the OpenClaw rule for an install
// policy command (src/security/install-policy.ts assertSecureCommandPath,
// OpenClaw 2026.8.35 and 2026.11.3) before setup names it, so setup never
// writes a command OpenClaw refuses, which blocks every install: a regular
// file, not a link, not group or world writable, owned by root or by the
// account that runs OpenClaw; every parent folder owned by root or that
// account and not group or world writable unless it is sticky. account is
// the separate-user OpenClaw account, or "" for this process account.
func openClawInstallPolicyPathTrusted(command, account string) error {
	uid := os.Geteuid()
	if account != "" {
		u, err := user.Lookup(account)
		if err != nil {
			return fmt.Errorf("look up the OpenClaw account %s: %w", account, err)
		}
		n, err := strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("the OpenClaw account %s has no numeric uid", account)
		}
		uid = n
	}
	info, err := os.Lstat(command)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", command)
	}
	if err := openClawInstallPolicyOwnerOK(command, info, uid, false); err != nil {
		return err
	}
	for dir := filepath.Dir(command); ; dir = filepath.Dir(dir) {
		dirInfo, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if err := openClawInstallPolicyOwnerOK(dir, dirInfo, uid, true); err != nil {
			return err
		}
		if parent := filepath.Dir(dir); parent == dir {
			return nil
		}
	}
}

func openClawInstallPolicyOwnerOK(p string, info os.FileInfo, uid int, dir bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", p)
	}
	if int(st.Uid) != 0 && int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not root or the OpenClaw account (uid %d)", p, st.Uid, uid)
	}
	if info.Mode().Perm()&0o022 != 0 && !(dir && info.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("%s is group or world writable (mode %04o)", p, info.Mode().Perm())
	}
	return nil
}
