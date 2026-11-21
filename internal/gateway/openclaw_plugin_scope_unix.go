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

package gateway

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// openClawStagedByAccount reports whether target resolves to a folder or
// file under /tmp or /var/tmp that account owns (not root): where OpenClaw
// stages installs for its install policy.
func openClawStagedByAccount(target, account string) bool {
	if account == "" || !filepath.IsAbs(target) {
		return false
	}
	u, err := user.Lookup(account)
	if err != nil || u.Uid == "0" {
		return false
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return false
	}
	under := false
	for _, root := range []string{"/tmp", "/var/tmp"} {
		rr, err := filepath.EvalSymlinks(root)
		if err == nil && strings.HasPrefix(resolved, rr+string(filepath.Separator)) {
			under = true
		}
	}
	if !under {
		return false
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(st.Uid) == uid
}
