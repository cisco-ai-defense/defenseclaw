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

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"syscall"
)

// otlpOpenNoFollow returns O_NOFOLLOW flag value for symlink-safe file opens.
func otlpOpenNoFollow() int {
	return syscall.O_NOFOLLOW
}

// otlpValidatePerm enforces that the token file is not group/other accessible.
// On Unix the file is created 0600, so anything else is a tampering signal.
func otlpValidatePerm(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("OTLP path-token %s has mode %o, want 600", path, mode)
	}
	return nil
}

// otlpValidateOwner checks that the file at the given path is owned by the
// current user. Returns nil if the check passes or is not applicable.
func otlpValidateOwner(path string, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != os.Getuid() {
			return fmt.Errorf("OTLP path-token %s uid %d does not match current uid %d", path, stat.Uid, os.Getuid())
		}
	}
	return nil
}
