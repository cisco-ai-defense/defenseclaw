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

//go:build unix

package sandboxapi

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkDaemonSocket refuses a sandbox daemon socket the caller does not
// own, or one in a directory another account can write: the daemon there
// would see the caller's sandboxes and requests.
func checkDaemonSocket(path string) error {
	uid := os.Getuid()
	owner := func(info os.FileInfo) int {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			return int(st.Uid)
		}
		return -1
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("sandbox daemon socket directory: %w", err)
	}
	if !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm()&0o022 != 0 || owner(dir) != uid {
		return fmt.Errorf("sandbox daemon socket directory %s is not yours alone", filepath.Dir(path))
	}
	sock, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sandbox daemon socket: %w", err)
	}
	if sock.Mode()&os.ModeSocket == 0 || owner(sock) != uid {
		return fmt.Errorf("%s is not your sandbox daemon's socket", path)
	}
	return nil
}
