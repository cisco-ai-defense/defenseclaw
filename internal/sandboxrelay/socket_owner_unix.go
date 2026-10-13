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

package sandboxrelay

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// checkSocketOwner checks the socket at path and its directory against
// trusted (root included by the caller). Lstat on both: a symlink is never
// followed to somewhere else.
func checkSocketOwner(path string, trusted []int) error {
	dirPath := filepath.Dir(path)
	dir, err := os.Lstat(dirPath)
	if err != nil {
		return fmt.Errorf("%w: hook socket directory: %v", ErrSocketUntrusted, err)
	}
	if !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is not a real directory", ErrSocketUntrusted, dirPath)
	}
	if dir.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by other accounts", ErrSocketUntrusted, dirPath)
	}
	if !slices.Contains(trusted, fileOwner(dir)) {
		return fmt.Errorf("%w: %s is not owned by the managed gateway", ErrSocketUntrusted, dirPath)
	}
	sock, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: hook socket: %v", ErrSocketUntrusted, err)
	}
	if sock.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %s is not a socket", ErrSocketUntrusted, path)
	}
	if !slices.Contains(trusted, fileOwner(sock)) {
		return fmt.Errorf("%w: %s is not owned by the managed gateway", ErrSocketUntrusted, path)
	}
	return nil
}

func fileOwner(info os.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
