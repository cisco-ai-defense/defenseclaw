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
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openClawPathOwnedForWriteOS accepts a missing path, or one this process
// account owns and may write.
func openClawPathOwnedForWriteOS(p string) error {
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read its owner")
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owner uid %d, this account uid %d", st.Uid, os.Geteuid())
	}
	if info.Mode().Perm()&0o200 == 0 {
		return fmt.Errorf("not writable by its owner (mode %04o)", info.Mode().Perm())
	}
	return nil
}
