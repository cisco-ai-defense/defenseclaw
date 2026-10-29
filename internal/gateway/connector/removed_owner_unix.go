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
	"os"
	"syscall"
)

// removedKeepOwner gives a rewritten agent config back the owner it had: a
// teardown that runs as root (a managed upgrade or uninstall) must not leave
// the user's file owned by root. until 1.1, with removed.go.
func removedKeepOwner(path string, before os.FileInfo) error {
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if now, ok := after.Sys().(*syscall.Stat_t); ok && now.Uid == st.Uid && now.Gid == st.Gid {
		return nil
	}
	return os.Lchown(path, int(st.Uid), int(st.Gid))
}
