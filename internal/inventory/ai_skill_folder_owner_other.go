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

package inventory

import (
	"os"
	"syscall"
)

// skillFolderManaged is skillFolderAdminOwned; tests replace it.
var skillFolderManaged = skillFolderAdminOwned

// skillManagedNeedsNoLink is false: a link above the folder does not change
// who may write it (/etc is a link on macOS), and the owner and mode are read
// from the folder's own handle.
const skillManagedNeedsNoLink = false

// skillFolderAdminOwned reports whether only root can write the opened skill
// folder: root owns it and neither its group nor others may write it. A
// folder outside every home that a user made is not reported as managed.
func skillFolderAdminOwned(dir *os.File, _ string) bool {
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// skillEntryAdminOwned is true: below a root-owned folder that neither the
// group nor others may write, only root can add or remove entries.
func skillEntryAdminOwned(*os.File, string) bool { return true }
