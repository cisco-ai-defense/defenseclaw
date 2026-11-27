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

// skillAdminUID is the owner a managed folder or file has: root. A test sets it
// to its own user so the owner check passes without root.
var skillAdminUID uint32

// skillFolderManaged is skillFolderAdminOwned; tests replace it.
var skillFolderManaged = skillFolderAdminOwned

// skillFolderAdminOwned reports whether only root can write the opened skill
// folder: root owns it and neither its group nor others may write it. A link
// above the folder does not change that (/etc is a link on macOS): the owner
// and mode are read from the folder's own handle. A folder outside every home
// that a user made is not reported as managed.
func skillFolderAdminOwned(dir *os.File, _ string) bool {
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == skillAdminUID
}

// skillEntryManaged is skillEntryAdminOwned; tests replace it.
var skillEntryManaged = skillEntryAdminOwned

// skillEntryAdminOwned reports whether the opened folder or file below a
// managed skill folder is also one only root can change: root owns it and
// neither its group nor others may write it. A file or subfolder a user owns
// or others may write makes the skill the user's, as on Windows (GAP-2147).
// Only the owner and the mode bits are read. A Linux POSIX access list that
// grants write shows in the group bits (the mask) and is caught; a macOS
// extended access list is not visible in them and is not read (a documented
// limit, rel-1-0-10:GAP-2165: the CGO-free build has no call that reads it
// from the handle).
func skillEntryAdminOwned(opened *os.File, _ string) bool {
	info, err := opened.Stat()
	if err != nil || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == skillAdminUID
}
