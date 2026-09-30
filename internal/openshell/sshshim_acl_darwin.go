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

//go:build darwin

package openshell

import (
	"io/fs"
	"sync"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// sshShimACLPassed maps a directory whose ACL passed to the identity and
// change time it had then. Changing an ACL updates the change time, so an
// entry added since is never missed; the directories above the temporary
// directory, the same for every shim, are then spared a /bin/ls each
// time. One entry per path keeps it bounded.
var sshShimACLPassed sync.Map // string -> sshShimACLStamp

type sshShimACLStamp struct {
	dev   int32
	ino   uint64
	ctime syscall.Timespec
}

// checkSSHShimACL refuses a path whose macOS ACL has an allow entry with a
// write-capable right (write, append, add_file, delete_child and the
// like): macOS grants those without changing the mode bits the other
// checks read, and an inheritable entry on a directory reaches the shim
// made in it. remember lets a pass for info, as it is now, stand.
func checkSSHShimACL(p string, info fs.FileInfo, remember bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	remember = remember && ok
	var stamp sshShimACLStamp
	if remember {
		stamp = sshShimACLStamp{dev: st.Dev, ino: st.Ino, ctime: st.Ctimespec}
		if prev, hit := sshShimACLPassed.Load(p); hit && prev.(sshShimACLStamp) == stamp {
			return nil
		}
	}
	if err := managed.ValidatePathACL(p); err != nil {
		return err
	}
	if remember {
		sshShimACLPassed.Store(p, stamp)
	}
	return nil
}
