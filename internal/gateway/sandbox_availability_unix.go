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

package gateway

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// sandboxAccountGroupIDs lists uid's group ids from the account database
// (NSS, so directory groups count); tests replace it.
var sandboxAccountGroupIDs = func(uid int) ([]int, error) {
	resolver := unixidentity.Default(context.Background())
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return nil, err
	}
	return resolver.GroupIDs(account)
}

// sandboxGroupName names a device's group for the user text ("" when it
// has no name); tests replace it.
var sandboxGroupName = func(gid int) string {
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		return g.Name
	}
	return ""
}

// sandboxPathAccess judges whether uid may read and write path, by the
// POSIX rule: the owner bits for its owner, else the group bits for a
// member of its group, else the other bits. ACLs are not consulted, so an
// ACL-only grant reads as no access (the gate then says sandboxes aren't
// available, never the reverse). A path that can't be examined exists but
// grants nothing.
func sandboxPathAccess(path string, uid int) sandboxDeviceAccess {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sandboxDeviceAccess{State: sandboxDeviceMissing}
		}
		return sandboxDeviceAccess{State: sandboxDeviceDenied}
	}
	st, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK {
		return sandboxDeviceAccess{State: sandboxDeviceDenied}
	}
	access := sandboxDeviceAccess{State: sandboxModeAccess(info.Mode().Perm(), int(st.Uid), int(st.Gid), uid, sandboxAccountGroupIDs)}
	if access.State == sandboxDeviceNotMember {
		access.Group = sandboxGroupName(int(st.Gid))
	}
	return access
}

// sandboxRecordTrusted reports a lifecycle record the gateway may believe:
// root's and writable by nobody else. Tests replace it.
var sandboxRecordTrusted = func(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

// sandboxModeAccess is sandboxPathAccess's rule for one file. The groups
// are looked up only when membership decides: a device whose group and
// other bits agree (/dev/kvm 0666) is judged without the directory, so an
// unreachable directory costs only the answers that depend on it.
func sandboxModeAccess(mode fs.FileMode, owner, group, uid int, groups func(int) ([]int, error)) sandboxDeviceState {
	if owner == uid {
		if mode&0o600 == 0o600 {
			return sandboxDeviceUsable
		}
		return sandboxDeviceDenied
	}
	groupRW, otherRW := mode&0o060 == 0o060, mode&0o006 == 0o006
	if groupRW == otherRW {
		if otherRW {
			return sandboxDeviceUsable
		}
		return sandboxDeviceDenied
	}
	gids, err := groups(uid)
	switch {
	case err != nil:
		return sandboxDeviceGroupsUnknown
	case slices.Contains(gids, group) == groupRW:
		// A member where the group may, or an outsider where others may.
		return sandboxDeviceUsable
	case groupRW:
		return sandboxDeviceNotMember
	}
	return sandboxDeviceDenied
}
