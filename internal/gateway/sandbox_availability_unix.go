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
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/posixacl"
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
// member of its group, else the other bits. For /dev/kvm, a named user ACL
// takes precedence over group and other bits. A path or ACL that cannot be
// examined grants nothing.
//
// On macOS the docker socket is Docker Desktop's link into the home of the
// account that started it last; the gateway's service account cannot look
// behind it, so the link itself decides (sandboxDockerDesktopAccess).
func sandboxPathAccess(path string, uid int) sandboxDeviceAccess {
	if path == sandboxDockerSocketPath && runtime.GOOS == "darwin" {
		return sandboxDockerDesktopAccess(path, uid, sandboxAccountHome)
	}
	return sandboxDevicePathAccess(path, uid, path == sandboxKVMDevicePath)
}

// sandboxAccountHome is uid's home folder from the account database;
// tests replace it.
var sandboxAccountHome = func(uid int) (string, error) {
	account, err := unixidentity.Default(context.Background()).LookupUID(uid)
	if err != nil {
		return "", err
	}
	return account.Home, nil
}

// sandboxDockerLinkTrusted reports a docker socket link only root can have
// made (Docker Desktop's privileged helper writes it in /var/run); tests
// replace it.
var sandboxDockerLinkTrusted = func(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// sandboxDockerDesktopAccess judges the macOS docker socket path for uid.
// Docker Desktop points it, as a root-owned link, at
// <home>/.docker/run/docker.sock of the account whose Docker Desktop
// started last, behind that account's 0700 ~/.docker. The managed gateway
// runs as a service account, so a stat through the link fails for it even
// when the link leads to the caller's own Docker Desktop, and every
// managed Mac account was told the socket isn't read-write for it
// (GAP-0007). A trusted link into the caller's own home is the caller's
// own Docker Desktop: usable, and the account's sandbox daemon checks that
// Docker answers when the sandbox starts. Anything else is judged through
// the link as before: another account's Docker Desktop stays denied.
func sandboxDockerDesktopAccess(path string, uid int, home func(int) (string, error)) sandboxDeviceAccess {
	access := sandboxDevicePathAccess(path, uid, false)
	if access.State != sandboxDeviceDenied {
		return access
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&fs.ModeSymlink == 0 || !sandboxDockerLinkTrusted(info) {
		return access
	}
	target, err := os.Readlink(path)
	if err != nil {
		return access
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	dir, err := home(uid)
	if err != nil {
		// The answer depends on an account record that could not be
		// looked up: provisional, as for groups (GAP-0507).
		return sandboxDeviceAccess{State: sandboxDeviceGroupsUnknown}
	}
	if dir = filepath.Clean(dir); dir == "/" || !filepath.IsAbs(dir) {
		return access
	}
	if filepath.Clean(target) == filepath.Join(dir, ".docker", "run", "docker.sock") {
		return sandboxDeviceAccess{State: sandboxDeviceUsable}
	}
	return access
}

func sandboxDevicePathAccess(path string, uid int, checkACL bool) sandboxDeviceAccess {
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
	if checkACL && uid != int(st.Uid) {
		acl, err := posixacl.ReadAccessXattr(path)
		if err != nil {
			return sandboxDeviceAccess{State: sandboxDeviceDenied}
		}
		if acl.Present {
			if found, allowed := acl.NamedUserAllows(uid, 0o6); found {
				if allowed {
					return sandboxDeviceAccess{State: sandboxDeviceUsable}
				}
				return sandboxDeviceAccess{State: sandboxDeviceDenied}
			}
		}
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
