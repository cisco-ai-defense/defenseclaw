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
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// openClawTokenDirOwnerOK is the owner rule for the folder of the plugin
// token file: this account, which writes the file there (a root-owned
// folder cannot take it, rel-1-0-10 GAP-0077), never the plugin account, so
// the plugin account cannot swap the file or the folder. Tests replace it.
var openClawTokenDirOwnerOK = func(uid uint32) bool { return int(uid) == os.Geteuid() }

// openClawBroadGroups are groups every standard account of a host is in;
// a plugin credential readable by one of them is readable by everyone.
var openClawBroadGroups = map[string]bool{"staff": true, "users": true, "everyone": true, "wheel": true, "admin": true, "root": true}

// openClawGroupHasMember reports whether account is a member of group g
// (its primary group or a supplementary one). Tests replace it.
var openClawGroupHasMember = func(g *user.Group, account string) bool {
	u, err := user.Lookup(account)
	if err != nil {
		return false
	}
	if u.Gid == g.Gid {
		return true
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, id := range ids {
		if id == g.Gid {
			return true
		}
	}
	return false
}

// publishOpenClawPluginToken writes the plugin credential to path with mode
// 0640 and group group, which must contain account and must not be a group
// every account is in. The folder and the folders above it must not be
// symlinks or writable by group or other (except sticky ones above the
// folder). The file is written next to path and renamed over it, so the
// plugin never reads a partial token and a symlink planted at path is
// replaced, not followed.
func publishOpenClawPluginToken(path, group, account, token string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("plugin_token_file must be an absolute path")
	}
	if group == "" {
		return fmt.Errorf("plugin_token_group is required: the group of the plugin account that may read the credential")
	}
	if openClawBroadGroups[group] {
		return fmt.Errorf("plugin_token_group %s is a group every account is in; create a group for the plugin account", group)
	}
	dir := filepath.Dir(path)
	for up := filepath.Dir(dir); up != filepath.Dir(up); up = filepath.Dir(up) {
		info, err := os.Lstat(up)
		if err != nil {
			return fmt.Errorf("folder %s: %w", up, err)
		}
		if info.Mode()&os.ModeSymlink != 0 && !openClawSystemSymlink(up) {
			return fmt.Errorf("folder %s is a symlink", up)
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("folder %s is group or other writable (mode %04o)", up, info.Mode().Perm())
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("folder %s: %w (create it as root or this account, mode 0755)", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("folder %s is not a plain folder", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("folder %s is group or other writable (mode %04o)", dir, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !openClawTokenDirOwnerOK(st.Uid) {
		return fmt.Errorf("folder %s must belong to the DefenseClaw account (mode 0755 or 0750), which writes the credential there", dir)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("plugin_token_group %s: %w", group, err)
	}
	if account != "" && !openClawGroupHasMember(g, account) {
		return fmt.Errorf("plugin_account %s is not in plugin_token_group %s", account, group)
	}
	// Giving the file to the group needs this account in it too (GAP-0080).
	if me, err := user.Current(); err == nil && os.Geteuid() != 0 && !openClawGroupHasMember(g, me.Username) {
		return fmt.Errorf("the DefenseClaw account %s is not in plugin_token_group %s; add both accounts to the group (usermod -aG %s %s), then restart the DefenseClaw gateway", me.Username, group, group, me.Username)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("plugin_token_group %s: gid %q", group, g.Gid)
	}
	tmp, err := os.CreateTemp(dir, ".openclaw-plugin-token-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.WriteString(token + "\n"); err == nil {
		err = tmp.Chown(-1, gid)
	}
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	keep = true
	if final, err := os.Lstat(path); err != nil || !final.Mode().IsRegular() {
		return errors.New("the published file is not a regular file")
	}
	return nil
}

// openClawSystemSymlink accepts the macOS compatibility links /etc, /var and
// /tmp (to /private/...), which only root can change.
func openClawSystemSymlink(p string) bool {
	switch p {
	case "/etc", "/var", "/tmp":
		return true
	}
	return false
}
