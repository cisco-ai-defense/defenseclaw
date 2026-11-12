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
// token file: root or this account, never the plugin account, so the plugin
// account cannot swap the file or the folder. Tests replace it.
var openClawTokenDirOwnerOK = func(uid uint32) bool { return uid == 0 || int(uid) == os.Geteuid() }

// publishOpenClawPluginToken writes the plugin credential to path with mode
// 0640 and group group (empty keeps the primary group of this account). The
// folder must exist, must not be a symlink and must not be group or other
// writable. The file is written next to path and renamed over it, so the
// plugin never reads a partial token and a symlink planted at path is
// replaced, not followed.
func publishOpenClawPluginToken(path, group, token string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("plugin_token_file must be an absolute path")
	}
	dir := filepath.Dir(path)
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
		return fmt.Errorf("folder %s must belong to root or this account", dir)
	}
	gid := -1
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("plugin_token_group %s: %w", group, err)
		}
		if gid, err = strconv.Atoi(g.Gid); err != nil {
			return fmt.Errorf("plugin_token_group %s: gid %q", group, g.Gid)
		}
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
	if _, err = tmp.WriteString(token + "\n"); err == nil && gid >= 0 {
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
