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

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stateRemovalBlockers names the machine-state folders and files the
// uninstall would fail to remove, before it changes anything. The state goes
// last, after the services, the hook registrations and, on a payload install
// or a macOS pkg, the binaries: an immutable file in the data folder made the
// uninstall fail after the CLI was gone, so it could not be rerun without
// reinstalling (p0-round GAP-1440). A folder must be writable to remove its
// entries; a file only fails on its own when it is immutable or on a
// read-only file system (access(2) answers EPERM or EROFS for root too).
// State an uninstall keeps (--keep-state, the administrator policies of a
// Linux uninstall, the sandbox store the accounts may keep) is not checked.
func (l *lifecycle) stateRemovalBlockers() []string {
	env := l.env
	if l.opts.KeepState && !l.opts.Purge {
		return nil
	}
	skip := map[string]bool{}
	if !l.opts.Purge {
		skip[env.P(filepath.Join(env.Layout.DataDir, sandboxStoreDirName))] = true
		skip[env.P(filepath.Join(env.Layout.DataDir, correlationKeyFileName))] = true
		if env.GOOS == "linux" {
			skip[env.P(env.Layout.PolicyDir)] = true
		}
	}
	var blocked []string
	add := func(path string, err error) {
		blocked = append(blocked, fmt.Sprintf("%s (%v)", path, err))
	}
	// The gateway's clean-session folder goes with every uninstall.
	for _, dir := range []string{env.Layout.ConfigDir, env.Layout.DataDir, env.Layout.GuardianAuthDir, managed.ForeignHookCleanDir(env.Layout.DataDir), env.Layout.LogDir, env.Layout.LifecycleDir} {
		if dir == "" {
			continue
		}
		root := env.P(dir)
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		if dir != env.Layout.LifecycleDir { // the lifecycle folder stays with its lock
			if err := unix.Access(filepath.Dir(root), unix.W_OK|unix.X_OK); err != nil {
				add(filepath.Dir(dir), err)
				continue
			}
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil // the removal reports what it cannot read
			}
			if skip[path] {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if err := unix.Access(path, unix.W_OK|unix.X_OK); err != nil {
					add(env.canonical(path), err)
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			if err := unix.Access(path, unix.W_OK); errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
				add(env.canonical(path), err)
			}
			return nil
		})
	}
	return blocked
}

// stateRemovalBlockedMessage is the uninstall_failed text for the paths of
// stateRemovalBlockers.
func (l *lifecycle) stateRemovalBlockedMessage(blocked []string) string {
	const shown = 3
	list := strings.Join(blocked, ", ")
	if len(blocked) > shown {
		list = strings.Join(blocked[:shown], ", ") + fmt.Sprintf(" and %d more", len(blocked)-shown)
	}
	clear := "`chattr -i`"
	if l.env.GOOS == "darwin" {
		clear = "`chflags nouchg` or `chflags noschg`"
	}
	return "nothing was changed: the uninstall could not remove " + list +
		", an immutable file or folder or a read-only file system; clear it (" + clear + ") and rerun `" + l.uninstallCommand() + "`"
}
