// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// createdParentDirsName is the list of shared parents the deployment created
// before it had a record, in the lifecycle directory: the macOS package
// preinstall writes the payload parents that did not exist
// (scripts/build-macos-enterprise-pkg.sh), and the lifecycle adds the
// parents its own first lock folder creates (/opt and /opt/cisco on macOS,
// ensureLifecycleDir). Seen later, they already exist, so without the list
// the lifecycle could not tell them from an administrator's folder. The next
// committed run moves them into the deployment record (CreatedDirs), and
// the uninstall removes them once empty, and no other parent (GAP-0091).
const createdParentDirsName = "created-parent-dirs"

// createdParentDirAllowed is every folder the list may name.
var createdParentDirAllowed = map[string]bool{
	"/opt": true, "/opt/cisco": true, "/usr/local": true, "/usr/local/bin": true,
}

func (e *Env) createdParentDirsPath() string {
	return filepath.Join(e.Layout.LifecycleDir, createdParentDirsName)
}

// ensureLifecycleDir creates the lifecycle directory, listing the allowed
// shared parents above it that it creates.
func (e *Env) ensureLifecycleDir() error {
	var absent []string
	if e.GOOS == "darwin" {
		for dir := filepath.Dir(e.Layout.LifecycleDir); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
			if _, err := os.Lstat(e.P(dir)); createdParentDirAllowed[dir] && errors.Is(err, os.ErrNotExist) {
				absent = append([]string{dir}, absent...)
			}
		}
	}
	if err := e.ensureDir(e.P(e.Layout.LifecycleDir), 0o700, rootOwner()); err != nil {
		return err
	}
	if len(absent) == 0 {
		return nil
	}
	// Best effort: an unlisted parent stays after an uninstall, the safe side.
	file, err := os.OpenFile(e.P(e.createdParentDirsPath()), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil
	}
	_, _ = file.WriteString(strings.Join(absent, "\n") + "\n")
	_ = file.Close()
	return nil
}

// createdParentDirs reads the list. A list that is not a root-owned regular
// file only root can write, or a name outside the allowed parents, is
// ignored: the folder then stays after an uninstall, the safe side.
func (e *Env) createdParentDirs() []string {
	if e.GOOS != "darwin" {
		return nil
	}
	path := e.P(e.createdParentDirsPath())
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil
	}
	if e.Trust(path, TrustAdminFile) != nil {
		return nil
	}
	data, err := readBounded(path, 4096)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, line := range strings.Split(string(data), "\n") {
		dir := strings.TrimSpace(line)
		if createdParentDirAllowed[dir] {
			dirs = mergeUnique(dirs, []string{dir})
		}
	}
	return dirs
}
