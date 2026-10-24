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

package openshell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AdminE2fsprogsTools are the e2fsprogs tools the macOS MicroVM driver
// formats every MicroVM's disks with.
var AdminE2fsprogsTools = []string{"mke2fs", "debugfs"}

// PackageE2fsprogsDir is the root-owned fallback carried by the managed
// macOS package. An explicit administrator setting always takes precedence.
const PackageE2fsprogsDir = "/opt/cisco/defenseclaw/share/e2fsprogs"

// AdminE2fsprogsToolDir is the folder the MicroVM driver gets e2fsprogs
// from under the administrator's enterprise.openshell.e2fsprogs_dir: its
// sbin or bin (an e2fsprogs install prefix, the layout of Homebrew's keg
// and of make install), else the folder itself when it holds the tools.
// The first of them holding both mke2fs and debugfs wins, so the one folder
// the gateway puts first on its PATH has both. ensure checks this folder and
// the gateway's exec shim runs with it: one rule, so ensure never accepts a
// directory the gateway then refuses (GAP-0506). "" when none holds both.
// isFile reports whether a path names a regular file (RegularFile; ensure
// maps the path below its root first).
func AdminE2fsprogsToolDir(dir string, isFile func(path string) bool) string {
	if dir == "" {
		return ""
	}
	for _, candidate := range []string{filepath.Join(dir, "sbin"), filepath.Join(dir, "bin"), dir} {
		found := true
		for _, tool := range AdminE2fsprogsTools {
			if !isFile(filepath.Join(candidate, tool)) {
				found = false
				break
			}
		}
		if found {
			return candidate
		}
	}
	return ""
}

// RegularFile reports whether path, after its links, is a regular file.
func RegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ManagedE2fsprogsToolDir chooses the tools put first on a managed Mac
// gateway's PATH. An administrator's configured directory is authoritative:
// a broken one never falls back to a user's build.
// trustedAdmin checks the chosen directory and both tool files by the same
// managed rules used by the exec shim. A tool the account owns or a symlink
// to one must not become a command on an administrator's PATH.
// Without an administrator value, the account's own build wins before the
// managed package fallback; a Homebrew keg is never selected (GAP-0004).
func ManagedE2fsprogsToolDir(adminDir, home string, uid int, trustedAdmin func(path string, file bool) error) (dir, problem string) {
	return managedE2fsprogsToolDir(adminDir, PackageE2fsprogsDir, home, uid, trustedAdmin)
}

func managedE2fsprogsToolDir(adminDir, packageDir, home string, uid int, trustedAdmin func(path string, file bool) error) (dir, problem string) {
	if adminDir != "" {
		tools := AdminE2fsprogsToolDir(adminDir, RegularFile)
		if tools == "" {
			if problem := inaccessibleE2fsprogsProblem(adminDir); problem != "" {
				return "", problem
			}
			return "", fmt.Sprintf("the administrator's e2fsprogs %s holds no mke2fs and debugfs side by side; set enterprise.openshell.e2fsprogs_dir to the install prefix or the folder that holds both tools", adminDir)
		}
		if trustedAdmin == nil {
			return "", fmt.Sprintf("the administrator's e2fsprogs %s cannot be trusted without a directory check", tools)
		}
		if err := trustedAdmin(tools, false); err != nil {
			return "", fmt.Sprintf("the administrator's e2fsprogs %s is not trusted: %v", tools, err)
		}
		for _, name := range AdminE2fsprogsTools {
			path := filepath.Join(tools, name)
			if err := trustedAdmin(path, true); err != nil {
				return "", fmt.Sprintf("the administrator's e2fsprogs tool %s is not trusted: %v", path, err)
			}
		}
		if problem := E2fsprogsAccessProblem(tools, os.Stat); problem != "" {
			return "", problem
		}
		return tools, ""
	}
	if filepath.IsAbs(home) {
		own := filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin")
		if ownedE2fsprogsTools(own, uid) {
			return own, ""
		}
	}
	if tools := AdminE2fsprogsToolDir(packageDir, RegularFile); tools != "" {
		if trustedAdmin == nil {
			return "", "the package e2fsprogs cannot be trusted without a directory check"
		}
		if err := trustedAdmin(tools, false); err != nil {
			return "", fmt.Sprintf("the package e2fsprogs %s is not trusted: %v", tools, err)
		}
		for _, name := range AdminE2fsprogsTools {
			if err := trustedAdmin(filepath.Join(tools, name), true); err != nil {
				return "", fmt.Sprintf("the package e2fsprogs tool %s is not trusted: %v", name, err)
			}
		}
		if problem := E2fsprogsAccessProblem(tools, os.Stat); problem != "" {
			return "", problem
		}
		return tools, ""
	}
	if problem := inaccessibleE2fsprogsProblem(packageDir); problem != "" {
		return "", problem
	}
	return "", "MicroVM sandboxes need mke2fs and debugfs in the administrator's enterprise.openshell.e2fsprogs_dir, your own ~/.local/opt/e2fsprogs/sbin, or the managed package; a Homebrew keg is not used on a managed computer"
}

// inaccessibleE2fsprogsProblem is used only after no complete pair could be
// inspected. An unused private sbin must not hide a usable bin. If several
// candidates are inaccessible, name them without claiming which holds tools.
func inaccessibleE2fsprogsProblem(prefix string) string {
	var inaccessible []string
	for _, candidate := range []string{filepath.Join(prefix, "sbin"), filepath.Join(prefix, "bin"), prefix} {
		info, err := os.Stat(candidate)
		if os.IsPermission(err) || (err == nil && info.IsDir() && info.Mode().Perm()&0o001 == 0) {
			inaccessible = append(inaccessible, candidate)
		}
	}
	if len(inaccessible) == 0 {
		return ""
	}
	return "the e2fsprogs tool folders cannot be traversed by every account: " + strings.Join(inaccessible, ", ") +
		"; ask your administrator to make the selected folder and its ancestors traversable (chmod o+x), then retry"
}

// E2fsprogsAccessProblem is the account-access check shared by ensure,
// doctor and the gateway shim. Root can see a private tool directory that
// the accounts' gateways cannot traverse; every sandbox account must be
// able to reach and execute both tools. stat maps canonical paths under
// ensure's test root, or is os.Stat in the account process.
func E2fsprogsAccessProblem(tools string, stat func(string) (os.FileInfo, error)) string {
	if problem := e2fsprogsDirectoryAccessProblem(tools, stat); problem != "" {
		return problem
	}
	for _, name := range AdminE2fsprogsTools {
		path := filepath.Join(tools, name)
		info, err := stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o001 == 0 {
			return path + " cannot be executed by every account; ask your administrator to grant execute access (chmod o+x), then retry"
		}
	}
	return ""
}

func e2fsprogsDirectoryAccessProblem(tools string, stat func(string) (os.FileInfo, error)) string {
	for dir := tools; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		info, err := stat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o001 == 0 {
			return dir + " cannot be traversed by every account; ask your administrator to grant directory traversal (chmod o+x), then retry"
		}
	}
	return ""
}

func ownedE2fsprogsTools(dir string, uid int) bool {
	for _, name := range AdminE2fsprogsTools {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 {
			return false
		}
		owner, ok := fileUID(info)
		if !ok || owner != uid {
			return false
		}
	}
	return true
}
