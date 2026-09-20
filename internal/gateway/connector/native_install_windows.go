//go:build windows

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
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// canonicalNativeWindowsInstallRoot returns the native setup's redirected
// per-user Programs root. The Known Folder API is authoritative here:
// environment variables and installer state cannot establish trust in an
// otherwise arbitrary executable tree.
func canonicalNativeWindowsInstallRoot() string {
	programs, err := winfolders.UserProgramFiles()
	if err != nil || strings.TrimSpace(programs) == "" {
		return ""
	}
	return filepath.Join(programs, "DefenseClaw")
}

// canonicalNativeWindowsHookBinary is the stable launcher path native Setup
// publishes outside both the replaceable install tree and the user data tree.
// Only this path is authorized by hookruntime to cold-start the exact installed
// gateway or become a disabled no-op during maintenance.
func canonicalNativeWindowsHookBinary() string {
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return ""
	}
	return filepath.Clean(paths.Launcher)
}

// canonicalNativeWindowsInstalledHookBinary is the legacy install-tree
// launcher path emitted by earlier native builds. It remains an owned teardown
// target, but new registrations use canonicalNativeWindowsHookBinary.
func canonicalNativeWindowsInstalledHookBinary() string {
	root := canonicalNativeWindowsInstallRoot()
	if strings.TrimSpace(root) == "" {
		return ""
	}
	return filepath.Join(root, "bin", windowsHookBinaryName)
}

// canonicalNativeWindowsInstalledGatewayBinary is the legacy install-tree
// gateway path used by native Codex notify registrations before the dedicated
// no-console hook launcher shipped. It is teardown authority only; new
// registrations must continue to use the stable HookRuntime launcher.
func canonicalNativeWindowsInstalledGatewayBinary() string {
	root := canonicalNativeWindowsInstallRoot()
	if strings.TrimSpace(root) == "" {
		return ""
	}
	return filepath.Join(root, "bin", windowsGatewayBinaryName)
}

func nativeWindowsPathHasNoReparsePoints(path string) bool {
	current, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		pointer, err := winpath.UTF16Ptr(current)
		if err != nil {
			return false
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
		current = parent
	}
}
