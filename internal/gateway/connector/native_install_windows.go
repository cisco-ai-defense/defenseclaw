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

	"golang.org/x/sys/windows"
)

// canonicalNativeWindowsInstallRoot returns the native setup's fixed per-user
// application root. The Known Folder API is authoritative here: environment
// variables and installer state are attacker-controlled inputs and cannot
// establish trust in an otherwise arbitrary executable tree.
func canonicalNativeWindowsInstallRoot() string {
	localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil || strings.TrimSpace(localAppData) == "" {
		return ""
	}
	return filepath.Join(localAppData, "Programs", "DefenseClaw")
}

func nativeWindowsPathHasNoReparsePoints(path string) bool {
	current, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for {
		pointer, err := windows.UTF16PtrFromString(current)
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
