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

//go:build windows

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func requirePrivatePath(path string, info os.FileInfo) error {
	if info.IsDir() {
		return safefile.ValidatePrivateDirectory(path)
	}
	return safefile.ValidatePrivateFile(path)
}

func sgwWindowsExecutionEnvironment(_ string) (map[string]string, error) {
	windowsRoot, err := windows.GetWindowsDirectory()
	if err != nil || !filepath.IsAbs(windowsRoot) {
		return nil, errors.New("resolve Windows system directory for s-gw")
	}
	powershell := filepath.Join(
		windowsRoot,
		"System32",
		"WindowsPowerShell",
		"v1.0",
		"powershell.exe",
	)
	resolved, err := filepath.EvalSymlinks(powershell)
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(powershell)) {
		return nil, errors.New("resolve trusted Windows PowerShell for s-gw")
	}
	info, err := os.Lstat(powershell)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("trusted Windows PowerShell is unavailable")
	}
	return map[string]string{
		"PATH": strings.Join([]string{
			filepath.Dir(powershell),
			filepath.Join(windowsRoot, "System32"),
			windowsRoot,
		}, string(os.PathListSeparator)),
		"SystemRoot":             windowsRoot,
		"WINDIR":                 windowsRoot,
		"SGW_TRUSTED_POWERSHELL": powershell,
	}, nil
}
