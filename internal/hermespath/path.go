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

// Package hermespath resolves the Hermes Agent user configuration directory.
// Hermes uses HERMES_HOME when explicitly configured, LocalAppData on native
// Windows, and ~/.hermes on Unix-like platforms. Native Windows never falls
// back to the legacy home.
package hermespath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var currentUserLocalAppDataForHome = currentUserLocalAppData

// HomeDir returns the Hermes user configuration directory for the host.
func HomeDir() string {
	configuredHome := os.Getenv("HERMES_HOME")
	if runtime.GOOS == "windows" {
		if strings.TrimSpace(configuredHome) != "" {
			return ResolveHomeDir(runtime.GOOS, configuredHome, "", "")
		}
		// Resolve the current token's Known Folder so inherited environment
		// overrides cannot redirect the updater-managed Hermes home.
		return ResolveHomeDir(runtime.GOOS, "", currentUserLocalAppDataForHome(), "")
	}
	userHome, _ := os.UserHomeDir()
	return ResolveHomeDir(
		runtime.GOOS,
		configuredHome,
		os.Getenv("LOCALAPPDATA"),
		userHome,
	)
}

// ConfigPath returns the host's resolved Hermes config.yaml path.
func ConfigPath() string {
	home := HomeDir()
	if strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, "config.yaml")
}

// ManagedExecutablePath returns the updater-managed Hermes executable for the
// current Windows token. HERMES_HOME is intentionally irrelevant here: it can
// select a supported configuration home, but it cannot redirect executable
// identity away from the official LocalAppData-managed virtual environment.
func ManagedExecutablePath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	home := ResolveHomeDir(runtime.GOOS, "", currentUserLocalAppDataForHome(), "")
	if home == "" {
		return ""
	}
	return filepath.Join(home, "hermes-agent", "venv", "Scripts", "hermes.exe")
}

// ResolveHomeDir is the pure, OS-parameterized core used by HomeDir and tests.
// Explicit HERMES_HOME always wins. Native Windows then uses
// %LOCALAPPDATA%\hermes. Unix-like hosts retain the historical ~/.hermes
// location. Windows returns empty when LocalAppData cannot be resolved so a
// legacy credential-bearing ~/.hermes tree never becomes current evidence.
func ResolveHomeDir(goos, configuredHome, localAppData, userHome string) string {
	rawConfiguredHome := configuredHome
	if configuredHome = strings.TrimSpace(configuredHome); configuredHome != "" {
		if goos == "windows" && (rawConfiguredHome != configuredHome ||
			strings.ContainsAny(configuredHome, "\x00\r\n") ||
			!isAbsoluteWindowsPath(configuredHome) ||
			(runtime.GOOS == "windows" && filepath.Clean(configuredHome) != configuredHome)) {
			return ""
		}
		return filepath.Clean(configuredHome)
	}
	if goos == "windows" {
		rawLocalAppData := localAppData
		if localAppData = strings.TrimSpace(localAppData); localAppData != "" {
			if rawLocalAppData != localAppData ||
				strings.ContainsAny(localAppData, "\x00\r\n") ||
				!isAbsoluteWindowsPath(localAppData) ||
				(runtime.GOOS == "windows" && filepath.Clean(localAppData) != localAppData) {
				return ""
			}
			if runtime.GOOS == "windows" {
				return filepath.Join(localAppData, "hermes")
			}
			return strings.TrimRight(localAppData, `\/`) + `\hermes`
		}
		return ""
	}
	return filepath.Join(strings.TrimSpace(userHome), ".hermes")
}

func isAbsoluteWindowsPath(path string) bool {
	if runtime.GOOS == "windows" {
		return filepath.IsAbs(path)
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return true
	}
	return len(path) >= 3 && path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/') &&
		((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
}
