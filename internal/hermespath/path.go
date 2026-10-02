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
	"encoding/json"
	"errors"
	"fmt"
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
// identity away from the official LocalAppData-managed install.
func ManagedExecutablePath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	home := ResolveHomeDir(runtime.GOOS, "", currentUserLocalAppDataForHome(), "")
	if home == "" {
		return ""
	}
	return managedExecutableUnderHome(home)
}

// managedExecutableCandidates lists the updater-managed Hermes executables
// under a Windows Hermes home, in preference order:
//
//   - hermes-agent\venv\Scripts\hermes.exe, the virtual-environment image of
//     the original installer;
//   - bin\hermes.exe, the launcher the bootstrap installer (Hermes 0.21.5 and
//     later) puts on PATH. It runs the leased environment under
//     installs\<id>\environments\<id>\venv, whose path changes with every
//     update, so the stable launcher is the image admission binds to.
//
// Both record the release in hermes-agent\install-stamp.json.
func managedExecutableCandidates(home string) []string {
	return []string{
		filepath.Join(home, "hermes-agent", "venv", "Scripts", "hermes.exe"),
		filepath.Join(home, "bin", "hermes.exe"),
	}
}

// managedExecutableUnderHome returns the first candidate that is a regular
// file, or the original virtual-environment path when none is present so
// callers report the historical location.
func managedExecutableUnderHome(home string) string {
	candidates := managedExecutableCandidates(home)
	for _, candidate := range candidates {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return candidates[0]
}

// ManagedExecutablePathForUserHome is ManagedExecutablePath for another
// user's profile home, for privileged services acting for that user (the
// calling token's known folders belong to the service). The default
// AppData\Local layout under the profile is assumed.
func ManagedExecutablePathForUserHome(userHome string) string {
	userHome = strings.TrimSpace(userHome)
	if runtime.GOOS != "windows" || userHome == "" {
		return ""
	}
	home := ResolveHomeDir(runtime.GOOS, "", filepath.Join(userHome, "AppData", "Local"), userHome)
	if home == "" {
		return ""
	}
	return managedExecutableUnderHome(home)
}

// InstalledVersionForManagedExecutable reads the release Hermes' updater
// recorded for an updater-managed executable (hermes-agent\install-stamp.json,
// baseVersion) without launching it. It refuses anything but a plain,
// bounded regular file beside the managed virtual environment.
func InstalledVersionForManagedExecutable(executable string) (string, error) {
	executable = strings.TrimSpace(executable)
	if executable == "" || !filepath.IsAbs(executable) {
		return "", errors.New("managed Hermes executable path is not absolute")
	}
	agent, err := managedExecutableAgentDir(executable)
	if err != nil {
		return "", err
	}
	stamp := filepath.Join(agent, "install-stamp.json")
	info, err := os.Lstat(stamp)
	if err != nil {
		return "", fmt.Errorf("inspect Hermes install stamp: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return "", errors.New("Hermes install stamp is not a bounded regular file")
	}
	data, err := os.ReadFile(stamp)
	if err != nil {
		return "", fmt.Errorf("read Hermes install stamp: %w", err)
	}
	var parsed struct {
		BaseVersion string `json:"baseVersion"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("parse Hermes install stamp: %w", err)
	}
	version := strings.TrimSpace(parsed.BaseVersion)
	if version == "" || strings.ContainsAny(version, "\x00\r\n") {
		return "", errors.New("Hermes install stamp has no base version")
	}
	return version, nil
}

// managedExecutableAgentDir returns the hermes-agent directory that holds the
// install stamp for one of the managedExecutableCandidates shapes.
func managedExecutableAgentDir(executable string) (string, error) {
	if !strings.EqualFold(filepath.Base(executable), "hermes.exe") {
		return "", errors.New("executable is not an updater-managed Hermes image")
	}
	parent := filepath.Dir(executable)
	if strings.EqualFold(filepath.Base(parent), "bin") {
		// Bootstrap launcher: <home>\bin\hermes.exe.
		return filepath.Join(filepath.Dir(parent), "hermes-agent"), nil
	}
	venv := filepath.Dir(parent)
	agent := filepath.Dir(venv)
	if !strings.EqualFold(filepath.Base(parent), "Scripts") || !strings.EqualFold(filepath.Base(venv), "venv") ||
		!strings.EqualFold(filepath.Base(agent), "hermes-agent") {
		return "", errors.New("executable is not the updater-managed Hermes virtual environment image or bootstrap launcher")
	}
	return agent, nil
}

// ConfigPathForUserHome resolves the Hermes config path inside another
// user's profile home. Privileged services acting for that user must use it
// instead of ConfigPath, which reads the calling token's known folders. On
// Windows the default AppData\Local layout under the profile is assumed; a
// redirected Local AppData is not followed.
func ConfigPathForUserHome(userHome string) string {
	userHome = strings.TrimSpace(userHome)
	if userHome == "" {
		return ""
	}
	localAppData := ""
	if runtime.GOOS == "windows" {
		localAppData = filepath.Join(userHome, "AppData", "Local")
	}
	home := ResolveHomeDir(runtime.GOOS, "", localAppData, userHome)
	if home == "" {
		return ""
	}
	return filepath.Join(home, "config.yaml")
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
