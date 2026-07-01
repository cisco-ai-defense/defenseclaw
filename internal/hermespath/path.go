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
// Windows, and ~/.hermes on Unix-like platforms and as a Windows fallback.
package hermespath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HomeDir returns the Hermes user configuration directory for the host.
func HomeDir() string {
	userHome, _ := os.UserHomeDir()
	return ResolveHomeDir(
		runtime.GOOS,
		os.Getenv("HERMES_HOME"),
		os.Getenv("LOCALAPPDATA"),
		userHome,
	)
}

// ConfigPath returns the host's resolved Hermes config.yaml path.
func ConfigPath() string {
	return filepath.Join(HomeDir(), "config.yaml")
}

// ResolveHomeDir is the pure, OS-parameterized core used by HomeDir and tests.
// Explicit HERMES_HOME always wins. Native Windows then uses
// %LOCALAPPDATA%\hermes. All other cases retain the historical ~/.hermes
// location, including Windows hosts where LocalAppData is unavailable.
func ResolveHomeDir(goos, configuredHome, localAppData, userHome string) string {
	if configuredHome = strings.TrimSpace(configuredHome); configuredHome != "" {
		return filepath.Clean(configuredHome)
	}
	if goos == "windows" {
		if localAppData = strings.TrimSpace(localAppData); localAppData != "" {
			return filepath.Join(localAppData, "hermes")
		}
	}
	return filepath.Join(strings.TrimSpace(userHome), ".hermes")
}
