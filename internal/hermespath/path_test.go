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

package hermespath

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveHomeDirPrecedence(t *testing.T) {
	userHome := filepath.Join("root", "users", "kevin")
	localAppData := `C:\Users\kevin\AppData\Local`
	configuredHome := `C:\Hermes Override`

	tests := []struct {
		name           string
		goos           string
		configuredHome string
		localAppData   string
		want           string
	}{
		{
			name:           "explicit override wins on Windows",
			goos:           "windows",
			configuredHome: configuredHome,
			localAppData:   localAppData,
			want:           configuredHome,
		},
		{
			name:           "whitespace-wrapped Windows override fails closed",
			goos:           "windows",
			configuredHome: "  " + configuredHome + "  ",
			localAppData:   localAppData,
			want:           "",
		},
		{
			name:         "Windows defaults to LocalAppData",
			goos:         "windows",
			localAppData: localAppData,
			want:         localAppData + `\hermes`,
		},
		{
			name: "Windows without LocalAppData fails closed",
			goos: "windows",
			want: "",
		},
		{
			name:           "relative Windows override fails closed",
			goos:           "windows",
			configuredHome: filepath.Join("relative", "hermes"),
			localAppData:   localAppData,
			want:           "",
		},
		{
			name:         "relative Windows LocalAppData fails closed",
			goos:         "windows",
			localAppData: filepath.Join("relative", "LocalAppData"),
			want:         "",
		},
		{
			name:         "Linux ignores LocalAppData",
			goos:         "linux",
			localAppData: localAppData,
			want:         filepath.Join(userHome, ".hermes"),
		},
		{
			name:         "macOS ignores LocalAppData",
			goos:         "darwin",
			localAppData: localAppData,
			want:         filepath.Join(userHome, ".hermes"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveHomeDir(tt.goos, tt.configuredHome, tt.localAppData, userHome)
			if got != tt.want {
				t.Fatalf("ResolveHomeDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWindowsUnavailableCurrentTokenLocalAppDataReturnsEmptyPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows current-token LocalAppData resolution")
	}
	t.Setenv("HERMES_HOME", "")
	previous := currentUserLocalAppDataForHome
	currentUserLocalAppDataForHome = func() string { return "" }
	t.Cleanup(func() { currentUserLocalAppDataForHome = previous })

	if got := HomeDir(); got != "" {
		t.Fatalf("HomeDir() = %q, want empty fail-closed result", got)
	}
	if got := ConfigPath(); got != "" {
		t.Fatalf("ConfigPath() = %q, want empty fail-closed result", got)
	}
	if got := ManagedExecutablePath(); got != "" {
		t.Fatalf("ManagedExecutablePath() = %q, want empty fail-closed result", got)
	}
}

func TestWindowsManagedExecutableUsesCurrentTokenLocalAppDataNotHermesHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows updater-managed executable path")
	}
	managedRoot := filepath.Join(t.TempDir(), "current-token-local-appdata")
	previous := currentUserLocalAppDataForHome
	currentUserLocalAppDataForHome = func() string { return managedRoot }
	t.Cleanup(func() { currentUserLocalAppDataForHome = previous })
	t.Setenv("HERMES_HOME", filepath.Join(t.TempDir(), "config-only-home"))

	want := filepath.Join(managedRoot, "hermes", "hermes-agent", "venv", "Scripts", "hermes.exe")
	if got := ManagedExecutablePath(); got != want {
		t.Fatalf("ManagedExecutablePath() = %q, want %q", got, want)
	}
}
