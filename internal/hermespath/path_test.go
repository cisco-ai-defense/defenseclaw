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
	"testing"
)

func TestResolveHomeDirPrecedence(t *testing.T) {
	userHome := filepath.Join("root", "users", "kevin")
	localAppData := filepath.Join("root", "users", "kevin", "AppData", "Local")
	configuredHome := filepath.Join("root", "Hermes Override")

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
			configuredHome: "  " + configuredHome + "  ",
			localAppData:   localAppData,
			want:           configuredHome,
		},
		{
			name:         "Windows defaults to LocalAppData",
			goos:         "windows",
			localAppData: localAppData,
			want:         filepath.Join(localAppData, "hermes"),
		},
		{
			name: "Windows without LocalAppData uses legacy fallback",
			goos: "windows",
			want: filepath.Join(userHome, ".hermes"),
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
