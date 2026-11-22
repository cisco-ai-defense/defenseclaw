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

// Package testenv provides cross-platform process identity isolation for tests.
package testenv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// SetHome redirects the current process's home and platform-specific user data
// directories to home for the lifetime of the test.
func SetHome(t testing.TB, home string) {
	t.Helper()
	keepGoToolchainEnv(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("NPM_CONFIG_PREFIX", filepath.Join(home, ".npm-global"))

	if runtime.GOOS != "windows" {
		return
	}

	t.Setenv("USERPROFILE", home)
	volume := filepath.VolumeName(home)
	t.Setenv("HOMEDRIVE", volume)
	t.Setenv("HOMEPATH", strings.TrimPrefix(home, volume))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
}

// keepGoToolchainEnv pins the go command's module cache, build cache, GOPATH
// and go env file to where they are before the home moves. Their defaults
// follow HOME and the user cache and config folders, so a test that builds a
// helper (go build ./cmd/defenseclaw-hook-post) after SetHome or
// IsolateAccount downloaded every module into the new home, and t.TempDir
// could not remove the read-only module files: the test failed in cleanup on
// a host without GOPATH or GOMODCACHE set (rel-1-0-10:GAP-0167). A value
// already set is kept.
func keepGoToolchainEnv(t testing.TB) {
	t.Helper()
	if os.Getenv("GOPATH") == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			t.Setenv("GOPATH", filepath.Join(home, "go"))
		}
	}
	if os.Getenv("GOMODCACHE") == "" {
		if gopath := filepath.SplitList(os.Getenv("GOPATH")); len(gopath) != 0 && gopath[0] != "" {
			t.Setenv("GOMODCACHE", filepath.Join(gopath[0], "pkg", "mod"))
		}
	}
	if os.Getenv("GOCACHE") == "" {
		if cache, err := os.UserCacheDir(); err == nil && cache != "" {
			t.Setenv("GOCACHE", filepath.Join(cache, "go-build"))
		}
	}
	if os.Getenv("GOENV") == "" {
		if config, err := os.UserConfigDir(); err == nil && config != "" {
			t.Setenv("GOENV", filepath.Join(config, "go", "env"))
		}
	}
}
