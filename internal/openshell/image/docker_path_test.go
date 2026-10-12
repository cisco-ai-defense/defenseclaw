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

// OpenShell runs on Linux and macOS only; these tests check its POSIX host
// paths and files.

//go:build !windows

package image

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A service whose PATH has no docker (a macOS LaunchAgent's) runs the docker
// installed in the usual places, with that folder on the PATH for its
// plugins (GAP-0443); the PATH's docker comes first.
func TestDockerBinaryOffThePath(t *testing.T) {
	missing := func(string) (string, error) { return "", errors.New("not found") }
	dir := t.TempDir()
	stat := func(p string) (os.FileInfo, error) {
		if p == "/opt/homebrew/bin/docker" {
			return os.Stat(dir)
		}
		if p == "/Applications/Docker.app/Contents/Resources/bin/docker" {
			return os.Stat(filepath.Join(dir, "."))
		}
		return nil, os.ErrNotExist
	}
	// A folder is not a docker binary.
	if bin, extra := DockerBinary("darwin", missing, stat); bin != "docker" || extra != nil {
		t.Fatalf("folders only: %q %v", bin, extra)
	}
	file := filepath.Join(dir, "docker")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	stat = func(p string) (os.FileInfo, error) {
		if p == "/usr/local/bin/docker" {
			return os.Stat(file)
		}
		return nil, os.ErrNotExist
	}
	if bin, extra := DockerBinary("darwin", missing, stat); bin != "/usr/local/bin/docker" || !slices.Contains(extra, "/usr/local/bin") {
		t.Fatalf("Docker Desktop's link: %q %v", bin, extra)
	}
	onPath := func(string) (string, error) { return "/usr/bin/docker", nil }
	if bin, extra := DockerBinary("darwin", onPath, stat); bin != "/usr/bin/docker" || extra != nil {
		t.Fatalf("the PATH's docker: %q %v", bin, extra)
	}
	if bin, _ := DockerBinary("windows", missing, stat); bin != "docker" {
		t.Fatalf("no installs known: %q", bin)
	}
}
