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

package manager

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0582: a managed Mac's LaunchAgent PATH has no docker; the container
// scan finds Docker Desktop's CLI where image builds do, and scans nothing
// only where no docker is installed.
func TestScanDockerFindsDockerOutsideThePath(t *testing.T) {
	cli := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(cli, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	noPath := func(string) (string, error) { return "", errors.New("not found") }
	desktop := func(p string) (os.FileInfo, error) {
		if p == "/usr/local/bin/docker" {
			return os.Stat(cli)
		}
		return nil, os.ErrNotExist
	}
	if bin, ok := scanDocker("darwin", noPath, desktop); !ok || bin != "/usr/local/bin/docker" {
		t.Fatalf("Docker Desktop outside the PATH: %q %v", bin, ok)
	}
	none := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if bin, ok := scanDocker("darwin", noPath, none); ok {
		t.Fatalf("no docker: %q %v, want none", bin, ok)
	}
	onPath := func(string) (string, error) { return "/opt/bin/docker", nil }
	if bin, ok := scanDocker("linux", onPath, none); !ok || bin != "/opt/bin/docker" {
		t.Fatalf("docker on the PATH: %q %v", bin, ok)
	}
}
