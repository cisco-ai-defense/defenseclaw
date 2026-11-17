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

//go:build !windows

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestSandboxModeAccess pins the POSIX rule the availability probe judges
// the docker socket and /dev/kvm by, and the cause it names (GAP-0257): an
// account outside the device's group, a mode that denies the account, or
// groups that could not be looked up where membership decides (GAP-0384).
func TestSandboxModeAccess(t *testing.T) {
	groups := func(int) ([]int, error) { return []int{100, 990}, nil }
	failing := func(int) ([]int, error) { return nil, errors.New("directory down") }
	for name, tc := range map[string]struct {
		mode         fs.FileMode
		owner, group int
		groups       func(int) ([]int, error)
		want         sandboxDeviceState
	}{
		"owner rw":                {0o600, 1001, 0, groups, sandboxDeviceUsable},
		"owner read only":         {0o466, 1001, 0, groups, sandboxDeviceDenied},
		"docker group member":     {0o660, 0, 990, groups, sandboxDeviceUsable},
		"group without write":     {0o646, 0, 990, groups, sandboxDeviceDenied},
		"not a member":            {0o660, 0, 991, groups, sandboxDeviceNotMember},
		"member, kvm 0640":        {0o640, 0, 990, groups, sandboxDeviceDenied},
		"world rw (kvm 0666)":     {0o666, 0, 36, groups, sandboxDeviceUsable},
		"groups unknown":          {0o660, 0, 990, failing, sandboxDeviceGroupsUnknown},
		"groups unknown, world":   {0o666, 0, 990, failing, sandboxDeviceUsable},
		"groups unknown, closed":  {0o600, 0, 990, failing, sandboxDeviceDenied},
		"owner beats world rw":    {0o066, 1001, 0, groups, sandboxDeviceDenied},
		"member beats world rw":   {0o606, 0, 990, groups, sandboxDeviceDenied},
		"outsider, world rw":      {0o606, 0, 991, groups, sandboxDeviceUsable},
		"other user, other group": {0o600, 0, 0, groups, sandboxDeviceDenied},
	} {
		if got := sandboxModeAccess(tc.mode, tc.owner, tc.group, 1001, tc.groups); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}

func TestSandboxPathAccessMissingAndOwned(t *testing.T) {
	if got := sandboxPathAccess(filepath.Join(t.TempDir(), "missing.sock"), os.Getuid()); got.State != sandboxDeviceMissing {
		t.Fatalf("missing path: %+v", got)
	}
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sandboxPathAccess(path, os.Getuid()); got.State != sandboxDeviceUsable {
		t.Fatalf("own 0600 file: %+v", got)
	}
}

// TestGAP0007DockerDesktopSocketLink pins how the managed gateway, a
// service account, judges the macOS docker socket: Docker Desktop's
// root-owned link into the 0700 ~/.docker of the account that started it.
// The gateway cannot stat through it, so the plain path rule said "denied"
// for the caller's own Docker Desktop and no managed Mac account could run
// a docker-driver sandbox (rel-1-0-10:GAP-0007). The link into the caller's
// own home is usable; one into another home, an untrusted link and a
// dangling one are not.
func TestGAP0007DockerDesktopSocketLink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a 0000 folder; the fixture needs a non-root account")
	}
	root := t.TempDir()
	home := filepath.Join(root, "Users", "dcm-std2")
	sockDir := filepath.Join(home, ".docker", "run")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sockDir, "docker.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "var", "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(runDir, "docker.sock")
	if err := os.Symlink(filepath.Join(sockDir, "docker.sock"), abs); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(runDir, "docker-rel.sock")
	if err := os.Symlink("../../Users/dcm-std2/.docker/run/docker.sock", rel); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(runDir, "docker-gone.sock")
	if err := os.Symlink(filepath.Join(root, "Users", "nobody", "docker.sock"), dangling); err != nil {
		t.Fatal(err)
	}
	// The service account cannot look behind the link: ~/.docker is not
	// searchable for it.
	dockerDir := filepath.Join(home, ".docker")
	if err := os.Chmod(dockerDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dockerDir, 0o700) })

	trusted := true
	saved := sandboxDockerLinkTrusted
	sandboxDockerLinkTrusted = func(fs.FileInfo) bool { return trusted }
	t.Cleanup(func() { sandboxDockerLinkTrusted = saved })

	uid := os.Getuid()
	own := func(int) (string, error) { return home, nil }
	if got := sandboxDevicePathAccess(abs, uid, false); got.State != sandboxDeviceDenied {
		t.Fatalf("fixture: the plain path rule should be denied behind ~/.docker, got %+v", got)
	}
	for name, tc := range map[string]struct {
		path    string
		home    func(int) (string, error)
		trusted bool
		want    sandboxDeviceState
	}{
		"own Docker Desktop":             {abs, own, true, sandboxDeviceUsable},
		"own Docker Desktop, relative":   {rel, own, true, sandboxDeviceUsable},
		"home with a trailing slash":     {abs, func(int) (string, error) { return home + "/", nil }, true, sandboxDeviceUsable},
		"another account's":              {abs, func(int) (string, error) { return filepath.Join(root, "Users", "dcm-std1"), nil }, true, sandboxDeviceDenied},
		"a link not made by root":        {abs, own, false, sandboxDeviceDenied},
		"home is the root folder":        {abs, func(int) (string, error) { return "/", nil }, true, sandboxDeviceDenied},
		"relative home":                  {abs, func(int) (string, error) { return "Users/dcm-std2", nil }, true, sandboxDeviceDenied},
		"account record unreachable":     {abs, func(int) (string, error) { return "", errors.New("directory down") }, true, sandboxDeviceGroupsUnknown},
		"Docker Desktop not started yet": {dangling, own, true, sandboxDeviceMissing},
	} {
		trusted = tc.trusted
		if got := sandboxDockerDesktopAccess(tc.path, uid, tc.home); got.State != tc.want {
			t.Errorf("%s: %+v, want state %d", name, got, tc.want)
		}
	}
}
