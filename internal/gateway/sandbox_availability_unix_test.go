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
