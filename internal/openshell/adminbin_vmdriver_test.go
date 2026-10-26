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

package openshell

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// GAP-0481: the administrator's MicroVM driver is found by one check that
// enterprise verify and the managed user's sandbox doctor both run.
func TestAdminVMDriver(t *testing.T) {
	trustAll := func(string) error { return nil }
	t.Run("missing", func(t *testing.T) {
		found, refused := AdminVMDriver("linux", func(string) bool { return false }, trustAll)
		if found != "" || len(refused) != 0 {
			t.Fatalf("found %q, refused %v on an empty host", found, refused)
		}
	})
	t.Run("present in a later folder", func(t *testing.T) {
		want := "/usr/local/libexec/openshell/openshell-driver-vm"
		found, refused := AdminVMDriver("linux", func(p string) bool { return p == want }, trustAll)
		if found != want || len(refused) != 0 {
			t.Fatalf("found %q, refused %v, want %q", found, refused, want)
		}
	})
	t.Run("one another account can change is refused for the next", func(t *testing.T) {
		brew := "/opt/homebrew/libexec/openshell/openshell-driver-vm"
		found, refused := AdminVMDriver("darwin", func(string) bool { return true }, func(p string) error {
			if p == "/usr/local/libexec/openshell/openshell-driver-vm" {
				return errors.New("writable by group")
			}
			return nil
		})
		if found != brew || len(refused) != 1 || !strings.Contains(refused[0], "/usr/local/libexec/openshell/openshell-driver-vm (writable by group)") {
			t.Fatalf("found %q, refused %v", found, refused)
		}
	})
	if dirs := UserVMDriverDirs("/home/u", "", ""); strings.Join(dirs[1:], ",") != strings.Join(AdminVMDriverDirs("linux"), ",") {
		t.Errorf("UserVMDriverDirs system tail = %v, want AdminVMDriverDirs", dirs[1:])
	}
}

// The administrator's install checks the archive against the digest this
// build pins (never a checksum file of the same release) and puts the
// driver root-owned into the first folder the lifecycle looks in.
func TestAdminVMDriverFixUsesThePinnedDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
	for _, tc := range []struct{ goos, goarch, archive, check, dir string }{
		{"linux", "amd64", "openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz", "sha256sum -c -", "/usr/libexec/openshell"},
		{"linux", "arm64", "openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz", "sha256sum -c -", "/usr/libexec/openshell"},
		{"darwin", "arm64", "openshell-driver-vm-aarch64-apple-darwin.tar.gz", "shasum -a 256 -c -", "/usr/local/libexec/openshell"},
	} {
		fix := AdminVMDriverFix(tc.goos, tc.goarch)
		digest := TarballPins[InstallerVersion][tc.archive]
		if digest == "" {
			t.Fatalf("%s/%s: no pinned digest for %s", tc.goos, tc.goarch, tc.archive)
		}
		for _, want := range []string{TarballBaseURL + InstallerTag + "/" + tc.archive, "echo '" + digest + "  " + tc.archive + "' | " + tc.check,
			"sudo install -m 0755 -o root", tc.dir + "/openshell-driver-vm"} {
			if !strings.Contains(fix.Command, want) {
				t.Errorf("%s/%s: command lacks %q:\n%s", tc.goos, tc.goarch, want, fix.Command)
			}
		}
		if strings.Contains(fix.Command, "checksums") || !fix.Sudo || fix.Apply != nil || !strings.Contains(fix.Summary, tc.dir) {
			t.Errorf("%s/%s: fix = %+v", tc.goos, tc.goarch, fix)
		}
	}
	if fix := AdminVMDriverFix("darwin", "amd64"); fix.Command != "" {
		t.Errorf("an Intel Mac gets a command: %+v", fix)
	}
}

// Repair a stale administrator driver in the directory the gateway selects,
// even when it is not the first administrator directory.
func TestOldAdminVMDriverRepairKeepsSelectedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
	for _, tc := range []struct{ dir, commandDir, commandTarget string }{
		{"/usr/lib/openshell", "/usr/lib/openshell", "/usr/lib/openshell/openshell-driver-vm"},
		{"/opt/openshell/libexec", "/opt/openshell/libexec", "/opt/openshell/libexec/openshell-driver-vm"},
		{"/opt/Open Shell/libexec", "'/opt/Open Shell/libexec'", "'/opt/Open Shell/libexec/openshell-driver-vm'"},
	} {
		m := &MicroVMHost{DriverBinary: tc.dir + "/openshell-driver-vm", DriverOlderThan: InstallerVersion}
		fix := m.vmDriverFix("amd64")
		if fix == nil || !fix.Sudo || !strings.Contains(fix.Summary, tc.dir) ||
			!strings.Contains(fix.Command, "sudo install -d -m 0755 -o root -g root "+tc.commandDir) ||
			!strings.Contains(fix.Command, "sudo install -m 0755 -o root -g root openshell-driver-vm "+tc.commandTarget) ||
			strings.Contains(fix.Command, " /usr/libexec/openshell/openshell-driver-vm") {
			t.Fatalf("selected directory %q: repair = %+v", tc.dir, fix)
		}
	}
}

// The gateway uses an explicit rendered driver_dir, so an alternate driver
// found by the administrator's search does not make a stale render usable.
func TestRenderedAdminVMDriverUsesTheGatewayPath(t *testing.T) {
	const live = "/usr/local/libexec/openshell/openshell-driver-vm"
	exists := func(p string) bool { return p == live }
	trusted := func(string) error { return nil }
	if found, _ := AdminVMDriver("linux", exists, trusted); found != live {
		t.Fatalf("administrator selection = %q", found)
	}
	for _, tc := range []struct {
		dir, want string
	}{
		{"/usr/local/libexec/openshell", live},
		{"/usr/libexec/openshell", ""},
		{"", ""},
		{"/tmp/unmanaged", ""},
	} {
		found, problem := RenderedAdminVMDriver("linux", tc.dir, exists, trusted)
		if found != tc.want || (problem == "") != (tc.want != "") || (tc.want == "" && !strings.Contains(problem, "driver_dir")) {
			t.Errorf("rendered %q: found %q, problem %q", tc.dir, found, problem)
		}
	}
	if found, problem := RenderedAdminVMDriver("linux", "/usr/local/libexec/openshell", exists, func(string) error {
		return errors.New("writable by group")
	}); found != "" || !strings.Contains(problem, "not trusted") {
		t.Fatalf("untrusted rendered driver: %q, %q", found, problem)
	}
}
