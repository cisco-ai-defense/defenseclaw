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

package sandboxcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// withAdminVMDriverAt makes the administrator's MicroVM driver check find
// found (refusing refused).
func withAdminVMDriverAt(t *testing.T, found string, refused ...string) {
	t.Helper()
	prev := managedAdminVMDriver
	managedAdminVMDriver = func(string) (string, []string) { return found, refused }
	t.Cleanup(func() { managedAdminVMDriver = prev })
}

func TestManagedDoctorRefusesStaleRenderedVMDriverDir(t *testing.T) {
	withManagedHost(t)
	app := newTestApp(t, "")
	app.GOOS = "linux"
	app.daemon.status.Managed = vmPrerequisiteStatus("none")
	app.HostDoctor = hostReport(nil)
	const live = "/usr/local/libexec/openshell"
	withAdminVMDriverAt(t, live+"/openshell-driver-vm")
	prevCheck, prevTrust, prevPaths := managedRenderedVMDriver, managedRenderedVMConfigTrust, managedRenderedGateway
	t.Cleanup(func() {
		managedRenderedVMDriver, managedRenderedVMConfigTrust, managedRenderedGateway = prevCheck, prevTrust, prevPaths
	})
	managedRenderedVMDriver = func(_, dir string) (string, string) {
		if dir == live {
			return live + "/openshell-driver-vm", ""
		}
		return "", "the rendered MicroVM driver_dir " + dir + " has no executable openshell-driver-vm"
	}
	managedRenderedVMConfigTrust = func(string, string) error { return nil }
	configPath := filepath.Join(t.TempDir(), "gateway.toml")
	managedRenderedGateway = func() *openshell.RenderedPaths { return &openshell.RenderedPaths{TOML: configPath} }
	writeConfig := func(dir string) {
		t.Helper()
		data, err := (openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverVM, DriverDir: dir}).TOML()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig("/usr/libexec/openshell")
	app.daemon.status.Managed.PendingRestart = true
	if row := app.runDoctor(bg).Get("managed-driver"); row == nil || row.Status != openshell.StatusWarn || row.Fix == nil ||
		!strings.Contains(row.Fix.Summary, "defenseclaw sandbox stop NAME") || strings.Contains(row.Fix.Summary, "ensure") {
		t.Fatalf("authorized switch waiting for the old VM: %+v", row)
	}
	app.daemon.status.Managed.PendingRestart = false
	if row := app.runDoctor(bg).Get("managed-driver"); row == nil || row.Status != openshell.StatusFail ||
		!strings.Contains(row.Detail, "/usr/libexec/openshell") || row.Fix == nil || !strings.Contains(row.Fix.Summary, "enterprise linux ensure") {
		t.Fatalf("stale rendered driver_dir: %+v", row)
	}
	app.GOOS = "darwin"
	if row := app.runDoctor(bg).Get("managed-driver"); row == nil || row.Status != openshell.StatusFail || row.Fix == nil ||
		!strings.Contains(row.Fix.Summary, "enterprise macos ensure") || strings.Contains(row.Fix.Summary, "enterprise darwin ensure") {
		t.Fatalf("macOS stale rendered driver_dir: %+v", row)
	}
	app.GOOS = "linux"
	writeConfig(live)
	if row := app.runDoctor(bg).Get("managed-driver"); row == nil || row.Status != openshell.StatusPass {
		t.Fatalf("current rendered driver_dir: %+v", row)
	}
}

func vmPrerequisiteStatus(fallback string) *sandboxapi.ManagedStatus {
	m := managedStatusFixture()
	m.InstallMode, m.Driver, m.DriverReason, m.DriverFallback = "prerequisite", "vm", "configured", fallback
	return m
}

// GAP-0481: the managed doctor checks the administrator's MicroVM driver
// live, as enterprise verify does, and never says ready without it.
func TestManagedDoctorChecksTheAdministratorsMicroVMDriver(t *testing.T) {
	app := &App{GOOS: "linux"}
	t.Run("missing fails with the path and the pinned-digest install", func(t *testing.T) {
		withAdminVMDriverAt(t, "")
		m := vmPrerequisiteStatus("none")
		c := app.withAdminVMDriver(managedDriverCheck(m), m)
		if c == nil || c.Status != openshell.StatusFail || c.Fix == nil || !c.Fix.Sudo {
			t.Fatalf("row = %+v", c)
		}
		has(t, c.Detail, "vm; MicroVM required (no docker fallback); but the MicroVM driver openshell-driver-vm is not installed",
			"/usr/libexec/openshell", "/usr/local/libexec/openshell", "no sandbox can start")
		has(t, c.Fix.Summary, "administrator step (contact it-security@example.com)", "root-owned into /usr/libexec/openshell")
		archive := "openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz"
		if managedVMDriverGoarch == "arm64" {
			archive = "openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz"
		}
		has(t, c.Fix.Command, openshell.TarballPins[openshell.InstallerVersion][archive], "sha256sum -c -")
		rep := &openshell.DoctorReport{Checks: []openshell.Check{*c}}
		if rep.OK() {
			t.Error("the report is ready without the MicroVM driver")
		}
	})
	t.Run("one another account can change fails and is named", func(t *testing.T) {
		withAdminVMDriverAt(t, "", "/usr/local/libexec/openshell/openshell-driver-vm (writable by group)")
		m := vmPrerequisiteStatus("none")
		c := app.withAdminVMDriver(managedDriverCheck(m), m)
		if c == nil || c.Status != openshell.StatusFail {
			t.Fatalf("row = %+v", c)
		}
		has(t, c.Detail, "an account other than root can change it", "/usr/local/libexec/openshell/openshell-driver-vm (writable by group)")
	})
	t.Run("present keeps the pass", func(t *testing.T) {
		withAdminVMDriverAt(t, "/usr/local/libexec/openshell/openshell-driver-vm")
		m := vmPrerequisiteStatus("none")
		c := app.withAdminVMDriver(managedDriverCheck(m), m)
		if c == nil || c.Status != openshell.StatusPass || c.Fix != nil || c.Detail != "vm; MicroVM required (no docker fallback)" {
			t.Fatalf("row = %+v", c)
		}
	})
	t.Run("the Linux docker fallback warns", func(t *testing.T) {
		withAdminVMDriverAt(t, "")
		m := vmPrerequisiteStatus("docker")
		c := app.withAdminVMDriver(managedDriverCheck(m), m)
		if c == nil || c.Status != openshell.StatusWarn {
			t.Fatalf("row = %+v", c)
		}
		has(t, c.Detail, "your sandboxes run on docker")
	})
	t.Run("a Mac fails with its folder", func(t *testing.T) {
		withAdminVMDriverAt(t, "")
		prev := managedVMDriverGoarch
		managedVMDriverGoarch = "arm64"
		t.Cleanup(func() { managedVMDriverGoarch = prev })
		m := vmPrerequisiteStatus("")
		c := (&App{GOOS: "darwin"}).withAdminVMDriver(managedDriverCheck(m), m)
		if c == nil || c.Status != openshell.StatusFail {
			t.Fatalf("row = %+v", c)
		}
		has(t, c.Detail, "/usr/local/libexec/openshell")
		has(t, c.Fix.Summary, "root-owned into /usr/local/libexec/openshell")
		has(t, c.Fix.Command, "shasum -a 256 -c -", openshell.TarballPins[openshell.InstallerVersion]["openshell-driver-vm-aarch64-apple-darwin.tar.gz"])
	})
	t.Run("not the administrator's driver: unchanged", func(t *testing.T) {
		withAdminVMDriverAt(t, "")
		for name, m := range map[string]*sandboxapi.ManagedStatus{
			"setup mode": func() *sandboxapi.ManagedStatus { m := vmPrerequisiteStatus("none"); m.InstallMode = "setup"; return m }(),
			"docker":     func() *sandboxapi.ManagedStatus { m := vmPrerequisiteStatus("none"); m.Driver = "docker"; return m }(),
			"fallback": func() *sandboxapi.ManagedStatus {
				m := vmPrerequisiteStatus("docker")
				m.Driver, m.DriverReason = "docker", "kvm_missing"
				return m
			}(),
		} {
			want := managedDriverCheck(m)
			if got := app.withAdminVMDriver(managedDriverCheck(m), m); (got == nil) != (want == nil) || (got != nil && (got.Status != want.Status || got.Detail != want.Detail)) {
				t.Errorf("%s: row = %+v, want %+v", name, got, want)
			}
		}
	})
}

// GAP-0005: before the managed gateway ran, `image build` read the account's
// own gateway.toml (none: docker) and built a docker image that the MicroVM
// run could not use. The daemon's managed driver decides.
func TestImageBuildTargetsTheManagedDriverBeforeTheGatewayRuns(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Gateway = nil
	ta.daemon.status.Managed = &sandboxapi.ManagedStatus{Driver: string(openshell.DriverVM)}
	if d := ta.gatewayDriverNow(bg); d.Name != openshell.DriverVM {
		t.Fatalf("driver = %q, want the managed vm driver", d.Name)
	}
}

// The organization moved from the MicroVM driver to docker while a stopped
// MicroVM sandbox stays the newest registration, whose driver the managed
// status names. With no gateway running, image build targets the next
// start's docker driver, and prune keeps the docker images; a MicroVM next
// start the docker fallback may still change prunes nothing of either kind.
func TestImageDriverAfterTheOrganizationChangedDrivers(t *testing.T) {
	for _, tc := range []struct {
		name               string
		managed            sandboxapi.ManagedStatus
		build              openshell.ComputeDriver
		pruneMicroVMTarget bool
	}{
		{"stopped vm registration, docker next", sandboxapi.ManagedStatus{Driver: "vm", NextDriver: "docker"}, openshell.DriverDocker, false},
		{"vm next, docker fallback", sandboxapi.ManagedStatus{Driver: "docker", NextDriver: "vm", DriverFallback: "docker"}, openshell.DriverVM, false},
		{"vm next, no fallback", sandboxapi.ManagedStatus{Driver: "docker", NextDriver: "vm", DriverFallback: "none"}, openshell.DriverVM, true},
		{"daemon before 1.0.4", sandboxapi.ManagedStatus{Driver: "vm"}, openshell.DriverVM, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Gateway = nil
			managed := tc.managed
			ta.daemon.status.Managed = &managed
			if d := ta.gatewayDriverNow(bg); d.Name != tc.build {
				t.Fatalf("image build targets %q, want %q", d.Name, tc.build)
			}
			ta.ok(t, ta.ImagePrune(bg, true))
			if opts := ta.images.pruned[0]; opts.MicroVMGateway != tc.pruneMicroVMTarget {
				t.Fatalf("prune options = %+v, want MicroVMGateway=%t", opts, tc.pruneMicroVMTarget)
			}
		})
	}
}
