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
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

const testStopSyncBinary = "/home/dev/.local/bin/defenseclaw-gateway"

func init() { stopSyncBinary = func() (string, error) { return testStopSyncBinary, nil } }

// GAP-0380: on a gateway already on MicroVMs whose only change is the stop
// sync, setup writes it with no restart question and no restart: the user
// manager reads it, and no sandbox stops.
func TestSetupGivesTheGatewayServiceTheStopSyncWithoutARestart(t *testing.T) {
	ta := setupApp(t, "", "", true)
	ta.GOOS = "linux"
	ta.IO.TTY = false
	ta.HostDoctor = linuxKVMReport(openshell.DriverVM, nil)
	ta.gateway.planFiles = []*openshell.FileChange{{Path: "/home/dev/.config/systemd/user/openshell-gateway.service.d/zz-defenseclaw-stop-sync.conf",
		ReloadOnly: true, Summary: []string{"ExecStop=..."}}}
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	_, _ = useGateway(ta)
	ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}))
	if p := ta.gateway.planned; len(p) != 1 || p[0].StopSync == nil || p[0].StopSync.Binary != testStopSyncBinary || ta.gateway.applied != 1 || ta.gateway.restarts != 0 {
		t.Fatalf("plans %+v, applied %d, restarts %d", p, ta.gateway.applied, ta.gateway.restarts)
	}
	has(t, ta.output(), "✓ the openshell-gateway service now syncs each running MicroVM's disk before it stops (a systemd drop-in; no restart)")
	lacks(t, ta.output(), "gateway configured and restarted")
}

// linuxKVMReport is a doctor report of a Linux host with KVM, e2fsprogs
// and the MicroVM driver, whose gateway runs driver; edit adjusts it.
func linuxKVMReport(driver openshell.ComputeDriver, edit func(*openshell.DoctorReport)) func(context.Context, *openshell.Doctor) *openshell.DoctorReport {
	return hostReport(func(r *openshell.DoctorReport) {
		r.Driver, r.ConfiguredDriver = driver, driver
		r.MicroVM = &openshell.MicroVMHost{Linux: true, E2fsprogs: "/usr/sbin", DriverBinary: "/home/dev/.local/libexec/openshell/openshell-driver-vm",
			ServiceUMask: "0022", StateDir: "/home/dev/.local/state/openshell/vm-driver", Identity: openshell.VMIdentity{UID: 1000, GID: 1000},
			Recommended: openshell.VMResources{VCPUs: 4, MemMiB: 4096, OverlayDiskMiB: 16384}}
		if driver == openshell.DriverVM {
			*r.Get(openshell.CheckIDLandlock) = openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusPass,
				Detail: "enforced by the MicroVM's own kernel; OpenShell refuses to start a sandbox without it (hard requirement)"}
		}
		if edit != nil {
			edit(r)
		}
	})
}

// noLinuxLandlock is the Landlock check of RHEL 9's 5.14 kernel.
var noLinuxLandlock = openshell.Check{ID: openshell.CheckIDLandlock, Title: "Landlock", Status: openshell.StatusFail,
	Detail: "the kernel has no Landlock support: landlock_create_ruleset: function not implemented",
	Fix:    &openshell.Fix{Summary: "use a kernel with Landlock ABI 3 or newer (Linux 6.2 upstream or a distribution backport)", Sudo: true}}

// TestSetupOffersMicroVMsOnALinuxHostWithKVM: the docker driver stays a
// Linux host's default (a no, and --yes, keep it); a yes plans the vm driver
// with this user as every sandbox's, in one plan and one restart, and
// gives the service the umask the guest needs when it has a stricter one.
func TestSetupOffersMicroVMsOnALinuxHostWithKVM(t *testing.T) {
	const question = `Run sandboxes in OpenShell MicroVMs? Each sandbox gets its own kernel and disk through KVM. ` +
		`(sets compute_driver = "vm" in the gateway's gateway.toml and restarts the gateway; OpenShell calls this driver experimental, ` +
		`and sandboxes made on the docker driver cannot start after the switch) [y/N]`
	for _, tc := range []struct {
		name    string
		input   string
		opts    SetupOptions
		umask   bool
		switch_ bool
	}{
		{name: "yes", input: "y\n", switch_: true},
		{name: "no", input: "n\n"},
		{name: "--yes takes the default, no", opts: SetupOptions{Yes: true}},
		{name: "a strict umask", input: "y\n", umask: true, switch_: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", true)
			ta.GOOS = "linux"
			if tc.opts.Yes {
				ta.IO.TTY = false
			}
			ta.HostDoctor = linuxKVMReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
				if tc.umask {
					r.MicroVM.ServiceUMask, r.MicroVM.UMaskTooStrict = "0077", true
				}
			})
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			_, _ = useGateway(ta)
			o := tc.opts
			o.SkipImages, o.NoWrappers = true, true
			ta.ok(t, ta.Setup(bg, o))
			if !tc.opts.Yes {
				has(t, ta.output(), question)
			}
			p := ta.gateway.planned
			if !tc.switch_ {
				lacks(t, ta.output(), "runs sandboxes in OpenShell MicroVMs")
				if len(p) != 0 && p[0].ComputeDriver == openshell.DriverVM {
					t.Fatalf("switched to vm without a yes: %+v", p)
				}
				return
			}
			wantUMask := ""
			if tc.umask {
				wantUMask = openshell.ServiceUMask
			}
			if len(p) != 1 || p[0].ComputeDriver != openshell.DriverVM || p[0].EnableBindMounts || p[0].ServiceUMask != wantUMask ||
				p[0].VMIdentity == nil || *p[0].VMIdentity != (openshell.VMIdentity{UID: 1000, GID: 1000}) || ta.gateway.applied != 1 {
				t.Fatalf("gateway plans = %+v, applied %d", p, ta.gateway.applied)
			}
			// GAP-0380: the same plan gives the service the stop sync.
			if s := p[0].StopSync; s == nil || s.Binary != testStopSyncBinary {
				t.Fatalf("stop sync = %+v", s)
			}
			has(t, ta.output(), "✓ gateway configured and restarted: it runs sandboxes in OpenShell MicroVMs",
				"every run works on a copy (the MicroVM driver mounts no host folders)")
			lacks(t, ta.output(), "Allow sandboxes to mount")
		})
	}
}

// TestSetupSwitchesALinuxKernelWithoutLandlockToMicroVMs: RHEL 9's 5.14
// kernel has no Landlock, which the docker driver needs; with KVM setup
// goes on to the MicroVM question (default yes, taken by --yes) instead of
// stopping at the machine check, and without KVM it stops there.
func TestSetupSwitchesALinuxKernelWithoutLandlockToMicroVMs(t *testing.T) {
	ta := setupApp(t, "\n", "", true)
	ta.GOOS = "linux"
	ta.HostDoctor = linuxKVMReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLinuxLandlock })
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	_, _ = useGateway(ta)
	ta.ok(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), "Landlock: the kernel has no Landlock support: landlock_create_ruleset: function not implemented; MicroVMs have their own kernel, which enforces it",
		"Run sandboxes in OpenShell MicroVMs? This kernel has no usable Landlock, which the docker driver needs, and MicroVMs have their own kernel. (")
	has(t, ta.output(), "[Y/n]")
	lacks(t, ta.output(), "cannot run sandboxes yet")
	if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverVM || ta.gateway.applied != 1 {
		t.Fatalf("gateway plans = %+v, applied %d", p, ta.gateway.applied)
	}

	// A no leaves the docker driver, and the kernel's Landlock failure stops setup.
	ta = setupApp(t, "n\n", "", true)
	ta.GOOS = "linux"
	ta.HostDoctor = linuxKVMReport(openshell.DriverDocker, func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLinuxLandlock })
	wantErr(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}), "this machine cannot run sandboxes yet (Landlock)")
	if len(ta.gateway.planned) != 0 {
		t.Fatalf("gateway plans = %+v", ta.gateway.planned)
	}

	// No KVM: no MicroVM question, and the Landlock failure stops setup.
	ta = setupApp(t, "", "", true)
	ta.GOOS = "linux"
	ta.HostDoctor = hostReport(func(r *openshell.DoctorReport) { *r.Get(openshell.CheckIDLandlock) = noLinuxLandlock })
	wantErr(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}), "this machine cannot run sandboxes yet (Landlock)")
	lacks(t, ta.output(), "MicroVMs")
}

// TestSetupStopsWhereALinuxHostCannotStartAMicroVM: nothing is installed for
// a Linux host (KVM access and e2fsprogs need an administrator, the driver
// is a verified download), and setup says what to do, whether the user
// chose MicroVMs now or the gateway already runs them.
func TestSetupStopsWhereALinuxHostCannotStartAMicroVM(t *testing.T) {
	lacking := func(r *openshell.DoctorReport) { r.MicroVM.E2fsprogs, r.MicroVM.DriverBinary = "", "" }
	for _, tc := range []struct {
		name   string
		driver openshell.ComputeDriver
		input  string
	}{{"chosen now", openshell.DriverDocker, "y\n"}, {"already on vm", openshell.DriverVM, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", true)
			ta.GOOS = "linux"
			ta.HostDoctor = linuxKVMReport(tc.driver, lacking)
			wantErr(t, ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true}), "this machine cannot run MicroVM sandboxes yet (MicroVM driver)")
			has(t, ta.output(), "✗ MicroVM driver: e2fsprogs (mke2fs and debugfs) is not installed",
				"openshell-driver-vm is not installed (NVIDIA's openshell package does not ship it)",
				"→ install e2fsprogs 1.43 or newer", "sudo dnf install e2fsprogs",
				"→ restore the gateway connection and confirm it runs OpenShell "+openshell.InstallerVersion+" before using this pinned install command; "+
					"install openshell-driver-vm from OpenShell "+openshell.InstallerTag, "→ then run `defenseclaw sandbox setup` again")
			if len(ta.gateway.planned) != 0 {
				t.Fatalf("gateway plans = %+v", ta.gateway.planned)
			}
		})
	}
}

// TestSetupWarnsOfACacheBuiltUnderAStrictUMask: a cache the driver built
// while the gateway ran with umask 0077 holds MicroVMs that cannot start;
// the plan fixes the umask, and setup says how to remove the cache.
func TestSetupWarnsOfACacheBuiltUnderAStrictUMask(t *testing.T) {
	ta := setupApp(t, "", "", true)
	ta.GOOS = "linux"
	ta.IO.TTY = false
	ta.HostDoctor = linuxKVMReport(openshell.DriverVM, func(r *openshell.DoctorReport) {
		r.MicroVM.ServiceUMask, r.MicroVM.UMaskTooStrict = "0077", true
		r.MicroVM.StaleCache = []string{"images/sandbox-prepared-rootfs-ext4-a"}
	})
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	_, _ = useGateway(ta)
	ta.ok(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}))
	has(t, ta.output(), "MicroVM driver: its cache under /home/dev/.local/state/openshell/vm-driver was built while the gateway ran with a umask stricter than 0022",
		"rm -rf /home/dev/.local/state/openshell/vm-driver/images /home/dev/.local/state/openshell/vm-driver/sandboxes /home/dev/.local/state/openshell/vm-driver/host-runtime")
	if p := ta.gateway.planned; len(p) != 1 || p[0].ServiceUMask != "0022" {
		t.Fatalf("gateway plans = %+v", p)
	}
}
