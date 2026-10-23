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

package openshell_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// linuxVMTOML is the gateway.toml of a Linux user (uid 1000, gid 1000)
// whose gateway runs the MicroVM driver.
const linuxVMTOML = `[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"

[openshell.drivers.vm]
sandbox_uid = 1000
sandbox_gid = 1000
vcpus = 4
mem_mib = 4096
overlay_disk_mib = 16384
`

// onLinuxMicroVMs makes the host a Linux machine with KVM, e2fsprogs and
// the MicroVM driver, whose gateway service runs vm with umask 0022.
func (f *doctorFixture) onLinuxMicroVMs() {
	f.fake = openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
	f.writeTOML(linuxVMTOML, f.started.Add(-time.Minute))
	f.kvm = nil
	for _, tool := range []string{"mke2fs", "debugfs"} {
		touchExecutable(f.t, filepath.Join(f.e2fsprogs, tool))
	}
	touchExecutable(f.t, f.linuxDriverPath())
	f.serviceUMask("0022")
	f.runner.On("systemctl --user daemon-reload", "", nil)
}

// linuxDriverPath is where OpenShell's release archive puts the driver.
func (f *doctorFixture) linuxDriverPath() string {
	return filepath.Join(f.home, ".local", "libexec", "openshell", "openshell-driver-vm")
}

// serviceUMask makes systemd report umask for the gateway service ("": none).
func (f *doctorFixture) serviceUMask(umask string) {
	f.runner.OnFunc("systemctl --user show openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
		out := f.unit("active", "enabled")
		if umask != "" {
			out += "UMask=" + umask + "\n"
		}
		return []byte(out), nil
	})
}

// dropIn is the systemd drop-in DefenseClaw gives the gateway service.
func (f *doctorFixture) dropIn() string {
	return filepath.Join(filepath.Dir(f.dir), "systemd", "user", "openshell-gateway.service.d", "zz-defenseclaw-umask.conf")
}

// TestDoctorOnLinuxRunningMicroVMs: on a Linux host whose gateway runs the
// MicroVM driver, Landlock is the MicroVM kernel's, Docker's network and
// root do not matter, the driver's own needs are checked in the order of
// the check list, and every one passes.
func TestDoctorOnLinuxRunningMicroVMs(t *testing.T) {
	f := newDoctorFixture(t)
	f.onLinuxMicroVMs()
	f.atRelease(openshell.InstallerVersion)
	r := f.run()
	var got []string
	for _, c := range r.Checks {
		got = append(got, c.ID)
	}
	want := []string{"platform", "user", "landlock", "docker", "docker-buildkit", "docker-host-network", "docker-file-sharing", "vm-driver", "vm-identity",
		"vm-resources", "disk", "linger", "gateway-service", "openshell-cli", "ssh-connection-sharing", "gateway-registration", "mtls-permissions", "gateway-version",
		"gateway-driver", "global-policy", "bind-mounts", "telemetry", "port-ingress", "port-egress"}
	if !r.OK() || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("checks = %v\nwant     %v\n%s", got, want, r)
	}
	const pass, skip = openshell.StatusPass, openshell.StatusSkip
	expectCheck(t, r, openshell.CheckIDLandlock, pass, "enforced by the MicroVM's own kernel")
	expectCheck(t, r, openshell.CheckIDDockerHostNetwork, skip, "the MicroVM driver does not use Docker's network")
	expectCheck(t, r, openshell.CheckIDVMDriver, pass, "e2fsprogs in "+f.e2fsprogs+"; "+f.linuxDriverPath())
	expectCheck(t, r, openshell.CheckIDVMIdentity, pass, "sandboxes run as 1000:1000, your user")
	expectCheck(t, r, openshell.CheckIDVMResources, pass, "every MicroVM gets 4 vCPUs, 4096 MiB of memory and a 16384 MiB disk for its changes")
	expectCheck(t, r, openshell.CheckIDDisk, pass, "40.0 GiB free under "+filepath.Join(f.home, ".local", "state", "openshell", "vm-driver"))
	expectCheck(t, r, openshell.CheckIDGatewayDriver, pass, "vm (OpenShell MicroVM; experimental upstream)")
	expectCheck(t, r, openshell.CheckIDBindMounts, skip, "mounts no host folders")
	m := r.MicroVM
	if m == nil || !m.Linux || m.KVM != "" || m.ServiceUMask != "0022" || m.UMaskTooStrict || m.HypervisorSigned || !m.KVMUsable() ||
		m.Identity != (openshell.VMIdentity{UID: 1000, GID: 1000}) || f.vmProbes != 0 {
		t.Fatalf("facts = %+v (Docker VM probes %d)", m, f.vmProbes)
	}
}

// TestDoctorChecksWhatLinuxMicroVMsNeed: each need of the MicroVM driver on
// Linux fails with the way on.
func TestDoctorChecksWhatLinuxMicroVMsNeed(t *testing.T) {
	const pass, warn, fail = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail
	permission := &fs.PathError{Op: "open", Path: "/dev/kvm", Err: syscall.EACCES}
	for _, tc := range []struct {
		name  string
		setup func(*doctorFixture)
		want  checkWant
		fix   *fixWant
		then  func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport)
	}{
		// A cloud VM without nested virtualization, or a host with the
		// kvm module not loaded.
		{name: "no /dev/kvm", setup: func(f *doctorFixture) { f.kvm = &fs.PathError{Op: "open", Path: "/dev/kvm", Err: syscall.ENOENT} },
			want: checkWant{"gateway-driver", fail, "vm (OpenShell MicroVM): /dev/kvm does not exist: this host exposes no hardware virtualization to Linux"},
			fix:  &fixWant{text: "nested virtualization", manual: true}},
		// A device a group may read but not write fails the open the
		// driver makes, whatever a group test says.
		{name: "/dev/kvm read-only", setup: func(f *doctorFixture) { f.kvm = permission },
			want: checkWant{"gateway-driver", fail, "/dev/kvm cannot be opened for reading and writing by this user: permission denied"},
			fix:  &fixWant{command: "sudo usermod -aG kvm $USER", sudo: true, manual: true}},
		{name: "/dev/kvm refuses", setup: func(f *doctorFixture) { f.kvm = errors.New("open /dev/kvm: no such device") },
			want: checkWant{"gateway-driver", fail, "/dev/kvm cannot be opened: open /dev/kvm: no such device (virtualization may be turned off"},
			fix:  &fixWant{text: "hardware virtualization", manual: true}},
		// The 0077 of NVIDIA's deb unit (OpenShell#4014).
		{name: "gateway umask 0077", setup: func(f *doctorFixture) { f.serviceUMask("0077") },
			want: checkWant{"gateway-driver", fail, "the openshell-gateway service runs with umask 0077"},
			fix:  &fixWant{text: "UMask=0022", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				if !r.MicroVM.UMaskTooStrict {
					t.Fatalf("facts = %+v", r.MicroVM)
				}
				// What the manager reports once it has read the drop-in.
				f.serviceUMask("0022")
				applyFixes(t, r, openshell.CheckIDGatewayDriver)
				data, err := os.ReadFile(f.dropIn())
				if err != nil || !strings.Contains(string(data), "[Service]\nUMask=0022\n") {
					t.Fatalf("drop-in = %q, %v", data, err)
				}
				// The manager reads the drop-in before the gateway restarts.
				var reload, restart = -1, -1
				for i, c := range f.runner.Calls() {
					switch openshelltest.Argv(c) {
					case "systemctl --user daemon-reload":
						reload = i
					case "systemctl --user restart openshell-gateway":
						restart = i
					}
				}
				if reload < 0 || restart < reload {
					t.Fatalf("daemon-reload at %d, restart at %d: %v", reload, restart, f.runner.Calls())
				}
			}},
		{name: "gateway umask 0027", setup: func(f *doctorFixture) { f.serviceUMask("0027") },
			want: checkWant{"gateway-driver", fail, "umask 0027"}},
		{name: "gateway umask 0002", setup: func(f *doctorFixture) { f.serviceUMask("0002") },
			want: checkWant{"gateway-driver", pass, "vm (OpenShell MicroVM"}},
		{name: "umask not reported", setup: func(f *doctorFixture) { f.serviceUMask("") },
			want: checkWant{"gateway-driver", pass, "vm (OpenShell MicroVM"}},
		{name: "e2fsprogs missing", setup: func(f *doctorFixture) { _ = os.RemoveAll(f.e2fsprogs) },
			want: checkWant{"vm-driver", fail, "e2fsprogs (mke2fs and debugfs) is not installed"},
			fix:  &fixWant{text: "sudo dnf install e2fsprogs", sudo: true, manual: true}},
		{name: "driver missing", setup: func(f *doctorFixture) {
			_ = os.Remove(f.linuxDriverPath())
			f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		}, want: checkWant{"vm-driver", fail, "openshell-driver-vm is not installed (NVIDIA's openshell package does not ship it)"},
			fix: &fixWant{text: "openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz", manual: true}},
		// A driver the gateway runs from a directory DefenseClaw does not
		// search is found by its process.
		{name: "driver found by its process", setup: func(f *doctorFixture) {
			_ = os.Remove(f.linuxDriverPath())
			elsewhere := filepath.Join(f.home, "opt", "openshell-driver-vm")
			touchExecutable(f.t, elsewhere)
			f.runner.On("ps -axww -o pid=,ppid=,uid=,args=", "  41 1 1000 /usr/bin/openshell-gateway\n  42 41 1000 "+elsewhere+" --bind-socket /run/x.sock\n", nil)
		}, want: checkWant{"vm-driver", pass, filepath.Join("opt", "openshell-driver-vm")}},
		// Sandboxes cannot start from a cache built under a strict umask,
		// whatever the umask is now.
		{name: "cache built under umask 0077", setup: func(f *doctorFixture) {
			images := filepath.Join(f.home, ".local", "state", "openshell", "vm-driver", "images")
			for _, name := range []string{"sandbox-prepared-rootfs-ext4-a", "overlay-templates/sandbox-overlay-ext4-v1"} {
				if err := os.MkdirAll(filepath.Join(images, name), 0o700); err != nil {
					f.t.Fatal(err)
				}
			}
			chmod(f.t, filepath.Join(images, "overlay-templates"), 0o755)
		}, want: checkWant{"vm-driver", warn, "has directories only you can open (images/overlay-templates/sandbox-overlay-ext4-v1, images/sandbox-prepared-rootfs-ext4-a)"},
			fix: &fixWant{text: "deletes the MicroVM sandboxes' disks", manual: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				stateDir := filepath.Join(f.home, ".local", "state", "openshell", "vm-driver")
				want := "systemctl --user stop openshell-gateway && rm -rf " + stateDir + "/images " + stateDir + "/sandboxes " + stateDir +
					"/host-runtime && systemctl --user start openshell-gateway"
				if got := r.Get(openshell.CheckIDVMDriver).Fix.Command; got != want {
					t.Fatalf("command = %q\nwant      %q", got, want)
				}
			}},
		{name: "cache built under umask 0022", setup: func(f *doctorFixture) {
			images := filepath.Join(f.home, ".local", "state", "openshell", "vm-driver", "images")
			if err := os.MkdirAll(filepath.Join(images, "sandbox-prepared-rootfs-ext4-a"), 0o755); err != nil {
				f.t.Fatal(err)
			}
			chmod(f.t, images, 0o700) // the driver's own, private
			chmod(f.t, filepath.Join(images, "sandbox-prepared-rootfs-ext4-a"), 0o755)
			// A disk being prepared is the driver's private scratch even
			// under a healthy umask.
			for _, name := range []string{"sandbox-prepared-rootfs-ext4-b.staging-1760000000-1", "overlay-templates/sandbox-overlay-ext4-v1.staging-1760000000-2"} {
				if err := os.MkdirAll(filepath.Join(images, name), 0o700); err != nil {
					f.t.Fatal(err)
				}
			}
			chmod(f.t, filepath.Join(images, "overlay-templates"), 0o755)
		}, want: checkWant{"vm-driver", pass, "e2fsprogs in "}},
		{name: "sandbox user not set", setup: func(f *doctorFixture) {
			f.writeTOML(strings.Replace(linuxVMTOML, "sandbox_uid = 1000\nsandbox_gid = 1000\n", "sandbox_uid = 1001\nsandbox_gid = 1001\n", 1), f.started.Add(-time.Minute))
		}, want: checkWant{"vm-identity", fail, "the MicroVM driver would run sandboxes as 1001:1001; DefenseClaw's images are built for 1000:1000"},
			fix: &fixWant{text: "set sandbox_uid = 1000 and sandbox_gid = 1000", auto: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onLinuxMicroVMs()
			tc.setup(f)
			r := f.run()
			c := expectCheck(t, r, tc.want.id, tc.want.status, tc.want.detail)
			if w := tc.fix; w != nil {
				if c.Fix == nil || (w.command != "" && c.Fix.Command != w.command) || !strings.Contains(c.Fix.Summary+" "+c.Fix.Command, w.text) ||
					(w.auto && (!c.Fix.Automatic || c.Fix.Apply == nil)) || (w.manual && (c.Fix.Automatic || c.Fix.Apply != nil)) || c.Fix.Sudo != w.sudo {
					t.Fatalf("%s fix = %+v, want %+v", c.ID, c.Fix, *w)
				}
			}
			if tc.then != nil {
				tc.then(t, f, r)
			}
		})
	}
}

// TestDoctorOffersMicroVMsOnALinuxHostWithKVM: a Linux host that runs the
// docker driver keeps its checks, and learns what a switch to MicroVMs
// would need only where /dev/kvm opens.
func TestDoctorOffersMicroVMsOnALinuxHostWithKVM(t *testing.T) {
	f := newDoctorFixture(t)
	r := f.run()
	if r.MicroVM != nil || r.Get(openshell.CheckIDVMDriver) != nil {
		t.Fatalf("a docker host without KVM got the MicroVM facts:\n%s", r)
	}
	f = newDoctorFixture(t)
	f.kvm = nil
	r = f.run()
	if m := r.MicroVM; m == nil || !m.KVMUsable() || m.E2fsprogs != "" || len(m.Problems()) != 2 || len(m.Fixes("amd64")) != 2 {
		t.Fatalf("facts = %+v", r.MicroVM)
	}
	if r.Get(openshell.CheckIDVMDriver) != nil {
		t.Fatalf("a docker host got MicroVM checks:\n%s", r)
	}
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "ABI 6")
}
