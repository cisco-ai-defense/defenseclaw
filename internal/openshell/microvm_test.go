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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// microVMTOML is the gateway.toml setup writes on a Mac for uid 501,
// gid 20.
const microVMTOML = `[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"

[openshell.drivers.vm]
sandbox_uid = 501
sandbox_gid = 20
vcpus = 4
mem_mib = 4096
overlay_disk_mib = 16384
`

// signedDriver is `codesign -d --entitlements -` of the formula's driver.
const signedDriver = "Executable=/opt/homebrew/Cellar/openshell/0.1.1/libexec/openshell-driver-vm\n" +
	"[Dict]\n\t[Key] com.apple.security.hypervisor\n\t[Value]\n\t\t[Bool] true\n"

// codesign is the command doctor checks the driver's signature with.
const codesign = "codesign -d --entitlements -"

// touchExecutable creates an executable file.
func touchExecutable(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "#!/bin/sh\n", 0o755)
}

// vmDriverPath is where the formula installs the MicroVM driver.
func (f *doctorFixture) vmDriverPath() string {
	return filepath.Join(f.brew, "opt", "openshell", "libexec", "openshell-driver-vm")
}

// onMicroVMs makes the host an Apple-silicon Mac on Docker Desktop, set up
// for the MicroVM driver as DefenseClaw's setup leaves it for uid 501,
// gid 20, whose gateway runs vm.
func (f *doctorFixture) onMicroVMs() {
	f.onBrew()
	f.fake = openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
	f.writeTOML(microVMTOML, f.started.Add(-time.Minute))
	f.runner.On("docker info", dockerInfoJSON("29.1.5", "Docker Desktop", nil), nil)
	f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) { return &openshell.DockerDesktop{}, nil }
	f.doctor.TempDir = func() string { return macTempDir }
	f.doctor.Geteuid, f.doctor.Getegid = func() int { return 501 }, func() int { return 20 }
	for _, tool := range []string{"mke2fs", "debugfs"} {
		touchExecutable(f.t, filepath.Join(f.e2fsprogs, tool))
	}
	touchExecutable(f.t, f.vmDriverPath())
	f.runner.On(codesign, signedDriver, nil)
	f.runner.On("brew install e2fsprogs", "", nil)
	f.runner.On("brew postinstall nvidia/openshell/openshell", "", nil)
}

// macTempDir is a Mac user's $TMPDIR.
const macTempDir = "/var/folders/1r/kq1tw76n1rv8s9wxygbgtglm0000gn/T/"

// TestDoctorOnAMacRunningMicroVMs: on a Mac whose gateway runs the
// MicroVM driver, Landlock is the MicroVM kernel's (no Docker VM probe),
// Docker Desktop's network does not matter and its file sharing only for
// the temp directory the image builds' hook-fire probe mounts from, bind
// mounts are not offered, and the driver's own needs are checked, in the
// order of the check list.
func TestDoctorOnAMacRunningMicroVMs(t *testing.T) {
	f := newDoctorFixture(t)
	f.onMicroVMs()
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
	const pass, warn, skip = openshell.StatusPass, openshell.StatusWarn, openshell.StatusSkip
	expectCheck(t, r, openshell.CheckIDPlatform, warn, "darwin/arm64: macOS sandboxes run in OpenShell MicroVMs (the vm driver, experimental upstream)")
	expectCheck(t, r, openshell.CheckIDLandlock, pass, "enforced by the MicroVM's own kernel; OpenShell refuses to start a sandbox without it (hard requirement)")
	expectCheck(t, r, openshell.CheckIDDockerHostNetwork, skip, "the MicroVM driver does not use Docker's network")
	expectCheck(t, r, openshell.CheckIDDockerFileSharing, pass, "/var/folders/1r/kq1tw76n1rv8s9wxygbgtglm0000gn/T is shared with Docker Desktop "+
		"(the hook-fire probe of an image build mounts a MicroVM's /etc/hosts from there; sandboxes mount nothing)")
	expectCheck(t, r, openshell.CheckIDVMDriver, pass, "e2fsprogs in "+f.e2fsprogs+"; "+f.vmDriverPath()+" signed for Apple's Hypervisor")
	expectCheck(t, r, openshell.CheckIDVMIdentity, pass, "sandboxes run as 501:20, your user")
	expectCheck(t, r, openshell.CheckIDVMResources, pass, "every MicroVM gets 4 vCPUs, 4096 MiB of memory and a 16384 MiB disk for its changes")
	stateDir := filepath.Join(f.home, ".local", "state", "openshell", "vm-driver")
	expectCheck(t, r, openshell.CheckIDDisk, pass, "40.0 GiB free under "+stateDir)
	expectCheck(t, r, openshell.CheckIDGatewayDriver, pass, "vm (OpenShell MicroVM; experimental upstream)")
	if c := expectCheck(t, r, openshell.CheckIDBindMounts, skip, "the OpenShell MicroVM (vm) driver mounts no host folders: every run works on a copy"); c.Fix != nil {
		t.Fatalf("bind mounts offered a fix on the MicroVM driver: %+v", c.Fix)
	}
	if f.vmProbes != 0 || f.probes != 0 {
		t.Fatalf("asked the Docker VM for Landlock %d times, probed client auth %d times", f.vmProbes, f.probes)
	}
	// The state directory does not exist yet: its nearest parent is measured.
	if f.diskProbed != f.home || r.Driver != openshell.DriverVM || r.ConfiguredDriver != openshell.DriverVM || r.MicroVM == nil ||
		r.MicroVM.Identity != (openshell.VMIdentity{UID: 501, GID: 20}) || !r.MicroVM.HypervisorSigned {
		t.Fatalf("facts = %+v, microvm %+v (disk probed at %q)", r, r.MicroVM, f.diskProbed)
	}
}

// TestDoctorOnAMacWithoutBuildx: DefenseClaw builds a MicroVM's images in
// Docker too, so on a Mac whose docker does not find its buildx plugin (a
// HOME without Docker Desktop's ~/.docker/cli-plugins) the BuildKit check
// fails, after the Docker check, with a fix that names Docker Desktop.
func TestDoctorOnAMacWithoutBuildx(t *testing.T) {
	f := newDoctorFixture(t)
	f.onMicroVMs()
	f.runner.On("docker buildx version", "docker: unknown command: docker buildx\n", errors.New("docker: exit status 1"))
	r := f.run()
	c := expectCheck(t, r, openshell.CheckIDDockerBuildKit, openshell.StatusFail, "docker's buildx plugin is not available")
	if c.Fix == nil || !strings.HasPrefix(c.Fix.Summary, "install Docker's buildx plugin (Docker Desktop provides it), and make sure DOCKER_CONFIG") ||
		c.Fix.Automatic || r.OK() || r.Checks[3].ID != openshell.CheckIDDocker || r.Checks[4].ID != openshell.CheckIDDockerBuildKit {
		t.Fatalf("BuildKit check = %+v, fix %+v\n%s", c, c.Fix, r)
	}
}

// TestDoctorMicroVMChecks runs each MicroVM check against one broken fact
// and, where the case says so, applies the fix it offers.
func TestDoctorMicroVMChecks(t *testing.T) {
	const pass, warn, fail = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail
	vmTOML := func(from, to string) func(*doctorFixture) {
		return func(f *doctorFixture) {
			f.writeTOML(strings.Replace(microVMTOML, from, to, 1), f.started.Add(-time.Minute))
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(*doctorFixture)
		want  checkWant
		fix   *fixWant
		then  func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport)
	}{
		{name: "e2fsprogs missing", setup: func(f *doctorFixture) { _ = os.RemoveAll(f.e2fsprogs) },
			want: checkWant{"vm-driver", fail, "e2fsprogs is not installed where the MicroVM driver looks for it"},
			fix:  &fixWant{command: "brew install e2fsprogs", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMDriver)
				if !f.runner.Called("brew install e2fsprogs") || f.runner.Called("brew postinstall") {
					t.Fatalf("calls = %v", f.runner.Calls())
				}
			}},
		// mkfs.ext4 is mke2fs by another name, which the driver takes too.
		{name: "e2fsprogs as mkfs.ext4", setup: func(f *doctorFixture) {
			_ = os.Remove(filepath.Join(f.e2fsprogs, "mke2fs"))
			touchExecutable(f.t, filepath.Join(f.e2fsprogs, "mkfs.ext4"))
		}, want: checkWant{"vm-driver", pass, "e2fsprogs in "}},
		// The driver runs under launchd, whose PATH is not the shell's.
		{name: "e2fsprogs only on PATH", setup: func(f *doctorFixture) {
			_ = os.RemoveAll(f.e2fsprogs)
			f.found["mke2fs"], f.found["debugfs"] = true, true
		}, want: checkWant{"vm-driver", fail, "mke2fs and debugfs are only on your PATH (/usr/bin)"}, fix: &fixWant{command: "brew install e2fsprogs", auto: true}},
		{name: "driver not signed", setup: func(f *doctorFixture) {
			f.runner.On(codesign, f.vmDriverPath()+": code object is not signed at all", errors.New("exit status 1"))
		}, want: checkWant{"vm-driver", fail, "openshell-driver-vm is not signed for Apple's Hypervisor (com.apple.security.hypervisor)"},
			fix: &fixWant{command: "brew postinstall nvidia/openshell/openshell", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMDriver)
				if !f.runner.Called("brew postinstall nvidia/openshell/openshell") {
					t.Fatalf("calls = %v", f.runner.Calls())
				}
			}},
		{name: "entitlement turned off", setup: func(f *doctorFixture) {
			f.runner.On(codesign, `<plist><dict><key>com.apple.security.hypervisor</key><false/><key>com.apple.security.cs.x</key><true/></dict></plist>`, nil)
		}, want: checkWant{"vm-driver", fail, "is not signed for Apple's Hypervisor"}},
		{name: "entitlement as a plist", setup: func(f *doctorFixture) {
			f.runner.On(codesign, `<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>`, nil)
		}, want: checkWant{"vm-driver", pass, "signed for Apple's Hypervisor"}},
		{name: "both missing", setup: func(f *doctorFixture) {
			_ = os.RemoveAll(f.e2fsprogs)
			f.runner.On(codesign, "code object is not signed at all", errors.New("exit status 1"))
		}, want: checkWant{"vm-driver", fail, "e2fsprogs is not installed"},
			fix: &fixWant{command: "brew install e2fsprogs && brew postinstall nvidia/openshell/openshell", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMDriver)
				if !f.runner.Called("brew install e2fsprogs") || !f.runner.Called("brew postinstall") {
					t.Fatalf("calls = %v", f.runner.Calls())
				}
			}},
		{name: "codesign unavailable", setup: func(f *doctorFixture) { f.runner.On(codesign, "", exec.ErrNotFound) },
			want: checkWant{"vm-driver", warn, "could not check the signature of"}},
		// A gateway that answers on vm runs the driver (TestDoctorOnReleaseBinaries);
		// one that does not answer tells nothing.
		{name: "driver not installed", setup: func(f *doctorFixture) {
			_ = os.Remove(f.vmDriverPath())
			f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		}, want: checkWant{"vm-driver", fail, "openshell-driver-vm is not installed (the nvidia/openshell/openshell formula installs it)"},
			fix: &fixWant{command: "defenseclaw sandbox setup --install-openshell", manual: true}},
		{name: "driver in driver_dir", setup: func(f *doctorFixture) {
			dir := filepath.Join(f.home, "libexec")
			touchExecutable(f.t, filepath.Join(dir, "openshell-driver-vm"))
			_ = os.Remove(f.vmDriverPath())
			vmTOML("[openshell.drivers.vm]\n", "[openshell.drivers.vm]\ndriver_dir = \""+dir+"\"\n")(f)
		}, want: checkWant{"vm-driver", pass, filepath.Join("libexec", "openshell-driver-vm") + " signed"}},
		// The driver pulls from a registry what it does not find for this
		// Mac, and DefenseClaw's image names never resolve there.
		{name: "an amd64 harness image", setup: func(f *doctorFixture) {
			f.doctor.ProbeImages = []string{"defenseclaw/sandbox:claudecode-1a2b"}
			f.runner.On("docker image inspect --format {{.Architecture}} defenseclaw/sandbox:claudecode-1a2b", "amd64\n", nil)
		}, want: checkWant{"vm-driver", warn, "harness images built for another architecture than arm64 cannot boot: defenseclaw/sandbox:claudecode-1a2b (amd64)"},
			fix: &fixWant{command: "defenseclaw sandbox image build --force", manual: true}},

		// Without sandbox_uid and sandbox_gid the driver runs the workload
		// as 1000:1000, which the images are not built for.
		{name: "sandbox user not set", setup: vmTOML("sandbox_uid = 501\nsandbox_gid = 20\n", ""),
			want: checkWant{"vm-identity", fail, "the MicroVM driver would run sandboxes as 1000:1000; DefenseClaw's images are built for 501:20"},
			fix:  &fixWant{text: "set sandbox_uid = 501 and sandbox_gid = 20 under [openshell.drivers.vm]", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMIdentity)
				st, err := f.doctor.Gateway.Read()
				if err != nil || st.VM.Identity() != (openshell.VMIdentity{UID: 501, GID: 20}) || !f.runner.Called("brew services restart") {
					t.Fatalf("after the fix: %+v, %v; calls %v", st, err, f.runner.Calls())
				}
			}},
		// gateway.env overrides gateway.toml.
		{name: "sandbox user from gateway.env", setup: func(f *doctorFixture) {
			writeFile(f.t, filepath.Join(f.dir, "gateway.env"), "OPENSHELL_VM_SANDBOX_UID=1000\n", 0o600)
		}, want: checkWant{"vm-identity", fail, "would run sandboxes as 1000:20"}},
		{name: "sandbox user changed since the restart", setup: vmTOML("", ""),
			then: func(t *testing.T, f *doctorFixture, _ *openshell.DoctorReport) {
				mark := filepath.Join(f.dir, ".defenseclaw-restart-pending")
				writeFile(t, mark, time.Now().UTC().Format(time.RFC3339Nano)+"\n", 0o600)
				r := f.run()
				c := expectCheck(t, r, openshell.CheckIDVMIdentity, warn, "restart the gateway if you have not since it changed")
				if c.Fix == nil || c.Fix.Command != "brew services restart nvidia/openshell/openshell" {
					t.Fatalf("fix = %+v", c.Fix)
				}
			}},

		{name: "resources at the driver's defaults", setup: vmTOML("vcpus = 4\nmem_mib = 4096\noverlay_disk_mib = 16384\n", ""),
			want: checkWant{"vm-resources", warn, "every MicroVM gets 2 vCPUs, 2048 MiB of memory and a 4096 MiB disk for its changes; an agent that builds code may need more"},
			fix:  &fixWant{auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMResources)
				st, _ := f.doctor.Gateway.Read()
				if got := st.VM.Resources(); got != (openshell.VMResources{VCPUs: 2, MemMiB: 4096, OverlayDiskMiB: 16384}) {
					t.Fatalf("resources after the fix = %+v", got)
				}
			}},
		// A smaller Mac is not asked for more than a quarter of its memory.
		{name: "resources on an 8 GB Mac", setup: func(f *doctorFixture) {
			f.doctor.HostMemory = func() uint64 { return 8 << 30 }
			vmTOML("mem_mib = 4096\n", "mem_mib = 2048\n")(f)
		}, want: checkWant{"vm-resources", pass, "2048 MiB of memory"}},
		// Every MicroVM gets the gateway-wide values: an organization's
		// maximum below them refuses every create.
		{name: "resources above the admin maximum", setup: func(f *doctorFixture) { f.doctor.MaxCPUMillis, f.doctor.MaxMemoryBytes = 2000, 3<<30 },
			want: checkWant{"vm-resources", fail, "your organization's openshell.admin.max_resources allows less, so every create is refused"},
			fix:  &fixWant{text: "lower vcpus and mem_mib", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDVMResources)
				st, _ := f.doctor.Gateway.Read()
				if got := st.VM.Resources(); got != (openshell.VMResources{VCPUs: 2, MemMiB: 3072, OverlayDiskMiB: 16384}) {
					t.Fatalf("resources after the fix = %+v", got)
				}
			}},
		{name: "admin maximum below one MicroVM", setup: func(f *doctorFixture) { f.doctor.MaxCPUMillis = 500 },
			want: checkWant{"vm-resources", fail, "below what any MicroVM gets"}, fix: &fixWant{text: "ask your administrator", manual: true}},

		{name: "disk low", setup: func(f *doctorFixture) { f.diskFree = 8 << 30 },
			want: checkWant{"disk", warn, "8.0 GiB free under"}, fix: &fixWant{text: "about 5 GB", manual: true}},
		{name: "disk too full", setup: func(f *doctorFixture) { f.diskFree = 4 << 30 },
			want: checkWant{"disk", fail, "MicroVM sandboxes need at least 6.0 GiB"}},
		// Only the disks prepared from images count: the driver's overlay
		// templates, the bootstrap rootfs every MicroVM boots with and a
		// preparation under way are its own state.
		{name: "prepared images", setup: func(f *doctorFixture) {
			images := filepath.Join(f.home, "vm-state", "images")
			for _, name := range []string{"sandbox-prepared-rootfs-ext4-a", "sandbox-prepared-rootfs-ext4-b", "sandbox-prepared-rootfs-ext4-c.staging-1",
				"overlay-templates", "sandbox-bootstrap-rootfs-ext4-openshell-0.1.1", "x.staging-1"} {
				if err := os.MkdirAll(filepath.Join(images, name), 0o700); err != nil {
					f.t.Fatal(err)
				}
				writeFile(f.t, filepath.Join(images, name, "rootfs.ext4"), strings.Repeat("x", 1<<16), 0o600)
			}
			writeFile(f.t, filepath.Join(images, "sandbox-prepared-rootfs-stray-file"), "x", 0o600)
			vmTOML("[openshell.drivers.vm]\n", "[openshell.drivers.vm]\nstate_dir = \""+filepath.Join(f.home, "vm-state")+"\"\n")(f)
		}, want: checkWant{"disk", pass, "; OpenShell keeps 2 MicroVM disks prepared from images there ("}},

		// Docker is still where the harness images are built.
		{name: "docker down", setup: func(f *doctorFixture) {
			f.runner.On("docker info", "Cannot connect to the Docker daemon", errors.New("exit status 1"))
		}, want: checkWant{"docker", fail, "; DefenseClaw builds the harness images in Docker, and the MicroVM driver reads them from it (docker export)"},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				expectCheck(t, r, openshell.CheckIDDockerHostNetwork, openshell.StatusSkip, "the MicroVM driver does not use Docker's network")
				expectCheck(t, r, openshell.CheckIDVMDriver, pass, "signed")
				expectCheck(t, r, openshell.CheckIDDisk, pass, "free under")
			}},
		// The gateway is a per-user service; a MicroVM mounts nothing.
		{name: "root", setup: func(f *doctorFixture) { f.doctor.Geteuid = func() int { return 0 } },
			want: checkWant{"user", fail, "running as root: OpenShell's gateway is a per-user service"},
			then: func(t *testing.T, _ *doctorFixture, r *openshell.DoctorReport) {
				if strings.Contains(r.Get(openshell.CheckIDUser).Detail, "mount") {
					t.Fatalf("user = %q", r.Get(openshell.CheckIDUser).Detail)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onMicroVMs()
			tc.setup(f)
			r := f.run()
			if tc.want.id != "" {
				c := expectCheck(t, r, tc.want.id, tc.want.status, tc.want.detail)
				if w := tc.fix; w != nil {
					if c.Fix == nil || (w.command != "" && c.Fix.Command != w.command) || !strings.Contains(c.Fix.Summary+" "+c.Fix.Command, w.text) ||
						(w.auto && (!c.Fix.Automatic || c.Fix.Apply == nil)) || (w.manual && (c.Fix.Automatic || c.Fix.Apply != nil)) {
						t.Fatalf("%s fix = %+v, want %+v", c.ID, c.Fix, *w)
					}
				}
			}
			if tc.then != nil {
				tc.then(t, f, r)
			}
		})
	}
}

// TestDoctorOnReleaseBinaries: on a Mac whose gateway runs OpenShell's
// release binaries (the ones the formula downloads) outside Homebrew, from
// a LaunchAgent of the user's own or started by hand, a gateway that
// answers on vm passes the MicroVM driver check, naming the driver it runs
// where it can, and the service check says how the gateway runs instead of
// failing with "not installed".
func TestDoctorOnReleaseBinaries(t *testing.T) {
	const pass, warn, fail = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail
	release := func(t *testing.T) (*doctorFixture, string) {
		f := newDoctorFixture(t)
		f.onMicroVMs()
		f.doctor.Gateway.BrewFormulaInstalled = func() bool { return false }
		_ = os.Remove(f.vmDriverPath())
		prefix := filepath.Join(f.home, "openshell-direct", "prefix")
		touchExecutable(t, filepath.Join(prefix, "libexec", "openshell-driver-vm"))
		return f, prefix
	}
	ps := func(prefix string) string {
		return "    1     0     0 /sbin/launchd\n" +
			" 7976  7974   501 " + filepath.Join(prefix, "bin", "openshell-gateway") + "\n" +
			" 7980  7974   502 /Users/other/bin/openshell-driver-vm\n" +
			" 7989  7976   501 " + filepath.Join(prefix, "libexec", "openshell-driver-vm") + "\n"
	}

	t.Run("started by hand", func(t *testing.T) {
		f, prefix := release(t)
		f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
		f.runner.On("launchctl list", "PID\tStatus\tLabel\n-\t0\tcom.apple.progressd\n", nil)
		r := f.run()
		driver := filepath.Join(prefix, "libexec", "openshell-driver-vm")
		expectCheck(t, r, openshell.CheckIDVMDriver, pass, "e2fsprogs in "+f.e2fsprogs+"; "+driver+" signed for Apple's Hypervisor")
		c := expectCheck(t, r, openshell.CheckIDGatewayService, warn, filepath.Join(prefix, "bin", "openshell-gateway")+
			" (process 7976) was started by hand, not Homebrew's nvidia/openshell/openshell service: it does not start again at login, and DefenseClaw cannot restart it")
		wantOutsideFormulaFix(t, c)
		if !r.OK() || !r.MicroVM.DriverRunning || r.MicroVM.DriverBinary != driver || len(r.MicroVM.Problems()) != 0 {
			t.Fatalf("report:\n%s\nmicrovm %+v", r, r.MicroVM)
		}
		if !f.runner.Called(codesign + " " + driver) {
			t.Fatalf("the running driver's signature was not checked: %v", f.runner.Calls())
		}
	})
	t.Run("a LaunchAgent", func(t *testing.T) {
		f, prefix := release(t)
		f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
		f.runner.On("launchctl list", "PID\tStatus\tLabel\n7976\t0\tcom.example.openshell-gateway\n", nil)
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDGatewayService, warn, filepath.Join(prefix, "bin", "openshell-gateway")+
			" runs under launchd (com.example.openshell-gateway), not Homebrew's nvidia/openshell/openshell service, so DefenseClaw cannot restart it")
		wantOutsideFormulaFix(t, c)
		if !r.OK() || !r.OpenShellOutsideFormula() {
			t.Fatalf("outside the formula %v\n%s", r.OpenShellOutsideFormula(), r)
		}
	})
	// The formula's post-install step signs only the formula's driver: a
	// release driver without the entitlement gets a fix that names it,
	// which doctor --fix does not run.
	t.Run("unsigned release driver", func(t *testing.T) {
		f, prefix := release(t)
		f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
		f.runner.On(codesign, "code object is not signed at all", errors.New("exit status 1"))
		r := f.run()
		driver := filepath.Join(prefix, "libexec", "openshell-driver-vm")
		c := expectCheck(t, r, openshell.CheckIDVMDriver, fail, driver+" is not signed for Apple's Hypervisor")
		if c.Fix == nil || c.Fix.Automatic || c.Fix.Apply != nil || strings.Contains(c.Fix.Command, "brew postinstall") ||
			!strings.Contains(c.Fix.Summary, driver) || !strings.Contains(c.Fix.Summary, "com.apple.security.hypervisor") {
			t.Fatalf("driver fix = %+v", c.Fix)
		}
		if r.MicroVM.DriverFromFormula {
			t.Fatalf("a release driver counts as the formula's: %+v", r.MicroVM)
		}
	})
	// The formula's driver that the running gateway names by its Cellar
	// path is the formula's too.
	t.Run("formula driver from ps", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.onMicroVMs()
		_ = os.Remove(f.vmDriverPath())
		driver := filepath.Join(f.brew, "Cellar", "openshell", "0.1.1", "libexec", "openshell-driver-vm")
		touchExecutable(t, driver)
		f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", " 7976  7974   501 "+filepath.Join(f.brew, "Cellar", "openshell", "0.1.1", "bin", "openshell-gateway")+"\n"+
			" 7989  7976   501 "+driver+"\n", nil)
		f.runner.On(codesign, "code object is not signed at all", errors.New("exit status 1"))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDVMDriver, fail, driver+" is not signed for Apple's Hypervisor")
		if c.Fix == nil || !c.Fix.Automatic || c.Fix.Command != "brew postinstall nvidia/openshell/openshell" || !r.MicroVM.DriverFromFormula {
			t.Fatalf("driver fix = %+v, microvm %+v", c.Fix, r.MicroVM)
		}
	})
	// The driver next to the openshell-gateway on PATH, in the libexec
	// beside its bin, is found without asking ps.
	t.Run("on PATH", func(t *testing.T) {
		f, prefix := release(t)
		lookPath := f.doctor.LookPath
		f.doctor.LookPath = func(name string) (string, error) {
			if name == "openshell-gateway" {
				return filepath.Join(prefix, "bin", name), nil
			}
			return lookPath(name)
		}
		r := f.run()
		expectCheck(t, r, openshell.CheckIDVMDriver, pass, filepath.Join(prefix, "libexec", "openshell-driver-vm")+" signed for Apple's Hypervisor")
		wantOutsideFormulaFix(t, expectCheck(t, r, openshell.CheckIDGatewayService, warn, "the gateway answers, but not Homebrew's nvidia/openshell/openshell service runs it (DefenseClaw could not tell what does)"))
	})
	// ps lists nothing: the answering gateway still runs the driver.
	t.Run("driver not found", func(t *testing.T) {
		f, _ := release(t)
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDVMDriver, pass, "; the gateway runs openshell-driver-vm (DefenseClaw did not find where, to check its signature)")
		if c.Fix != nil || !r.OK() {
			t.Fatalf("fix %+v\n%s", c.Fix, r)
		}
	})
	// Homebrew reports no start time, and a gateway it does not run has no
	// service: the start of the openshell-gateway process ps lists decides
	// whether DefenseClaw's pending-restart mark is still pending (retest:
	// a mark from Sep 28 18:12 warned under a gateway started Sep 29 04:37).
	t.Run("restart mark older than the gateway", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			markAge time.Duration
			etime   string
			pending string
		}{
			{"restarted since", 10 * time.Hour, "01:30:00", ""},
			{"restarted days after", 50 * time.Hour, "1-02:03:04", ""},
			{"not restarted since", time.Hour, "02:00:00", "gateway.toml, but the gateway has not been restarted since it changed"},
			{"in the mark's second", 0, "00:00", "but the gateway has not been restarted since it changed"},
			{"no start known", 10 * time.Hour, "", "gateway.toml; restart the gateway if you have not since it changed"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f, prefix := release(t)
				f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
				if tc.etime != "" {
					f.runner.On("ps -o etime= -p 7976", "   "+tc.etime+"\n", nil)
				} else {
					f.runner.On("ps -o etime= -p 7976", "", errors.New("exit status 1"))
				}
				mark := filepath.Join(f.dir, ".defenseclaw-restart-pending")
				at := time.Now().Add(-tc.markAge)
				writeFile(t, mark, at.UTC().Format(time.RFC3339Nano)+"\n", 0o600)
				if err := os.Chtimes(mark, at, at); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"gateway.toml", "gateway.env"} {
					if _, err := os.Stat(filepath.Join(f.dir, name)); err == nil {
						old := at.Add(-time.Minute)
						if err := os.Chtimes(filepath.Join(f.dir, name), old, old); err != nil {
							t.Fatal(err)
						}
					}
				}
				r := f.run()
				if tc.pending != "" {
					expectCheck(t, r, openshell.CheckIDVMIdentity, warn, tc.pending)
					return
				}
				expectCheck(t, r, openshell.CheckIDVMIdentity, pass, "sandboxes run as 501:20, your user")
			})
		}
	})
	// The start ps reports is only good to the second: a gateway.toml
	// written just before the gateway started, in its second, is loaded
	// (it warned on this Mac, gateway.toml at 04:37:34.4 under a gateway
	// started at 04:37:34), and one written well after it is not.
	t.Run("configuration written as the gateway started", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			after   time.Duration
			pending bool
		}{
			{"in the start's second", 900 * time.Millisecond, false},
			{"a minute after", time.Minute, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f, prefix := release(t)
				f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
				f.runner.On("ps -o etime= -p 7976", "   01:00:00\n", nil)
				at := time.Now().Add(-time.Hour).Add(tc.after)
				if err := os.Chtimes(filepath.Join(f.dir, "gateway.toml"), at, at); err != nil {
					t.Fatal(err)
				}
				r := f.run()
				if tc.pending {
					expectCheck(t, r, openshell.CheckIDVMIdentity, warn, "but the gateway has not been restarted since it changed")
					return
				}
				expectCheck(t, r, openshell.CheckIDVMIdentity, pass, "sandboxes run as 501:20, your user")
			})
		}
	})
	// A gateway that does not answer proves nothing.
	t.Run("gateway down", func(t *testing.T) {
		f, prefix := release(t)
		f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", ps(prefix), nil)
		f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		r := f.run()
		expectCheck(t, r, openshell.CheckIDVMDriver, fail, "openshell-driver-vm is not installed")
		wantOutsideFormulaFix(t, expectCheck(t, r, openshell.CheckIDGatewayService, fail, "nvidia/openshell/openshell is not installed"))
		// Not `brew services start` of the formula that is not installed.
		wantOutsideFormulaFix(t, expectCheck(t, r, openshell.CheckIDGatewayVersion, fail, "the gateway is not answering"))
	})
}

// wantOutsideFormulaFix wants the gateway service fix setup gives for an
// OpenShell installed another way than the Homebrew formula (setup refuses
// it before it reads --install-openshell).
func wantOutsideFormulaFix(t *testing.T, c *openshell.Check) {
	t.Helper()
	if c.Fix == nil || c.Fix.Automatic || c.Fix.Summary != openshell.OpenShellOutsideFormulaFix || c.Fix.Command != "defenseclaw sandbox setup --install-openshell" {
		t.Fatalf("service fix = %+v", c.Fix)
	}
}

// TestDoctorFollowsTheDriverTheGatewayRuns: a gateway can run vm through
// a variable DefenseClaw does not read (the launchd environment, F9): the
// machine checks follow the driver it reports, not a docker Landlock Fail
// next to a vm Pass.
func TestDoctorFollowsTheDriverTheGatewayRuns(t *testing.T) {
	f := newDoctorFixture(t)
	f.onMicroVMs()
	f.writeTOML(strings.Replace(microVMTOML, "compute_driver = \"vm\"\n", "", 1), f.started.Add(-time.Minute))
	f.vmErr = openshell.ErrLandlockMissing
	r := f.run()
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "enforced by the MicroVM's own kernel")
	expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusPass, "vm (OpenShell MicroVM")
	expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusSkip, "mounts no host folders")
	if f.vmProbes != 0 || r.Driver != openshell.DriverVM || r.ConfiguredDriver != openshell.DriverDocker {
		t.Fatalf("probes %d, driver %q, configured %q", f.vmProbes, r.Driver, r.ConfiguredDriver)
	}
	// With the gateway down, the configuration decides.
	f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
	r = f.run()
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusFail, "has no Landlock")
	expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusSkip, "")
}

// DockerEngineOS is the one `docker info` a run on a docker-driver Mac
// makes to tell Docker Desktop (refused up front) from another Docker VM.
func TestDockerEngineOS(t *testing.T) {
	r := &openshelltest.Runner{}
	r.On("docker info --format {{.OperatingSystem}}", "Docker Desktop\n", nil)
	got, err := openshell.DockerEngineOS(context.Background(), r)
	if err != nil || got != "Docker Desktop" || !openshell.IsDockerDesktop(got) {
		t.Fatalf("DockerEngineOS = %q, %v", got, err)
	}
	r.On("docker info", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n", errors.New("exit status 1"))
	if got, err := openshell.DockerEngineOS(context.Background(), r); err == nil || got != "" || !strings.Contains(err.Error(), "Cannot connect") {
		t.Fatalf("DockerEngineOS of a Docker that does not answer = %q, %v", got, err)
	}
	if openshell.IsDockerDesktop("Ubuntu 24.04.2 LTS") {
		t.Fatal("Colima's engine taken for Docker Desktop")
	}
}

// TestDoctorOnADockerMac: on a Mac whose gateway runs the docker driver,
// sandboxes run on the Docker VM's kernel. Without Landlock there the
// driver check fails with a fix that switches the gateway to MicroVMs,
// and what that switch needs is checked; a Docker VM with Landlock
// (Colima) passes as before.
func TestDoctorOnADockerMac(t *testing.T) {
	docker := func(t *testing.T) *doctorFixture {
		f := newDoctorFixture(t)
		f.onMicroVMs()
		f.fake = openshelltest.New()
		f.writeTOML(disabledTOML, f.started.Add(-time.Minute))
		return f
	}

	t.Run("Docker Desktop", func(t *testing.T) {
		f := docker(t)
		f.vmErr = openshell.ErrLandlockMissing
		r := f.run()
		expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusFail, "Docker Desktop's Linux VM (kernel 6.12.65-linuxkit) has no Landlock")
		c := expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusFail, "docker: the Linux VM Docker runs in has no usable Landlock, so no sandbox can start on it")
		if c.Fix == nil || !c.Fix.Automatic || !strings.Contains(c.Fix.Summary, `set compute_driver = "vm"`) {
			t.Fatalf("fix = %+v", c.Fix)
		}
		expectCheck(t, r, openshell.CheckIDVMDriver, openshell.StatusPass, "signed for Apple's Hypervisor")
		expectCheck(t, r, openshell.CheckIDVMIdentity, openshell.StatusSkip, "the gateway runs the docker driver")
		// No Docker Desktop setting can help without Landlock: its host
		// networking and file sharing warnings asked for one (the #1019
		// retest), and are skipped, saying why.
		for id, why := range map[string]string{
			openshell.CheckIDDockerHostNetwork: "OpenShell MicroVMs, the way on, do not use Docker's network",
			openshell.CheckIDDockerFileSharing: "OpenShell MicroVMs, the way on, mount no project folder",
		} {
			c := expectCheck(t, r, id, openshell.StatusSkip, "not needed: without a usable Landlock in the Linux VM Docker runs in, "+
				"no sandbox starts there whatever this setting is, and "+why)
			if c.Fix != nil {
				t.Fatalf("%s fix = %+v", id, c.Fix)
			}
		}
		if r.Driver != openshell.DriverDocker {
			t.Fatalf("driver = %q", r.Driver)
		}

		// The restarted gateway must run vm, or the switch is undone.
		applied, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDGatewayDriver, nil })
		if err != nil || len(applied) != 1 || applied[0].Applied || !strings.Contains(applied[0].Error, "runs the docker compute driver, not vm") {
			t.Fatalf("applied = %+v, %v", applied, err)
		}
		if got := readFile(t, filepath.Join(f.dir, "gateway.toml")); got != disabledTOML {
			t.Fatalf("the failed switch was not rolled back:\n%s", got)
		}

		// The restarted gateway runs vm: the switch stays, with the user and
		// the resources.
		// Each run closes the gateway it asked.
		f.fake = openshelltest.New()
		r = f.run()
		f.restartedOn = openshell.DriverVM
		applyFixes(t, r, openshell.CheckIDGatewayDriver)
		st, err := f.doctor.Gateway.Read()
		if err != nil || st.ComputeDriver != openshell.DriverVM || st.VM.Identity() != (openshell.VMIdentity{UID: 501, GID: 20}) ||
			st.VM.Resources() != (openshell.VMResources{VCPUs: 4, MemMiB: 4096, OverlayDiskMiB: 16384}) {
			t.Fatalf("after the switch: %+v, %v", st, err)
		}
		f.fake = openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
		r = f.run()
		expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusPass, "vm (OpenShell MicroVM")
		expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "MicroVM's own kernel")
	})

	// Every MicroVM gets the gateway-wide values: the switch never writes
	// more than an organization's maximum allows, or every create after
	// it would be refused.
	t.Run("an organization's maximum", func(t *testing.T) {
		f := docker(t)
		f.vmErr = openshell.ErrLandlockMissing
		f.doctor.MaxCPUMillis, f.doctor.MaxMemoryBytes = 2000, 3<<30
		r := f.run()
		if r.MicroVM == nil || r.MicroVM.Recommended != (openshell.VMResources{VCPUs: 2, MemMiB: 3072, OverlayDiskMiB: 16384}) {
			t.Fatalf("microvm = %+v", r.MicroVM)
		}
		f.restartedOn = openshell.DriverVM
		applyFixes(t, r, openshell.CheckIDGatewayDriver)
		st, err := f.doctor.Gateway.Read()
		if err != nil || st.ComputeDriver != openshell.DriverVM || st.VM.Resources() != (openshell.VMResources{VCPUs: 2, MemMiB: 3072, OverlayDiskMiB: 16384}) {
			t.Fatalf("after the switch: %+v (vm %+v), %v", st, st.VM, err)
		}
		f.fake = openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
		expectCheck(t, f.run(), openshell.CheckIDVMResources, openshell.StatusPass, "every MicroVM gets 2 vCPUs, 3072 MiB of memory")
	})

	t.Run("Landlock not checked", func(t *testing.T) {
		f := docker(t)
		f.vmErr = openshell.ErrNoProbeImage
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusWarn, "whether the Linux VM Docker runs in has Landlock is not known")
		if c.Fix == nil || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		// Landlock may be there: the Docker Desktop settings still count.
		expectCheck(t, r, openshell.CheckIDDockerHostNetwork, openshell.StatusWarn, "Docker Desktop does not report the host networking setting")
	})

	t.Run("a Docker VM with Landlock", func(t *testing.T) {
		f := docker(t)
		r := f.run()
		expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusPass, "docker")
		expectCheck(t, r, openshell.CheckIDVMDriver, openshell.StatusSkip, "the gateway runs the docker driver")
		expectCheck(t, r, openshell.CheckIDVMResources, openshell.StatusSkip, "the gateway runs the docker driver")
		expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "disabled")
		expectCheck(t, r, openshell.CheckIDDisk, openshell.StatusSkip, "images live in the Docker Desktop VM disk")
		expectCheck(t, r, openshell.CheckIDDockerHostNetwork, openshell.StatusWarn, "Docker Desktop does not report the host networking setting")
		expectCheck(t, r, openshell.CheckIDDockerFileSharing, openshell.StatusWarn, "Docker Desktop does not report its shared directories")
	})

	t.Run("configured for MicroVMs, not restarted", func(t *testing.T) {
		f := docker(t)
		f.writeTOML(microVMTOML, f.started.Add(-time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusWarn, "docker, but its configuration selects vm (OpenShell MicroVM): the gateway has not been restarted since")
		if c.Fix == nil || c.Fix.Command != "brew services restart nvidia/openshell/openshell" || c.Fix.Apply == nil {
			t.Fatalf("fix = %+v", c.Fix)
		}
		if r.Driver != openshell.DriverDocker || r.ConfiguredDriver != openshell.DriverVM {
			t.Fatalf("driver %q, configured %q", r.Driver, r.ConfiguredDriver)
		}
	})

	t.Run("an Intel Mac", func(t *testing.T) {
		f := docker(t)
		f.doctor.GOARCH = "amd64"
		expectCheck(t, f.run(), openshell.CheckIDPlatform, openshell.StatusFail, "darwin/amd64: the OpenShell MicroVM driver runs on Apple silicon only")
	})
}

// TestDoctorOnLinuxWithTheVMDriver: DefenseClaw certifies the MicroVM
// driver on macOS only; on Linux doctor says so, and offers no bind mounts
// on it.
func TestDoctorOnLinuxWithTheVMDriver(t *testing.T) {
	f := newDoctorFixture(t)
	f.fake = openshelltest.New(openshelltest.WithDriver(openshell.DriverVM))
	r := f.run()
	expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusWarn, "not certified by DefenseClaw off macOS")
	expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusSkip, "mounts no host folders")
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "ABI 6")
	if r.Get(openshell.CheckIDVMDriver) != nil || r.MicroVM != nil {
		t.Fatalf("Linux got the macOS MicroVM checks:\n%s", r)
	}
}

// On the MicroVM driver the file sharing check is of the temp directory
// the hook-fire probe of an image build mounts a MicroVM's /etc/hosts and
// /etc/resolv.conf from: Docker Desktop shares /var/folders and /tmp by
// default (a settings store that names no directories keeps the
// defaults), and a list without it fails with where to add it.
func TestDoctorChecksTheProbesFileSharingOnMicroVMs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tmp    string
		shared []string
		status openshell.CheckStatus
		detail string
	}{
		{"defaults", macTempDir, nil, openshell.StatusPass, "/var/folders/1r/kq1tw76n1rv8s9wxygbgtglm0000gn/T is shared with Docker Desktop"},
		{"tmp", "/tmp", []string{"/Users", "/tmp"}, openshell.StatusPass, "/tmp is shared with Docker Desktop"},
		{"home only", macTempDir, []string{"/Users"}, openshell.StatusFail,
			"/var/folders/1r/kq1tw76n1rv8s9wxygbgtglm0000gn/T is not shared with Docker Desktop, so the hook-fire probe cannot run an image with a MicroVM's name resolution and the gateway refuses every image"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onMicroVMs()
			f.doctor.TempDir = func() string { return tc.tmp }
			f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) { return &openshell.DockerDesktop{FileSharing: tc.shared}, nil }
			c := expectCheck(t, f.run(), openshell.CheckIDDockerFileSharing, tc.status, tc.detail)
			if (tc.status == openshell.StatusFail) != (c.Fix != nil && strings.Contains(c.Fix.Summary, "Docker Desktop → Settings → Resources → File sharing")) {
				t.Fatalf("fix = %+v", c.Fix)
			}
		})
	}
}
