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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// What OpenShell's MicroVM (vm) driver needs on a Linux host, which runs a
// MicroVM on KVM instead of Apple's Hypervisor: /dev/kvm opened for reading
// and writing by the user the gateway runs as, e2fsprogs, the
// openshell-driver-vm binary, and a gateway service whose umask is no
// stricter than 0022. The driver builds its guest root disk from
// directories the gateway process creates, and with the 0077 of NVIDIA's
// deb unit they are 0700 and owned by the host uid: the sandbox's own uid
// then cannot traverse /newroot, and every MicroVM dies with "read
// /proc/self/status: Permission denied" (OpenShell 0.1.2 to 0.1.5,
// NVIDIA/OpenShell#4014, still open: the drop-in stays until a release
// that fixes it is SupportedMin).
const (
	kvmDevice = "/dev/kvm"
	// ServiceUMask is the umask DefenseClaw gives the gateway service of a
	// MicroVM gateway on Linux.
	ServiceUMask = "0022"
	// vmUnitDropIn is the systemd drop-in DefenseClaw writes for it. Drop-ins
	// apply in name order, ASCII order (digits before letters), and the last
	// UMask= wins: this one sorts after override.conf, which `systemctl edit`
	// makes, and after the numbered ones.
	vmUnitDropIn = "zz-defenseclaw-umask.conf"
)

// linuxE2fsprogsDirs are where a Linux host has e2fsprogs' mke2fs and
// debugfs: the directories of a systemd user service's default PATH.
var linuxE2fsprogsDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// openKVM opens /dev/kvm for reading and writing, the way the MicroVM
// driver does and as the user it runs as. Group membership is not the
// test: RHEL makes the device world read-write, Ubuntu's is 0660 kvm.
func openKVM() error {
	f, err := os.OpenFile(kvmDevice, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// kvmProblem says, for an error from opening /dev/kvm, why this host
// cannot run a MicroVM, and what to do about it.
func kvmProblem(err error) (problem string, fix *Fix) {
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, fs.ErrNotExist):
		return kvmDevice + " does not exist: this host exposes no hardware virtualization to Linux",
			&Fix{Summary: "run MicroVM sandboxes on a host with KVM (on a cloud VM, an instance type with nested virtualization enabled; on a physical or local " +
				"virtual machine, turn virtualization on in the firmware or hypervisor and load the kvm_intel or kvm_amd module)"}
	case errors.Is(err, fs.ErrPermission):
		return kvmDevice + " cannot be opened for reading and writing by this user: " + errText(err),
			&Fix{Summary: "give your user read and write access to " + kvmDevice + ": it is read-write for the kvm group on most distributions (add your user, then log in again); " +
				"where its mode does not let the group write (ls -l " + kvmDevice + "), an administrator changes the device's udev rule",
				Command: "sudo usermod -aG kvm $USER", Sudo: true}
	}
	return kvmDevice + " cannot be opened: " + errText(err) + " (virtualization may be turned off in the firmware or by the hypervisor)",
		&Fix{Summary: "turn hardware virtualization on for this host, or run MicroVM sandboxes elsewhere"}
}

// errText is err without the operation and path os wraps around the
// errno.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// memTotal is MemTotal of /proc/meminfo in bytes (0: not found).
func memTotal(meminfo []byte) uint64 {
	sc := bufio.NewScanner(bytes.NewReader(meminfo))
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return 0
		}
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			n <<= 10
		}
		return n
	}
	return 0
}

// UMaskTooStrict reports whether a gateway service's umask (as systemd
// prints it: "0022") hides directories from group and others, which a
// MicroVM's guest needs to traverse. An empty or unreadable umask is not
// known to be strict.
func UMaskTooStrict(umask string) bool {
	n, err := strconv.ParseUint(strings.TrimSpace(umask), 8, 32)
	return err == nil && n&0o055 != 0
}

// staleVMCache lists the directories of the MicroVM driver's cache under
// stateDir that only their owner can open (mode without group and other
// read and execute): the prepared images and overlay templates, and the
// host runtime the supervisor unpacks. The driver makes them with its
// process's umask, so under a gateway umask stricter than 0022 they are
// 0700 and no MicroVM prepared from them starts, however the umask is
// fixed afterwards. Names are relative to stateDir.
func staleVMCache(stateDir string) []string {
	if stateDir == "" {
		return nil
	}
	var out []string
	check := func(rel string) {
		if info, err := os.Lstat(filepath.Join(stateDir, rel)); err == nil && info.IsDir() && info.Mode().Perm()&0o055 != 0o055 {
			out = append(out, rel)
		}
	}
	check("host-runtime")
	images := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(images)
	if err != nil {
		return out
	}
	for _, e := range entries {
		// A preparation in progress, or left behind, is the driver's
		// private scratch ("<name>.staging-<epoch>-<n>", which it may open
		// 0700 under any umask) and no prepared image: it says nothing of
		// the umask the finished directories were made under.
		if !e.IsDir() || isVMStaging(e.Name()) {
			continue
		}
		check(filepath.Join("images", e.Name()))
		if e.Name() == "overlay-templates" {
			sub, _ := os.ReadDir(filepath.Join(images, e.Name()))
			for _, s := range sub {
				if s.IsDir() && !isVMStaging(s.Name()) {
					check(filepath.Join("images", e.Name(), s.Name()))
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// isVMStaging reports whether name is a directory where the driver prepares
// a disk (image.VMStaging).
func isVMStaging(name string) bool { return strings.Contains(name, ".staging") }

// staleVMCacheFix is the way out of a cache built under a strict umask:
// stop the gateway (stopping every MicroVM), remove what the driver
// rebuilds on the next start, and start it again. The sandboxes' own
// disks go with it, which a cache like this could not start anyway.
func staleVMCacheFix(stateDir string) *Fix {
	q := shellQuote(stateDir)
	return &Fix{
		Summary: "remove the driver's cache so it is rebuilt with the new umask (this deletes the MicroVM sandboxes' disks; none of them could start, " +
			"and each harness image prepares its disk again on its first run, about a minute and 5 GB)",
		Command: fmt.Sprintf("systemctl --user stop %s && rm -rf %s/images %s/sandboxes %s/host-runtime && systemctl --user start %s",
			GatewayService, q, q, q, GatewayService),
	}
}

// vmDriverArchive is the name of OpenShell's release archive of the
// MicroVM driver for goarch ("" when it publishes none).
func vmDriverArchive(goarch string) string {
	switch goarch {
	case "amd64":
		return "openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz"
	case "arm64":
		return "openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz"
	}
	return ""
}

// InstallE2fsprogsFix is what to do on a Linux host without the e2fsprogs
// the MicroVM driver formats its disks with.
func InstallE2fsprogsFix() *Fix {
	return &Fix{Summary: "install e2fsprogs 1.43 or newer, whose mke2fs and debugfs the MicroVM driver formats every MicroVM's disks with",
		Command: "sudo dnf install e2fsprogs   # Debian and Ubuntu: sudo apt install e2fsprogs", Sudo: true}
}

// InstallVMDriverFix is what to do on a Linux host without the
// openshell-driver-vm binary, which NVIDIA's package does not install: its
// release publishes it as an archive of its own. The archive is checked
// against the digest compiled in for InstallerVersion (TarballPins), not
// against a checksum file fetched from the same release as the archive,
// which proved only that the two downloads agreed (#1224).
func InstallVMDriverFix(goarch string) *Fix {
	archive := vmDriverArchive(goarch)
	if archive == "" {
		return &Fix{Summary: "OpenShell publishes its MicroVM driver for amd64 and arm64 Linux only"}
	}
	digest := TarballPins[InstallerVersion][archive]
	if digest == "" {
		return &Fix{Summary: "this DefenseClaw build pins no digest for OpenShell " + InstallerTag + "'s " + archive + "; install " + vmDriverBinary + " from that release by hand"}
	}
	base := TarballBaseURL + InstallerTag + "/"
	return &Fix{
		Summary: "install " + vmDriverBinary + " from OpenShell " + InstallerTag + " into ~/.local/libexec/openshell, after checking the archive against the SHA-256 " +
			"this DefenseClaw build pins for it (the openshell package ships no MicroVM driver)",
		Command: "d=$(mktemp -d) && cd \"$d\" && curl -fsSLO " + base + archive +
			" && echo '" + digest + "  " + archive + "' | sha256sum -c - && mkdir -p ~/.local/libexec/openshell && tar -xzf " + archive +
			" -C ~/.local/libexec/openshell " + vmDriverBinary + " && chmod 0755 ~/.local/libexec/openshell/" + vmDriverBinary + "; cd - >/dev/null; rm -rf \"$d\"",
	}
}

// linuxMicroVMHost finds what the MicroVM driver needs on this Linux
// host.
func (r *doctorRun) linuxMicroVMHost(ctx context.Context) *MicroVMHost {
	m := &MicroVMHost{Linux: true, Identity: VMIdentity{UID: int64(r.Geteuid()), GID: int64(r.Getegid())},
		Recommended: RecommendedVMResources(r.HostMemory()).Within(r.MaxCPUMillis, r.MaxMemoryBytes)}
	if err := r.OpenKVM(); err != nil {
		m.KVM, m.kvmFix = kvmProblem(err)
	}
	m.E2fsprogs = e2fsprogsIn(r.E2fsprogsDirs)
	m.DriverRunning = r.running.Name == DriverVM
	m.DriverBinary = r.findVMDriver(ctx)
	m.StateDir = r.vmStateDir()
	m.StaleCache = staleVMCache(m.StateDir)
	if r.service != nil {
		m.ServiceUMask = r.service.UMask
		m.UMaskTooStrict = UMaskTooStrict(r.service.UMask)
	}
	return m
}

// linuxMicroVMChecks makes, once, the machine checks of a Linux host
// whose gateway runs MicroVMs, which differ from the docker driver's the
// Linux checks were made for before the compute driver was known: the
// MicroVM's own kernel enforces Landlock, Docker's network and the Docker
// root's space do not matter, and the driver has needs of its own. They
// replace the earlier ones in place. On a host with KVM that runs another
// driver, what a switch needs is gathered (DoctorReport.MicroVM) and no
// check changes.
func (r *doctorRun) linuxMicroVMChecks(ctx context.Context) {
	if r.machineDone {
		return
	}
	r.machineDone = true
	m := r.linuxMicroVMHost(ctx)
	if r.driver() != DriverVM {
		if m.KVM == "" {
			r.micro, r.report.MicroVM = m, m
		}
		return
	}
	r.micro, r.report.MicroVM = m, m
	if c := r.report.Get(CheckIDLandlock); c != nil {
		*c = Check{ID: CheckIDLandlock, Title: "Landlock", Status: StatusPass,
			Detail: "enforced by the MicroVM's own kernel; OpenShell refuses to start a sandbox without it (hard requirement)"}
	}
	if c := r.report.Get(CheckIDDockerHostNetwork); c != nil {
		*c = Check{ID: CheckIDDockerHostNetwork, Title: checkTitles[CheckIDDockerHostNetwork], Status: StatusSkip, Detail: "the MicroVM driver does not use Docker's network"}
	}
	vm := []Check{r.linuxVMDriverCheck(), r.vmIdentityCheck(ctx), r.vmResourcesCheck(), r.vmDiskCheck()}
	for i := range r.report.Checks {
		if r.report.Checks[i].ID == CheckIDDisk {
			r.report.Checks = slices.Replace(r.report.Checks, i, i+1, vm...)
			return
		}
	}
	r.report.Checks = append(r.report.Checks, vm...)
}

// linuxVMDriverCheck checks what the MicroVM driver needs on this Linux
// host besides KVM and the service's umask (the Gateway compute driver
// check's): e2fsprogs, the driver binary, and a cache not built under a
// strict umask.
func (r *doctorRun) linuxVMDriverCheck() Check {
	c := Check{ID: CheckIDVMDriver, Title: "MicroVM driver"}
	m := r.micro
	problems := m.toolProblems()
	stateDir, stale := m.StateDir, m.StaleCache
	switch {
	case len(problems) > 0:
		c.Status, c.Detail = StatusFail, strings.Join(problems, "; ")
	case len(stale) > 0:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("the driver's cache under %s has directories only you can open (%s): it was built while the gateway ran with a umask stricter than %s, "+
			"and no MicroVM prepared from it starts", stateDir, shortNames(stale, 3), ServiceUMask)
	case m.DriverBinary == "":
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("e2fsprogs in %s; the gateway runs %s (DefenseClaw did not find where)", m.E2fsprogs, vmDriverBinary)
	default:
		c.Status, c.Detail = StatusPass, fmt.Sprintf("e2fsprogs in %s; %s", m.E2fsprogs, m.DriverBinary)
	}
	switch {
	case m.E2fsprogs == "":
		c.Fix = InstallE2fsprogsFix()
	case m.DriverBinary == "" && !m.DriverRunning:
		c.Fix = InstallVMDriverFix(r.GOARCH)
	case len(stale) > 0:
		c.Fix = m.StaleCacheFix()
	}
	return c
}

// StaleCacheFix is the way out of StaleCache (nil when there is none).
func (m *MicroVMHost) StaleCacheFix() *Fix {
	if len(m.StaleCache) == 0 {
		return nil
	}
	fix := staleVMCacheFix(m.StateDir)
	if m.UMaskTooStrict {
		// Rebuilt under the same umask it would be stale again.
		fix.Summary = "once the gateway service's umask is fixed (the Gateway compute driver check), " + fix.Summary
	}
	return fix
}

// Fixes are the ways on from what keeps a Linux host from starting a
// MicroVM (Problems): none of them DefenseClaw can do itself, as each
// needs an administrator or a download the user verifies.
func (m *MicroVMHost) Fixes(goarch string) []*Fix {
	var out []*Fix
	if m.KVM != "" && m.kvmFix != nil {
		out = append(out, m.kvmFix)
	}
	if m.E2fsprogs == "" {
		out = append(out, InstallE2fsprogsFix())
	}
	if m.DriverBinary == "" && !m.DriverRunning {
		out = append(out, InstallVMDriverFix(goarch))
	}
	return out
}

// shortNames lists up to n names, then how many more.
func shortNames(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:n], ", "), len(names)-n)
}

// linuxDriverCheck is the Gateway compute driver check of a Linux
// gateway that runs the MicroVM driver: it passes only where a MicroVM can
// start, behind an open of /dev/kvm for reading and writing and a gateway
// service umask the guest can traverse.
func (r *doctorRun) linuxDriverCheck(c Check) Check {
	const what = "vm (OpenShell MicroVM)"
	m := r.micro
	switch {
	case m == nil:
		c.Status, c.Detail = StatusPass, "vm (OpenShell MicroVM; experimental upstream)"
	case m.KVM != "":
		c.Status, c.Detail = StatusFail, what+": "+m.KVM
		c.Fix = m.kvmFix
	case m.UMaskTooStrict:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s: the %s service runs with umask %s, which makes the directories the driver builds every MicroVM's disk from unreadable to the sandbox's "+
			"own user, and every MicroVM fails to start (\"read /proc/self/status: Permission denied\")", what, GatewayService, m.ServiceUMask)
		c.Fix = r.gatewayChangeFix("give the "+GatewayService+" service UMask="+ServiceUMask+" (a systemd drop-in, "+vmUnitDropIn+")",
			"(the driver's cache built under the old umask must be removed too: the MicroVM driver check says how)", r.applyGateway(GatewayChanges{ServiceUMask: ServiceUMask}))
	default:
		c.Status, c.Detail = StatusPass, "vm (OpenShell MicroVM; experimental upstream)"
	}
	return c
}

// toolProblems are what keeps a Linux host from starting a MicroVM besides
// KVM: e2fsprogs and the driver binary.
func (m *MicroVMHost) toolProblems() []string {
	var out []string
	if m.E2fsprogs == "" {
		out = append(out, "e2fsprogs (mke2fs and debugfs) is not installed: the MicroVM driver formats every MicroVM's disks with them")
	}
	if m.DriverBinary == "" && !m.DriverRunning {
		out = append(out, vmDriverBinary+" is not installed (NVIDIA's openshell package does not ship it)")
	}
	return out
}
