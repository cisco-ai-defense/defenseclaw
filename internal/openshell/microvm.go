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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Free space the MicroVM driver's state directory needs: the first start
// of each image prepares a MicroVM disk of about 5 GB there.
const (
	VMDiskFailBytes = 6 << 30
	VMDiskWarnBytes = 12 << 30
)

// Homebrew commands that prepare a Mac for the MicroVM driver.
const (
	// InstallE2fsprogsCommand installs the e2fsprogs the driver formats
	// its disks with. Homebrew installs it keg-only, where the driver
	// looks for it.
	InstallE2fsprogsCommand = "brew install e2fsprogs"
	// ResignVMDriverCommand reruns the formula's post-install step, which
	// signs its MicroVM driver for Apple's Hypervisor.
	ResignVMDriverCommand = "brew postinstall " + GatewayFormula
)

// e2fsprogsDirs are where OpenShell 0.1.1's MicroVM driver looks for
// mke2fs (or mkfs.ext4) and debugfs besides its PATH: the Homebrew kegs.
// The driver runs under launchd, whose PATH is not the shell's.
var e2fsprogsDirs = []string{
	"/opt/homebrew/opt/e2fsprogs/sbin", "/opt/homebrew/opt/e2fsprogs/bin",
	"/usr/local/opt/e2fsprogs/sbin", "/usr/local/opt/e2fsprogs/bin",
}

// vmDriverBinary is the MicroVM driver's executable.
const vmDriverBinary = "openshell-driver-vm"

// hypervisorEntitlement is what a process needs to run a VM through
// Apple's Hypervisor framework.
const hypervisorEntitlement = "com.apple.security.hypervisor"

// MicroVMHost is what OpenShell's MicroVM (vm) driver needs on a Mac, as
// doctor found it.
type MicroVMHost struct {
	// E2fsprogs is the directory the driver finds mke2fs and debugfs in;
	// empty when it finds none. OnPath names a copy only the shell's PATH
	// has, which the driver under launchd may not see.
	E2fsprogs string `json:"e2fsprogs,omitempty"`
	OnPath    string `json:"e2fsprogs_on_path,omitempty"`
	// OwnBrewPrefix is the Homebrew prefix when it is a per-user one,
	// which the driver does not search for e2fsprogs (empty for
	// /opt/homebrew and /usr/local).
	OwnBrewPrefix string `json:"homebrew_prefix,omitempty"`
	// DriverBinary is the openshell-driver-vm the gateway starts; empty
	// when none was found.
	DriverBinary string `json:"driver_binary,omitempty"`
	// DriverFromFormula reports that DriverBinary is the one in the
	// nvidia/openshell/openshell formula's keg, the only one the
	// formula's post-install step (ResignVMDriverCommand) signs.
	DriverFromFormula bool `json:"driver_from_formula,omitempty"`
	// DriverRunning reports that the answering gateway runs the MicroVM
	// driver, so it is installed, whether DefenseClaw found where
	// (DriverBinary) or not: OpenShell's release binaries outside
	// Homebrew, for one.
	DriverRunning bool `json:"driver_running,omitempty"`
	// HypervisorSigned reports that DriverBinary carries Apple's
	// Hypervisor entitlement; SignatureUnknown that codesign could not
	// tell.
	HypervisorSigned bool   `json:"hypervisor_signed"`
	SignatureUnknown string `json:"signature_unknown,omitempty"`
	// Identity is the uid and gid DefenseClaw's images are built for,
	// this user's, which the driver must run sandboxes as.
	Identity VMIdentity `json:"identity"`
	// Recommended is what DefenseClaw sets up every MicroVM with, within
	// the organization's openshell.admin.max_resources.
	Recommended VMResources `json:"recommended"`
}

// Problems are what keeps the driver from starting a MicroVM here.
func (m *MicroVMHost) Problems() []string {
	var out []string
	if m.E2fsprogs == "" {
		problem := "e2fsprogs is not installed where the MicroVM driver looks for it, Homebrew's keg (opt/e2fsprogs under /opt/homebrew or /usr/local): " +
			"the driver formats every MicroVM's disks with its mke2fs and debugfs"
		if m.OwnBrewPrefix != "" {
			problem += "; it does not look in your Homebrew at " + m.OwnBrewPrefix
		}
		out = append(out, problem)
	}
	switch {
	case m.DriverBinary == "" && !m.DriverRunning:
		out = append(out, vmDriverBinary+" is not installed (the "+GatewayFormula+" formula installs it)")
	case m.DriverBinary != "" && !m.HypervisorSigned && m.SignatureUnknown == "":
		out = append(out, m.DriverBinary+" is not signed for Apple's Hypervisor ("+hypervisorEntitlement+"), so it cannot start a MicroVM")
	}
	return out
}

// macChecks makes, once, the machine checks of a Mac, which depend on the
// compute driver: on vm sandboxes run in OpenShell MicroVMs, with their
// own kernel and disks; on docker they run on the kernel of the Linux VM
// Docker runs in. They go where the Landlock check would, in the order
// the check list gives.
func (r *doctorRun) macChecks(ctx context.Context) {
	if r.GOOS == "linux" || r.machineDone {
		return
	}
	r.machineDone = true
	r.micro = r.microVMHost(ctx)
	r.report.MicroVM = r.micro
	docker := r.dockerFound
	var checks []Check
	if r.driver() == DriverVM {
		landlock := Check{ID: CheckIDLandlock, Title: "Landlock", Status: StatusPass,
			Detail: "enforced by the MicroVM's own kernel; OpenShell refuses to start a sandbox without it (hard requirement)"}
		if docker.Status == StatusFail {
			docker.Detail += "; DefenseClaw builds the harness images in Docker, and the MicroVM driver reads them from it (docker export)"
		}
		checks = []Check{landlock, docker, r.buildKit,
			{ID: CheckIDDockerHostNetwork, Title: checkTitles[CheckIDDockerHostNetwork], Status: StatusSkip, Detail: "the MicroVM driver does not use Docker's network"},
			r.vmFileSharingCheck(), r.vmDriverCheck(ctx), r.vmIdentityCheck(ctx), r.vmResourcesCheck(), r.vmDiskCheck()}
	} else {
		landlock := r.dockerVMLandlockCheck(ctx)
		hostNet, sharing, disk := r.dockerDriverChecks(r.dockerRoot)
		if landlock.Status == StatusFail {
			// No Docker Desktop setting lets a sandbox start on a VM
			// kernel without Landlock, and the way on, MicroVMs, uses
			// neither of these: the doctor does not ask for a change that
			// cannot help.
			hostNet = mootWithoutLandlock(hostNet, "OpenShell MicroVMs, the way on, do not use Docker's network")
			sharing = mootWithoutLandlock(sharing, "OpenShell MicroVMs, the way on, mount no project folder")
		}
		// What a switch to MicroVMs needs is checked when the doctor
		// offers one.
		vmDriver := Check{ID: CheckIDVMDriver, Title: "MicroVM driver", Status: StatusSkip, Detail: "the gateway runs the docker driver"}
		if landlock.Status != StatusPass {
			vmDriver = r.vmDriverCheck(ctx)
		}
		skip := "the gateway runs the docker driver (a switch to MicroVMs sets it)"
		checks = []Check{landlock, docker, r.buildKit, hostNet, sharing, vmDriver,
			{ID: CheckIDVMIdentity, Title: "MicroVM sandbox user", Status: StatusSkip, Detail: skip},
			{ID: CheckIDVMResources, Title: "MicroVM resources", Status: StatusSkip, Detail: skip}, disk}
	}
	r.landlock = checks[0].Status
	r.report.Checks = slices.Insert(r.report.Checks, r.machineAt, checks...)
}

// mootWithoutLandlock skips a Docker Desktop setting check (host
// networking, file sharing) that warned or failed on a Mac whose Docker VM
// has no Landlock, saying why: its fix, a change in Docker Desktop's
// settings, cannot make a sandbox start there. One that passed stays.
func mootWithoutLandlock(c Check, microVMs string) Check {
	if c.Status != StatusWarn && c.Status != StatusFail {
		return c
	}
	c.Status, c.Fix = StatusSkip, nil
	c.Detail = "not needed: without a usable Landlock in the Linux VM Docker runs in, no sandbox starts there whatever this setting is, and " + microVMs
	return c
}

// dockerDesktopSharing are the directories Docker Desktop for Mac shares
// with its VM by default; its settings store names them only once they are
// changed.
var dockerDesktopSharing = []string{"/Users", "/Volumes", "/private", "/tmp", "/var/folders"}

// vmFileSharingCheck is the Docker file sharing check of a gateway on the
// MicroVM driver. Its sandboxes mount no host folders, but the hook-fire
// probe that checks every image built for them runs the harness in a
// Docker container with a MicroVM's /etc/hosts and /etc/resolv.conf,
// which it mounts from the system temp directory (image.Builder.TempDir):
// Docker Desktop shares it by default (/var/folders, the user's $TMPDIR,
// and /tmp). Unshared, every image stays unchecked for a MicroVM, which
// the gateway then refuses to boot.
func (r *doctorRun) vmFileSharingCheck() Check {
	c := Check{ID: CheckIDDockerFileSharing, Title: checkTitles[CheckIDDockerFileSharing]}
	tmp := filepath.Clean(r.TempDir())
	what := " (the hook-fire probe of an image build mounts a MicroVM's /etc/hosts from there; sandboxes mount nothing)"
	switch {
	case !r.docker:
		c.Status, c.Detail = StatusSkip, "the Docker daemon is not available"
		return c
	case !r.desktop:
		c.Status, c.Detail = StatusSkip, "bind mounts come straight from the host filesystem"
		return c
	}
	dd, err := r.DockerDesktop()
	shared := dockerDesktopSharing
	switch {
	case err != nil || dd == nil:
		c.Status, c.Detail = StatusWarn, "could not read the Docker Desktop settings"
		if err != nil {
			c.Detail += ": " + err.Error()
		}
		c.Fix = &Fix{Summary: "make sure " + tmp + " is under a shared directory (Docker Desktop → Settings → Resources → File sharing)"}
		return c
	case dd.FileSharing != nil:
		shared = dd.FileSharing
	}
	resolved, _ := filepath.EvalSymlinks(tmp)
	if sharedDir(shared, tmp) || (resolved != "" && sharedDir(shared, resolved)) {
		c.Status, c.Detail = StatusPass, tmp+" is shared with Docker Desktop"+what
		return c
	}
	c.Status = StatusFail
	c.Detail = tmp + " is not shared with Docker Desktop, so the hook-fire probe cannot run an image with a MicroVM's name resolution and the gateway refuses every image" + what
	c.Fix = &Fix{Summary: "add " + tmp + " in Docker Desktop → Settings → Resources → File sharing (it is shared by default: /var/folders and /tmp)"}
	return c
}

// microVMHost finds what the MicroVM driver needs on this Mac.
func (r *doctorRun) microVMHost(ctx context.Context) *MicroVMHost {
	m := &MicroVMHost{Identity: VMIdentity{UID: int64(r.Geteuid()), GID: int64(r.Getegid())},
		Recommended: RecommendedVMResources(r.HostMemory()).Within(r.MaxCPUMillis, r.MaxMemoryBytes)}
	m.E2fsprogs = e2fsprogsIn(r.E2fsprogsDirs)
	if prefix := r.brewPrefix(); driverSkipsHomebrew(prefix, r.E2fsprogsDirs) {
		m.OwnBrewPrefix = prefix
	}
	if m.E2fsprogs == "" {
		mke2fs, err1 := r.LookPath("mke2fs")
		_, err2 := r.LookPath("debugfs")
		if err1 == nil && err2 == nil {
			m.OnPath = filepath.Dir(mke2fs)
		}
	}
	m.DriverRunning = r.running.Name == DriverVM
	m.DriverBinary = r.findVMDriver(ctx)
	m.DriverFromFormula = r.inFormulaKeg(m.DriverBinary)
	if m.DriverBinary != "" {
		out, err := r.Runner.Output(ctx, Command{Name: "codesign", Args: []string{"-d", "--entitlements", "-", m.DriverBinary}, Timeout: 30 * time.Second})
		switch {
		case errors.Is(err, exec.ErrNotFound):
			m.SignatureUnknown = "codesign is not available: " + err.Error()
		default:
			// An unsigned binary fails with "code object is not signed at
			// all": that is an answer too.
			m.HypervisorSigned = hasEntitlement(string(out), hypervisorEntitlement)
		}
	}
	return m
}

// e2fsprogsIn is the first of dirs holding e2fsprogs' mke2fs (or its
// mkfs.ext4 name) and debugfs.
func e2fsprogsIn(dirs []string) string {
	for _, dir := range dirs {
		if (executable(filepath.Join(dir, "mke2fs")) || executable(filepath.Join(dir, "mkfs.ext4"))) && executable(filepath.Join(dir, "debugfs")) {
			return dir
		}
	}
	return ""
}

func executable(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// findVMDriver is the openshell-driver-vm the gateway starts: the one in
// [openshell.drivers.vm] driver_dir, else the formula's (libexec, else
// bin, of the keg under the Homebrew prefix), else one in the directories
// the gateway itself searches (~/.local/libexec/openshell,
// /usr/libexec/openshell, /usr/local/libexec/openshell,
// /usr/local/libexec), else the one next to the openshell-gateway on PATH
// (in its directory or the libexec beside it, as OpenShell's release
// archives lay them out). A gateway that runs the driver from anywhere
// else names it through its running process.
func (r *doctorRun) findVMDriver(ctx context.Context) string {
	var dirs []string
	if r.config != nil && filepath.IsAbs(r.config.VM.DriverDir) {
		dirs = append(dirs, r.config.VM.DriverDir)
	}
	if prefix := r.Gateway.BrewPrefix; prefix != "" {
		keg := filepath.Join(prefix, "opt", path.Base(GatewayFormula))
		dirs = append(dirs, filepath.Join(keg, "libexec"), filepath.Join(keg, "bin"))
	}
	if home, err := r.HomeDir(); err == nil && filepath.IsAbs(home) {
		dirs = append(dirs, filepath.Join(home, ".local", "libexec", "openshell"))
	}
	dirs = append(dirs, "/usr/libexec/openshell", "/usr/local/libexec/openshell", "/usr/local/libexec")
	if gw, err := r.LookPath(GatewayBinary); err == nil && filepath.IsAbs(gw) {
		bins := []string{filepath.Dir(gw)}
		if real, err := filepath.EvalSymlinks(gw); err == nil && filepath.Dir(real) != bins[0] {
			bins = append(bins, filepath.Dir(real))
		}
		for _, bin := range bins {
			dirs = append(dirs, bin, filepath.Join(filepath.Dir(bin), "libexec"))
		}
	}
	for _, dir := range dirs {
		if p := filepath.Join(dir, vmDriverBinary); executable(p) {
			return p
		}
	}
	if r.running.Name != DriverVM || r.GOOS != "darwin" {
		return ""
	}
	parent := 0
	if gw := r.gatewayProcess(ctx); gw != nil {
		parent = gw.pid
	}
	p := findProcess(r.processes(ctx), vmDriverBinary, parent)
	if p == nil && parent != 0 {
		p = findProcess(r.processes(ctx), vmDriverBinary, 0)
	}
	if p != nil && executable(p.path) {
		return p.path
	}
	return ""
}

// VMDriverSigningFix is what to do about a MicroVM driver outside the
// Homebrew formula that is not signed for Apple's Hypervisor: the
// formula's post-install step signs only its own.
func VMDriverSigningFix(driver string) string {
	return "sign " + driver + " with the " + hypervisorEntitlement + " entitlement (codesign), or install OpenShell from its " +
		GatewayFormula + " Homebrew formula, which signs its own driver"
}

// inFormulaKeg reports whether p lies in the nvidia/openshell/openshell
// formula's keg under the Homebrew prefix (opt/openshell, or the Cellar
// directory it links to).
func (r *doctorRun) inFormulaKeg(p string) bool {
	prefix := r.Gateway.BrewPrefix
	if p == "" || prefix == "" {
		return false
	}
	name := path.Base(GatewayFormula)
	var roots []string
	for _, root := range []string{filepath.Join(prefix, "opt", name), filepath.Join(prefix, "Cellar", name)} {
		roots = append(roots, root)
		if real, err := filepath.EvalSymlinks(root); err == nil {
			roots = append(roots, real)
		}
	}
	paths := []string{p}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		paths = append(paths, real)
	}
	for _, p := range paths {
		for _, root := range roots {
			if rel, err := filepath.Rel(root, p); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// hasEntitlement reports whether `codesign -d --entitlements -` output
// grants key, in the "[Key] ... [Bool] true" form or as a plist.
func hasEntitlement(out, key string) bool {
	i := strings.Index(out, key)
	if i < 0 {
		return false
	}
	rest := out[i+len(key):]
	if j := strings.IndexAny(rest, "[<"); j >= 0 {
		// The value follows the key: skip the key's own closing tag.
		rest = strings.TrimPrefix(rest[j:], "</key>")
	}
	for _, next := range []string{"[Key]", "<key>"} {
		if j := strings.Index(rest, next); j >= 0 {
			rest = rest[:j]
		}
	}
	return strings.Contains(rest, "true")
}

// vmDriverCheck checks what the MicroVM driver needs on this Mac:
// e2fsprogs where it looks, its binary signed for Apple's Hypervisor,
// and harness images for this Mac's architecture.
func (r *doctorRun) vmDriverCheck(ctx context.Context) Check {
	c := Check{ID: CheckIDVMDriver, Title: "MicroVM driver"}
	m := r.micro
	var warnings []string
	if m.E2fsprogs == "" && m.OnPath != "" {
		warnings = append(warnings, "mke2fs and debugfs are only on your PATH ("+m.OnPath+"); the driver runs under launchd, whose PATH may not have them")
	}
	if m.SignatureUnknown != "" {
		warnings = append(warnings, "could not check the signature of "+m.DriverBinary+": "+m.SignatureUnknown)
	}
	if foreign := r.foreignImages(ctx); len(foreign) > 0 {
		// The driver pulls from a registry what it does not find locally
		// for this Mac, and DefenseClaw's image names never resolve there.
		warnings = append(warnings, "harness images built for another architecture than arm64 cannot boot: "+strings.Join(foreign, ", "))
	}
	problems := m.Problems()
	var cmds []string
	var steps []func(context.Context) error
	if m.E2fsprogs == "" && m.OwnBrewPrefix == "" {
		cmds, steps = append(cmds, InstallE2fsprogsCommand), append(steps, func(ctx context.Context) error { return brewTerminal(ctx, r.Runner, "install", "e2fsprogs") })
	}
	// The formula's post-install step signs the formula's driver only.
	unsigned := m.DriverBinary != "" && !m.HypervisorSigned && m.SignatureUnknown == ""
	if unsigned && m.DriverFromFormula {
		cmds, steps = append(cmds, ResignVMDriverCommand), append(steps, func(ctx context.Context) error { return brew(ctx, r.Runner, "postinstall", GatewayFormula) })
	}
	switch {
	case len(problems) > 0:
		c.Status, c.Detail = StatusFail, strings.Join(append(problems, warnings...), "; ")
	case len(warnings) > 0:
		c.Status, c.Detail = StatusWarn, strings.Join(warnings, "; ")
	case m.DriverBinary == "":
		// The gateway runs it: it is installed and starts.
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("e2fsprogs in %s; the gateway runs %s (DefenseClaw did not find where, to check its signature)", m.E2fsprogs, vmDriverBinary)
	default:
		c.Status = StatusPass
		c.Detail = fmt.Sprintf("e2fsprogs in %s; %s signed for Apple's Hypervisor", m.E2fsprogs, m.DriverBinary)
	}
	switch {
	case len(steps) > 0:
		c.Fix = &Fix{Summary: "install what the MicroVM driver needs with Homebrew", Command: strings.Join(cmds, " && "), Automatic: true,
			Apply: func(ctx context.Context) error {
				for _, step := range steps {
					if err := step(ctx); err != nil {
						return err
					}
				}
				return nil
			}}
	case m.E2fsprogs == "" && m.OwnBrewPrefix != "":
		c.Fix = &Fix{Summary: E2fsprogsOwnPrefixFix(m.OwnBrewPrefix)}
	case unsigned:
		c.Fix = &Fix{Summary: VMDriverSigningFix(m.DriverBinary)}
	case m.DriverBinary == "" && !m.DriverRunning:
		c.Fix = &Fix{Summary: "install OpenShell from its Homebrew formula", Command: installOpenShellCommand}
	case c.Status == StatusWarn && m.SignatureUnknown == "":
		c.Fix = &Fix{Summary: "build the harness images again on this Mac", Command: "defenseclaw sandbox image build --force"}
	}
	return c
}

// foreignImages are the local harness images built for another
// architecture than arm64, the only one the MicroVM driver boots on a
// Mac. An image that cannot be inspected is left to the images check.
func (r *doctorRun) foreignImages(ctx context.Context) []string {
	if !r.docker {
		return nil
	}
	var out []string
	for _, img := range r.ProbeImages {
		if img == "" {
			continue
		}
		arch, err := r.Runner.Output(ctx, Command{Name: "docker", Args: []string{"image", "inspect", "--format", "{{.Architecture}}", img}, Timeout: 30 * time.Second})
		if a := strings.TrimSpace(string(arch)); err == nil && a != "" && a != "arm64" {
			out = append(out, img+" ("+a+")")
		}
	}
	return out
}

// brewTerminal runs a Homebrew command the user consented to attached to
// the terminal, so that a long install shows Homebrew's own progress (a
// Homebrew without bottles for its prefix builds from source for many
// minutes, and captured output left the user looking at one line).
func brewTerminal(ctx context.Context, run Runner, args ...string) error {
	if err := run.Run(ctx, Command{Name: "brew", Args: args}); err != nil {
		return fmt.Errorf("brew %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// brew runs a Homebrew command the user consented to.
func brew(ctx context.Context, run Runner, args ...string) error {
	if out, err := run.Output(ctx, Command{Name: "brew", Args: args, Timeout: 30 * time.Minute}); err != nil {
		return fmt.Errorf("brew %s: %v: %s", strings.Join(args, " "), err, lastLine(out))
	}
	return nil
}

// vmConfig is the MicroVM driver's configuration (zero when the gateway
// configuration cannot be read).
func (r *doctorRun) vmConfig() VMConfig {
	if r.config == nil {
		return VMConfig{}
	}
	return r.config.VM
}

// vmIdentityCheck checks that the driver runs sandboxes as this user,
// whom DefenseClaw's images are built for: the driver's default,
// 1000:1000, leaves HOME unwritable and the hooks unable to run.
func (r *doctorRun) vmIdentityCheck(ctx context.Context) Check {
	c := Check{ID: CheckIDVMIdentity, Title: "MicroVM sandbox user"}
	if r.config == nil {
		c.Status, c.Detail = StatusSkip, "gateway configuration unreadable"
		return c
	}
	have, want := r.vmConfig().Identity(), r.micro.Identity
	switch {
	case have != want:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("the MicroVM driver would run sandboxes as %s; DefenseClaw's images are built for %s", have, want)
		c.Fix = r.gatewayChangeFix(fmt.Sprintf("set sandbox_uid = %d and sandbox_gid = %d under [openshell.drivers.vm] in %s", want.UID, want.GID, r.config.TOMLPath),
			"(gateway-wide: every MicroVM sandbox on it then runs as you)", r.applyGateway(GatewayChanges{VMIdentity: &want}))
	case r.nothingToRestart():
		// No gateway runs, to restart or to have loaded it: the one
		// OpenShell's install starts does.
		c.Status, c.Detail = StatusPass, fmt.Sprintf("sandboxes run as %s, your user, once the gateway is installed and started (set in %s)", want, r.config.TOMLPath)
	case r.restartPending(ctx, r.config):
		c.Status, c.Detail = StatusWarn, fmt.Sprintf("%s in %s, but the gateway has not been restarted since it changed", want, r.config.TOMLPath)
		if r.gatewayStartedAt(ctx).IsZero() {
			// No start time known: DefenseClaw's mark says only that no
			// restart of its own followed its change.
			c.Detail = fmt.Sprintf("%s in %s; restart the gateway if you have not since it changed", want, r.config.TOMLPath)
		}
		c.Fix = r.gatewayChangeFix("", "to load its changed configuration", nil)
	case r.startUnknown(ctx):
		c.Status, c.Detail = StatusWarn, fmt.Sprintf("%s in %s, %s", want, r.config.TOMLPath, restartUnknown)
		c.Fix = r.gatewayChangeFix("", "if you have not since it changed", nil)
	default:
		c.Status, c.Detail = StatusPass, fmt.Sprintf("sandboxes run as %s, your user", want)
	}
	return c
}

// vmResourcesCheck shows what every MicroVM gets. The driver cannot
// limit one sandbox, so an organization's openshell.admin.max_resources
// is judged against these gateway-wide values: above it, every create is
// refused.
func (r *doctorRun) vmResourcesCheck() Check {
	c := Check{ID: CheckIDVMResources, Title: "MicroVM resources"}
	if r.config == nil {
		c.Status, c.Detail = StatusSkip, "gateway configuration unreadable"
		return c
	}
	have := r.vmConfig().Resources()
	c.Detail = fmt.Sprintf("every MicroVM gets %d vCPUs, %d MiB of memory and a %d MiB disk for its changes", have.VCPUs, have.MemMiB, have.OverlayDiskMiB)
	maxCPUs := r.MaxCPUMillis / 1000
	maxMiB := r.MaxMemoryBytes >> 20
	cpuOver := r.MaxCPUMillis > 0 && have.VCPUs*1000 > r.MaxCPUMillis
	memOver := r.MaxMemoryBytes > 0 && have.MemMiB > maxMiB
	switch {
	case (cpuOver && maxCPUs < 1) || (memOver && maxMiB < 1):
		c.Status = StatusFail
		c.Detail += "; your organization's openshell.admin.max_resources is below what any MicroVM gets, so every create is refused"
		c.Fix = &Fix{Summary: "ask your administrator to allow at least 1 CPU and the memory of one MicroVM in openshell.admin.max_resources"}
	case cpuOver || memOver:
		lower := VMResources{}
		if cpuOver {
			lower.VCPUs = maxCPUs
		}
		if memOver {
			lower.MemMiB = maxMiB
		}
		c.Status = StatusFail
		c.Detail += "; your organization's openshell.admin.max_resources allows less, so every create is refused"
		c.Fix = r.gatewayChangeFix("lower vcpus and mem_mib under [openshell.drivers.vm] in "+r.config.TOMLPath+" to the maximum", "",
			r.applyGateway(GatewayChanges{VMResources: &lower}))
	default:
		want := r.micro.Recommended
		raise := VMResources{}
		if have.MemMiB < want.MemMiB {
			raise.MemMiB = want.MemMiB
		}
		if have.OverlayDiskMiB < 8192 {
			raise.OverlayDiskMiB = want.OverlayDiskMiB
		}
		if raise == (VMResources{}) {
			c.Status = StatusPass
			break
		}
		c.Status = StatusWarn
		c.Detail += "; an agent that builds code may need more"
		c.Fix = r.gatewayChangeFix("raise them under [openshell.drivers.vm] in "+r.config.TOMLPath, "(the disk is sparse on the host: it costs nothing until used)",
			r.applyGateway(GatewayChanges{VMResources: &raise}))
	}
	return c
}

// vmStateDir is the MicroVM driver's state directory, which holds its
// prepared images.
func (r *doctorRun) vmStateDir() string {
	home, err := r.HomeDir()
	if err != nil {
		home = ""
	}
	return VMStateDir(r.vmConfig().StateDir, home)
}

// pruneCommand removes DefenseClaw's superseded harness images, and the
// MicroVM disks prepared from them.
const pruneCommand = "defenseclaw sandbox image prune"

// vmDiskCheck measures the free space where the MicroVM driver keeps its
// prepared images, and what they take: OpenShell's cache, which it keeps
// after the sandboxes go. `sandbox image prune`, `image rm` and teardown
// remove the disks of the images they remove, and nothing else of it.
func (r *doctorRun) vmDiskCheck() Check {
	c := Check{ID: CheckIDDisk, Title: checkTitles[CheckIDDisk]}
	dir := r.vmStateDir()
	if dir == "" {
		c.Status, c.Detail = StatusWarn, "the MicroVM driver's state directory is unknown (no home directory)"
		return c
	}
	free, err := FreeUnder(r.DiskFree, dir)
	if err != nil {
		c.Status, c.Detail = StatusWarn, fmt.Sprintf("could not measure free space under %s: %v", dir, err)
		return c
	}
	c.Detail = fmt.Sprintf("%s free under %s", humanBytes(free), dir)
	if n, size := preparedDisks(filepath.Join(dir, "images")); n > 0 {
		c.Detail += fmt.Sprintf("; OpenShell keeps %s there (%s), and `%s` removes those of the images it removes",
			plural(n, "MicroVM disk prepared from an image", "MicroVM disks prepared from images"), humanBytes(size), pruneCommand)
	}
	fix := &Fix{Summary: "free space on this volume: the first start of each harness image prepares a MicroVM disk of about 5 GB in " + dir +
		"; prune removes DefenseClaw's superseded harness images and the MicroVM disks prepared from them " +
		"(a backup or indexing app that holds a removed file open keeps its space until it lets go: `lsof +L1` lists them)",
		Command: pruneCommand}
	switch {
	case free < VMDiskFailBytes:
		c.Status, c.Fix = StatusFail, fix
		c.Detail += fmt.Sprintf("; MicroVM sandboxes need at least %s", humanBytes(VMDiskFailBytes))
	case free < VMDiskWarnBytes:
		c.Status, c.Fix = StatusWarn, fix
		c.Detail += fmt.Sprintf("; %s or more is recommended", humanBytes(VMDiskWarnBytes))
	default:
		c.Status = StatusPass
	}
	return c
}

// PreparedDiskPrefix starts the name of each directory under the MicroVM
// driver's image cache (<state_dir>/images) that holds a root disk it
// prepared from an image. OpenShell 0.1.1 names them
// sandbox-prepared-rootfs-ext4-umoci-v3-openshell-0.1.1-configured-501-20-sha256-<image ID>
// on a gateway that sets sandbox_uid and sandbox_gid, and
// ...-image-account-sha256-<image ID> on one that does not. The cache holds
// the driver's own state next to them (overlay-templates, the
// sandbox-bootstrap-rootfs-* it boots every MicroVM with, .staging
// directories of a preparation under way), which is not a prepared disk.
const PreparedDiskPrefix = "sandbox-prepared-rootfs-"

// preparedDisks counts the root disks the driver prepared from images under
// dir (PreparedDiskPrefix) and the disk they take (allocated, not their
// larger sparse size).
func preparedDisks(dir string) (n int, size uint64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), PreparedDiskPrefix) || strings.Contains(e.Name(), ".staging") {
			continue
		}
		n++
		_ = filepath.WalkDir(filepath.Join(dir, e.Name()), func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				size += allocatedBytes(info)
			}
			return nil
		})
	}
	return n, size
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// microVMChanges are what a switch to MicroVMs writes: the driver, this
// user as every sandbox's, and the recommended resources where the
// configuration leaves them unset.
func (r *doctorRun) microVMChanges() GatewayChanges {
	ch := GatewayChanges{ComputeDriver: DriverVM}
	if m := r.micro; m != nil {
		id := m.Identity
		ch.VMIdentity = &id
		if res := r.vmConfig().Unset(m.Recommended); res != (VMResources{}) {
			ch.VMResources = &res
		}
	}
	return ch
}

// microVMFix switches the gateway to the MicroVM driver.
func (r *doctorRun) microVMFix() *Fix {
	where := "gateway.toml"
	if r.config != nil {
		where = r.config.TOMLPath
	}
	fix := r.gatewayChangeFix(`run sandboxes in OpenShell MicroVMs: set compute_driver = "vm" and your user as the sandboxes' in `+where,
		"(sandboxes made on the docker driver cannot start after the switch)", r.applyGateway(r.microVMChanges()))
	if fix.Automatic {
		fix.Command = "defenseclaw sandbox setup"
	}
	return fix
}
