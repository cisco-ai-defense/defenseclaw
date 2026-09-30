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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Landlock probe errors.
var (
	// ErrLandlockMissing means the kernel has no Landlock support.
	ErrLandlockMissing = errors.New("openshell: the kernel does not support Landlock")
	// ErrLandlockDisabled means Landlock is built in but not enabled.
	ErrLandlockDisabled = errors.New("openshell: Landlock is disabled on this kernel")
)

// Host requirements doctor enforces.
const (
	// MinLandlockABI is the oldest Landlock ABI OpenShell's
	// hard_requirement mode accepts (ABI 3, Linux 6.2, adds truncate).
	MinLandlockABI = 3
	// MinDockerMajor is the oldest Docker Engine major release.
	MinDockerMajor = 28
	// DiskFailBytes and DiskWarnBytes bound the free space under the
	// Docker root: the community base image alone is about 4 GB and the
	// first overlay build adds about 3 GB.
	DiskFailBytes = 5 << 30
	DiskWarnBytes = 10 << 30
)

// Doctor check IDs. Port checks are CheckIDPortPrefix + PortRequirement.Name.
const (
	CheckIDPlatform          = "platform"
	CheckIDUser              = "user"
	CheckIDLandlock          = "landlock"
	CheckIDDocker            = "docker"
	CheckIDDockerBuildKit    = "docker-buildkit"
	CheckIDDockerHostNetwork = "docker-host-network"
	CheckIDDockerFileSharing = "docker-file-sharing"
	CheckIDVMDriver          = "vm-driver"
	CheckIDVMIdentity        = "vm-identity"
	CheckIDVMResources       = "vm-resources"
	CheckIDDisk              = "disk"
	CheckIDLinger            = "linger"
	CheckIDGatewayService    = "gateway-service"
	CheckIDCLI               = "openshell-cli"
	CheckIDSSHSharing        = "ssh-connection-sharing"
	CheckIDRegistration      = "gateway-registration"
	CheckIDMTLS              = "mtls-permissions"
	CheckIDGatewayVersion    = "gateway-version"
	CheckIDGatewayDriver     = "gateway-driver"
	CheckIDGlobalPolicy      = "global-policy"
	CheckIDBindMounts        = "bind-mounts"
	CheckIDTelemetry         = "telemetry"
	CheckIDPortPrefix        = "port-"
	installOpenShellCommand  = "defenseclaw sandbox setup --install-openshell"
	setupCommand             = "defenseclaw sandbox setup"
)

// CheckStatus is a doctor verdict.
type CheckStatus string

// Check verdicts. Fail blocks sandboxes; warn degrades them or needs
// attention; skip means the check does not apply or could not run
// because an earlier check failed.
const (
	StatusPass CheckStatus = "pass"
	StatusWarn CheckStatus = "warn"
	StatusFail CheckStatus = "fail"
	StatusSkip CheckStatus = "skip"
)

// Fix is the remedy for a failing or warning check.
type Fix struct {
	Summary string `json:"summary"`
	// Command is a copy-pasteable shell command, when one exists.
	Command string `json:"command,omitempty"`
	// Sudo marks commands that need administrator rights. Doctor never
	// runs them itself.
	Sudo bool `json:"sudo,omitempty"`
	// Automatic reports whether Apply is available.
	Automatic bool `json:"automatic"`
	// RestartsGateway marks an Apply that restarts the OpenShell gateway,
	// which stops every sandbox running on it (their disks flushed first
	// where the driver's stop would not keep what they wrote).
	RestartsGateway bool `json:"restarts_gateway,omitempty"`
	// Apply performs the fix as the current user; nil when the operator
	// must act. Callers ask for consent first (ApplyFixes does).
	Apply func(ctx context.Context) error `json:"-"`
}

// Check is one doctor finding.
type Check struct {
	ID     string      `json:"id"`
	Title  string      `json:"title"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    *Fix        `json:"fix,omitempty"`
}

// DoctorReport is the result of Doctor.Run.
type DoctorReport struct {
	Checks []Check `json:"checks"`
	// Facts gathered on the way, for display.
	Registration *Registration `json:"registration,omitempty"`
	CLIVersion   string        `json:"cli_version,omitempty"`
	// CLIPath is the openshell the CLI check found on PATH.
	CLIPath        string `json:"cli_path,omitempty"`
	GatewayVersion string `json:"gateway_version,omitempty"`
	DockerVersion  string `json:"docker_version,omitempty"`
	DockerRootDir  string `json:"docker_root_dir,omitempty"`
	// Service is the gateway service as its manager reports it.
	Service *ServiceState `json:"service,omitempty"`
	// Driver is the compute driver sandboxes run on: the one the gateway
	// reports when it answers, else ConfiguredDriver. ConfiguredDriver is
	// the one the gateway's configuration selects (docker when it names
	// none); when the two differ, the gateway has not been restarted on
	// its configuration.
	Driver           ComputeDriver `json:"driver,omitempty"`
	ConfiguredDriver ComputeDriver `json:"configured_driver,omitempty"`
	// MicroVM is what OpenShell's MicroVM driver needs on this Mac (nil
	// off macOS).
	MicroVM *MicroVMHost `json:"microvm,omitempty"`
}

// OK reports whether no check failed.
func (r *DoctorReport) OK() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

// OpenShellOutsideFormula reports a Mac whose OpenShell CLI was installed
// another way than the Homebrew formula DefenseClaw runs the gateway
// through (from the release binaries, say): see GatewayUnmanaged.
func (r *DoctorReport) OpenShellOutsideFormula() bool {
	cli := r.Get(CheckIDCLI)
	return cli != nil && cli.Status != StatusFail && r.Service != nil && r.Service.Manager == "brew" && !r.Service.Installed
}

// OpenShellOutsideUnit reports a Linux host whose supported OpenShell CLI
// came without the openshell-gateway user unit DefenseClaw starts and
// restarts the gateway through: it was installed another way than NVIDIA's
// installer (from the release binaries, say). See GatewayUnmanaged.
func (r *DoctorReport) OpenShellOutsideUnit() bool {
	cli := r.Get(CheckIDCLI)
	return cli != nil && cli.Status != StatusFail && r.Service != nil && r.Service.Manager == "systemd" && !r.Service.Installed
}

// GatewayUnmanaged reports an OpenShell installed another way than the one
// whose service DefenseClaw starts and restarts the gateway through
// (OpenShellOutsideFormula on a Mac, OpenShellOutsideUnit on Linux): its
// gateway runs by hand, or under something of the user's. DefenseClaw uses
// that gateway while it answers, but cannot start or restart it: setup
// writes a gateway change for its operator to restart the gateway on, and
// stops only where it would have to start it. installOpenShellCommand
// alone does not bring the service: DefenseClaw's install step finds the
// supported CLI and does not run NVIDIA's installer.
func (r *DoctorReport) GatewayUnmanaged() bool {
	return r.OpenShellOutsideFormula() || r.OpenShellOutsideUnit()
}

// OpenShellInstallNeeded reports whether DefenseClaw's install step
// (Installer.Install) would run NVIDIA's installer on this host: no
// OpenShell CLI, one whose release it cannot read, or one older than
// SupportedMin, which it upgrades. Over a supported CLI it installs
// nothing, and one newer than supported it refuses, so there every other
// failing check (the gateway, its service, the MicroVM driver) is its
// fix's, not the install's. Setup offers the install only then, and the
// TUI presets it only then (`sandbox doctor --json` reports it as
// openshell_install).
func (r *DoctorReport) OpenShellInstallNeeded() bool {
	cli := r.Get(CheckIDCLI)
	switch {
	case cli == nil:
		return true
	case cli.Status != StatusFail:
		return false
	case r.CLIVersion == "":
		return true
	}
	v, err := ParseVersion(r.CLIVersion)
	return err != nil || v.Compare(mustParse(SupportedBelow)) < 0
}

// Get returns the check with id, or nil.
func (r *DoctorReport) Get(id string) *Check {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			return &r.Checks[i]
		}
	}
	return nil
}

// String renders the report as a table with fixes underneath.
func (r *DoctorReport) String() string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, c := range r.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.ToUpper(string(c.Status)), c.Title, c.Detail)
	}
	_ = tw.Flush()
	for _, c := range r.Checks {
		if c.Fix == nil || c.Status == StatusPass || c.Status == StatusSkip {
			continue
		}
		fmt.Fprintf(&b, "fix %s: %s", c.ID, c.Fix.Summary)
		if c.Fix.Command != "" {
			fmt.Fprintf(&b, "\n    %s", c.Fix.Command)
		}
		if c.Fix.Automatic {
			b.WriteString("\n    (doctor --fix can do this)")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// FixOutcome reports one ApplyFixes attempt. Title is the check's, which
// the consent question names it by.
type FixOutcome struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

// ApplyFixes runs the automatic fixes of failing and warning checks, in
// report order, each after consent. A declined fix is skipped; a failed
// one is reported and the rest still run. Re-run Doctor afterwards.
func (r *DoctorReport) ApplyFixes(ctx context.Context, consent func(Check) (bool, error)) ([]FixOutcome, error) {
	var out []FixOutcome
	for _, c := range r.Checks {
		if c.Fix == nil || c.Fix.Apply == nil || c.Status == StatusPass || c.Status == StatusSkip {
			continue
		}
		ok, err := consent(c)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		o := FixOutcome{ID: c.ID, Title: c.Title}
		if err := c.Fix.Apply(ctx); err != nil {
			o.Error = err.Error()
		} else {
			o.Applied = true
		}
		out = append(out, o)
	}
	return out, nil
}

// PortRequirement is a loopback port DefenseClaw needs for sandboxes.
type PortRequirement struct {
	// Name is "ingress" or "egress".
	Name string
	Port int
	// ServedByDaemon means the running DefenseClaw daemon already listens
	// there, so the port being taken is expected.
	ServedByDaemon bool
}

// DockerDesktop are the Docker Desktop settings doctor reads.
type DockerDesktop struct {
	// HostNetworking is nil when the setting could not be read.
	HostNetworking *bool
	// FileSharing lists shared host directories (nil: unknown).
	FileSharing []string
}

// Doctor diagnoses the host for OpenShell sandboxes. Every probe is a
// field so tests (and callers with better knowledge) can inject it; nil
// fields use the real system.
type Doctor struct {
	GOOS, GOARCH string
	Runner       Runner
	LookPath     func(string) (string, error)
	Discover     DiscoverOptions
	// Dial connects to the discovered gateway.
	Dial func(*Registration) (Client, error)
	// Gateway reads the gateway configuration and service; it defaults to
	// a configurator over Discover.ConfigDir, Runner and GOOS.
	Gateway *GatewayConfigurator
	// CLI is the openshell binary (default DefaultBinary).
	CLI string

	// Ports are checked for availability on 127.0.0.1.
	Ports []PortRequirement
	// DaemonUID is the DefenseClaw daemon's uid when known; the gateway
	// must run as the same user.
	DaemonUID *int
	// WantTelemetry is openshell.upstream_telemetry; nil only reports.
	WantTelemetry *bool
	// BindMountsOptional downgrades disabled bind mounts to a warning
	// (copy-only workdir mode).
	BindMountsOptional bool
	// MaxCPUMillis and MaxMemoryBytes are openshell.admin.max_resources (0:
	// no maximum). The MicroVM driver gives every sandbox the gateway-wide
	// vcpus and mem_mib, which must not exceed them.
	MaxCPUMillis, MaxMemoryBytes int64

	LandlockABI func() (int, error)
	// DockerVMLandlockABI asks, off Linux, the kernel of the VM Docker runs
	// containers in for its Landlock ABI and release (dockerVMLandlock by
	// default); ErrNoProbeImage when no image to ask in is local.
	DockerVMLandlockABI func(ctx context.Context) (abi int, kernel string, err error)
	// ProbeImages are local images DockerVMLandlockABI may run in after
	// DefaultBaseImage (the overlay images DefenseClaw built on it). On
	// the MicroVM driver their architecture is checked too.
	ProbeImages []string
	// E2fsprogsDirs are where the MicroVM driver looks for e2fsprogs'
	// mke2fs and debugfs, which Homebrew installs keg-only, off PATH
	// (default the kegs the driver knows).
	E2fsprogsDirs []string
	// HostMemory is this machine's memory in bytes (0: unknown), which
	// the recommended MicroVM memory is sized from.
	HostMemory func() uint64
	DiskFree   func(path string) (uint64, error)
	Listen     func(network, address string) (net.Listener, error)
	Geteuid    func() int
	// Getegid is the user's group, which with Geteuid the MicroVM driver
	// must run sandboxes as (DefenseClaw's images are built for them).
	Getegid       func() int
	Username      func() (string, error)
	HomeDir       func() (string, error)
	DockerDesktop func() (*DockerDesktop, error)
	// TempDir is the system temp directory (default os.TempDir), where
	// the hook-fire probe of an image build writes what it mounts into its
	// containers (image.Builder.TempDir).
	TempDir func() string
	// DockerGroup reports whether the user belongs to the docker group
	// and whether this session already carries that membership.
	DockerGroup func() (member, inSession bool, err error)
	// SSHShim makes the ssh the OpenShell CLI runs with (NewSSHShim over
	// PATH by default); the check removes it afterwards.
	SSHShim func() (*SSHShim, error)
	// Getenv reads the environment docker runs in (DOCKER_BUILDKIT).
	Getenv func(string) string
}

func (d *Doctor) defaults() {
	if d.GOOS == "" {
		d.GOOS = runtime.GOOS
	}
	if d.GOARCH == "" {
		d.GOARCH = runtime.GOARCH
	}
	if d.Runner == nil {
		d.Runner = ExecRunner{}
	}
	if d.LookPath == nil {
		d.LookPath = exec.LookPath
	}
	if d.Dial == nil {
		d.Dial = func(reg *Registration) (Client, error) { return Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second}) }
	}
	if d.CLI == "" {
		d.CLI = DefaultBinary
	}
	if d.Gateway == nil {
		d.Gateway = &GatewayConfigurator{Dir: d.Discover.ConfigDir, Runner: d.Runner, GOOS: d.GOOS, Discover: d.Discover, CLI: d.CLI, LookPath: d.LookPath}
	}
	if d.LandlockABI == nil {
		d.LandlockABI = landlockABI
	}
	if d.DockerVMLandlockABI == nil {
		d.DockerVMLandlockABI = func(ctx context.Context) (int, string, error) {
			return dockerVMLandlock(ctx, d.Runner, append([]string{DefaultBaseImage}, d.ProbeImages...))
		}
	}
	if d.E2fsprogsDirs == nil {
		d.E2fsprogsDirs = e2fsprogsDirs
	}
	if d.HostMemory == nil {
		d.HostMemory = hostMemory
	}
	if d.DiskFree == nil {
		d.DiskFree = diskFree
	}
	if d.Listen == nil {
		d.Listen = net.Listen
	}
	if d.Geteuid == nil {
		d.Geteuid = os.Geteuid
	}
	if d.Getegid == nil {
		d.Getegid = os.Getegid
	}
	if d.Username == nil {
		d.Username = func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		}
	}
	if d.HomeDir == nil {
		d.HomeDir = os.UserHomeDir
	}
	if d.DockerDesktop == nil {
		d.DockerDesktop = func() (*DockerDesktop, error) { return readDockerDesktop(d.GOOS, d.HomeDir) }
	}
	if d.TempDir == nil {
		d.TempDir = os.TempDir
	}
	if d.DockerGroup == nil {
		d.DockerGroup = dockerGroupMembership
	}
	if d.SSHShim == nil {
		d.SSHShim = func() (*SSHShim, error) { return NewSSHShim(os.Getenv("PATH")) }
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
}

// doctorRun carries facts between checks.
type doctorRun struct {
	*Doctor
	report  *DoctorReport
	desktop bool
	docker  bool
	reg     *Registration
	regErr  error
	client  Client
	cli     Version
	gateway *GatewayHealth
	service *ServiceState

	// config is the gateway configuration read up front (nil when it
	// cannot be read; checkGatewayConfig says why), configured the compute
	// driver it selects.
	config     *GatewayConfigState
	configured ComputeDriver
	// running is the compute driver the answering gateway reports, once
	// checkGateway has asked (zero Name until then, or when it reports one
	// DefenseClaw does not drive: driverErr).
	running   Driver
	driverErr error
	// Off Linux the machine checks depend on the compute driver: they are
	// made once it is known (macChecks) and inserted at machineAt, after
	// the user check. dockerFound, dockerRoot and buildKit are the Docker
	// checks made on the way; landlock is the Landlock verdict.
	machineAt   int
	machineDone bool
	dockerFound Check
	dockerRoot  string
	buildKit    Check
	landlock    CheckStatus
	micro       *MicroVMHost
	// procs are this user's processes, once a Mac's check has listed them
	// (processes).
	procs     []process
	procsDone bool
	// started is when the running gateway started, once gatewayStartedAt
	// has asked (startedDone).
	started     time.Time
	startedDone bool
	// startedApprox is set when started came from ps (to the second).
	startedApprox bool
}

func (r *doctorRun) add(c Check) { r.report.Checks = append(r.report.Checks, c) }

// driver is the compute driver sandboxes run on: the one the gateway
// reports once checkGateway has asked it, else the configured one.
func (r *doctorRun) driver() ComputeDriver {
	if r.running.Name != "" {
		return r.running.Name
	}
	return r.configured
}

// traits is driver's row of the driver table; known is false for a
// driver DefenseClaw does not drive.
func (r *doctorRun) traits() (d Driver, known bool) { return LookupDriver(string(r.driver())) }

// Run executes every check. It never returns an error: problems are
// checks.
func (d *Doctor) Run(ctx context.Context) *DoctorReport {
	d.defaults()
	r := &doctorRun{Doctor: d, report: &DoctorReport{}, configured: DriverDocker}
	defer func() {
		if r.client != nil {
			_ = r.client.Close()
		}
	}()
	if !r.checkPlatform() {
		return r.report
	}
	if st, err := r.Gateway.Read(); err == nil {
		r.config = st
		if st.ComputeDriver != "" {
			r.configured = st.ComputeDriver
		}
	}
	r.report.ConfiguredDriver, r.report.Driver = r.configured, r.configured
	r.checkUser()
	if r.GOOS == "linux" {
		r.checkLandlock()
		r.checkDocker(ctx)
	} else {
		// Where sandboxes run, and so what the machine needs, is the
		// compute driver's, which an answering gateway names only in
		// checkGateway: those checks keep their place (macChecks).
		r.machineAt = len(r.report.Checks)
		r.dockerFound, r.dockerRoot = r.dockerCheck(ctx)
		r.buildKit = r.buildKitCheck(ctx)
	}
	r.checkLinger(ctx)
	r.checkService(ctx)
	r.checkCLI(ctx)
	r.checkSSHSharing(ctx)
	r.checkRegistration()
	r.checkGateway(ctx)
	r.macChecks(ctx)
	r.unmanagedService(ctx)
	r.stoppedServiceAnswers()
	r.checkGatewayConfig(ctx)
	r.checkPorts()
	r.report.Driver = r.driver()
	return r.report
}

func (r *doctorRun) checkPlatform() bool {
	c := Check{ID: CheckIDPlatform, Title: "Platform", Detail: r.GOOS + "/" + r.GOARCH}
	switch {
	case r.GOOS == "linux" && (r.GOARCH == "amd64" || r.GOARCH == "arm64"):
		c.Status = StatusPass
	case r.GOOS == "darwin" && r.GOARCH == "arm64":
		c.Status = StatusWarn
		c.Detail += ": macOS sandboxes run in OpenShell MicroVMs (the vm driver, experimental upstream)"
	case r.GOOS == "darwin":
		c.Status = StatusFail
		c.Detail += ": the OpenShell MicroVM driver runs on Apple silicon only"
		if translated(r.GOOS, r.GOARCH) {
			c.Detail += "; this is the Intel build of DefenseClaw running under Rosetta: install the arm64 build"
		}
	case r.GOOS == "linux":
		c.Status = StatusFail
		c.Detail += ": OpenShell supports amd64 and arm64 only"
	default:
		c.Status = StatusFail
		c.Detail += ": OpenShell sandboxes run on Linux and macOS only (WSL2 is not supported)"
	}
	r.add(c)
	return r.GOOS == "linux" || r.GOOS == "darwin"
}

func (r *doctorRun) checkUser() {
	c := Check{ID: CheckIDUser, Title: "User", Status: StatusPass}
	uid := r.Geteuid()
	name, _ := r.Username()
	c.Detail = fmt.Sprintf("%s (uid %d)", name, uid)
	switch {
	case uid == 0:
		c.Status = StatusFail
		c.Detail = "running as root: OpenShell's gateway is a per-user service"
		if d, _ := LookupDriver(string(r.configured)); d.HostMounts {
			c.Detail += " and sandboxes mount your files as your uid"
		}
		c.Fix = &Fix{Summary: "run DefenseClaw and OpenShell as your own user, not root or a service account"}
	case r.DaemonUID != nil && *r.DaemonUID != uid:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("the DefenseClaw daemon runs as uid %d but this user is uid %d; it must drive the gateway as the same user", *r.DaemonUID, uid)
		c.Fix = &Fix{Summary: "run the DefenseClaw daemon as the user who owns the OpenShell gateway"}
	}
	r.add(c)
}

// checkLandlock checks the Linux host's own kernel, which sandboxes run on.
func (r *doctorRun) checkLandlock() {
	c := Check{ID: CheckIDLandlock, Title: "Landlock"}
	abi, err := r.LandlockABI()
	switch {
	case errors.Is(err, ErrLandlockDisabled):
		c.Status = StatusFail
		c.Detail = "the kernel has Landlock but it is not enabled"
		c.Fix = &Fix{Summary: "add landlock to the kernel's lsm= boot parameter (e.g. lsm=landlock,lockdown,yama,integrity,apparmor) and reboot", Sudo: true}
	case err != nil:
		c.Status = StatusFail
		c.Detail = "the kernel has no Landlock support: " + err.Error()
		c.Fix = &Fix{Summary: fmt.Sprintf("use a Linux kernel 6.2 or newer with Landlock (ABI %d+)", MinLandlockABI), Sudo: true}
	case abi < MinLandlockABI:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("Landlock ABI %d; OpenShell needs ABI %d or newer", abi, MinLandlockABI)
		c.Fix = &Fix{Summary: "upgrade to a Linux kernel 6.2 or newer", Sudo: true}
	default:
		c.Status, c.Detail = StatusPass, fmt.Sprintf("ABI %d", abi)
	}
	r.add(c)
}

// dockerInfo is the subset of `docker info --format '{{json .}}'` doctor
// reads.
type dockerInfo struct {
	ServerVersion   string   `json:"ServerVersion"`
	DockerRootDir   string   `json:"DockerRootDir"`
	OperatingSystem string   `json:"OperatingSystem"`
	SecurityOptions []string `json:"SecurityOptions"`
	ServerErrors    []string `json:"ServerErrors"`
}

func (r *doctorRun) checkDocker(ctx context.Context) {
	c, root := r.dockerCheck(ctx)
	r.add(c)
	r.add(r.buildKitCheck(ctx))
	hostNet, sharing, disk := r.dockerDriverChecks(root)
	r.add(hostNet)
	r.add(sharing)
	r.add(disk)
}

// dockerDriverChecks are the checks of what the docker driver needs of
// the Docker daemon: host networking, file sharing and disk space under
// its root.
func (r *doctorRun) dockerDriverChecks(root string) (hostNet, sharing, disk Check) {
	if !r.docker {
		skip := func(id string) Check {
			return Check{ID: id, Title: checkTitles[id], Status: StatusSkip, Detail: "the Docker daemon is not available"}
		}
		return skip(CheckIDDockerHostNetwork), skip(CheckIDDockerFileSharing), skip(CheckIDDisk)
	}
	hostNet, sharing = r.dockerDesktopChecks()
	return hostNet, sharing, r.diskCheck(root)
}

// dockerCheck probes the Docker daemon and returns its root directory.
func (r *doctorRun) dockerCheck(ctx context.Context) (Check, string) {
	c := Check{ID: CheckIDDocker, Title: "Docker"}
	installFix := &Fix{Summary: fmt.Sprintf("install Docker Engine %d or newer (Docker Desktop on macOS)", MinDockerMajor), Command: "https://docs.docker.com/engine/install/"}
	if _, err := r.LookPath("docker"); err != nil {
		c.Status, c.Detail, c.Fix = StatusFail, "docker is not installed", installFix
		return c, ""
	}
	out, err := r.Runner.Output(ctx, Command{Name: "docker", Args: []string{"info", "--format", "{{json .}}"}, Timeout: 30 * time.Second})
	var info dockerInfo
	jsonErr := json.Unmarshal(firstJSONLine(out), &info)
	serverErr := strings.Join(info.ServerErrors, "; ")
	if serverErr == "" && err != nil {
		serverErr = strings.TrimSpace(string(out))
		if serverErr == "" {
			serverErr = err.Error()
		}
	}
	if serverErr != "" || jsonErr != nil || info.ServerVersion == "" {
		if serverErr == "" {
			serverErr = "unexpected docker info output"
		}
		c.Status, c.Detail = StatusFail, "the Docker daemon is not reachable: "+serverErr
		c.Fix = r.dockerAccessFix(serverErr)
		return c, ""
	}
	r.docker = true
	r.report.DockerVersion, r.report.DockerRootDir = info.ServerVersion, info.DockerRootDir
	r.desktop = IsDockerDesktop(info.OperatingSystem)
	c.Detail = fmt.Sprintf("Docker %s (%s)", info.ServerVersion, info.OperatingSystem)
	major, _ := strconv.Atoi(strings.SplitN(info.ServerVersion, ".", 2)[0])
	switch {
	case major < MinDockerMajor:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("Docker %s is older than %d", info.ServerVersion, MinDockerMajor)
		c.Fix = installFix
	case slices.Contains(info.SecurityOptions, "name=rootless"):
		c.Status = StatusFail
		c.Detail += ": rootless Docker keeps containers off the host network, so sandboxes cannot reach DefenseClaw"
		c.Fix = &Fix{Summary: "run OpenShell against a rootful Docker Engine (add yourself to the docker group)"}
	default:
		c.Status = StatusPass
	}
	return c, info.DockerRootDir
}

// buildKitCheck checks that `docker build` would use BuildKit, which the
// sandbox image Dockerfiles need (BuildKitProblem).
func (r *doctorRun) buildKitCheck(ctx context.Context) Check {
	c := Check{ID: CheckIDDockerBuildKit, Title: "Docker BuildKit"}
	if !r.docker {
		c.Status, c.Detail = StatusSkip, "the Docker daemon is not available"
		return c
	}
	out, err := r.Runner.Output(ctx, Command{Name: "docker", Args: BuildKitArgs, Timeout: 30 * time.Second})
	if problem, fix := BuildKitProblem(r.GOOS, r.Getenv("DOCKER_BUILDKIT"), out, err); problem != "" {
		c.Status, c.Detail, c.Fix = StatusFail, problem, &Fix{Summary: fix}
		return c
	}
	c.Status, c.Detail = StatusPass, "docker build uses BuildKit"
	if v := BuildKitVersion(out); v != "" {
		c.Detail += " (buildx " + v + ")"
	}
	return c
}

func firstJSONLine(out []byte) []byte {
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "{") {
			return []byte(line)
		}
	}
	return nil
}

func (r *doctorRun) dockerAccessFix(msg string) *Fix {
	if !strings.Contains(strings.ToLower(msg), "permission denied") {
		if r.GOOS == "darwin" {
			return &Fix{Summary: "start Docker Desktop"}
		}
		return &Fix{Summary: "start the Docker daemon", Command: "sudo systemctl enable --now docker", Sudo: true}
	}
	member, inSession, err := r.DockerGroup()
	if err == nil && member && !inSession {
		return &Fix{Summary: "you are in the docker group, but this login session predates it; log out and back in (or run `newgrp docker`)"}
	}
	name, _ := r.Username()
	if name == "" {
		name = "$USER"
	}
	return &Fix{Summary: "add yourself to the docker group, then log out and back in", Command: "sudo usermod -aG docker " + shellQuote(name), Sudo: true}
}

var checkTitles = map[string]string{
	CheckIDDockerHostNetwork: "Docker host networking",
	CheckIDDockerFileSharing: "Docker file sharing",
	CheckIDDisk:              "Disk space",
}

func (r *doctorRun) dockerDesktopChecks() (hostNet, sharing Check) {
	hostNet = Check{ID: CheckIDDockerHostNetwork, Title: checkTitles[CheckIDDockerHostNetwork]}
	sharing = Check{ID: CheckIDDockerFileSharing, Title: checkTitles[CheckIDDockerFileSharing]}
	if !r.desktop {
		hostNet.Status, hostNet.Detail = StatusPass, "Docker Engine shares the host network"
		sharing.Status, sharing.Detail = StatusSkip, "bind mounts come straight from the host filesystem"
		return hostNet, sharing
	}
	dd, err := r.DockerDesktop()
	if err != nil || dd == nil {
		hostNet.Status, hostNet.Detail = StatusWarn, "could not read the Docker Desktop settings"
		if err != nil {
			hostNet.Detail += ": " + err.Error()
		}
		hostNet.Fix = &Fix{Summary: "make sure Docker Desktop → Settings → Resources → Network → Enable host networking is on"}
		sharing.Status, sharing.Detail = StatusWarn, "could not read the Docker Desktop settings"
		sharing.Fix = &Fix{Summary: "make sure your project folders are under a shared directory (Docker Desktop → Settings → Resources → File sharing)"}
		return
	}
	switch {
	case dd.HostNetworking == nil:
		hostNet.Status, hostNet.Detail = StatusWarn, "Docker Desktop does not report the host networking setting"
		hostNet.Fix = &Fix{Summary: "use Docker Desktop 4.34 or newer and turn on Settings → Resources → Network → Enable host networking"}
	case *dd.HostNetworking:
		hostNet.Status, hostNet.Detail = StatusPass, "enabled in Docker Desktop"
	default:
		hostNet.Status, hostNet.Detail = StatusFail, "Docker Desktop host networking is off; the OpenShell supervisor needs it"
		hostNet.Fix = &Fix{Summary: "turn on Docker Desktop → Settings → Resources → Network → Enable host networking, then apply and restart"}
	}
	home, _ := r.HomeDir()
	switch {
	case dd.FileSharing == nil:
		sharing.Status, sharing.Detail = StatusWarn, "Docker Desktop does not report its shared directories"
	case home != "" && sharedDir(dd.FileSharing, home):
		sharing.Status, sharing.Detail = StatusPass, home+" is shared with Docker Desktop"
	default:
		sharing.Status, sharing.Detail = StatusFail, home+" is not shared with Docker Desktop, so project folders cannot be mounted"
		sharing.Fix = &Fix{Summary: "add your home directory in Docker Desktop → Settings → Resources → File sharing"}
	}
	return hostNet, sharing
}

func sharedDir(shared []string, path string) bool {
	for _, s := range shared {
		s = filepath.Clean(s)
		if path == s || strings.HasPrefix(path, s+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (r *doctorRun) diskCheck(root string) Check {
	c := Check{ID: CheckIDDisk, Title: checkTitles[CheckIDDisk]}
	if r.desktop {
		c.Status, c.Detail = StatusSkip, "images live in the Docker Desktop VM disk"
		return c
	}
	if root == "" {
		c.Status, c.Detail = StatusWarn, "docker did not report its root directory"
		return c
	}
	free, err := r.DiskFree(root)
	if err != nil {
		c.Status, c.Detail = StatusWarn, fmt.Sprintf("could not measure free space under %s: %v", root, err)
		return c
	}
	c.Detail = fmt.Sprintf("%s free under %s", humanBytes(free), root)
	// DefenseClaw's own prune first: on a shared machine `docker system
	// prune` also removes other people's stopped containers, networks and
	// build cache.
	prune := &Fix{
		Summary: "remove DefenseClaw's unused sandbox images (rather than `docker system prune`, which also removes " +
			"every stopped container, unused network and build cache on this machine, other users' too)",
		Command: pruneCommand,
	}
	switch {
	case free < DiskFailBytes:
		c.Status, c.Fix = StatusFail, prune
		c.Detail += fmt.Sprintf("; sandbox images need at least %s", humanBytes(DiskFailBytes))
	case free < DiskWarnBytes:
		c.Status, c.Fix = StatusWarn, prune
		c.Detail += fmt.Sprintf("; %s or more is recommended", humanBytes(DiskWarnBytes))
	default:
		c.Status = StatusPass
	}
	return c
}

func humanBytes(n uint64) string {
	const gib = 1 << 30
	if n >= gib {
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}

func (r *doctorRun) checkLinger(ctx context.Context) {
	c := Check{ID: CheckIDLinger, Title: "systemd linger"}
	defer func() { r.add(c) }()
	if r.GOOS != "linux" {
		c.Status, c.Detail = StatusSkip, "Homebrew services run while you are logged in"
		return
	}
	name, err := r.Username()
	if err != nil || name == "" {
		c.Status, c.Detail = StatusWarn, "could not determine the user name"
		return
	}
	out, err := r.Runner.Output(ctx, Command{Name: "loginctl", Args: []string{"show-user", name, "--property=Linger", "--value"}, Timeout: 10 * time.Second})
	fix := &Fix{Summary: "let your user services (the OpenShell gateway) keep running after you log out", Command: "sudo loginctl enable-linger " + shellQuote(name), Sudo: true}
	switch v := strings.TrimSpace(string(out)); {
	case err != nil:
		c.Status, c.Detail, c.Fix = StatusWarn, "could not query loginctl: "+strings.TrimSpace(v+" "+err.Error()), fix
	case v == "yes":
		c.Status, c.Detail = StatusPass, "enabled for "+name
	default:
		c.Status, c.Detail, c.Fix = StatusWarn, "off: the gateway and its sandboxes stop when you log out", fix
	}
}

func (r *doctorRun) checkService(ctx context.Context) {
	c := Check{ID: CheckIDGatewayService, Title: "Gateway service"}
	defer func() { r.add(c) }()
	st, err := r.Gateway.ServiceState(ctx)
	if err != nil {
		c.Status, c.Detail = StatusFail, err.Error()
		if r.GOOS == "linux" {
			c.Fix = &Fix{Summary: "run doctor from a login session with a systemd user manager (XDG_RUNTIME_DIR set), and enable linger"}
		}
		return
	}
	r.service, r.report.Service = st, st
	start := r.startCommand()
	switch {
	case !st.Installed:
		c.Status, c.Detail = StatusFail, st.Unit+" is not installed"
		c.Fix = &Fix{Summary: "install OpenShell", Command: installOpenShellCommand}
	case !st.Active:
		c.Status, c.Detail = StatusFail, st.Unit+" is "+st.Status
		c.Fix = &Fix{Summary: "start the gateway and enable it at login", Command: strings.Join(start.argv(), " "), Automatic: true, Apply: r.runAndWait(start, true)}
	case !st.Enabled:
		c.Status, c.Detail = StatusWarn, st.Unit+" runs but does not start at login"
		c.Fix = &Fix{Summary: "enable the gateway at login", Command: strings.Join(start.argv(), " "), Automatic: true, Apply: r.runAndWait(start, false)}
	default:
		c.Status, c.Detail = StatusPass, st.Unit+" "+st.Status
	}
}

func (r *doctorRun) startCommand() serviceCommand {
	if r.GOOS == "darwin" {
		return serviceCommand{"brew", []string{"services", "start", GatewayFormula}}
	}
	return serviceCommand{"systemctl", []string{"--user", "enable", "--now", GatewayService}}
}

// runAndWait runs a service command, then waits for a healthy gateway
// the way a configuration change does. starts marks a command that starts
// a stopped gateway, which then runs the configuration on disk.
func (r *doctorRun) runAndWait(c serviceCommand, starts bool) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := r.Gateway.defaults(); err != nil {
			return err
		}
		if out, err := r.Runner.Output(ctx, Command{Name: c.name, Args: c.args, Timeout: 2 * time.Minute}); err != nil {
			return fmt.Errorf("%s: %v: %s", c, err, strings.TrimSpace(string(out)))
		}
		if err := r.Gateway.VerifyGateway(ctx); err != nil {
			return err
		}
		if starts {
			r.Gateway.clearRestartPending()
		}
		return nil
	}
}

// gatewayRecoveryFix restarts a gateway that runs but does not answer
// (starting it again would do nothing) and starts one that is stopped. With
// no gateway service to start (serviceMissing), OpenShell's installer is
// what puts one there: `brew services start` of a formula that is not
// installed fails ("Formula `openshell` is not installed"). Where an
// OpenShell installed another way is there, its gateway is the user's to
// start (unmanagedFix).
func (r *doctorRun) gatewayRecoveryFix() *Fix {
	switch {
	case r.serviceMissing() && r.report.GatewayUnmanaged():
		return r.unmanagedFix(startYourself)
	case r.serviceMissing():
		return &Fix{Summary: "install OpenShell, whose " + r.service.Unit + " service runs the gateway", Command: installOpenShellCommand}
	case r.service != nil && r.service.Active:
		return &Fix{Summary: "restart the gateway", Command: r.Gateway.restartCommand().String(), Automatic: true, RestartsGateway: true, Apply: r.Gateway.Restart}
	}
	start := r.startCommand()
	return &Fix{Summary: "start the gateway", Command: start.String(), Automatic: true, Apply: r.runAndWait(start, true)}
}

// serviceMissing reports that the service manager has no gateway service:
// the nvidia/openshell/openshell formula (macOS) or the openshell-gateway
// user unit (Linux) is not installed, so DefenseClaw has none to start or
// restart the gateway through, whether no gateway runs or one runs another
// way. It is false when the service's state is unknown.
func (r *doctorRun) serviceMissing() bool { return r.service != nil && !r.service.Installed }

// unmanagedFix is the fix of an OpenShell installed another way than the
// one whose service DefenseClaw starts and restarts the gateway through
// (DoctorReport.GatewayUnmanaged), which the doctor cannot take: first is
// what to do with that OpenShell's gateway, which its user runs. The other
// way on is a gateway DefenseClaw runs, for which that OpenShell goes
// first: DefenseClaw's install step would find its CLI and install
// nothing.
func (r *doctorRun) unmanagedFix(first string) *Fix {
	found := strings.TrimSpace("OpenShell " + r.report.CLIVersion)
	if r.report.CLIPath != "" {
		found += " at " + r.report.CLIPath
	}
	service, install := "Homebrew's "+GatewayFormula+" service", "install the formula"
	if r.GOOS != "darwin" {
		service, install = "the "+GatewayService+" user service, which NVIDIA's installer sets up", "install OpenShell with NVIDIA's installer"
	}
	return &Fix{Summary: first + ". DefenseClaw starts and restarts the gateway only through " + service + ", and the " + found +
		" was installed another way. For a gateway DefenseClaw starts and restarts, stop that one and remove that OpenShell " +
		"(DefenseClaw's install step would find it and install nothing), then " + install,
		Command: installOpenShellCommand}
}

// unmanagedFix's first steps: for an unmanaged gateway that answers, and
// for one that does not.
const (
	restartYourself = "after a gateway change, restart this gateway yourself, the way you started it"
	startYourself   = "start that OpenShell's gateway yourself, the way you started it before"
)

// gatewayVersionFix is the fix of a gateway that answers with an
// unsupported OpenShell release, or another one than the CLI's. install
// (installOpenShellCommand) is it only where NVIDIA's installer would run:
// with no CLI, or one it upgrades. A supported CLI DefenseClaw's install
// step finds, and installs nothing (Installer.Install), so the gateway
// that answers is not the one that CLI's install runs: the gateway service
// is restarted, so that it runs the gateway installed with the CLI, which
// is automatic only where that service runs the gateway, and only once for
// these releases: after a restart that left them (releaseRestarted), the
// service runs another OpenShell's gateway (otherOpenShellFix). Without
// the service, the gateway of an OpenShell installed another way is the
// user's to replace (unmanagedFix).
func (r *doctorRun) gatewayVersionFix(install *Fix) *Fix {
	if r.cli == (Version{}) || CheckSupported(r.cli) != nil {
		return install
	}
	release := gatewayRelease(r.gateway)
	answers := "the gateway that answers runs " + describeRelease(release) + ", not the OpenShell " + r.cli.String() +
		" installed here, so installing OpenShell would change nothing"
	service := r.serviceName()
	switch {
	case r.serviceMissing() && r.report.GatewayUnmanaged():
		return r.unmanagedFix(answers + ": stop that gateway, then start the OpenShell " + r.cli.String() + " one yourself")
	case r.service != nil && r.service.Installed && r.service.Active && r.releaseRestarted(release):
		return r.otherOpenShellFix(release)
	case r.service != nil && r.service.Installed && r.service.Active:
		return &Fix{Summary: answers + ": restart " + service + " so it runs the gateway installed with the CLI",
			Command: r.Gateway.restartCommand().String(), Automatic: true, RestartsGateway: true, Apply: r.restartOnCLIRelease}
	case r.service != nil && r.service.Installed:
		// The service is stopped: something else runs that gateway, and
		// the service's would not get its port.
		return &Fix{Summary: answers + ", and " + service + " is stopped, so something else runs that gateway: stop it, then start the service",
			Command: r.startCommand().String()}
	}
	return &Fix{Summary: answers + ": stop that gateway, then start the OpenShell " + r.cli.String() + " gateway"}
}

// stoppedServiceAnswers gives the Gateway service check of an installed
// service that is stopped while a healthy gateway answers anyway its way
// on: something else runs that gateway, whose port the service's would
// not get, and the start's wait would take the other gateway for the
// started one and call the fix done. It runs after checkGateway, which
// asks the gateway.
func (r *doctorRun) stoppedServiceAnswers() {
	c := r.report.Get(CheckIDGatewayService)
	if c == nil || c.Status != StatusFail || r.service == nil || !r.service.Installed || r.service.Active ||
		r.gateway == nil || !r.gateway.Healthy || r.reg == nil {
		return
	}
	c.Fix = &Fix{Summary: r.serviceName() + " is stopped, but a gateway answers at " + r.reg.Endpoint +
		": something else runs it, and the service's gateway would not get its port. Stop that gateway, then start the service",
		Command: r.startCommand().String()}
}

// serviceName names the gateway service DefenseClaw starts and restarts
// the gateway through.
func (r *doctorRun) serviceName() string {
	if r.GOOS == "darwin" {
		return "Homebrew's " + GatewayFormula + " service"
	}
	return "the " + GatewayService + " user service"
}

// gatewayRelease is the release a gateway answers with: its version, else
// the raw one it reported.
func gatewayRelease(h *GatewayHealth) string {
	if h.Version != (Version{}) {
		return h.Version.String()
	}
	return h.RawVersion
}

// describeRelease names a gatewayRelease: "OpenShell 0.0.40", or an
// unrecognized one quoted.
func describeRelease(release string) string {
	if v, err := ParseVersion(release); err == nil {
		return "OpenShell " + v.String()
	}
	return "an unrecognized OpenShell release (" + strconv.Quote(release) + ")"
}

// otherOpenShellFix is the way on once a restart of the gateway service
// left a gateway of release, another than the supported CLI's: the service
// runs another OpenShell's gateway, which another restart would not
// change, and the install does not replace while the CLI is found
// (Installer.Install). That other OpenShell goes first, its gateway
// stopped, since removing its files leaves the running one answering;
// without it setup says what comes next.
func (r *doctorRun) otherOpenShellFix(release string) *Fix {
	return &Fix{Summary: r.serviceName() + " runs another OpenShell's gateway: restarted, it still answers with " + describeRelease(release) +
		", not the OpenShell " + r.cli.String() + " of the CLI at " + r.report.CLIPath +
		". Stop that gateway (`" + r.stopCommand().String() + "`) and remove that other OpenShell, then install OpenShell " + SupportedMin,
		Command: installOpenShellCommand}
}

// stopCommand stops the gateway service.
func (r *doctorRun) stopCommand() serviceCommand {
	if r.GOOS == "darwin" {
		return serviceCommand{"brew", []string{"services", "stop", GatewayFormula}}
	}
	return serviceCommand{"systemctl", []string{"--user", "stop", GatewayService}}
}

// restartOnCLIRelease restarts the gateway service (gatewayVersionFix) and
// asks the restarted gateway its release. When it is still not the CLI's,
// the service runs another OpenShell's gateway: the error is that way on
// (otherOpenShellFix), and the restart is recorded so the doctor does not
// offer it again for these releases (releaseRestarted). The restart's
// wait (WaitForGateway) fails at once on an unsupported release, which is
// that answer too; one that could not restart the gateway (the service
// manager refused, or the sandboxes could not be flushed) tells nothing.
func (r *doctorRun) restartOnCLIRelease(ctx context.Context) error {
	err := r.Gateway.Restart(ctx)
	if errors.Is(err, errRestartCommand) || errors.Is(err, ErrUnflushed) {
		return err
	}
	var release string
	var unsupported *ErrUnsupportedVersion
	if errors.As(err, &unsupported) {
		release = unsupported.Found.String()
	} else {
		h, herr := r.healthNow(ctx)
		switch {
		case herr != nil && err == nil:
			return herr
		case herr != nil || !h.Healthy:
			return err
		case h.Version.Compare(r.cli) == 0:
			if err == nil {
				r.forgetReleaseRestart()
			}
			return err
		}
		release = gatewayRelease(h)
	}
	r.recordReleaseRestart(release)
	fix := r.otherOpenShellFix(release)
	return fmt.Errorf("%s with `%s`", fix.Summary, fix.Command)
}

// healthNow asks the gateway of the registration the doctor checked.
func (r *doctorRun) healthNow(ctx context.Context) (*GatewayHealth, error) {
	client, err := r.Dial(r.reg)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Health(ctx)
}

// releaseRestart is a restart of the gateway service that left a gateway
// of Gateway's release, not the CLI's (restartOnCLIRelease), recorded in
// the gateway's configuration directory (releaseRestartFile).
type releaseRestart struct {
	Gateway string `json:"gateway"`
	CLI     string `json:"cli"`
	CLIPath string `json:"cli_path"`
}

func (r *doctorRun) releaseRestartPath() (string, error) {
	if err := r.Gateway.defaults(); err != nil {
		return "", err
	}
	return filepath.Join(r.Gateway.Dir, releaseRestartFile), nil
}

// releaseRestarted reports a restart recorded for a gateway of release
// and this CLI: restarting again would bring the same gateway back. A
// release or CLI that changed since (an OpenShell removed or installed)
// is another mismatch, whose restart is offered again, and a gateway
// that stopped answering, or answers with the CLI's release, ends the
// record (checkGateway): a later mismatch gets one restart again.
func (r *doctorRun) releaseRestarted(release string) bool {
	path, err := r.releaseRestartPath()
	if err != nil {
		return false
	}
	data, err := safefile.ReadRegularFileBounded(path, 4<<10)
	var got releaseRestart
	if err != nil || json.Unmarshal(data, &got) != nil {
		return false
	}
	return got == releaseRestart{Gateway: release, CLI: r.cli.String(), CLIPath: r.report.CLIPath}
}

func (r *doctorRun) recordReleaseRestart(release string) {
	path, err := r.releaseRestartPath()
	if err != nil {
		return
	}
	data, err := json.Marshal(releaseRestart{Gateway: release, CLI: r.cli.String(), CLIPath: r.report.CLIPath})
	if err != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = safefile.Write(path, append(data, '\n'))
}

func (r *doctorRun) forgetReleaseRestart() {
	if path, err := r.releaseRestartPath(); err == nil {
		_ = os.Remove(path)
	}
}

// nothingToRestart reports no gateway service and no gateway answering:
// no gateway runs to restart, and the configuration on disk is what the
// one OpenShell's install starts loads.
func (r *doctorRun) nothingToRestart() bool {
	return r.serviceMissing() && (r.gateway == nil || !r.gateway.Healthy)
}

// takesEffectOnStart says when a gateway setting takes effect where no
// gateway runs (nothingToRestart).
const takesEffectOnStart = "it takes effect once the gateway is installed and started"

// gatewayChangeFix is the fix of a gateway setting, which the gateway
// loads when it starts: change is what to change, which apply writes
// before it restarts the gateway, or "" (apply nil) when the configuration
// on disk only needs loading; after ends the summary (a reason, or a
// parenthesis). DefenseClaw restarts the gateway only through its service.
// Without one (serviceMissing) the fix is the operator's, and says when
// the change takes effect: once a gateway is installed and started where
// none runs, or when the one run another way is restarted that way. It is
// nil with no change and no gateway: there is nothing to do.
func (r *doctorRun) gatewayChangeFix(change, after string, apply func(context.Context) error) *Fix {
	end := func(s string) string {
		switch {
		case after == "":
			return s
		case change == "" && r.serviceMissing():
			return s + ", " + after
		}
		return s + " " + after
	}
	switch {
	case !r.serviceMissing() && change == "":
		return &Fix{Summary: end("restart the gateway"), Command: r.Gateway.restartCommand().String(), Automatic: true, RestartsGateway: true, Apply: r.Gateway.Restart}
	case !r.serviceMissing():
		return &Fix{Summary: end(change + " and restart the gateway"), Automatic: true, RestartsGateway: true, Apply: apply}
	case r.nothingToRestart() && change == "":
		return nil
	case r.nothingToRestart():
		return &Fix{Summary: end(change) + "; " + takesEffectOnStart}
	}
	how := "restart the gateway the way you started it"
	if change != "" {
		how = change + ", then " + how
	}
	return &Fix{Summary: end(how) + "; DefenseClaw restarts it only through the " + r.service.Unit + " service, which is not installed"}
}

// credentialFailure reports an error from the gateway refusing
// DefenseClaw's TLS credentials, or from the credentials themselves,
// rather than from a gateway that is down.
func credentialFailure(err error) bool {
	if IsUnauthenticated(err) || IsPermissionDenied(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") || strings.Contains(msg, "authentication handshake failed")
}

func (r *doctorRun) checkCLI(ctx context.Context) {
	c := Check{ID: CheckIDCLI, Title: "OpenShell CLI"}
	defer func() { r.add(c) }()
	install := &Fix{Summary: "install OpenShell " + SupportedMin, Command: installOpenShellCommand}
	path, err := r.LookPath(r.CLI)
	if err != nil {
		c.Status, c.Detail, c.Fix = StatusFail, r.CLI+" is not on PATH", install
		return
	}
	r.report.CLIPath = path
	out, err := r.Runner.Output(ctx, Command{Name: path, Args: []string{"--version"}, Timeout: 30 * time.Second})
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	v, perr := VersionFromOutput(line)
	if err != nil || perr != nil {
		c.Status, c.Detail, c.Fix = StatusFail, fmt.Sprintf("%s --version: %q", path, strings.TrimSpace(line)), install
		return
	}
	r.cli, r.report.CLIVersion = v, v.String()
	if err := CheckSupported(v); err != nil {
		c.Status, c.Detail, c.Fix = StatusFail, err.Error(), install
		if v.Compare(mustParse(SupportedBelow)) >= 0 {
			// Installer.Install refuses a newer CLI: it does not downgrade.
			c.Fix = &Fix{Summary: "DefenseClaw's install step does not downgrade OpenShell: remove OpenShell " + v.String() +
				", then install OpenShell " + SupportedMin, Command: installOpenShellCommand}
		}
		return
	}
	c.Status, c.Detail = StatusPass, fmt.Sprintf("%s at %s", v, path)
}

func (r *doctorRun) checkRegistration() {
	c := Check{ID: CheckIDRegistration, Title: "Gateway registration"}
	m := Check{ID: CheckIDMTLS, Title: "Gateway mTLS files"}
	defer func() { r.add(c); r.add(m) }()
	reg, err := Discover(r.Discover)
	r.reg, r.regErr, r.report.Registration = reg, err, reg
	var perm *PermissionError
	errors.As(err, &perm)
	switch {
	case err == nil || (errors.Is(err, ErrInsecureCredentials) && reg != nil):
		c.Status, c.Detail = StatusPass, fmt.Sprintf("%s at %s (%s)", reg.Name, reg.Endpoint, reg.AuthMode)
		if warnings, _ := registrationIssues(reg); len(warnings) > 0 {
			c.Status = StatusWarn
			c.Detail += "; " + joinWarnings(warnings)
			c.Fix = registrationModeFix(warnings)
		}
	case errors.Is(err, ErrInsecureRegistration):
		c.Status, c.Detail = StatusFail, err.Error()
		if perm != nil {
			c.Fix = &Fix{Summary: "make the gateway registration yours and writable only by you, or register the gateway again",
				Command: perm.Fix, Sudo: strings.HasPrefix(perm.Fix, "sudo ")}
			if perm.FixMode != 0 {
				path, mode := perm.Path, perm.FixMode
				c.Fix.Automatic, c.Fix.Apply = true, func(context.Context) error { return chmodOwned(path, mode) }
			}
		}
	case errors.Is(err, ErrUnauthenticatedGateway):
		c.Status, c.Detail = StatusFail, err.Error()
		c.Fix = &Fix{Summary: "serve the local gateway over mTLS (the OpenShell package default; remove OPENSHELL_DISABLE_TLS from gateway.env) and register it with its client certificate",
			Command: "openshell gateway add https://127.0.0.1:17670 --local --name " + DefaultGatewayName}
	case errors.Is(err, ErrNoGateway), errors.Is(err, ErrGatewayNotFound):
		c.Status, c.Detail = StatusFail, err.Error()
		c.Fix = &Fix{Summary: "register the local gateway", Command: "openshell gateway add https://127.0.0.1:17670 --local --name " + DefaultGatewayName}
	case errors.Is(err, ErrRemoteGateway):
		c.Status, c.Detail = StatusFail, err.Error()
		c.Fix = &Fix{Summary: "select the local gateway with openshell.gateway.name, or `openshell gateway select " + DefaultGatewayName + "`"}
	default:
		c.Status, c.Detail = StatusFail, err.Error()
	}
	if c.Status == StatusFail {
		m.Status, m.Detail = StatusSkip, "no usable registration"
		return
	}
	tlsWarnings, _ := CheckTLSFiles(reg.TLS)
	switch {
	case perm != nil:
		m.Status, m.Detail = StatusFail, perm.Error()
		m.Fix = &Fix{Summary: "make the gateway credentials private to you", Command: perm.Fix}
		if perm.FixMode != 0 && perm.Fix != "" {
			path, mode := perm.Path, perm.FixMode
			m.Fix.Automatic, m.Fix.Apply = true, func(context.Context) error { return chmodOwned(path, mode) }
		}
	case err != nil:
		m.Status, m.Detail = StatusFail, err.Error()
	case len(tlsWarnings) > 0:
		m.Status, m.Detail = StatusWarn, strings.Join(tlsWarnings, "; ")
		files := *reg.TLS
		m.Fix = &Fix{Summary: "drop group write access from the gateway credentials", Automatic: true,
			Command: "chmod 700 " + shellQuote(filepath.Dir(files.Key)) + " && chmod 644 " + shellQuote(files.CA) + " " + shellQuote(files.Cert),
			Apply: func(context.Context) error {
				return errors.Join(chmodOwned(filepath.Dir(files.Key), 0o700), chmodOwned(files.CA, 0o644), chmodOwned(files.Cert, 0o644))
			}}
	default:
		m.Status, m.Detail = StatusPass, "private key is owner-only"
	}
}

func joinWarnings(warnings []modeWarning) string {
	parts := make([]string, len(warnings))
	for i, w := range warnings {
		parts[i] = w.String()
	}
	return strings.Join(parts, "; ")
}

// registrationModeFix drops group write access from the registration
// entries that warned; it is automatic when the caller owns all of them.
func registrationModeFix(warnings []modeWarning) *Fix {
	paths := make([]string, len(warnings))
	automatic := true
	for i, w := range warnings {
		paths[i] = shellQuote(w.path)
		automatic = automatic && w.fixMode != 0
	}
	fix := &Fix{Summary: "drop group write access from the gateway registration", Command: "chmod go-w " + strings.Join(paths, " ")}
	if !automatic {
		fix.Command, fix.Sudo = "sudo "+fix.Command, true
		return fix
	}
	fix.Automatic = true
	fix.Apply = func(context.Context) error {
		var errs []error
		for _, w := range warnings {
			errs = append(errs, chmodOwned(w.path, w.fixMode))
		}
		return errors.Join(errs...)
	}
	return fix
}

// chmodOwned changes the mode of a caller-owned file or directory, never
// through a symlink.
func chmodOwned(path string, mode fs.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) || !ownedByCaller(info) {
		return fmt.Errorf("openshell: refusing to chmod %s", path)
	}
	return os.Chmod(path, mode)
}

func (r *doctorRun) checkGateway(ctx context.Context) {
	version := Check{ID: CheckIDGatewayVersion, Title: "Gateway"}
	driver := Check{ID: CheckIDGatewayDriver, Title: "Gateway compute driver"}
	global := Check{ID: CheckIDGlobalPolicy, Title: "Global policy"}
	defer func() { r.add(version); r.add(driver); r.add(global) }()
	skipRest := func(why string) {
		driver.Status, driver.Detail = StatusSkip, why
		global.Status, global.Detail = StatusSkip, why
	}
	if r.reg == nil || r.regErr != nil {
		version.Status, version.Detail = StatusSkip, "no usable registration"
		skipRest("no usable registration")
		return
	}
	client, err := r.Dial(r.reg)
	if err == nil {
		r.client = client
		r.gateway, err = client.Health(ctx)
	}
	if err != nil || !r.gateway.Healthy {
		if err == nil || !credentialFailure(err) {
			r.forgetReleaseRestart()
		}
		version.Status = StatusFail
		switch {
		case err != nil && credentialFailure(err):
			version.Detail = "the gateway refused DefenseClaw's TLS credentials: " + err.Error()
			version.Fix = &Fix{Summary: "register the local gateway again, so the CLI's client certificate matches the gateway's CA",
				Command: fmt.Sprintf("openshell gateway remove %s && openshell gateway add %s --local --name %s", r.reg.Name, shellQuote(r.reg.Endpoint), r.reg.Name)}
		case err != nil:
			version.Detail = "the gateway is not answering: " + err.Error()
			version.Fix = r.gatewayRecoveryFix()
		default:
			version.Detail = "the gateway reports unhealthy"
			version.Fix = r.gatewayRecoveryFix()
		}
		skipRest("the gateway is not answering")
		return
	}
	r.report.GatewayVersion = r.gateway.RawVersion
	if err := r.gateway.CheckVersion(); err != nil {
		version.Status, version.Detail = StatusFail, err.Error()
		version.Fix = r.gatewayVersionFix(&Fix{Summary: "install OpenShell " + SupportedMin, Command: installOpenShellCommand})
	} else if r.cli != (Version{}) && r.cli.Compare(r.gateway.Version) != 0 {
		version.Status = StatusWarn
		version.Detail = fmt.Sprintf("gateway %s but CLI %s; keep them on the same release", r.gateway.Version, r.cli)
		version.Fix = r.gatewayVersionFix(&Fix{Summary: "reinstall OpenShell so the CLI and gateway match", Command: installOpenShellCommand})
	} else {
		version.Status, version.Detail = StatusPass, fmt.Sprintf("%s healthy at %s", r.gateway.Version, r.reg.Endpoint)
		if r.cli != (Version{}) {
			r.forgetReleaseRestart()
		}
	}

	info, err := client.GatewayInfo(ctx)
	if err == nil {
		r.running, r.driverErr = GatewayDriver(info)
	}
	// The Landlock verdict, which the driver check follows off Linux,
	// depends on the driver just learned.
	r.macChecks(ctx)
	driver = r.driverCheck(err)

	rev, err := client.GlobalPolicy(ctx)
	switch {
	case err != nil:
		global.Status, global.Detail = StatusWarn, "global policy status: "+err.Error()
	case rev != nil:
		global.Status = StatusWarn
		global.Detail = fmt.Sprintf("a gateway-global policy (version %d) overrides every sandbox policy: DefenseClaw profiles and approvals are disabled", rev.Version)
		global.Fix = &Fix{Summary: "remove the global policy unless your organization requires it", Command: "openshell policy delete --global"}
	default:
		global.Status, global.Detail = StatusPass, "none; sandbox policies apply"
	}
}

// driverCheck judges the compute driver the gateway reports (infoErr:
// GetGatewayInfo failed). On a Mac sandboxes run in MicroVMs: the docker
// driver passes only on a Docker VM whose kernel has Landlock, and
// otherwise the fix switches the gateway to vm.
func (r *doctorRun) driverCheck(infoErr error) Check {
	c := Check{ID: CheckIDGatewayDriver, Title: "Gateway compute driver"}
	mac := r.GOOS == "darwin"
	switch {
	case infoErr != nil:
		c.Status, c.Detail = StatusWarn, "gateway info: "+infoErr.Error()
	case r.driverErr != nil:
		c.Status, c.Detail = StatusFail, strings.TrimPrefix(r.driverErr.Error(), "openshell: ")
		c.Fix = &Fix{Summary: "run the local gateway with the docker compute driver (OPENSHELL_COMPUTE_DRIVER=docker in gateway.env)"}
		if mac {
			c.Fix = r.microVMFix()
		}
	case r.running.Name == DriverVM && !mac:
		c.Status, c.Detail = StatusWarn, "vm (OpenShell MicroVM): not certified by DefenseClaw off macOS"
	case r.running.Name == DriverVM:
		c.Status, c.Detail = StatusPass, "vm (OpenShell MicroVM; experimental upstream)"
	case r.configured == DriverVM:
		// The configuration selects MicroVMs; the gateway still runs on
		// what it started with.
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%s, but its configuration selects vm (OpenShell MicroVM): the gateway has not been restarted since", r.running.Name)
		c.Fix = r.gatewayChangeFix("", "to run sandboxes in MicroVMs", nil)
	case mac && r.landlock == StatusFail:
		c.Status = StatusFail
		c.Detail = fmt.Sprintf("%s: the Linux VM Docker runs in has no usable Landlock, so no sandbox can start on it", r.running.Name)
		c.Fix = r.microVMFix()
	case mac && r.landlock != StatusPass:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%s: whether the Linux VM Docker runs in has Landlock is not known, and macOS sandboxes run in OpenShell MicroVMs", r.running.Name)
		c.Fix = r.microVMFix()
	default:
		c.Status, c.Detail = StatusPass, string(r.running.Name)
	}
	return c
}

func (r *doctorRun) checkGatewayConfig(ctx context.Context) {
	mounts := Check{ID: CheckIDBindMounts, Title: "Project bind mounts"}
	tele := Check{ID: CheckIDTelemetry, Title: "OpenShell telemetry"}
	defer func() { r.add(mounts); r.add(tele) }()
	st, err := r.Gateway.Read()
	if err != nil {
		mounts.Status, mounts.Detail = StatusFail, err.Error()
		tele.Status, tele.Detail = StatusSkip, "gateway configuration unreadable"
		return
	}
	env, envErr := r.Gateway.serviceEnv(r.service)
	if errors.Is(envErr, ErrNoGatewayService) {
		// A gateway run another way: its environment is not known, and
		// its settings are the files DefenseClaw reads.
		env, envErr = nil, nil
	}
	if d, known := r.traits(); known && !d.HostMounts {
		// Nothing to enable, and no reason to edit docker settings or
		// restart the gateway for them.
		mounts.Status, mounts.Detail = StatusSkip, d.MountRefusal+": every run works on a copy"
		r.telemetryCheck(ctx, &tele, st, envErr)
		return
	}
	// Bind mounts reach any host path through the gateway's root Docker
	// daemon: they are only for a gateway nobody else can drive.
	blocked, unverified := r.bindMountSafety(ctx, st, env, envErr)
	switch {
	case st.BindMounts.Enabled() && errors.Is(blocked, ErrUnauthenticatedGateway):
		mounts.Status = StatusFail
		mounts.Detail = fmt.Sprintf("enabled in %s on a gateway that accepts unauthenticated calls: any local user can mount host paths into a sandbox", st.TOMLPath)
		mounts.Fix = &Fix{Summary: "serve the gateway over mTLS, or set enable_bind_mounts = false in " + st.TOMLPath + " and restart it"}
	case st.BindMounts.Enabled() && errors.Is(blocked, ErrGatewayMismatch):
		mounts.Status, mounts.Detail = StatusFail, fmt.Sprintf("enabled in %s, but %v", st.TOMLPath, blocked)
		mounts.Fix = &Fix{Summary: "run DefenseClaw against the configuration and gateway the openshell-gateway service uses"}
	case st.BindMounts.Enabled() && blocked != nil:
		mounts.Status = StatusFail
		mounts.Detail = fmt.Sprintf("enabled in %s, but others can reach the gateway and mount any host path into a sandbox: %v", st.TOMLPath, blocked)
		mounts.Fix = &Fix{Summary: "serve the gateway over mTLS with client certificates on loopback only, or set enable_bind_mounts = false in " + st.TOMLPath + " and restart it"}
	case !st.BindMounts.Enabled():
		mounts.Status = StatusFail
		if r.BindMountsOptional {
			mounts.Status = StatusWarn
		}
		mounts.Detail = fmt.Sprintf("disabled in %s; only --copy sandboxes work", st.TOMLPath)
		switch why := errors.Join(blocked, unverified); {
		case why == nil && r.serviceMissing():
			// A gateway run another way, which DefenseClaw cannot restart
			// on the change: setup writes it, and its operator restarts it.
			mounts.Fix = r.gatewayChangeFix("let sandboxes mount the project folder: `"+setupCommand+"` enables bind mounts in "+st.TOMLPath, "", nil)
		case why == nil:
			mounts.Fix = &Fix{Summary: "let sandboxes mount the project folder (edits gateway.toml with a backup and restarts the gateway)", Automatic: true,
				RestartsGateway: true, Apply: r.applyGateway(GatewayChanges{EnableBindMounts: true})}
		default:
			mounts.Fix = &Fix{Summary: "DefenseClaw enables bind mounts only on a gateway reachable by you alone over mTLS; fix this first: " + why.Error()}
		}
	case r.restartPending(ctx, st) && r.nothingToRestart():
		mounts.Status, mounts.Detail = StatusPass, "enabled in "+st.TOMLPath+"; "+takesEffectOnStart
	case r.restartPending(ctx, st):
		mounts.Status, mounts.Detail = StatusWarn, "enabled in "+st.TOMLPath+", but the gateway has not been restarted since it changed"
		mounts.Fix = r.gatewayChangeFix("", "to load its changed configuration", nil)
		if r.gatewayStartedAt(ctx).IsZero() {
			// No start time known: DefenseClaw's mark says only that no
			// restart of its own followed its change.
			mounts.Detail = "enabled in " + st.TOMLPath + "; restart the gateway if you have not since gateway.toml changed"
		}
	case unverified != nil && r.gateway != nil && r.gateway.Healthy:
		mounts.Status, mounts.Detail = StatusWarn, "enabled, but DefenseClaw could not confirm that only you can reach the gateway: "+unverified.Error()
	case r.startUnknown(ctx):
		// Setup writes the change for a gateway run another way, and its
		// user restarts it: without its start, "enabled" may be only the
		// file's.
		mounts.Status, mounts.Detail = StatusWarn, "enabled in "+st.TOMLPath+", "+restartUnknown
		mounts.Fix = r.gatewayChangeFix("", "if you have not since "+filepath.Base(st.TOMLPath)+" changed", nil)
	default:
		mounts.Status, mounts.Detail = StatusPass, "enabled for the docker driver"
	}
	r.telemetryCheck(ctx, &tele, st, envErr)
}

// telemetryCheck compares OpenShell's usage telemetry with
// openshell.upstream_telemetry. The setting is gateway.env's, which a
// gateway no gateway service runs has loaded only once its user restarted
// it after the file changed (manual).
func (r *doctorRun) telemetryCheck(ctx context.Context, tele *Check, st *GatewayConfigState, envErr error) {
	on := st.TelemetryEnabled()
	state := map[bool]string{true: "on", false: "off"}[on]
	manual := st.EnvExists && r.serviceMissing() && !r.nothingToRestart()
	// Only gateway.env holds the setting.
	envOnly := *st
	envOnly.TOMLModTime = time.Time{}
	switch {
	case r.GOOS == "darwin":
		// The Homebrew service's wrapper sources gateway.env before it
		// starts the gateway, but launchd cannot be asked which one, so
		// DefenseClaw leaves the telemetry to the user there.
		tele.Status, tele.Detail = StatusSkip, "DefenseClaw changes it on Linux only; the Homebrew service reads "+EnvTelemetryEnabled+" from "+st.EnvPath
	case errors.Is(envErr, ErrGatewayMismatch):
		tele.Status, tele.Detail = StatusWarn, envErr.Error()
	case r.WantTelemetry != nil && *r.WantTelemetry != on:
		want := strconv.FormatBool(*r.WantTelemetry)
		tele.Status = StatusWarn
		tele.Detail = fmt.Sprintf("OpenShell usage telemetry is %s but openshell.upstream_telemetry is %s", state, want)
		tele.Fix = r.gatewayChangeFix("set "+EnvTelemetryEnabled+"="+want+" in gateway.env", "",
			r.applyGateway(GatewayChanges{Env: map[string]string{EnvTelemetryEnabled: want}}))
	case manual && r.restartPending(ctx, &envOnly):
		tele.Status = StatusWarn
		tele.Detail = "OpenShell usage telemetry is " + state + " in " + st.EnvPath + ", but the gateway has not been restarted since it changed"
		tele.Fix = r.gatewayChangeFix("", "with the variables in "+filepath.Base(st.EnvPath)+" in its environment, to load them", nil)
	case manual && r.startUnknown(ctx):
		tele.Status, tele.Detail = StatusWarn, "OpenShell usage telemetry is "+state+" in "+st.EnvPath+", "+restartUnknown
		tele.Fix = r.gatewayChangeFix("", "with the variables in "+filepath.Base(st.EnvPath)+" in its environment, if you have not since it changed", nil)
	default:
		tele.Status, tele.Detail = StatusPass, "OpenShell usage telemetry is "+state
	}
}

// bindMountSafety decides whether bind mounts are safe on the gateway.
// blocked is evidence against them: an unauthenticated registration, a
// service that is not the gateway DefenseClaw configures, or settings or a
// probe showing that clients without the certificate get in. unverified
// means DefenseClaw could not check (another check already explains why,
// or the probe was inconclusive).
func (r *doctorRun) bindMountSafety(ctx context.Context, st *GatewayConfigState, env map[string]string, envErr error) (blocked, unverified error) {
	if errors.Is(r.regErr, ErrUnauthenticatedGateway) {
		return r.regErr, nil
	}
	if errors.Is(envErr, ErrGatewayMismatch) {
		return envErr, nil
	}
	if envErr != nil {
		return nil, envErr
	}
	if r.reg == nil || r.regErr != nil {
		return nil, errors.New("the gateway registration is unusable")
	}
	if err := gatewayExposure(r.reg, st, env, r.serviceMissing()); err != nil {
		return err, nil
	}
	if r.gateway == nil || !r.gateway.Healthy {
		return nil, errors.New("the gateway is not answering")
	}
	if err := r.Gateway.ProbeClientAuth(ctx, r.reg); err != nil {
		if errors.Is(err, ErrGatewayExposed) {
			return err, nil
		}
		return nil, err
	}
	return nil, nil
}

// restartPending is restartPending for the running gateway. The start is
// read first: it also says whether it came from ps (startedApprox).
func (r *doctorRun) restartPending(ctx context.Context, st *GatewayConfigState) bool {
	started := r.gatewayStartedAt(ctx)
	return restartPending(st, started, r.startedApprox)
}

// restartPending reports configuration the gateway that started at
// started has not loaded: DefenseClaw's pending-restart mark from before
// that start (or any mark when the start is unknown), or a file changed
// after it. systemd reports the start to the microsecond, ps on a Mac to
// the second (gatewayStartedAt; approx).
func restartPending(st *GatewayConfigState, started time.Time, approx bool) bool {
	if !st.RestartPendingSince.IsZero() && (started.IsZero() || !started.After(st.RestartPendingSince)) {
		return true
	}
	if started.IsZero() {
		return false
	}
	if approx {
		// The start comes from ps's elapsed time (whole seconds, taken a
		// second early), so a file written just before the gateway started,
		// in its second, would look newer than it: setup writes the
		// configuration and then starts the gateway. A change counts from
		// psStartSlack after that start.
		started = started.Add(psStartSlack)
	}
	return st.TOMLModTime.Truncate(time.Microsecond).After(started) || st.EnvModTime.Truncate(time.Microsecond).After(started)
}

// psStartSlack is how much later than a start taken from ps a gateway's
// configuration may be written and still count as loaded.
const psStartSlack = 2 * time.Second

// gatewayStartedAt is when the running gateway started, to tell what
// configuration it loaded: the service's start (systemd), else the start
// of this user's openshell-gateway process (gatewayPID), which Homebrew's
// service does not report and a gateway run another way has no service
// for. It is zero when neither is known.
func (r *doctorRun) gatewayStartedAt(ctx context.Context) time.Time {
	if r.service != nil && !r.service.StartedAt.IsZero() {
		return r.service.StartedAt
	}
	if r.startedDone {
		return r.started
	}
	r.startedDone = true
	pid := r.gatewayPID(ctx)
	if pid == 0 {
		return time.Time{}
	}
	out, err := r.Runner.Output(ctx, Command{Name: "ps", Args: []string{"-o", "etime=", "-p", strconv.Itoa(pid)}, Timeout: 10 * time.Second})
	if err != nil {
		return time.Time{}
	}
	up, ok := parseElapsed(strings.TrimSpace(string(out)))
	if !ok {
		return time.Time{}
	}
	// ps counts whole seconds: the start is taken a second early, so a
	// mark written in the second the gateway started stays pending.
	r.started, r.startedApprox = time.Now().Add(-up-time.Second), true
	return r.started
}

// gatewayPID is the process of this user's running openshell-gateway, or
// 0: on a Mac the one ps lists (gatewayProcess), on Linux the first whose
// command line pgrep matches (gatewayCommandLine). Linux's ps -o comm= is
// the name cut to 15 characters, which processes cannot tell from another.
func (r *doctorRun) gatewayPID(ctx context.Context) int {
	switch r.GOOS {
	case "darwin":
		if gw := r.gatewayProcess(ctx); gw != nil {
			return gw.pid
		}
		return 0
	case "linux":
	default:
		return 0
	}
	out, err := r.Runner.Output(ctx, Command{Name: "pgrep", Args: []string{"-u", strconv.Itoa(r.Geteuid()), "-f", gatewayCommandLine},
		Timeout: 10 * time.Second})
	if err != nil {
		return 0
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// gatewayCommandLine is the pattern pgrep -f finds a gateway's process by:
// a command line whose first word is openshell-gateway, with its path or
// without.
const gatewayCommandLine = "^([^ ]*/)?" + GatewayBinary + "( |$)"

// startUnknown reports a gateway that answers, which no gateway service
// runs, and whose start DefenseClaw could not find (gatewayStartedAt):
// whether its user restarted it on the configuration on disk is not
// known.
func (r *doctorRun) startUnknown(ctx context.Context) bool {
	return r.serviceMissing() && !r.nothingToRestart() && r.gatewayStartedAt(ctx).IsZero()
}

// restartUnknown ends the detail of a gateway setting where startUnknown.
const restartUnknown = "but DefenseClaw cannot tell whether the gateway was restarted on it: it found no start time for that gateway, which runs another way"

// parseElapsed reads ps's etime, "[[dd-]hh:]mm:ss".
func parseElapsed(s string) (time.Duration, bool) {
	var days int
	if d, rest, ok := strings.Cut(s, "-"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 {
			return 0, false
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	total := 0
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || len(p) == 0 {
			return 0, false
		}
		total = total*60 + n
	}
	return time.Duration(days)*24*time.Hour + time.Duration(total)*time.Second, true
}

func (c serviceCommand) String() string { return strings.Join(c.argv(), " ") }

func (r *doctorRun) applyGateway(ch GatewayChanges) func(context.Context) error {
	return func(ctx context.Context) error {
		plan, err := r.Gateway.Plan(ctx, ch)
		if err != nil {
			return err
		}
		_, err = r.Gateway.Apply(ctx, plan)
		return err
	}
}

func (r *doctorRun) checkPorts() {
	gatewayPort := 0
	if r.reg != nil {
		if _, p, err := net.SplitHostPort(r.reg.Target()); err == nil {
			gatewayPort, _ = strconv.Atoi(p)
		}
	}
	for _, p := range r.Ports {
		c := Check{ID: CheckIDPortPrefix + p.Name, Title: fmt.Sprintf("Sandbox %s port", p.Name)}
		reconfigure := &Fix{Summary: fmt.Sprintf("choose a free port with openshell.%s_port", p.Name)}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port))
		switch {
		case p.Port < 1 || p.Port > 65535:
			c.Status, c.Detail, c.Fix = StatusFail, fmt.Sprintf("invalid port %d", p.Port), reconfigure
		case p.Port == gatewayPort:
			c.Status, c.Detail, c.Fix = StatusFail, fmt.Sprintf("%d is the OpenShell gateway's port", p.Port), reconfigure
		default:
			ln, err := r.Listen("tcp", addr)
			switch {
			case err == nil:
				_ = ln.Close()
				c.Status, c.Detail = StatusPass, addr+" is free"
			case p.ServedByDaemon:
				c.Status, c.Detail = StatusPass, addr+" is served by the DefenseClaw daemon"
			default:
				c.Status, c.Detail, c.Fix = StatusFail, addr+" is in use by another process", reconfigure
			}
		}
		r.add(c)
	}
}

// dockerGroupMembership reports whether the user is listed in the docker
// group and whether the current process carries it.
func dockerGroupMembership() (member, inSession bool, err error) {
	g, err := user.LookupGroup("docker")
	if err != nil {
		return false, false, err
	}
	u, err := user.Current()
	if err != nil {
		return false, false, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false, false, err
	}
	member = slices.Contains(ids, g.Gid)
	gid, _ := strconv.Atoi(g.Gid)
	groups, _ := os.Getgroups()
	return member, slices.Contains(groups, gid), nil
}

// readDockerDesktop reads Docker Desktop's settings store.
func readDockerDesktop(goos string, home func() (string, error)) (*DockerDesktop, error) {
	dir, err := home()
	if err != nil {
		return nil, err
	}
	var candidates []string
	if goos == "darwin" {
		base := filepath.Join(dir, "Library", "Group Containers", "group.com.docker")
		candidates = []string{filepath.Join(base, "settings-store.json"), filepath.Join(base, "settings.json")}
	} else {
		base := filepath.Join(dir, ".docker", "desktop")
		candidates = []string{filepath.Join(base, "settings-store.json"), filepath.Join(base, "settings.json")}
	}
	for _, path := range candidates {
		data, err := safefile.ReadRegularFileBounded(path, 4<<20)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return parseDockerDesktop(data)
	}
	return nil, fmt.Errorf("no Docker Desktop settings under %s", dir)
}

func parseDockerDesktop(data []byte) (*DockerDesktop, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse Docker Desktop settings: %w", err)
	}
	dd := &DockerDesktop{}
	for k, v := range raw {
		switch strings.ToLower(k) {
		case "hostnetworkingenabled":
			var b bool
			if json.Unmarshal(v, &b) == nil {
				dd.HostNetworking = &b
			}
		case "filesharingdirectories":
			var dirs []string
			if json.Unmarshal(v, &dirs) == nil {
				dd.FileSharing = dirs
			}
		}
	}
	return dd, nil
}
