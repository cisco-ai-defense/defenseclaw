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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The sandbox daemon readies the account's OpenShell before every managed
// create and start (spec 2.8).
//
// Setup mode (enterprise.openshell.install: setup): the daemon installs the
// pinned OpenShell release from NVIDIA's tarballs into the account's
// ~/.local (openshell.TarballInstaller: NVIDIA's checksum file and the digest
// this build pins must both match), starts the account's OpenShell gateway
// unit (defenseclaw-openshell-gateway.service, or the LaunchAgent
// com.cisco.defenseclaw.openshell-gateway), whose exec shim sets umask 0022,
// the rendered configuration and a pinned PATH, waits until the gateway
// listens on 127.0.0.1:<gateway_port> as this account, and registers it with
// the account's openshell CLI. When the daemon exits with no sandbox running
// it stops that gateway again, so the gateway port is free for the next
// account (D9).
//
// Prerequisite mode (enterprise.openshell.install: prerequisite): the
// administrator installed OpenShell machine-wide. The daemon does the same
// as in setup mode except the install: the account's gateway unit runs the
// administrator's openshell-gateway through the exec shim on the rendered
// configuration, the daemon starts it on demand, waits for it and registers
// it with the administrator's openshell CLI, and stops it again when no
// sandbox runs (GAP-0186, GAP-0221, GAP-0377). A gateway of the account's
// that its managed unit did not start (NVIDIA's own unit on the account's
// own files, say) runs whatever the account configured: the daemon compares
// that configuration with the one the lifecycle rendered from
// enterprise.openshell, and a difference pauses sandboxes
// (sandboxapi.SettingsDrift) and is reported to the managed gateway (event
// settings_drift).

const (
	openShellGatewayUnit          = "defenseclaw-openshell-gateway.service"
	openShellGatewayRepairCommand = "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos repair"
	daemonSystemctl               = "/usr/bin/systemctl"
	daemonLaunchctl               = "/bin/launchctl"
	renderedGatewayDriftField     = "gateway configuration"

	// openShellPrerequisiteReason is the refusal detail of a missing
	// OpenShell prerequisite.
	openShellPrerequisiteReason = "openshell_prerequisite_missing"
	// openShellTLSDirRel is the account's local OpenShell TLS directory
	// below its home: the exec shim's generate-certs writes it and
	// `openshell gateway add --local` reads it.
	openShellTLSDirRel = ".local/state/openshell/tls"
)

// openShellLaunchAgentsDir holds the LaunchAgent plists; a var for tests.
var openShellLaunchAgentsDir = openshell.LaunchAgentsDir

// openShellGatewayAgent is the installed OpenShell gateway job: its label
// carries the gateway program's tag (openshell.LaunchAgentLabel).
func openShellGatewayAgent() (label, plist string) {
	return openshell.FindLaunchAgent(openShellLaunchAgentsDir, openshell.GatewayAgentBase)
}

// Waits for the OpenShell gateway; vars so tests run at speed.
var (
	openShellGatewayStartWait = 90 * time.Second
	openShellGatewayPollEvery = 500 * time.Millisecond
	openShellGatewayHealAfter = 3 * time.Second
	// openShellGatewayRestartEvery is how often the start wait looks
	// whether the account's gateway unit stopped before it listened
	// (Linux): a start asked while the unit was still stopping (after a
	// SIGTERM, say) was a no-op, and the unit then stayed inactive for the
	// whole wait (rel-1-0-2:GAP-0419, #1202). It is started again, up to
	// openShellGatewayRestarts times.
	openShellGatewayRestartEvery = 3 * time.Second
	openShellGatewayRestarts     = 3
)

// daemonOpenShell is what the daemon does with the account's OpenShell;
// tests replace it.
type daemonOpenShell interface {
	// Drift lists where the account's OpenShell gateway configuration
	// differs from the rendered one, for a gateway the managed unit did not
	// start (nil otherwise).
	Drift(s sandboxrelay.DaemonSettings) ([]openshell.SettingDrift, error)
	// RenderedConfigDrift is a cheap status probe of the lifecycle's pinned
	// render; it does not inspect a running process or change readiness.
	RenderedConfigDrift(s sandboxrelay.DaemonSettings) bool
	// Prepare starts and registers the account's OpenShell gateway (setup
	// mode installs it first). started reports that it started the gateway
	// now.
	Prepare(ctx context.Context, s sandboxrelay.DaemonSettings) (started bool, err error)
	// Stop stops the account's managed OpenShell gateway and reports
	// whether it did.
	Stop(ctx context.Context, s sandboxrelay.DaemonSettings) bool
	// PortHolder reports who listens on the gateway port: the uid (-1 for
	// another account's process this account cannot see) and whether
	// anything does.
	PortHolder(s sandboxrelay.DaemonSettings) (uid int, held bool)
	// OtherGateways lists the OpenShell gateways of this account that the
	// managed unit did not start, each as "pid N: command".
	OtherGateways(ctx context.Context, s sandboxrelay.DaemonSettings) []string
}

// accountOpenShell is the daemonOpenShell of this account.
type accountOpenShell struct {
	goos string
	uid  int
	home string
	logf func(string, ...any)

	// Seams.
	install      func(ctx context.Context, version, home string) (*openshell.TarballResult, error)
	run          func(ctx context.Context, name string, args, env []string) (string, error)
	portHolder   func(port int) (uid int, held bool)
	readUser     func(goos string) (*openshell.GatewayConfigState, error)
	readRendered func(tomlPath, envPath string) (openshell.RenderedGateway, string, error)
	configDir    func() (string, error)
	discover     func(openshell.DiscoverOptions) (*openshell.Registration, error)
	// adminBinary finds the administrator's copy of an OpenShell binary
	// (prerequisite mode).
	adminBinary func(name string) (string, error)
	// gid is the account's group, which with uid the MicroVM workloads run as.
	gid int
	// portPID is the process that listens on a port (0 when unknown) and
	// procArgs its command line, words joined by spaces.
	portPID  func(port int) int
	procArgs func(ctx context.Context, pid int) (string, error)
	// accountProcs lists the account's processes, a line each: the pid and
	// the command line.
	accountProcs func(ctx context.Context) (string, error)
	// hostProcs lists every account's processes, a line each: the uid, the
	// pid and the command line.
	hostProcs func(ctx context.Context) (string, error)

	// stopSync syncs the disk of every MicroVM the OpenShell gateway
	// registered as gateway lists ready and says on out which it synced
	// (openshell.SyncGatewaySandboxes), and recordUnsynced notes the ones it
	// could not for the sandbox feed (manager.RecordUnsyncedStops). The
	// macOS stop runs them: launchd gives the LaunchAgent no stop command.
	stopSync       func(ctx context.Context, gateway string, out io.Writer) error
	recordUnsynced func(names []string)

	// installed is the release this process installed or found intact.
	mu        sync.Mutex
	installed string
}

var _ daemonOpenShell = (*accountOpenShell)(nil)

// newAccountOpenShell is the daemon's OpenShell for this account.
func newAccountOpenShell(goos string, uid int, home string, logf func(string, ...any)) *accountOpenShell {
	return &accountOpenShell{
		goos: goos, uid: uid, gid: os.Getegid(), home: home, logf: logf,
		adminBinary: func(name string) (string, error) { return adminOpenShell(goos, name) },
		install: func(ctx context.Context, version, home string) (*openshell.TarballResult, error) {
			// The proxy is the process environment's: the lifecycle puts
			// enterprise.network into the daemon unit's environment.
			t := &openshell.TarballInstaller{Version: version, Home: home}
			return t.Install(ctx)
		},
		run:        runServiceCommand,
		portHolder: loopbackPortHolder,
		readUser: func(goos string) (*openshell.GatewayConfigState, error) {
			g := &openshell.GatewayConfigurator{GOOS: goos, Managed: true}
			return g.Read()
		},
		readRendered: openshell.ReadRenderedGateway,
		configDir:    openshell.UserConfigDir,
		discover:     openshell.Discover,
		stopSync: func(ctx context.Context, gateway string, out io.Writer) error {
			return openshell.SyncGatewaySandboxes(ctx, openshell.DiscoverOptions{Gateway: gateway}, out)
		},
		portPID:  loopbackPortPID,
		procArgs: processArgs,
		accountProcs: func(ctx context.Context) (string, error) {
			return runServiceCommand(ctx, "/bin/ps", []string{"-ww", "-u", strconv.Itoa(uid), "-o", "pid=,args="}, nil)
		},
		hostProcs: func(ctx context.Context) (string, error) {
			return runServiceCommand(ctx, "/bin/ps", []string{"-ww", "-A", "-o", "uid=,pid=,args="}, nil)
		},
	}
}

// adminOpenShell is the administrator's copy of the OpenShell binary name:
// root-owned, closed to every other writer, in a system folder
// (openshell.AdminBinary); a seam for tests.
var adminOpenShell = func(goos, name string) (string, error) {
	return openshell.AdminBinary(goos, name, func(path string) error {
		return managed.ValidateTrustedFilePath(path, "OpenShell")
	})
}

// accountHome is the daemon account's home: the account database's, or
// $HOME for a directory account the pure-Go lookup cannot see.
func accountHome(uid int) string {
	home := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		home = u.HomeDir
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}

// openShellCLI is the setup-mode openshell CLI of the account at home.
func openShellCLI(home string) string {
	return filepath.Join(home, ".local", "bin", openshell.DefaultBinary)
}

// gatewayPort is enterprise.openshell.gateway_port (its default when 0).
func gatewayPort(s sandboxrelay.DaemonSettings) int {
	if p := s.Enterprise.GatewayPort; p > 0 {
		return p
	}
	return config.DefaultEnterpriseOpenShellGatewayPort
}

// gatewayRegistrationName is the registration the daemon's manager uses.
func gatewayRegistrationName(s sandboxrelay.DaemonSettings) string {
	if n := s.Operational.GatewayName; n != "" {
		return n
	}
	return openshell.DefaultGatewayName
}

// openShellPrerequisiteError refuses a create or start whose OpenShell is
// not ready; what is missing is the account's own.
func openShellPrerequisiteError(format string, args ...any) error {
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: "OpenShell is not ready for your account on this computer",
		Detail:  openShellPrerequisiteReason + ": " + fmt.Sprintf(format, args...)}
}

// accountBusyError is Q2's neutral refusal: another account holds the
// OpenShell gateway port.
func accountBusyError() error {
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: sandboxAccountBusyMessage, Detail: SandboxAccountBusyReason}
}

// Drift lists where the gateway on the account's gateway port runs other
// settings than the rendered ones; no gateway running means Prepare starts
// the managed unit, so there is nothing to compare.
//
// A gateway of the managed unit runs what its exec shim execs: the install
// mode's openshell-gateway with --config on the rendered file and nothing
// else. It never reads the account's own ~/.config/openshell/gateway.toml,
// so an edit there changes nothing (GAP-0512); what is compared is the
// command line the gateway actually runs, which a drop-in that replaces the
// unit's ExecStart or adds flags changes. A gateway of the account's that
// the managed unit did not start (NVIDIA's own unit, say) runs the
// account's own configuration, which is compared with the render
// (prerequisite mode). The render itself must be trustworthy either way.
func (o *accountOpenShell) Drift(s sandboxrelay.DaemonSettings) ([]openshell.SettingDrift, error) {
	e := s.Enterprise
	compare := e.Install != config.EnterpriseOpenShellInstallSetup && e.GatewayConfigPath != ""
	var want openshell.RenderedGateway
	var renderedDrift []openshell.SettingDrift
	if e.GatewayConfigPath != "" {
		// Both install modes run the administrator's rendered file (the
		// managed unit's exec shim), so a hand edit of it is drift in setup
		// mode too: reported, as status reports it, never a pause
		// (blockingOpenShellDrift). Setup mode, whose gateway may also run
		// the account's own install, does not fail on a render it cannot
		// read (GAP-0730).
		envPath := filepath.Join(filepath.Dir(e.GatewayConfigPath), openshell.GatewayEnvFile)
		var digest string
		var err error
		want, digest, err = o.readRendered(e.GatewayConfigPath, envPath)
		switch {
		case err != nil && compare:
			return nil, err
		case err == nil && e.GatewayConfigDigest != "" && digest != e.GatewayConfigDigest:
			renderedDrift = []openshell.SettingDrift{{Field: renderedGatewayDriftField, Want: "installed render", Have: "changed"}}
		}
	}
	if holder, held := o.portHolder(gatewayPort(s)); !held || holder != o.uid {
		return renderedDrift, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if o.managedUnitActive(ctx) {
		return append(renderedDrift, o.commandDrift(ctx, s)...), nil
	}
	if !compare {
		return renderedDrift, nil
	}
	want = want.ForAccount(int64(o.uid), int64(o.gid))
	have, err := o.readUser(o.goos)
	if err != nil {
		return append(renderedDrift, openshell.SettingDrift{Field: renderedGatewayDriftField, Want: "readable", Have: "unreadable"}), nil
	}
	return append(renderedDrift, tighterDrift(have.Drift(want), want)...), nil
}

func (o *accountOpenShell) RenderedConfigDrift(s sandboxrelay.DaemonSettings) bool {
	e := s.Enterprise
	if e.GatewayConfigPath == "" || e.GatewayConfigDigest == "" {
		return false
	}
	envPath := filepath.Join(filepath.Dir(e.GatewayConfigPath), openshell.GatewayEnvFile)
	_, digest, err := o.readRendered(e.GatewayConfigPath, envPath)
	return err != nil || digest != e.GatewayConfigDigest
}

// commandDrift compares the command line of the gateway on the account's
// gateway port with the one the managed unit's exec shim execs: the install
// mode's openshell-gateway, --config and one of the rendered files
// (managedConfigs). A listener that is not openshell-gateway
// itself, or one whose command cannot be read, is not judged.
func (o *accountOpenShell) commandDrift(ctx context.Context, s sandboxrelay.DaemonSettings) []openshell.SettingDrift {
	if o.portPID == nil || o.procArgs == nil {
		return nil
	}
	pid := o.portPID(gatewayPort(s))
	if pid <= 0 {
		return nil
	}
	have, err := o.procArgs(ctx, pid)
	if err != nil {
		return nil
	}
	words := strings.Fields(have)
	if len(words) == 0 || filepath.Base(words[0]) != openshell.GatewayBinary {
		return nil
	}
	binary := o.gatewayBinary(s)
	cfg := s.Enterprise.GatewayConfigPath
	if binary == "" || cfg == "" {
		return nil
	}
	for _, path := range o.managedConfigs(cfg) {
		if strings.Join(words, " ") == binary+" --config "+path {
			return nil
		}
	}
	return []openshell.SettingDrift{{Field: "gateway command", Want: binary + " --config " + cfg, Have: strings.Join(words, " ")}}
}

// managedConfigs are the rendered files the managed unit's exec shim starts
// the account's gateway on: the rendered gateway.toml cfg and, on Linux, the
// docker fallback's and the 1.0.1 upgrade bridge's docker configuration
// (openshell.GatewayDefaultNamespaceTOMLFile, GAP-0587; remove that one
// with the bridge when 1.0.1 is out of support).
func (o *accountOpenShell) managedConfigs(cfg string) []string {
	if o.goos != "linux" {
		return []string{cfg}
	}
	dir := filepath.Dir(cfg)
	return []string{cfg, filepath.Join(dir, openshell.GatewayFallbackTOMLFile), filepath.Join(dir, openshell.GatewayDefaultNamespaceTOMLFile)}
}

// gatewayBinary is the openshell-gateway the managed unit's exec shim runs
// in the install mode ("" when there is none to name).
func (o *accountOpenShell) gatewayBinary(s sandboxrelay.DaemonSettings) string {
	if s.Enterprise.Install == config.EnterpriseOpenShellInstallSetup {
		if o.home == "" {
			return ""
		}
		return filepath.Join(o.home, ".local", "bin", openshell.GatewayBinary)
	}
	if o.adminBinary == nil {
		return ""
	}
	path, err := o.adminBinary(openshell.GatewayBinary)
	if err != nil {
		return ""
	}
	return path
}

// PortHolder reports who listens on the account's gateway port.
func (o *accountOpenShell) PortHolder(s sandboxrelay.DaemonSettings) (int, bool) {
	return o.portHolder(gatewayPort(s))
}

// OtherGateways lists the openshell-gateway processes of this account that
// are not the managed unit's, each as "pid N: command line". Two gateways of
// one account share its MicroVM driver's state directory: the second sweeps
// the first's sandboxes and stops them, which a private gateway started by
// hand did to a running managed sandbox (GAP-0610). Nothing is judged when the
// managed command line is not known: the managed gateway would then be listed
// itself.
func (o *accountOpenShell) OtherGateways(ctx context.Context, s sandboxrelay.DaemonSettings) []string {
	if o.accountProcs == nil {
		return nil
	}
	binary, cfg := o.gatewayBinary(s), s.Enterprise.GatewayConfigPath
	if binary == "" || cfg == "" {
		return nil
	}
	managedCommand := map[string]bool{}
	for _, path := range o.managedConfigs(cfg) {
		managedCommand[binary+" --config "+path] = true
	}
	out, err := o.accountProcs(ctx)
	if err != nil {
		return nil
	}
	var others []string
	for _, line := range strings.Split(out, "\n") {
		words := strings.Fields(line)
		if len(words) < 2 || filepath.Base(words[1]) != openshell.GatewayBinary {
			continue
		}
		if pid, err := strconv.Atoi(words[0]); err != nil || pid == os.Getpid() {
			continue
		}
		command := strings.Join(words[1:], " ")
		if managedCommand[command] {
			continue
		}
		if len(command) > 200 {
			command = command[:200] + "…"
		}
		others = append(others, "pid "+words[0]+": "+command)
	}
	return others
}

// tighterDrift drops the differences that are tighter than the render: an
// OpenShell telemetry the account turned off where the organization allows
// it is no drift.
func tighterDrift(drift []openshell.SettingDrift, want openshell.RenderedGateway) []openshell.SettingDrift {
	var out []openshell.SettingDrift
	for _, d := range drift {
		if d.Field == "OpenShell telemetry" && want.TelemetryEnabled {
			continue
		}
		out = append(out, d)
	}
	return out
}

// Prepare readies the account's OpenShell: in setup mode it installs the
// pinned release first; in both modes it starts the account's gateway unit
// and registers the gateway with the OpenShell CLI of the install mode.
func (o *accountOpenShell) Prepare(ctx context.Context, s sandboxrelay.DaemonSettings) (bool, error) {
	port := gatewayPort(s)
	cli := ""
	if s.Enterprise.Install == config.EnterpriseOpenShellInstallSetup {
		if o.home == "" {
			return false, openShellPrerequisiteError("your account has no home directory to install OpenShell into")
		}
		// A gateway of this account that already listens runs the install this
		// process checked; one that must be started gets its files checked
		// again first (the installer hashes them and downloads nothing when
		// they are intact).
		holder, held := o.portHolder(port)
		if err := o.ensureInstalled(ctx, s.Enterprise.Version, !held || holder != o.uid); err != nil {
			return false, err
		}
		cli = openShellCLI(o.home)
	} else {
		// The administrator's OpenShell: found before anything is started,
		// so a missing or untrusted install is said in one place.
		var err error
		if cli, err = o.adminBinary(openshell.DefaultBinary); err != nil {
			return false, openShellPrerequisiteError("the administrator's OpenShell is not usable: %v", err)
		}
	}
	started, err := o.ensureRunning(ctx, port, s.Enterprise.GatewayConfigPath)
	if err != nil {
		return started, err
	}
	return started, o.ensureRegistered(ctx, cli, gatewayRegistrationName(s), port)
}

// otherAccountManagedGateway reports a managed gateway, the managed unit's
// command line on the rendered configuration cfg on any port, that another
// account runs (false when the processes cannot be listed). Every managed
// docker gateway keeps its sandboxes in one namespace
// (openshell.ManagedDockerNamespace), and a docker gateway's start
// force-removes that namespace's supervisors, so one started while another
// account's runs ends that account's sandboxes. The one managed port keeps
// them apart while both use it, but an account whose gateway_port switch
// waits for its sandboxes to stop still runs its gateway on the old port
// while the new one is free (GAP-0566). The gateways of the 1.0.1 upgrade
// bridge share OpenShell's default namespace the same way, so they count
// too (managedConfigs).
func (o *accountOpenShell) otherAccountManagedGateway(ctx context.Context, cfg string) bool {
	if o.hostProcs == nil || cfg == "" {
		return false
	}
	configs := map[string]bool{}
	for _, path := range o.managedConfigs(cfg) {
		configs[path] = true
	}
	out, err := o.hostProcs(ctx)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		words := strings.Fields(line)
		// uid pid <openshell-gateway> --config <rendered file>: the binary
		// is the install mode's (the account's own in setup mode), the
		// configuration the administrator's.
		if len(words) != 5 || filepath.Base(words[2]) != openshell.GatewayBinary || words[3] != "--config" || !configs[words[4]] {
			continue
		}
		if uid, err := strconv.Atoi(words[0]); err == nil && uid != o.uid {
			return true
		}
	}
	return false
}

// ensureInstalled installs the pinned release: once per process unless
// recheck is set. The installer itself downloads nothing when an intact
// install of the release is there.
func (o *accountOpenShell) ensureInstalled(ctx context.Context, version string, recheck bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if version == "" {
		return openShellPrerequisiteError("setup mode needs enterprise.openshell.version to be an exact release; ask IT to set it")
	}
	if o.installed == version && !recheck {
		return nil
	}
	res, err := o.install(ctx, version, o.home)
	if err != nil {
		return openShellPrerequisiteError("OpenShell %s could not be installed into your ~/.local: %v", version, err)
	}
	if !res.Already {
		o.logf("installed OpenShell %s from NVIDIA's release tarballs (%d files)", version, len(res.Files))
	}
	o.installed = version
	return nil
}

// ensureRunning starts the account's gateway unit unless the gateway port
// is already this account's, and waits until it is. Another account's
// listener on the port, or another account's managed gateway on the
// rendered configuration cfg on any port, refuses with the neutral
// account-busy text.
func (o *accountOpenShell) ensureRunning(ctx context.Context, port int, cfg string) (bool, error) {
	if holder, held := o.portHolder(port); held {
		if holder == o.uid {
			return false, nil
		}
		return false, accountBusyError()
	}
	if o.otherAccountManagedGateway(ctx, cfg) {
		// Neutral, like the refusal: whose gateway it is stays out of this
		// account's log.
		o.logf("another account's managed OpenShell gateway runs: yours starts once it has stopped")
		return false, accountBusyError()
	}
	reloaded, err := o.startUnit(ctx)
	if err != nil {
		// The service manager's command line and job text stay in the log:
		// they name nothing the person can act on (#1202).
		o.logf("start your OpenShell gateway: %v", err)
		if holder, held := o.portHolder(port); held && holder != o.uid {
			// Another account's gateway holds the port (its idle gateway
			// had not stopped yet), so this account's could not bind it.
			return true, accountBusyError()
		}
		var reloadErr *openShellLaunchAgentReloadError
		if errors.As(err, &reloadErr) {
			return true, openShellPrerequisiteError("your OpenShell gateway's LaunchAgent could not be reloaded; run `%s`", openShellGatewayRepairCommand)
		}
		// The unit's state stays in the log too (#1202, GAP-0419).
		state := o.unitState(ctx)
		o.logf("your OpenShell gateway could not be started: %s", state)
		return true, openShellPrerequisiteError("your OpenShell gateway could not be started%s; "+
			"`defenseclaw sandbox doctor` shows why", unitStateForPerson(state))
	}
	deadline := time.Now().Add(openShellGatewayStartWait)
	healAt := time.Now().Add(openShellGatewayHealAfter)
	healChecked := reloaded
	restartAt, restarts := time.Now().Add(openShellGatewayRestartEvery), 0
	for {
		if holder, held := o.portHolder(port); held {
			if holder == o.uid {
				o.logf("your OpenShell gateway listens on 127.0.0.1:%d", port)
				return true, nil
			}
			return true, accountBusyError()
		}
		if time.Now().After(deadline) {
			// The address and the unit's state are for the log; the person
			// reads a sentence (GAP-0419).
			state := o.unitState(ctx)
			o.logf("your OpenShell gateway did not start listening on 127.0.0.1:%d within %s (%s)", port, openShellGatewayStartWait, state)
			return true, openShellPrerequisiteError("your OpenShell gateway did not start listening within %s%s; "+
				"`defenseclaw sandbox doctor` shows why", openShellGatewayStartWait, unitStateForPerson(state))
		}
		if o.goos == "linux" && restarts < openShellGatewayRestarts && !time.Now().Before(restartAt) {
			restartAt = time.Now().Add(openShellGatewayRestartEvery)
			if o.unitStopped(ctx) {
				restarts++
				o.logf("your OpenShell gateway stopped before it listened (%s): starting it again", o.unitState(ctx))
				if _, err := o.startUnit(ctx); err != nil {
					o.logf("start your OpenShell gateway again: %v", err)
				}
			}
		}
		if o.goos == "darwin" && !healChecked && !time.Now().Before(healAt) {
			healChecked = true
			domain := o.launchDomain(ctx)
			label, _ := openShellGatewayAgent()
			target := domain + "/" + label
			out, printErr := o.run(ctx, daemonLaunchctl, []string{"print", target}, nil)
			if printErr == nil && openshell.ParseLaunchAgentState([]byte(out)).Failure(false) != "" {
				if err := o.reloadLaunchAgent(ctx, domain); err != nil {
					o.logf("reload your OpenShell gateway LaunchAgent: %v", err)
					return true, openShellPrerequisiteError("your OpenShell gateway's LaunchAgent could not be reloaded; run `%s`", openShellGatewayRepairCommand)
				}
				if err := o.kickstartLaunchAgent(ctx, target); err != nil {
					o.logf("start your reloaded OpenShell gateway LaunchAgent: %v", err)
					return true, openShellPrerequisiteError("your OpenShell gateway could not be started (%s); `defenseclaw sandbox doctor` shows why", o.unitState(ctx))
				}
			}
		}
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-time.After(openShellGatewayPollEvery):
		}
	}
}

// ensureRegistered registers the gateway with the account's openshell CLI
// unless a usable registration of that name already points at it with the
// client certificates of the managed gateway's local PKI. A registration of
// that name pointing elsewhere, or holding other certificates, is replaced:
// another OpenShell gateway the account starts writes its own client
// certificates into the registration of the default name when it starts,
// and the account's openshell CLI then fails every call to the managed
// gateway with BadSignature (GAP-0495).
func (o *accountOpenShell) ensureRegistered(ctx context.Context, cli, name string, port int) error {
	tlsDir := filepath.Join(o.home, filepath.FromSlash(openShellTLSDirRel))
	if reg, err := o.discover(openshell.DiscoverOptions{Gateway: name}); err == nil && registrationPortOf(reg) == port {
		// Only the managed unit's gateway is known to use tlsDir: another
		// gateway of the account's (NVIDIA's or Homebrew's own service) has
		// its own PKI, which the registration rightly holds.
		if registrationHasClientOf(reg, tlsDir) || !o.managedUnitActive(ctx) {
			return nil
		}
		o.logf("the OpenShell registration %s holds client certificates that are not your managed gateway's (another gateway of your account wrote them); registering it again", name)
	}
	env := append(os.Environ(), openshell.EnvLocalTLSDir+"="+tlsDir)
	if dir, err := o.configDir(); err == nil {
		if _, err := os.Lstat(filepath.Join(dir, "gateways", name, "metadata.json")); err == nil {
			if out, err := o.run(ctx, cli, []string{"gateway", "remove", name}, env); err != nil {
				o.logf("replace the OpenShell registration %s: gateway remove: %v: %s", name, err, firstOutputLine(out))
			}
		}
	}
	if dir, err := o.configDir(); err == nil {
		// The openshell CLI stores the gateway's mTLS bundle below this
		// folder and reports a folder it cannot write as "failed to store
		// mTLS bundle": say which folder the account cannot write instead
		// (GAP-0588).
		if err := configDirWritable(dir); err != nil {
			return openShellPrerequisiteError("%v", err)
		}
	}
	endpoint := "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if out, err := o.run(ctx, cli, []string{"gateway", "add", endpoint, "--local", "--name", name}, env); err != nil {
		return openShellPrerequisiteError("your OpenShell gateway could not be registered with your openshell CLI: %v: %s", err, firstOutputLine(out))
	}
	reg, err := o.discover(openshell.DiscoverOptions{Gateway: name})
	if err != nil {
		return openShellPrerequisiteError("the OpenShell registration %s is not usable: %v", name, err)
	}
	if p := registrationPortOf(reg); p != port {
		return openShellPrerequisiteError("the OpenShell registration %s points at port %d, not %d", name, p, port)
	}
	o.logf("registered your OpenShell gateway as %s (%s)", name, endpoint)
	return nil
}

// configDirWritable checks that the account can store a gateway registration
// below dir (the openshell CLI's config folder, ~/.config/openshell): the
// folder is made when it is missing, and a file is made and removed in its
// gateways folder. A failure names the folder that stops the account: the
// deepest one that exists, a root-owned ~/.config say (GAP-0588).
func configDirWritable(dir string) error {
	gateways := filepath.Join(dir, "gateways")
	err := os.MkdirAll(gateways, 0o700)
	if err == nil {
		var f *os.File
		if f, err = os.CreateTemp(gateways, ".defenseclaw-write-check-*"); err == nil {
			name := f.Name()
			_ = f.Close()
			_ = os.Remove(name)
			return nil
		}
	}
	blocker := gateways
	for {
		if _, serr := os.Lstat(blocker); serr == nil || blocker == filepath.Dir(blocker) {
			break
		}
		blocker = filepath.Dir(blocker)
	}
	return fmt.Errorf("your account cannot write %s, where your openshell CLI keeps its gateway registrations (%v); "+
		"ask IT to give your account ownership of that folder, then run again", blocker, err)
}

// registrationHasClientOf reports whether an mTLS registration holds the
// client certificates of the local PKI in tlsDir (ca.crt, client/tls.crt
// and client/tls.key, which `openshell gateway add --local` copies). A
// registration without mTLS files, or a PKI that cannot be read, is not
// judged: there is nothing to compare it with.
func registrationHasClientOf(reg *openshell.Registration, tlsDir string) bool {
	if reg == nil || reg.TLS == nil {
		return true
	}
	pairs := [][2]string{
		{reg.TLS.CA, filepath.Join(tlsDir, "ca.crt")},
		{reg.TLS.Cert, filepath.Join(tlsDir, "client", "tls.crt")},
		{reg.TLS.Key, filepath.Join(tlsDir, "client", "tls.key")},
	}
	for _, p := range pairs {
		want, err := readBounded(p[1], 1<<20)
		if err != nil || want == nil {
			return true
		}
		have, err := readBounded(p[0], 1<<20)
		if err != nil || !bytes.Equal(have, want) {
			return false
		}
	}
	return true
}

// managedUnitActive reports whether the account's managed gateway unit runs:
// the gateway on the port is then the one that runs the rendered
// configuration.
func (o *accountOpenShell) managedUnitActive(ctx context.Context) bool {
	switch o.goos {
	case "linux":
		out, err := o.run(ctx, daemonSystemctl, []string{"--user", "is-active", openShellGatewayUnit}, userManagerEnv(o.uid))
		return err == nil && strings.TrimSpace(out) == "active"
	case "darwin":
		label, _ := openShellGatewayAgent()
		out, err := o.run(ctx, daemonLaunchctl, []string{"print", o.launchDomain(ctx) + "/" + label}, nil)
		return err == nil && strings.Contains(out, "state = running")
	}
	return false
}

// Stop stops the account's managed gateway unit (no sandbox of the account
// runs), so the gateway port is free for the next account. A gateway the
// managed unit did not start is the account's own and is left running.
func (o *accountOpenShell) Stop(ctx context.Context, s sandboxrelay.DaemonSettings) bool {
	if s.Enterprise.Install != config.EnterpriseOpenShellInstallSetup && !o.managedUnitActive(ctx) {
		return false
	}
	var err error
	var out string
	switch o.goos {
	case "linux":
		out, err = o.run(ctx, daemonSystemctl, []string{"--user", "stop", openShellGatewayUnit}, userManagerEnv(o.uid))
	case "darwin":
		label, _ := openShellGatewayAgent()
		target := o.launchDomain(ctx) + "/" + label
		if _, perr := o.run(ctx, daemonLaunchctl, []string{"print", target}, nil); perr != nil {
			return false
		}
		o.syncBeforeStop(ctx, s)
		out, err = o.run(ctx, daemonLaunchctl, []string{"kill", "SIGTERM", target}, nil)
	default:
		return false
	}
	if err != nil {
		o.logf("stop your OpenShell gateway: %v: %s", err, firstOutputLine(out))
		return false
	}
	o.logf("stopped your OpenShell gateway: no sandbox of yours runs")
	return true
}

// syncBeforeStop syncs the disk of every MicroVM the account's gateway lists
// ready right before the macOS stop of its LaunchAgent (GAP-0380). The
// daemon counted none a moment ago, but a raw openshell client can start one
// in between, and the gateway's stop ends it with what its guest had not
// synced. On Linux the managed unit's second ExecStop does this
// (sandbox-daemon sync-sandboxes --managed); launchd runs no stop command.
// A sandbox it could not sync is noted for the feed (stop_unflushed); the
// stop goes ahead either way, as on Linux.
func (o *accountOpenShell) syncBeforeStop(ctx context.Context, s sandboxrelay.DaemonSettings) {
	if o.stopSync == nil {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, openshell.StopSyncTimeout)
	defer cancel()
	var out bytes.Buffer
	err := o.stopSync(sctx, gatewayRegistrationName(s), &out)
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line != "" {
			o.logf("%s", line)
		}
	}
	names := openshell.UnsyncedSandboxes(err)
	switch {
	case len(names) > 0 && o.recordUnsynced != nil:
		o.recordUnsynced(names)
	case err != nil && len(names) == 0:
		o.logf("sync the MicroVMs before the OpenShell gateway stops: %v", err)
	}
}

// startUnit starts the account's OpenShell gateway unit.
func (o *accountOpenShell) startUnit(ctx context.Context) (bool, error) {
	switch o.goos {
	case "linux":
		out, err := o.run(ctx, daemonSystemctl, []string{"--user", "start", openShellGatewayUnit}, userManagerEnv(o.uid))
		return false, commandError(daemonSystemctl+" --user start "+openShellGatewayUnit, out, err)
	case "darwin":
		domain := o.launchDomain(ctx)
		label, plist := openShellGatewayAgent()
		target := domain + "/" + label
		printed, err := o.run(ctx, daemonLaunchctl, []string{"print", target}, nil)
		if err != nil {
			out, err := o.run(ctx, daemonLaunchctl, []string{"bootstrap", domain, plist}, nil)
			if err := commandError(daemonLaunchctl+" bootstrap "+domain, out, err); err != nil {
				return false, err
			}
		} else if openshell.ParseLaunchAgentState([]byte(printed)).Failure(false) != "" {
			if err := o.reloadLaunchAgent(ctx, domain); err != nil {
				return false, err
			}
			return true, o.kickstartLaunchAgent(ctx, target)
		}
		return false, o.kickstartLaunchAgent(ctx, target)
	}
	return false, fmt.Errorf("sandboxes run on Linux and macOS only")
}

type openShellLaunchAgentReloadError struct{ err error }

func (e *openShellLaunchAgentReloadError) Error() string {
	return "your OpenShell gateway's LaunchAgent could not be reloaded; run `" + openShellGatewayRepairCommand + "`: " + e.err.Error()
}
func (e *openShellLaunchAgentReloadError) Unwrap() error { return e.err }

func (o *accountOpenShell) reloadLaunchAgent(ctx context.Context, domain string) error {
	label, plist := openShellGatewayAgent()
	target := domain + "/" + label
	if out, err := o.run(ctx, daemonLaunchctl, []string{"bootout", target}, nil); err != nil {
		o.logf("boot out your OpenShell gateway LaunchAgent: %v: %s", err, firstOutputLine(out))
	}
	out, err := o.run(ctx, daemonLaunchctl, []string{"bootstrap", domain, plist}, nil)
	if err := commandError(daemonLaunchctl+" bootstrap "+domain, out, err); err != nil {
		return &openShellLaunchAgentReloadError{err: err}
	}
	return nil
}

func (o *accountOpenShell) kickstartLaunchAgent(ctx context.Context, target string) error {
	out, err := o.run(ctx, daemonLaunchctl, []string{"kickstart", target}, nil)
	return commandError(daemonLaunchctl+" kickstart "+target, out, err)
}

// launchDomain is the launchd domain of the account's OpenShell gateway
// agent (openshell.LaunchDomain): the one its job is loaded in, else the
// graphical session when there is one, else the background session of an
// ssh login.
func (o *accountOpenShell) launchDomain(ctx context.Context) string {
	label, _ := openShellGatewayAgent()
	domain, _ := openshell.LaunchDomain(o.uid, openshell.GatewayAgentBase, label, func(domain string) (string, error) {
		return o.run(ctx, daemonLaunchctl, []string{"print", domain}, nil)
	})
	return domain
}

var launchdLastExit = lazyregexp.New(`last exit code = (\d+)`)

// unitState says what the gateway unit is doing, for a start that timed out.
// unitStateForPerson is unitState as the person reads it, in parentheses:
// the sentences they can act on (the unit is missing, a prerequisite of the
// account is missing). The service manager's raw states (active and sub
// state, exit status, unknown) are for the log only (GAP-0419, #1202).
func unitStateForPerson(state string) string {
	if strings.HasPrefix(state, "its service unit was not found") || strings.HasPrefix(state, "it exited 78") {
		return " (" + state + ")"
	}
	return ""
}

// unitStopped reports whether the account's gateway unit is inactive or
// failed (Linux), but not for the exec shim's exit 78 (a missing
// prerequisite, which another start does not fix).
func (o *accountOpenShell) unitStopped(ctx context.Context) bool {
	out, err := o.run(ctx, daemonSystemctl, []string{"--user", "show", "-p", "ActiveState", "-p", "ExecMainStatus", openShellGatewayUnit}, userManagerEnv(o.uid))
	if err != nil {
		return false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			fields[k] = v
		}
	}
	state := fields["ActiveState"]
	return (state == "inactive" || state == "failed") && fields["ExecMainStatus"] != strconv.Itoa(78)
}

// Exit status 78 is the exec shim's: a prerequisite of the account is missing.
func (o *accountOpenShell) unitState(ctx context.Context) string {
	status := ""
	switch o.goos {
	case "linux":
		out, err := o.run(ctx, daemonSystemctl, []string{"--user", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "ExecMainStatus", openShellGatewayUnit}, userManagerEnv(o.uid))
		if err != nil {
			return "its state is unknown"
		}
		fields := map[string]string{}
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				fields[k] = v
			}
		}
		switch {
		case fields["LoadState"] == "not-found":
			return "its service unit was not found on this computer"
		case fields["ActiveState"] == "":
			return "its state is unknown"
		}
		status = fields["ExecMainStatus"]
		if status != strconv.Itoa(78) {
			return fmt.Sprintf("the unit is %s/%s, last exit status %s", fields["ActiveState"], fields["SubState"], firstNonEmptyString(status, "none"))
		}
	case "darwin":
		label, _ := openShellGatewayAgent()
		out, err := o.run(ctx, daemonLaunchctl, []string{"print", o.launchDomain(ctx) + "/" + label}, nil)
		if err != nil {
			return "its state is unknown"
		}
		m := launchdLastExit.FindStringSubmatch(out)
		if m == nil {
			return "it has not exited"
		}
		if status = m[1]; status != strconv.Itoa(78) {
			return "its last exit code is " + status
		}
	default:
		return "its state is unknown"
	}
	return "it exited 78: a prerequisite of your account is missing"
}

// registrationPortOf is the port of a registration's endpoint (0 when it
// has none).
func registrationPortOf(reg *openshell.Registration) int {
	if reg == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(reg.Target())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

// loopbackPortHolder reports who listens on 127.0.0.1:port. A port that
// accepts connections but has no listener this process can see (macOS lsof
// lists only this account's processes) is another account's (-1).
func loopbackPortHolder(port int) (int, bool) {
	return portHolderSeen(port, daemon.FindPortHolder, func(addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", addr, time.Second)
	})
}

// portHolderSeen is loopbackPortHolder with its lookup and dial. The
// listener is looked up again after a dial that connected: the account's
// own gateway that starts listening between the first lookup and the dial
// (the daemon polls the port while the gateway it just started binds it)
// is then seen as the account's, not as another account's (r103 GAP-0038:
// a fresh run after kept sandboxes was refused as "another account is
// using them" the moment its own gateway came up).
func portHolderSeen(port int, find func(string, int) (daemon.PortHolder, error), dial func(string) (net.Conn, error)) (int, bool) {
	holder, err := find("127.0.0.1", port)
	if err == nil && holder.UID >= 0 {
		return holder.UID, true
	}
	conn, derr := dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if derr != nil {
		return 0, false
	}
	_ = conn.Close()
	if holder, err := find("127.0.0.1", port); err == nil && holder.UID >= 0 {
		return holder.UID, true
	}
	return -1, true
}

// loopbackPortPID is the process that listens on 127.0.0.1:port, 0 when
// none this account can see does.
func loopbackPortPID(port int) int {
	holder, err := daemon.FindPortHolder("127.0.0.1", port)
	if err != nil {
		return 0
	}
	return holder.PID
}

// processArgs is the command line of one of the account's processes, its
// words joined by spaces: /proc/<pid>/cmdline on Linux, ps on macOS.
func processArgs(ctx context.Context, pid int) (string, error) {
	if runtime.GOOS == "linux" {
		data, err := readBounded("/proc/"+strconv.Itoa(pid)+"/cmdline", 1<<16)
		if err != nil || data == nil {
			return "", fmt.Errorf("read the command line of process %d: %v", pid, err)
		}
		return strings.Join(strings.Fields(strings.ReplaceAll(string(data), "\x00", " ")), " "), nil
	}
	out, err := runServiceCommand(ctx, "/bin/ps", []string{"-ww", "-o", "args=", "-p", strconv.Itoa(pid)}, nil)
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(out), " "), nil
}

// runServiceCommand runs one command and returns its combined output.
func runServiceCommand(ctx context.Context, name string, args, env []string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// userManagerEnv is the environment `systemctl --user` finds the account's
// manager with: the daemon's own, plus the runtime directory when the
// daemon was started without one.
func userManagerEnv(uid int) []string {
	env := os.Environ()
	for _, entry := range env {
		if strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
			return env
		}
	}
	dir := "/run/user/" + strconv.Itoa(uid)
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		env = append(env, "XDG_RUNTIME_DIR="+dir)
	}
	return env
}

// commandError folds a command's output into its error.
func commandError(what, out string, err error) error {
	if err == nil {
		return nil
	}
	if line := firstOutputLine(out); line != "" {
		return fmt.Errorf("%s: %s", what, line)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func firstOutputLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}

// driftFieldInvalid is what an event's settings field may not hold
// (defenseclaw.openshell.settings.field is ^[a-z][a-z0-9_.]{0,63}$).
var driftFieldInvalid = lazyregexp.New(`[^a-z0-9_.]+`)

// driftEventField is a drift's field as the settings_drift record names it:
// "gateway listener" is gateway_listener.
func driftEventField(field string) string {
	f := strings.Trim(driftFieldInvalid.ReplaceAllString(strings.ToLower(field), "_"), "_.")
	if len(f) > 64 {
		f = f[:64]
	}
	if f == "" || f[0] < 'a' || f[0] > 'z' {
		return "gateway_configuration"
	}
	return f
}

// driftFields joins the fields of drift for the user's notice.
func driftFields(drift []openshell.SettingDrift) string {
	fields := make([]string, 0, len(drift))
	for _, d := range drift {
		fields = append(fields, d.Field)
	}
	return strings.Join(fields, ", ")
}

// readyOpenShell readies the account's OpenShell for a create or start under
// registration: a gateway of the account's own that drifted from the rendered
// configuration pauses sandboxes and is reported; otherwise the account's
// managed gateway is started and registered (and in setup mode installed
// first). The caller holds the lifecycle.
func (d *SandboxDaemon) readyOpenShell(ctx context.Context, s sandboxrelay.DaemonSettings, registration string) error {
	drift, err := d.openShell.Drift(s)
	if err != nil {
		return openShellPrerequisiteError("the administrator's rendered OpenShell configuration cannot be read: %v", err)
	}
	if len(drift) > 0 {
		for _, item := range drift {
			d.logf("OpenShell settings drift: %s", item)
		}
		d.reportDrift(ctx, registration, drift)
		drift = blockingOpenShellDrift(drift)
	}
	if len(drift) > 0 {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: sandboxapi.SettingsDrift(driftFields(drift)), Detail: sandboxrelay.EventSettingsDrift}
	}
	return d.prepareOpenShell(ctx, s)
}

// A changed rendered file is reported to the organization, while a user
// sandbox keeps its prior create/start behavior until the administrator
// repairs that file. Other setting differences retain their existing pause.
func blockingOpenShellDrift(drift []openshell.SettingDrift) []openshell.SettingDrift {
	var blocking []openshell.SettingDrift
	for _, item := range drift {
		if item.Field != renderedGatewayDriftField || item.Have != "changed" {
			blocking = append(blocking, item)
		}
	}
	return blocking
}

// prepareOpenShell starts and registers the account's OpenShell gateway
// (openShell.Prepare) and keeps it for openShellGatewayLinger. The caller
// holds the lifecycle.
func (d *SandboxDaemon) prepareOpenShell(ctx context.Context, s sandboxrelay.DaemonSettings) error {
	started, err := d.openShell.Prepare(ctx, s)
	if (started || err == nil) && d.rt != nil && d.rt.manager != nil {
		// The manager may have just failed to reach the gateway that was
		// not running or not registered yet: dial it again now.
		d.rt.manager.ForgetGatewayError()
	}
	if err == nil {
		d.openShellUsed.Store(time.Now().UnixNano())
	}
	return err
}

// openShellForKept readies the account's gateway for a call on a kept
// sandbox (stop, delete, or a list that cannot say a phase): the daemon
// stops the gateway when no sandbox of the account runs, and a stopped
// gateway refused those calls with "nothing listens on 127.0.0.1:<port>"
// (GAP-0492). A gateway of the account that listens is used as it is;
// another account's refuses with the neutral account-busy text. wait says
// whether to wait for a create or start in progress (a list does not).
func (d *SandboxDaemon) openShellForKept(ctx context.Context, wait bool) error {
	s := d.currentSettings()
	if uid, held := d.openShell.PortHolder(s); held {
		if uid == d.uid {
			return nil
		}
		return accountBusyError()
	}
	if wait {
		if err := d.lockLifecycle(ctx); err != nil {
			return managedBusyError(err)
		}
	} else if !d.tryLockLifecycle() {
		return managedBusyError(errors.New("a create or start is in progress"))
	}
	defer d.unlockLifecycle()
	return d.prepareOpenShell(ctx, s)
}

// keepOpenShellLocked repairs the account's gateway registration while a
// sandbox of the account runs (another gateway the account started may have
// overwritten its client certificates, GAP-0495): only for the account's own
// gateway on the port with no settings drift. The caller holds the
// lifecycle.
func (d *SandboxDaemon) keepOpenShellLocked(ctx context.Context) {
	s := d.currentSettings()
	if uid, held := d.openShell.PortHolder(s); !held || uid != d.uid {
		return
	}
	if drift, err := d.openShell.Drift(s); err != nil || len(blockingOpenShellDrift(drift)) > 0 {
		return
	}
	if _, err := d.openShell.Prepare(ctx, s); err != nil {
		d.logf("check your OpenShell gateway registration: %v", err)
	}
}

// stopIdleOpenShellLocked stops the account's managed gateway once no
// sandbox of the account runs and openShellGatewayLinger has passed since
// the daemon last readied it, so the one gateway port is free for the next
// account at once, not when the daemon idles out after 30 minutes
// (GAP-0465). handover says a stop or delete of the account's last sandbox
// asks (handoverOpenShell). The caller holds the lifecycle.
func (d *SandboxDaemon) stopIdleOpenShellLocked(ctx context.Context, handover bool) {
	if since := time.Since(time.Unix(0, d.openShellUsed.Load())); since < openShellGatewayLinger {
		d.scheduleCheck(openShellGatewayLinger - since + time.Second)
		return
	}
	s := d.currentSettings()
	if uid, held := d.openShell.PortHolder(s); !held || uid != d.uid {
		return
	}
	if d.rt != nil && d.rt.manager != nil {
		// No sandbox of the account runs, but one made with OpenShell's own
		// CLI may: sweep the gateway for foreign sandboxes first, so they
		// are stopped and recorded for the managed gateway under the
		// organization's foreign_sandboxes policy. Stopped at once, a raw
		// sandbox went to error with its gateway and no foreign_sandbox
		// record reached the administrator (GAP-0263).
		// The person's foreign_sandboxes in the managed settings decides
		// while no registration names a floor (GAP-0058): read them again
		// when they are stale.
		d.refreshStaleSettings(ctx)
		sweep, cancel := context.WithTimeout(ctx, foreignSweepTimeout)
		running, err := d.sweepForeign(sweep)
		cancel()
		switch {
		case err != nil && !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable):
			// The gateway answered, but its sandboxes could not be read:
			// nothing proves that none of the account's runs, so it is kept,
			// and looked at again soon.
			d.logf("check the OpenShell gateway for sandboxes before stopping it: %v; it keeps running", err)
			d.scheduleCheck(foreignRecheckEvery)
			return
		case err != nil:
			// DefenseClaw cannot connect to it (Unavailable), and its
			// port is this account's (PortHolder): a gateway whose
			// registration or certificates broke still runs its MicroVMs,
			// which the stop would end with no flush. Only the account's
			// processes tell that none runs.
			if n, verr := d.microVMs(ctx); verr != nil || n > 0 {
				d.logf("the OpenShell gateway does not answer (%v) and %s; it keeps running", err, microVMsHeld(n, verr))
				d.scheduleCheck(foreignRecheckEvery)
				return
			}
		case !running:
		case handover:
			// One the policy leaves running (alert) does not hold the one
			// gateway port against the next account once the person's last
			// sandbox ended: it was recorded above and stops with the
			// gateway, so the hand-over still ends within the sweep's bound
			// (GAP-0237).
			d.logf("the last sandbox ended: stopping the OpenShell gateway with the sandboxes DefenseClaw did not start on it")
		default:
			// Otherwise it keeps its gateway while it runs; look again soon,
			// so the port is free shortly after it ends (GAP-0237).
			d.scheduleCheck(foreignRecheckEvery)
			return
		}
		// The sweep read the gateway's sandboxes afresh, right before the
		// stop: one of the account's that OpenShell does not report stopped
		// (started since the count, by another OpenShell client) keeps it
		// (manager.HoldsCompute).
		if n, err := d.runningSandboxes(ctx); err != nil || n > 0 {
			d.scheduleCheck(foreignRecheckEvery)
			return
		}
	}
	if d.openShell.Stop(ctx, s) && d.rt != nil && d.rt.manager != nil {
		d.rt.manager.GatewayStopped()
	}
}

// sweepForeign reconciles the account's gateway, which stops or reports
// the foreign sandboxes on it under foreign_sandboxes, and reports whether
// the policy leaves one running there.
func (d *SandboxDaemon) sweepForeign(ctx context.Context) (bool, error) {
	if d.opts.sweepForeign != nil {
		return d.opts.sweepForeign(ctx)
	}
	if err := d.rt.manager.Reconcile(ctx); err != nil {
		return false, err
	}
	return d.rt.manager.ForeignSandboxesRunning(), nil
}

// handoverOpenShell releases the shared gateway port before a successful
// stop or delete returns. A preflight still gets its linger; completed
// lifecycle work does not keep the previous account's idle gateway alive.
func (d *SandboxDaemon) handoverOpenShell(ctx context.Context) {
	if d.stops.Load() != 1 {
		d.openShellUsed.Store(0)
		return // another stop or delete still uses the gateway
	}
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), foreignSweepTimeout+15*time.Second)
	defer cancel()
	if err := d.lockLifecycle(check); err != nil {
		d.openShellUsed.Store(0)
		d.scheduleCheck(time.Second)
		return
	}
	defer d.unlockLifecycle()
	n, err := d.runningSandboxes(check)
	if err != nil || n != 0 {
		return
	}
	d.releaseListeners()
	d.openShellUsed.Store(0)
	d.stopIdleOpenShellLocked(check, true)
}

// foreignSweepTimeout bounds the foreign-sandbox sweep before an idle
// gateway stops.
const foreignSweepTimeout = 30 * time.Second

// foreignRecheckEvery is how often an idle gateway that a foreign sandbox
// keeps is looked at again (stopIdleOpenShellLocked). A variable for tests.
var foreignRecheckEvery = 15 * time.Second

// accountBusyReportEvery paces the account-busy reports: a client that retries
// in a loop sends at most one batch per interval, which carries every refusal
// since the last one. accountBusyRetryMax bounds the wait between retries of
// a batch the managed gateway did not take. Variables for tests.
var (
	accountBusyReportEvery = 5 * time.Second
	accountBusyRetryMax    = 5 * time.Minute
)

// accountBusyReports are the account-busy refusals not yet taken by the
// managed gateway: at most MaxUnregisteredEventRecords, each its own record.
type accountBusyReports struct {
	mu       sync.Mutex
	pending  []sandboxrelay.Event
	dropped  int // refusals beyond the bound since the last batch (logged)
	lastSent time.Time
	backoff  time.Duration // after a failed batch; zero once one is taken
	sending  bool
	timer    *time.Timer
}

// reportAccountBusy tells the managed gateway that a run of the account was
// refused because another account is using the sandboxes of this computer
// (err is the refusal), so the refusal is in the managed audit and telemetry
// with the reason account_busy (GAP-0598). The refusal comes before any
// registration exists, so the record goes without one; it names nobody else.
// harnessName is the agent of the run when the refusal knows it. Every
// refusal is kept until a batch reaches the gateway: one inside the pace goes
// with the next batch, and a batch that failed is sent again (GAP-0660). The
// refusal itself never depends on the report.
func (d *SandboxDaemon) reportAccountBusy(ctx context.Context, harnessName string, err error) {
	if e := sandboxapi.AsError(err); e == nil || e.Detail != SandboxAccountBusyReason || d.relay == nil {
		return
	}
	raw, marshalErr := json.Marshal(map[string]string{"harness": harnessName})
	if marshalErr != nil {
		return
	}
	ev := sandboxrelay.Event{Kind: sandboxrelay.EventAccountBusy, Time: time.Now().UTC(), Payload: raw}
	d.busy.mu.Lock()
	if len(d.busy.pending) >= sandboxrelay.MaxUnregisteredEventRecords {
		d.busy.dropped++
	} else {
		d.busy.pending = append(d.busy.pending, ev)
	}
	d.busy.mu.Unlock()
	d.flushAccountBusy(ctx)
}

// flushAccountBusy sends the pending account-busy refusals in one batch when
// the pace allows, and otherwise schedules the batch for when it does.
func (d *SandboxDaemon) flushAccountBusy(ctx context.Context) {
	b := &d.busy
	b.mu.Lock()
	if b.sending || len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	if wait := time.Until(b.lastSent.Add(max(accountBusyReportEvery, b.backoff))); wait > 0 {
		d.scheduleAccountBusyLocked(wait)
		b.mu.Unlock()
		return
	}
	events, dropped := b.pending, b.dropped
	b.pending, b.dropped, b.sending, b.lastSent = nil, 0, true, time.Now()
	b.mu.Unlock()
	if dropped > 0 {
		d.logf("%d more account-busy refusals inside %s were not reported", dropped, accountBusyReportEvery)
	}
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	relayErr := d.relay.Events(reportCtx, sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Events: events})
	cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sending = false
	if relayErr != nil {
		d.logf("report %d account-busy refusals (sent again later): %v", len(events), relayErr)
		b.pending = append(events, b.pending...)
		if over := len(b.pending) - sandboxrelay.MaxUnregisteredEventRecords; over > 0 {
			b.pending, b.dropped = b.pending[:sandboxrelay.MaxUnregisteredEventRecords], b.dropped+over
		}
		b.backoff = min(max(2*b.backoff, accountBusyReportEvery), accountBusyRetryMax)
	} else {
		b.backoff = 0
	}
	if len(b.pending) > 0 {
		d.scheduleAccountBusyLocked(max(accountBusyReportEvery, b.backoff))
	}
}

// scheduleAccountBusyLocked flushes the pending refusals after wait, unless a
// flush is already scheduled. The caller holds d.busy.mu.
func (d *SandboxDaemon) scheduleAccountBusyLocked(wait time.Duration) {
	if d.busy.timer != nil {
		return
	}
	d.busy.timer = time.AfterFunc(wait, func() {
		d.busy.mu.Lock()
		d.busy.timer = nil
		d.busy.mu.Unlock()
		d.flushAccountBusy(context.Background())
	})
}

// reportDrift posts one settings_drift record per field under
// registration; the managed gateway stamps the person and emits them.
func (d *SandboxDaemon) reportDrift(ctx context.Context, registration string, drift []openshell.SettingDrift) {
	if registration == "" {
		return
	}
	now := time.Now().UTC()
	events := make([]sandboxrelay.Event, 0, len(drift))
	for _, item := range drift {
		raw, err := json.Marshal(map[string]string{"field": driftEventField(item.Field)})
		if err != nil {
			continue
		}
		events = append(events, sandboxrelay.Event{Kind: sandboxrelay.EventSettingsDrift, Time: now, Payload: raw})
	}
	if err := d.relay.Events(context.WithoutCancel(ctx), sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: registration, Events: events}); err != nil {
		d.logf("report the OpenShell settings drift: %v", err)
	}
}

// stopOpenShellIfIdle stops the account's managed gateway when the daemon
// exits with no sandbox of the account that holds it (manager.HoldsCompute)
// and no MicroVM running as the account (microVMs: one made with
// OpenShell's own CLI, or one on a gateway DefenseClaw can no longer
// read), which the stop would end with no flush. It counts them right
// before the stop, holding the lifecycle, so no create or start of the
// daemon's comes between; one it cannot take within the bound keeps the
// gateway.
func (d *SandboxDaemon) stopOpenShellIfIdle() {
	s := d.currentSettings()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.lockLifecycle(ctx); err != nil {
		return
	}
	defer d.unlockLifecycle()
	if n, err := d.runningSandboxes(ctx); err != nil || n > 0 {
		return
	}
	if n, err := d.microVMs(ctx); err != nil || n > 0 {
		d.logf("the OpenShell gateway keeps running: %s", microVMsHeld(n, err))
		return
	}
	d.openShell.Stop(ctx, s)
}

// microVMsHeld says why the account's MicroVMs keep its gateway (microVMs
// counted n, or failed with err).
func microVMsHeld(n int, err error) string {
	if err != nil {
		return "the MicroVMs of this account could not be counted (" + err.Error() + ")"
	}
	if n == 1 {
		return "1 MicroVM runs as this account, which the stop would end with no flush"
	}
	return strconv.Itoa(n) + " MicroVMs run as this account, which the stop would end with no flush"
}
