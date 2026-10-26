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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A standalone managed computer runs sandboxes in a per-user sandbox daemon,
// `defenseclaw-gateway sandbox-daemon`, under the user's own account. It
// has no API listener, no guardrails and no config file: its settings come
// from the managed gateway (GET settings on the hook socket), every create
// is resolved and registered there (policy/resolve, bind), and every hook,
// notify, inspect and OTLP call of its sandboxes is relayed there
// (forwarding mode, sandboxRelayForwarder). Its CLI API is the sandbox REST
// API on a 0600 unix socket whose peer must be the daemon's own uid.
//
// The ingress and egress ports are bound at the first create and released
// when the user has no sandbox running (D3): the first account to run a
// sandbox holds them, and another account's create is refused with the
// neutral account-busy text. An idle daemon exits (D10); a restart the
// managed gateway's settings or an upgrade asks for waits until no sandbox
// of the user runs ("pending restart").

// RuntimeOptions select how a sandbox runtime runs (buildSandboxRuntime).
// The zero value is the per-user gateway's runtime.
type RuntimeOptions struct {
	// Managed is a standalone managed computer's per-user sandbox daemon:
	// no config file and no local evaluation. Relay and Settings are
	// required.
	Managed bool
	// Relay is the managed gateway's hook socket.
	Relay sandboxrelay.Client
	// Settings are the managed gateway's daemon settings at start.
	Settings *sandboxrelay.DaemonSettings
}

// Sandbox daemon defaults.
const (
	// DefaultSandboxDaemonIdleAfter is D10's idle exit: no sandbox running
	// and no CLI connection for this long.
	DefaultSandboxDaemonIdleAfter = 30 * time.Minute
	// defaultSandboxDaemonTick paces the idle, restart and listener checks.
	defaultSandboxDaemonTick = time.Minute
	// sandboxDaemonRegistrationsFile keeps the daemon's registrations.
	sandboxDaemonRegistrationsFile = "registrations.json"
)

// SandboxAccountBusyReason is the detail of a create refused because
// another account holds the sandbox ports (D9); the message is Q2's
// neutral text and names nobody.
const SandboxAccountBusyReason = "sandbox_account_busy"

// sandboxAccountBusyMessage is Q2's neutral text: it names nobody, says why
// (one account at a time) and when it clears.
const sandboxAccountBusyMessage = sandboxapi.AccountBusyMessage + " (one account at a time). " +
	"Try again when that account has no sandbox running."

// openShellGatewayLinger is how long the account's OpenShell gateway is
// kept after the daemon last readied it with no sandbox running: a run's
// preflight readies it and its create follows. Then the gateway is stopped,
// which frees the one gateway port for the next account (D9, GAP-0465).
var openShellGatewayLinger = time.Minute

// ErrSandboxDaemonRestart is what Run returns when it exits for a deferred
// restart (an upgrade or a setting change) once no sandbox runs. The
// command exits 0 and the service manager starts the new daemon on the
// next connection.
var ErrSandboxDaemonRestart = errors.New("sandbox daemon: restarting for an upgrade or a setting change")

// SandboxDaemonOptions configure NewSandboxDaemon.
type SandboxDaemonOptions struct {
	RuntimeOptions
	// StateDir is the daemon's state directory (0700, outside
	// ~/.defenseclaw). Required.
	StateDir string
	// Listener is the CLI socket: the socket-activated one, or one
	// BindSandboxDaemonSocket bound. Required.
	Listener net.Listener
	// IdleAfter is the idle exit (DefaultSandboxDaemonIdleAfter when zero,
	// never when negative); Tick paces the checks.
	IdleAfter time.Duration
	Tick      time.Duration
	// PollInterval paces the policy/current poll of each registration
	// (sandboxrelay.PolicyPollInterval when zero).
	PollInterval time.Duration
	// Executable is the binary watched for an upgrade ("" uses
	// os.Executable; "-" watches nothing).
	Executable string
	// Health receives the sandbox subsystem state; nil creates one.
	Health *SidecarHealth
	// Logf receives operational messages; nil writes to stderr.
	Logf func(format string, args ...any)
	// newRuntime builds the runtime and countRunning counts the running
	// sandboxes; tests replace them.
	newRuntime   func(*SandboxDaemon) (*sandboxRuntime, error)
	countRunning func(context.Context) (int, error)
	// countMicroVMs counts the MicroVMs that run as this account
	// (openshell.CountMicroVMs); tests replace it.
	countMicroVMs func(context.Context) (int, error)
	// sweepForeign replaces the foreign-sandbox sweep before an idle
	// gateway stops (SandboxDaemon.sweepForeign); tests only.
	sweepForeign func(context.Context) (bool, error)
	// listPhases is the phase of each sandbox by name (sandboxPhases: the
	// manager's list when nil); tests replace it.
	listPhases func(context.Context) (map[string]string, bool)
	// openShell readies the account's OpenShell (newAccountOpenShell when
	// nil); tests replace it.
	openShell daemonOpenShell
	// goos and vmProbe pick a create's compute driver
	// (SandboxDaemon.selectDriver); tests replace them.
	goos    string
	vmProbe func(sandboxrelay.DaemonSettings) openshell.VMProbeResult
	// dockerEngine checks that the account's Docker answers, which a Mac's
	// MicroVM sandboxes boot their images from (daemonDockerEngine when
	// nil); tests replace it.
	dockerEngine func(context.Context) error
	// mcpRead reads the user's own MCP servers of a harness, user scope
	// only (config.ReadUserMCPServersForConnector when nil in
	// NewSandboxDaemon); tests replace it.
	mcpRead func(connector string) ([]config.MCPServerEntry, error)
}

// SandboxDaemon is a managed computer's per-user sandbox daemon.
type SandboxDaemon struct {
	opts  SandboxDaemonOptions
	uid   int
	relay sandboxrelay.Client
	logf  func(string, ...any)
	api   *APIServer
	rt    *sandboxRuntime
	regs  *daemonRegistrations

	settingsMu sync.RWMutex
	settings   sandboxrelay.DaemonSettings
	// settingsAt is when the settings were last read (UnixNano): a status
	// or a create older than sandboxDaemonSettingsTTL reads them again.
	settingsAt atomic.Int64
	cfg        atomic.Pointer[config.Config]
	// refresh asks the supervision for a policy poll of every registration
	// now: a relayed answer or a confirmation named another policy
	// generation (observeGeneration).
	refresh chan struct{}
	// leases is how fresh each registration's policy is for the new
	// connections of its sandbox's egress proxy (confirmEgressPolicy), and
	// each registration's turn for its policy requests (askPolicy).
	leases egressLeases
	// adoptMu serializes the adoptions of the running sandboxes' floor
	// with the re-resolution of their policies (adoptLocked); adopted is
	// the registration change count (daemonRegistrations.changeCount) the
	// policies in force reflect.
	adoptMu sync.Mutex
	adopted atomic.Uint64

	// floorMu guards the default floor for new runs and no-run views. Existing
	// sandboxes resolve against their own confirmed registration floors.
	floorMu sync.Mutex
	floor   *config.OpenShellAdminConfig

	// Lazy listeners (D3).
	listenMu     sync.Mutex
	listenCancel context.CancelFunc
	listenDone   chan struct{}
	listenFailed atomic.Pointer[listenerFailure]
	runCtx       context.Context

	// lifecycle (capacity 1) serializes managed creates and starts with
	// each other and with the release of the listeners: a create holds it
	// from the resolve through the registration, so no release closes the
	// listeners under it. Each create pins the floor it reads.
	lifecycle chan struct{}
	// conns counts the open CLI connections; lastActive is the last CLI
	// activity (UnixNano).
	conns      atomic.Int64
	lastActive atomic.Int64

	pendingRestart atomic.Bool
	exe            os.FileInfo
	// stops counts the stops and deletes under way. Their sandboxes leave
	// the running phases before OpenShell says they stopped, and the
	// supervision must not stop the account's OpenShell gateway or exit for
	// a pending restart under them (GAP-0462).
	stops atomic.Int64

	// openShellUsed is when the daemon last readied the account's OpenShell
	// gateway (UnixNano), which openShellGatewayLinger keeps; checkNow asks
	// the supervision for a check before its next tick, which checkTimer
	// schedules.
	openShellUsed atomic.Int64
	// busy keeps the runs refused because another account uses the
	// sandboxes until the managed gateway took their reports.
	busy       accountBusyReports
	checkNow   chan struct{}
	checkMu    sync.Mutex
	checkTimer *time.Timer

	// home is the account's home; openShell readies its OpenShell before
	// every create and start (sandbox_daemon_openshell.go).
	home      string
	openShell daemonOpenShell

	// lastDriver is the compute driver the last create chose and why. It
	// supplies a reason only when a running gateway reports that driver.
	lastDriver atomic.Pointer[openshell.DriverChoice]

	// starting holds the names of the sandboxes a Start is starting (name
	// -> struct{}): the policy poll reports them running, not the stopped
	// phase OpenShell lists until a resumed MicroVM is up (#1204).
	starting sync.Map
}

// NewSandboxDaemon prepares the daemon: the sandbox runtime in forwarding
// mode over opts.Relay with opts.Settings, the CLI API and the
// registrations kept in StateDir.
func NewSandboxDaemon(opts SandboxDaemonOptions) (*SandboxDaemon, error) {
	switch {
	case !opts.Managed || opts.Relay == nil || opts.Settings == nil:
		return nil, errors.New("sandbox daemon: the managed gateway relay and its settings are required")
	case opts.StateDir == "" || !filepath.IsAbs(opts.StateDir):
		return nil, errors.New("sandbox daemon: an absolute state directory is required")
	case opts.Listener == nil:
		return nil, errors.New("sandbox daemon: the CLI socket is required")
	}
	uid := os.Getuid()
	if uid <= 0 {
		return nil, errors.New("sandbox daemon: run sandboxes as your own user, not root")
	}
	if opts.IdleAfter == 0 {
		opts.IdleAfter = DefaultSandboxDaemonIdleAfter
	}
	if opts.Tick <= 0 {
		opts.Tick = defaultSandboxDaemonTick
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = sandboxrelay.PolicyPollInterval
	}
	if opts.Health == nil {
		opts.Health = NewSidecarHealth()
	}
	if opts.Logf == nil {
		opts.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[sandbox-daemon] "+format+"\n", args...)
		}
	}
	if opts.newRuntime == nil {
		opts.newRuntime = newSandboxDaemonRuntime
	}
	if opts.goos == "" {
		opts.goos = runtime.GOOS
	}
	if opts.vmProbe == nil {
		opts.vmProbe = daemonVMProbe
	}
	if opts.dockerEngine == nil {
		opts.dockerEngine = daemonDockerEngine
	}
	if opts.mcpRead == nil {
		opts.mcpRead = config.ReadUserMCPServersForConnector
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox daemon: state directory: %w", err)
	}
	if err := os.Chmod(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox daemon: state directory: %w", err)
	}
	regs, err := loadDaemonRegistrations(filepath.Join(opts.StateDir, sandboxDaemonRegistrationsFile))
	if err != nil {
		return nil, err
	}
	d := &SandboxDaemon{
		opts: opts, uid: uid, relay: opts.Relay, logf: opts.Logf, regs: regs,
		settings: *opts.Settings, refresh: make(chan struct{}, 1), lifecycle: make(chan struct{}, 1), checkNow: make(chan struct{}, 1),
		home: accountHome(uid), openShell: opts.openShell,
	}
	if d.openShell == nil {
		d.openShell = newAccountOpenShell(runtime.GOOS, uid, d.home, opts.Logf)
	}
	d.settingsAt.Store(time.Now().UnixNano())
	// The registrations file is the user's own. Until the managed gateway
	// confirms a complete floor, the manager reads the strictest floor.
	d.cfg.Store(d.buildConfig())
	d.touch()
	if exe := opts.Executable; exe != "-" {
		if exe == "" {
			exe, _ = os.Executable()
		}
		if exe != "" {
			if info, err := os.Stat(exe); err == nil {
				d.exe = info
				d.opts.Executable = exe
			}
		}
	}
	cfg := d.config()
	d.api = newAPIServer(managed.StandaloneAPIAddr, opts.Health, nil, nil, nil, cfg)
	rt, err := opts.newRuntime(d)
	if err != nil {
		return nil, err
	}
	d.rt = rt
	return d, nil
}

// newSandboxDaemonRuntime is the daemon's sandbox runtime: the per-user
// gateway's, in forwarding mode, reading the managed settings.
func newSandboxDaemonRuntime(d *SandboxDaemon) (*sandboxRuntime, error) {
	host := &manager.HostUser{UID: d.uid, GID: os.Getgid()}
	return buildSandboxRuntime(d.api, sandboxRuntimeDeps{
		config:           d.config,
		configForSandbox: d.configForSandbox,
		health:           d.opts.Health,
		hostUser:         host,
		// The daemon has no telemetry destination: its lifecycle and egress
		// records go to the managed gateway, which stamps and exports them
		// (sandbox_daemon_telemetry.go, GAP-0003).
		telemetry: newDaemonRelayTelemetry(d.relay, d.telemetryRegistration, d.logf),
		// The user's own MCP servers, as the managed gateway judged them
		// for the run (sandbox_daemon_mcp.go).
		mcp: daemonMCPInventory{},
		// Every ask answer, unblock and user block goes to the managed
		// gateway, which checks it against the person's floor and keeps it
		// (sandbox_decisions_client.go); it also names the registration of
		// a sandbox this daemon created before its record says so.
		persist:      d.decisionsClient(),
		registration: d.registrationOf,
		onGeneration: d.observeGeneration,
		// Every new connection of a sandbox's egress proxy is decided with
		// the policy the managed gateway confirmed (GAP-0172).
		egressRefresh: d.egressRefresh,
		// An unblock or an ask's answer is judged under the policy the
		// managed gateway confirmed within the last second (GAP-0132).
		confirmPolicy: d.confirmSandboxPolicy,
	}, d.opts.RuntimeOptions)
}

// decisionsClient is the daemon manager's persister: the managed gateway's
// decisions, with the registration and the guardrail profile the daemon
// holds for each of its sandboxes.
func (d *SandboxDaemon) decisionsClient() *sandboxDecisionsClient {
	c := newSandboxDecisionsClient(d.relay, func(name string) (string, bool) {
		return d.registrationOf(sandboxauth.Binding{SandboxName: name})
	})
	c.profiles = func(name string) (string, bool) {
		r, ok := d.regs.get(name)
		if !ok || r.Revoked {
			return "", false
		}
		return r.Profile, true
	}
	return c
}

// config is the configuration the daemon's manager reads.
func (d *SandboxDaemon) config() *config.Config { return d.cfg.Load() }

// currentSettings returns the managed gateway's settings now.
func (d *SandboxDaemon) currentSettings() sandboxrelay.DaemonSettings {
	d.settingsMu.RLock()
	defer d.settingsMu.RUnlock()
	return d.settings
}

// buildConfig turns the managed settings and the current floor into the
// configuration the manager reads. Managed hosts are copy-only (D2): the
// floor never allows a live mount.
func (d *SandboxDaemon) buildConfig() *config.Config {
	d.floorMu.Lock()
	floor := d.floor
	d.floorMu.Unlock()
	return d.buildConfigWith(floor)
}

// configWithFloor is the configuration the manager would read under floor:
// what an explain or a policy test of the caller's own policy resolves
// against, without changing the floor the running sandboxes use.
func (d *SandboxDaemon) configWithFloor(floor config.OpenShellAdminConfig) *config.Config {
	return d.buildConfigWith(&floor)
}

// configForSandbox resolves a kept sandbox against its own confirmed floor.
// A missing, unconfirmed or revoked registration uses the closed floor, so
// its status still names the deny and it cannot borrow another run's policy.
func (d *SandboxDaemon) configForSandbox(name string) *config.Config {
	r, ok := d.regs.get(name)
	if !ok || !r.Confirmed || r.Revoked {
		return d.buildConfigWith(nil)
	}
	return d.configWithFloor(r.Floor)
}

// buildConfigWith is buildConfig under floor (nil: the closed floor).
func (d *SandboxDaemon) buildConfigWith(floor *config.OpenShellAdminConfig) *config.Config {
	s := d.currentSettings()
	cfg := config.DefaultConfig()
	cfg.DataDir = d.opts.StateDir
	cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	if _, port, err := net.SplitHostPort(managed.StandaloneAPIAddr); err == nil {
		cfg.Gateway.APIPort, _ = strconv.Atoi(port)
	}
	op := s.Operational
	o := &cfg.OpenShell
	o.Enabled = s.Enabled && s.Available
	o.IngressPort, o.EgressPort = op.IngressPort, op.EgressPort
	o.Gateway.Name, o.Gateway.Workspace = op.GatewayName, op.GatewayWorkspace
	o.Image.Base, o.Image.HarnessVersions = op.Image.Base, op.Image.HarnessVersions
	o.Approvals.DebounceMs, o.Approvals.AgentProposals = op.Approvals.DebounceMs, op.Approvals.AgentProposals
	o.MCP.Import, o.MCP.HostPorts = op.MCP.Import, op.MCP.HostPorts
	o.Harnesses, o.Wrappers = op.Harnesses, op.Wrappers
	o.TokenDelivery, o.Middleware.Enabled = op.TokenDelivery, op.Middleware
	o.LLM, o.KeepHeadless, o.UpstreamTelemetry = op.LLM, op.KeepHeadless, op.UpstreamTelemetry
	// Only the administrator's trusted CAs: the account names none.
	o.TrustedCAPEM, o.TrustedCAError = op.TrustedCAs, op.TrustedCAError
	o.Workdir.Mode = config.OpenShellWorkdirCopy
	if s.Enterprise.Install == config.EnterpriseOpenShellInstallSetup {
		if d.home != "" {
			// Setup mode's OpenShell is the one the daemon installed into
			// the account's ~/.local, which the unit's PATH does not hold.
			o.Binary = openShellCLI(d.home)
		}
	} else if cli, err := adminOpenShell(runtime.GOOS, openshell.DefaultBinary); err == nil {
		// Prerequisite mode's is the administrator's, which the PATH of a
		// macOS LaunchAgent (/usr/bin:/bin:...) does not hold either.
		o.Binary = cli
	}
	if floor != nil {
		o.Admin = *floor
	} else {
		o.Admin = closedSandboxFloor()
		// No registration names a floor yet: a sandbox DefenseClaw did not
		// start is judged under the person's own foreign_sandboxes, which
		// the managed gateway's settings carry, and stopped without them
		// (GAP-0058).
		if strings.EqualFold(s.ForeignSandboxes, config.OpenShellForeignSandboxesAlert) {
			o.Admin.ForeignSandboxes = config.OpenShellForeignSandboxesAlert
		}
	}
	off := false
	o.Admin.AllowMount = &off
	return cfg
}

// closedSandboxFloor is the floor before the managed gateway named one: the
// strictest posture, so nothing the daemon does without a registration is
// looser than any organization floor. It holds the manager only: an explain,
// a status or a policy test asks the managed gateway for the caller's own
// floor instead, and a create resolves there first (GAP-0197).
func closedSandboxFloor() config.OpenShellAdminConfig {
	off := false
	return config.OpenShellAdminConfig{
		MinProfile: "strict", AllowYolo: &off, AllowMount: &off, AllowHostPorts: &off,
		AllowUnblock: &off, AllowLearnMode: &off, Allowed: &off,
	}
}

// reloadConfig rebuilds the configuration after a settings or floor change.
func (d *SandboxDaemon) reloadConfig() { d.cfg.Store(d.buildConfig()) }

// useAuthorityPack installs the required pack the managed gateway's answer
// carries, so this daemon resolves the run's sandbox with that pack and never
// reads the administrator's root-only pack file, which it cannot read
// (GAP-0440). The pack must match the floor's required_pack_digest pin.
func useAuthorityPack(resp sandboxrelay.ResolveResponse, floor config.OpenShellAdminConfig) (*packs.Pack, error) {
	pack, err := packs.AuthorityPack(resp.Effective, resp.RequiredPack, floor)
	if err == nil {
		err = packs.UseAuthorityPack(floor, pack)
	}
	return pack, err
}

// useCurrentPack installs only content delivered with a confirmed gateway
// policy answer. A registrations.json pack is a user claim, including when
// its declared digest appears to match the floor.
func useCurrentPack(cp sandboxrelay.CurrentPolicy) error {
	if cp.Floor == nil {
		return errors.New("managed gateway omitted the complete sandbox policy floor")
	}
	pack, err := packs.AuthorityPack(nil, cp.RequiredPack, *cp.Floor)
	if err != nil {
		return err
	}
	return packs.UseAuthorityPack(*cp.Floor, pack)
}

// managedResolveFloor reads the organization floor F of a resolve answer:
// the "floor" member of its packs.Effective wire form, in openshell.admin's
// key names. An answer without one cannot be applied (fail closed).
func managedResolveFloor(resp sandboxrelay.ResolveResponse) (config.OpenShellAdminConfig, error) {
	if len(resp.Effective) == 0 {
		return config.OpenShellAdminConfig{}, errors.New("the managed gateway's policy answer has no effective policy")
	}
	var wire struct {
		Floor *config.OpenShellAdminConfig `yaml:"floor"`
	}
	if err := yaml.Unmarshal(resp.Effective, &wire); err != nil || wire.Floor == nil {
		return config.OpenShellAdminConfig{}, errors.New("the managed gateway's policy answer has no organization floor")
	}
	return *wire.Floor, nil
}

// registrationOf names the managed registration of a binding's sandbox
// (SandboxIngressConfig.Registration). A revoked one is none.
func (d *SandboxDaemon) registrationOf(b sandboxauth.Binding) (string, bool) {
	r, ok := d.regs.get(b.SandboxName)
	if !ok || r.Revoked {
		return "", false
	}
	return r.ID, true
}

// telemetryRegistration is the registration of sandbox name for its
// telemetry records: also a revoked one, whose last records (the deleting
// and deleted phases, the ends of its connections) the managed gateway takes
// for a while once the daemon reported the sandbox deleted
// (sandboxTelemetryAdmit).
func (d *SandboxDaemon) telemetryRegistration(name string) (string, bool) {
	r, ok := d.regs.get(name)
	return r.ID, ok && r.ID != ""
}

// observeGeneration learns the policy generation a relayed answer for
// registration carries. It is the managed gateway's view of the caller's own
// policy (sandboxViewGeneration), a digest that only ever compares for
// equality: ordered as a counter, a new policy whose digest happened to be
// smaller than one seen before was ignored until the next minute's poll, and
// a running sandbox kept the old egress lists 20-50 s after ensure
// (GAP-0172). One that differs from the registration's ends its egress
// lease, so its sandbox's next connection confirms the policy first
// (confirmEgressPolicy), and asks for a poll of every registration now. It
// does not block: the relayed answer is on its way to the sandbox.
func (d *SandboxDaemon) observeGeneration(registration string, g uint64) {
	if g == 0 {
		return
	}
	r, ok := d.regs.byID(registration)
	if !ok || r.Revoked || r.Generation == g {
		return
	}
	d.leases.expire(registration)
	d.askPoll()
}

// askPoll asks the supervision for a policy poll of every registration now.
func (d *SandboxDaemon) askPoll() {
	select {
	case d.refresh <- struct{}{}:
	default:
	}
}

// touch records CLI activity for the idle exit.
func (d *SandboxDaemon) touch() { d.lastActive.Store(time.Now().UnixNano()) }

// Handler is the daemon's CLI API: the sandbox REST API, served only to
// the daemon's own uid.
func (d *SandboxDaemon) Handler() http.Handler {
	mux := http.NewServeMux()
	// The packs of the caller's own chain are the managed gateway's to
	// list; the per-user gateway has no such route (GAP-0181).
	mux.HandleFunc("GET "+sandboxapi.PathPolicyPacks, d.handlePacks)
	mux.HandleFunc("GET "+sandboxapi.PathPolicyPacks+"/{name}", d.handlePacks)
	mux.Handle("/", d.api.sandboxAPIHandler())
	h := d.api.apiCSRFProtect(mux)
	return sandboxDaemonPeerCheck(d.uid, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.touch()
		h.ServeHTTP(w, r)
	}))
}

// handlePacks answers GET policy/packs[/{name}]: the packs of the caller's
// own effective chain as the managed gateway lists them, for one of the
// caller's sandboxes (?sandbox=NAME) or a new run of an agent
// (?harness=NAME). A pack outside that chain is not found, whether it exists
// or not.
func (d *SandboxDaemon) handlePacks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	registration := ""
	if name := q.Get("sandbox"); name != "" {
		registration, _ = d.registrationOf(sandboxauth.Binding{SandboxName: name})
	}
	connector := d.managedConnector(q.Get("harness"))
	if name := r.PathValue("name"); name != "" {
		view, err := d.relay.Pack(r.Context(), registration, connector, name)
		if err != nil {
			writeSandboxError(w, managedPackError(err))
			return
		}
		d.api.writeJSON(w, http.StatusOK, sandboxapi.ManagedPack(view))
		return
	}
	views, err := d.relay.Packs(r.Context(), registration, connector)
	if err != nil {
		writeSandboxError(w, managedPackError(err))
		return
	}
	list := make([]sandboxapi.ManagedPack, 0, len(views))
	for _, v := range views {
		list = append(list, sandboxapi.ManagedPack(v))
	}
	d.api.writeJSON(w, http.StatusOK, list)
}

// managedPackError is a packs refusal: a pack outside the caller's chain is
// not found, with the gateway's text; anything else as managedRelayError.
func managedPackError(err error) error {
	var refused *sandboxrelay.Error
	if errors.As(err, &refused) && refused.Status == http.StatusNotFound {
		return &sandboxapi.Error{Code: sandboxapi.CodeNotFound, Status: http.StatusNotFound,
			Message: firstNonEmptyString(refused.Message, "no pack of that name is part of your sandbox policy")}
	}
	return managedRelayError(err)
}

type sandboxDaemonPeerKey struct{}

// sandboxDaemonConnContext stamps a CLI connection with its peer's kernel
// credentials; one whose credentials cannot be read carries none.
func sandboxDaemonConnContext(ctx context.Context, conn net.Conn) context.Context {
	creds, err := peercred.FromConn(conn)
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, sandboxDaemonPeerKey{}, creds)
}

// sandboxDaemonPeerCheck refuses every request whose peer is not uid: the
// socket is 0600, and the kernel-reported peer is checked all the same.
func sandboxDaemonPeerCheck(uid int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		creds, ok := r.Context().Value(sandboxDaemonPeerKey{}).(peercred.Credentials)
		if !ok || creds.UID != uid {
			writeSandboxError(w, &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Status: http.StatusForbidden,
				Message: "this sandbox daemon serves only its own account"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// A daemon that cannot run sandboxes now (the managed gateway is not
// reachable, or refuses this account's settings) answers its CLI socket
// with the reason for sandboxDaemonUnavailableLinger after the last
// request, at most sandboxDaemonUnavailableMax, then exits 0. Exiting at
// once would have socket activation (or the launcher) start it again for
// every queued connection; answering tells the user why.
const (
	sandboxDaemonUnavailableLinger = 15 * time.Second
	sandboxDaemonUnavailableMax    = 2 * time.Minute
)

// ServeSandboxDaemonUnavailable answers every request of the daemon's own
// account on ln with why sandboxes cannot run (cause, as the sandbox API
// error a relay failure maps to) until the socket idles, then returns nil.
// It closes ln.
func ServeSandboxDaemonUnavailable(ctx context.Context, ln net.Listener, cause error) error {
	return serveSandboxDaemonUnavailable(ctx, ln, cause, sandboxDaemonUnavailableLinger, sandboxDaemonUnavailableMax)
}

func serveSandboxDaemonUnavailable(ctx context.Context, ln net.Listener, cause error, linger, limit time.Duration) error {
	var refusal *sandboxapi.Error
	if !errors.As(managedRelayError(cause), &refusal) {
		refusal = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: "the managed DefenseClaw gateway is not reachable"}
	}
	var conns, last atomic.Int64
	last.Store(time.Now().UnixNano())
	srv := &http.Server{
		Handler: sandboxDaemonPeerCheck(os.Getuid(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			last.Store(time.Now().UnixNano())
			writeSandboxError(w, refusal)
		})),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       sandboxDaemonConnContext,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				conns.Add(1)
			case http.StateClosed, http.StateHijacked:
				conns.Add(-1)
			}
			last.Store(time.Now().UnixNano())
		},
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	step := linger / 4
	if step <= 0 || step > time.Second {
		step = time.Second
	}
	tick := time.NewTicker(step)
	defer tick.Stop()
	deadline := time.Now().Add(limit)
	var err error
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case err = <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			break wait
		case now := <-tick.C:
			idle := conns.Load() == 0 && now.Sub(time.Unix(0, last.Load())) >= linger
			if idle || now.After(deadline) {
				break wait
			}
		}
	}
	shutdownCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	done()
	return err
}

// Run serves the CLI API, the manager, the policy poll and the lazy
// listeners until ctx ends (nil), the daemon idles out (nil) or a deferred
// restart is due (ErrSandboxDaemonRestart).
func (d *SandboxDaemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctl := &managedSandboxController{Manager: d.rt.manager, d: d}
	d.api.SetSandboxController(ctl)
	d.listenMu.Lock()
	d.runCtx = ctx
	d.listenMu.Unlock()

	srv := &http.Server{
		Handler:           d.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext:       sandboxDaemonConnContext,
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				d.conns.Add(1)
				d.touch()
			case http.StateClosed, http.StateHijacked:
				d.conns.Add(-1)
				d.touch()
			}
		},
	}
	// Before the manager reconciles anything, the managed gateway confirms
	// the registrations the user's own registrations file names: only a
	// confirmed registration's floor is adopted, and a revoked one's
	// sandbox is stopped once the manager runs.
	revoked := d.revalidate(ctx)

	var wg sync.WaitGroup
	serveErr := make(chan error, 1)
	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := srv.Serve(d.opts.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := d.rt.manager.Run(ctx); err != nil && ctx.Err() == nil {
			d.logf("manager: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		d.pollLoop(ctx)
	}()
	d.opts.Health.SetSandbox(StateRunning, "", nil)
	for _, r := range revoked {
		d.stopRevoked(ctx, r)
	}
	// A daemon restarted while sandboxes run (a crash) binds the ports
	// again at once, or stops them: their hooks must reach this daemon.
	listenersFailed := false
	listFailed := false
	if d.lockLifecycle(ctx) == nil {
		if n, err := d.runningSandboxes(ctx); err != nil {
			listFailed = true
		} else if n > 0 {
			if err := d.ensureListeners(); err != nil {
				d.logf("listeners at start: %v", err)
				listenersFailed = true
			}
		}
		d.unlockLifecycle()
	}
	if listFailed {
		go d.retryStartupListeners(ctx)
	}
	if listenersFailed {
		go d.containLostListener(ctx, "ingress")
	}

	err := d.superviseLoop(ctx, serveErr)
	// The setup-mode OpenShell gateway goes with the daemon when no sandbox
	// of the account runs: it frees the gateway port for the next account.
	d.stopOpenShellIfIdle()
	cancel()
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	done()
	d.releaseListeners()
	wg.Wait()
	d.api.SetSandboxController(nil)
	d.opts.Health.SetSandbox(StateStopped, "", nil)
	return err
}

// retryStartupListeners waits out a transient OpenShell List failure. Only
// an actual bind failure needs containment; a recovered List with free ports
// lets the daemon restore its listeners without stopping healthy sandboxes.
func (d *SandboxDaemon) retryStartupListeners(ctx context.Context) {
	every := d.rt.recheck
	if every <= 0 {
		every = time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		if err := d.lockLifecycle(ctx); err != nil {
			return
		}
		n, err := d.runningSandboxes(ctx)
		if err == nil && n > 0 {
			if bindErr := d.ensureListeners(); bindErr != nil {
				d.logf("listeners at start: %v", bindErr)
				d.unlockLifecycle()
				d.containLostListener(ctx, "ingress")
				return
			}
		}
		d.unlockLifecycle()
		if err == nil {
			return
		}
	}
}

// superviseLoop runs the idle, restart and listener checks.
func (d *SandboxDaemon) superviseLoop(ctx context.Context, serveErr <-chan error) error {
	tick := time.NewTicker(d.opts.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErr:
			return fmt.Errorf("sandbox daemon: serve the CLI socket: %w", err)
		case <-d.refresh:
			d.pollOnce(ctx)
		case <-tick.C:
			if stop, err := d.check(ctx); stop {
				return err
			}
		case <-d.checkNow:
			if stop, err := d.check(ctx); stop {
				return err
			}
		}
	}
}

// scheduleCheck asks for a supervision pass after delay (an earlier one
// already scheduled is moved).
func (d *SandboxDaemon) scheduleCheck(delay time.Duration) {
	d.checkMu.Lock()
	defer d.checkMu.Unlock()
	if d.checkTimer != nil {
		d.checkTimer.Stop()
	}
	d.checkTimer = time.AfterFunc(delay, func() {
		select {
		case d.checkNow <- struct{}{}:
		default:
		}
	})
}

// check is one supervision pass. It reports whether Run should return, and
// with what.
func (d *SandboxDaemon) check(ctx context.Context) (bool, error) {
	d.checkUpgrade()
	// A stop or delete in progress waits on the account's OpenShell
	// gateway: releasing it or exiting for a restart now cancels that wait,
	// and the stop failed with "context canceled" and a refused connection
	// although the sandbox stopped (GAP-0462). The stop schedules the next
	// check when it ends.
	if d.stops.Load() > 0 {
		return false, nil
	}
	// A create or start in progress holds the lifecycle: nothing to release
	// or exit for now. Held from the count through the release, so no create
	// begins in between and finds its listeners closed under it.
	if !d.tryLockLifecycle() {
		return false, nil
	}
	defer d.unlockLifecycle()
	running, err := d.runningSandboxes(ctx)
	if err != nil {
		return false, nil
	}
	if running > 0 {
		d.keepOpenShellLocked(ctx)
		return false, nil
	}
	// A stop that began during the list (its sandbox already stopping, so
	// not counted) holds the release off too: the count before the list
	// alone left that window open (GAP-0462). A stop counts itself before
	// it asks OpenShell anything, so one that begins after this read found
	// its sandbox among the running ones above.
	if d.stops.Load() > 0 {
		return false, nil
	}
	d.releaseListeners()
	d.stopIdleOpenShellLocked(ctx, false)
	if d.pendingRestart.Load() {
		d.logf("no sandbox runs: restarting for the pending upgrade or setting change")
		return true, ErrSandboxDaemonRestart
	}
	if d.opts.IdleAfter > 0 && d.conns.Load() == 0 &&
		time.Since(time.Unix(0, d.lastActive.Load())) >= d.opts.IdleAfter {
		d.logf("idle for %s with no sandbox running: exiting", d.opts.IdleAfter)
		return true, nil
	}
	return false, nil
}

// checkUpgrade marks a restart pending when the daemon's binary changed on
// disk (a package upgrade).
func (d *SandboxDaemon) checkUpgrade() {
	if d.exe == nil || d.pendingRestart.Load() {
		return
	}
	now, err := os.Stat(d.opts.Executable)
	if err != nil || !os.SameFile(now, d.exe) || !now.ModTime().Equal(d.exe.ModTime()) || now.Size() != d.exe.Size() {
		d.logf("the sandbox daemon was upgraded: restart pending until no sandbox runs")
		d.pendingRestart.Store(true)
	}
}

// runningSandboxes counts the user's sandboxes that may be running or hold
// compute (manager.HoldsCompute): while one does, the daemon neither
// stops the account's OpenShell gateway nor exits for a pending restart,
// which would take the gateway with it.
func (d *SandboxDaemon) runningSandboxes(ctx context.Context) (int, error) {
	if d.opts.countRunning != nil {
		return d.opts.countRunning(ctx)
	}
	if !d.currentSettings().Enabled {
		// The organization removed the managed OpenShell setup. Its gateway
		// cannot answer, and an idle daemon must still serve policy views.
		return d.rt.manager.KnownComputeCount(), nil
	}
	list, err := d.rt.manager.List(ctx)
	if err != nil {
		return 0, err
	}
	return sandboxesHoldingCompute(list), nil
}

// microVMs counts the MicroVMs that run as this account
// (openshell.CountMicroVMs): what the daemon trusts before it stops the
// account's gateway when it cannot read the gateway's own account of its
// sandboxes, which a stop would end with no flush.
func (d *SandboxDaemon) microVMs(ctx context.Context) (int, error) {
	if d.opts.countMicroVMs != nil {
		return d.opts.countMicroVMs(ctx)
	}
	return openshell.CountMicroVMs(ctx, openshell.ExecRunner{})
}

// sandboxesHoldingCompute counts the sandboxes of list that may run or
// hold compute (manager.HoldsCompute): a MicroVM counts until OpenShell
// reports it stopped, deleting or gone, completed and error states
// included (but for one whose VM is gone).
func sandboxesHoldingCompute(list []sandboxapi.Sandbox) int {
	n := 0
	for _, sb := range list {
		if manager.HoldsCompute(sb) {
			n++
		}
	}
	return n
}

// sandboxMayRun reports a phase in which a sandbox may be running.
func sandboxMayRun(phase string) bool {
	switch audit.SandboxPhase(phase) {
	case audit.SandboxPhaseProvisioning, audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseUnknown:
		return true
	}
	return false
}

// refreshSettings reads the managed gateway's settings after a generation
// change. A change of what the daemon was started with (the OpenShell
// install, driver or ports, or sandboxes turned off) is a restart, deferred
// until no sandbox runs; anything else applies now.
func (d *SandboxDaemon) refreshSettings(ctx context.Context) {
	if err := d.readSettings(ctx); err != nil {
		d.logf("refresh the managed settings: %v", err)
	}
}

// readSettings is refreshSettings that returns the failed read; the
// settings it had stay.
func (d *SandboxDaemon) readSettings(ctx context.Context) error {
	next, err := d.relay.Settings(ctx)
	if err != nil {
		return err
	}
	d.settingsMu.Lock()
	prev := d.settings
	d.settings = next
	d.settingsMu.Unlock()
	d.settingsAt.Store(time.Now().UnixNano())
	if sandboxDaemonRestartNeeded(prev, next) && !d.pendingRestart.Load() {
		d.logf("the managed settings changed: restart pending until no sandbox runs")
		d.pendingRestart.Store(true)
	}
	d.reloadConfig()
	return nil
}

// sandboxDaemonSettingsTTL is how long a status or a create trusts the
// managed settings the daemon read, availability included, before reading
// them again: as long as the managed gateway keeps its availability verdict
// (sandboxAvailabilityTTL). Whether the account can run a sandbox changes
// without a new policy generation (a group, the /dev/kvm or docker socket
// mode, the lifecycle's prerequisites), and the require-sandbox gate judges
// every hook with the live answer, so the launcher and the gate never keep
// two verdicts. A daemon with no sandbox running polls nothing, and its
// start-up answer would otherwise stay until it restarts (GAP-0256,
// GAP-0335).
const sandboxDaemonSettingsTTL = sandboxAvailabilityTTL

// refreshStaleSettings reads the managed settings again when they are older
// than sandboxDaemonSettingsTTL. A failed read keeps the ones it has.
func (d *SandboxDaemon) refreshStaleSettings(ctx context.Context) {
	if time.Since(time.Unix(0, d.settingsAt.Load())) < sandboxDaemonSettingsTTL {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, managedViewTimeout)
	defer cancel()
	d.refreshSettings(ctx)
}

// freshSettings is the managed settings no older than
// sandboxDaemonSettingsTTL: what a status and a create judge with.
func (d *SandboxDaemon) freshSettings(ctx context.Context) sandboxrelay.DaemonSettings {
	d.refreshStaleSettings(ctx)
	return d.currentSettings()
}

// createSettings is the managed settings a create judges with, read from
// the managed gateway now and not trusted within sandboxDaemonSettingsTTL:
// they carry the administrator's trusted CAs, which decide the image a new
// sandbox may run. A run right after the administrator pointed
// openshell.trusted_ca_bundle at a file the gateway refuses started from
// the image of the CAs before, while doctor already said none can be used
// (GAP-0201). A failed read refuses the create.
func (d *SandboxDaemon) createSettings(ctx context.Context) (sandboxrelay.DaemonSettings, error) {
	rctx, cancel := context.WithTimeout(ctx, managedViewTimeout)
	defer cancel()
	if err := d.readSettings(rctx); err != nil {
		d.logf("read the managed settings for a create: %v", err)
		return sandboxrelay.DaemonSettings{}, managedRelayError(err)
	}
	return d.currentSettings(), nil
}

// sandboxDaemonRestartNeeded reports a settings change the running daemon
// cannot apply in place.
func sandboxDaemonRestartNeeded(prev, next sandboxrelay.DaemonSettings) bool {
	return prev.Enterprise != next.Enterprise ||
		prev.Operational.IngressPort != next.Operational.IngressPort ||
		prev.Operational.EgressPort != next.Operational.EgressPort ||
		prev.Operational.GatewayName != next.Operational.GatewayName ||
		prev.Operational.GatewayWorkspace != next.Operational.GatewayWorkspace
}

// pollLoop polls policy/current for every live registration: a revoked
// one stops its sandbox, a newer generation refreshes the settings, and
// the confirmed floor is applied at once.
func (d *SandboxDaemon) pollLoop(ctx context.Context) {
	t := time.NewTicker(d.opts.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.pollOnce(ctx)
		}
	}
}

func (d *SandboxDaemon) pollOnce(ctx context.Context) {
	for _, r := range d.pollRegistrations(ctx, true) {
		d.stopRevoked(ctx, r)
	}
}

// pollRegistrations asks policy/current for every live registration. A
// registration the gateway no longer knows, revoked or expired, or whose
// subject changed, is marked revoked and returned (its sandbox is to be
// stopped); one it answers is confirmed and takes the complete floor, each in
// the registration's turn (askPolicy), and with adopt the floor of the
// sandboxes that run becomes the manager's (adoptRunningFloor). A generation
// that moved reads the managed settings again and re-resolves the policies.
// A transient refusal (429, 403, 5xx) or an unreachable gateway changes
// nothing: the relayed hooks fail closed meanwhile.
//
// The egress leases of the registrations it confirmed renew only once the
// adoption returned. Renewed in the loop, a connection of a sandbox whose
// answer had moved its policy took the lease's fast path while the poll
// still waited on another registration's answer, and was decided under the
// floor before the change (GAP-0172).
func (d *SandboxDaemon) pollRegistrations(ctx context.Context, adopt bool) []daemonRegistration {
	var revoked []daemonRegistration
	var answered []policyAnswer
	moved := false
	phases, listed := d.sandboxPhases(ctx)
	for _, r := range d.regs.list() {
		if r.Revoked {
			continue
		}
		running, report := sandboxStateReport(phases, listed, r.Sandbox)
		if _, starting := d.starting.Load(r.Sandbox); starting {
			// Start reported it running; a resumed MicroVM is listed stopped
			// until it is up, and a stopped report then refused the agent's
			// first hooks (403) right after `sandbox connect` (#1204).
			running, report = true, true
		}
		// With report, tell the gateway whether the sandbox runs: a stopped
		// one's registration authorizes no relayed call (GAP-0505).
		ans := d.askPolicy(ctx, r, report, running)
		if ans.gone {
			// A status's confirmation (confirmRunningView) that marked it
			// first stops it.
			if d.regs.markRevokedText(r.Sandbox, ans.reason, ans.stopText) {
				r.Revoked, r.RevokedReason, r.StopText = true, ans.reason, ans.stopText
				revoked = append(revoked, r)
			}
			continue
		}
		if ans.err != nil {
			continue
		}
		moved = moved || ans.moved
		answered = append(answered, ans)
	}
	if moved {
		d.refreshSettings(ctx)
	}
	if adopt {
		d.adoptMu.Lock()
		// The policy requests above can overlap a Create or Start. Re-list
		// inside the adoption lock so an older phase snapshot cannot put a
		// previous registration's floor back in force.
		adoptPhases, adoptListed := d.sandboxPhases(ctx)
		d.adoptLocked(adoptPhases, adoptListed, moved)
		d.adoptMu.Unlock()
		if adoptListed {
			for _, a := range answered {
				d.leases.renew(a.id, a.sent)
			}
		}
	}
	regs := d.regs.list()
	d.leases.prune(regs)
	d.regs.pruneApplied(regs)
	return revoked
}

// adoptRunningFloor makes the floor of the registrations of the sandboxes
// that run now (phases, from the manager's list) the one the manager
// resolves against, when it differs from the current one. Only a running
// sandbox's floor is adopted. A stopped sandbox's registration keeps the
// floor it was created under (an earlier profile's required pack, say)
// while its live fields follow every configuration change; adopting it on
// such a change put a sandbox created since under the stopped one's pack
// and approvals (GAP-0693). A stopped sandbox's floor becomes the manager's
// when it starts again (Start); each confirmed sandbox keeps its own floor.
//
// The closed start-up floor is the exception: with no running sandbox's
// floor, it takes the newest confirmed registration's, as revalidate does
// at start. A managed gateway that did not answer at start left it closed,
// and a poll that then confirmed only a stopped sandbox's registration
// adopted nothing, so that sandbox's status and list said "your
// organization does not let you run sandboxes" (strict, deny) until a start
// or a restart (GAP-0462). An unconfirmed or revoked registration's floor
// is never adopted: the floor stays closed. A new floor re-resolves every
// sandbox's policy at once, and reports true. Callers hold adoptMu
// (adoptLocked), so a later adoption never puts back the floor of an
// earlier one that read the registrations before it.
func (d *SandboxDaemon) adoptRunningFloor(phases map[string]string) bool {
	floor := d.regs.newestFloor(func(name string) bool { return sandboxMayRun(phases[name]) })
	var newest *config.OpenShellAdminConfig
	if floor == nil {
		newest = d.regs.newestFloor(nil)
	}
	d.floorMu.Lock()
	if floor == nil && d.floor == nil {
		floor = newest
	}
	changed := floor != nil && (d.floor == nil || !reflect.DeepEqual(*d.floor, *floor))
	if changed {
		d.floor = floor
	}
	d.floorMu.Unlock()
	if changed {
		d.reloadConfig()
		d.rt.manager.RefreshPolicies()
	}
	return changed
}

// sandboxPhases is the phase of each of the user's sandboxes by name; ok is
// false when the manager cannot list them, and then nothing is reported (a
// registration no report renews lapses after sandboxreg.LiveLease).
func (d *SandboxDaemon) sandboxPhases(ctx context.Context) (map[string]string, bool) {
	if !d.currentSettings().Enabled {
		// A stopped registration is kept while sandboxes are off. The
		// account gateway cannot answer without the managed setup, so do
		// not try to infer a live phase for the policy report.
		return nil, false
	}
	if d.opts.listPhases != nil {
		return d.opts.listPhases(ctx)
	}
	if d.rt == nil || d.rt.manager == nil {
		return nil, false
	}
	list, err := d.rt.manager.List(ctx)
	if err != nil {
		return nil, false
	}
	phases := make(map[string]string, len(list))
	for _, sb := range list {
		phases[sb.Name] = sb.Phase
	}
	return phases, true
}

// sandboxStateReport is the state report the policy poll makes for the
// sandbox name, from the manager's list (phases; listed false: it could not
// list): whether it runs, and whether to report at all. A sandbox gone from
// the list is reported stopped. A phase OpenShell could not confirm
// (unknown: its gateway is down, as after the account's last sandbox stopped
// and the daemon restarted) is not reported: as a running report it renewed
// the lease of stopped sandboxes for good and root's list kept them live
// (GAP-0488). Unreported, the lease lapses after sandboxreg.LiveLease unless
// a confirmed phase renews it.
func sandboxStateReport(phases map[string]string, listed bool, name string) (running, report bool) {
	if !listed {
		return false, false
	}
	phase, ok := phases[name]
	if ok && audit.SandboxPhase(phase) == audit.SandboxPhaseUnknown {
		return false, false
	}
	return sandboxMayRun(phase), true
}

// reportStopped tells the managed gateway that name's sandbox stopped, so
// its registration authorizes no relayed call until it starts again. A
// failure is left to the next poll.
func (d *SandboxDaemon) reportStopped(ctx context.Context, name string) {
	r, ok := d.regs.get(name)
	if !ok || r.Revoked {
		return
	}
	cp, err := d.relay.Report(ctx, r.ID, false)
	if reason, gone := registrationGone(err); gone {
		d.regs.markRevoked(name, reason)
		return
	}
	if err != nil {
		d.logf("report %s stopped: %v", name, err)
		return
	}
	if cp.Revoked {
		d.regs.markRevokedText(name, cp.RevokedReason, cp.RevokedReason)
	}
}

// registrationGone reports a policy/current or bind refusal that ends a
// registration for good, and its reason: 404 sandbox_registration_unknown,
// 410 revoked or expired, 409 sandbox_subject_changed. Every other refusal
// (the 429 budget, the CSRF 403, a 5xx) and every transport failure is
// transient.
func registrationGone(err error) (string, bool) {
	var refused *sandboxrelay.Error
	if !errors.As(err, &refused) {
		return "", false
	}
	switch refused.Status {
	case http.StatusNotFound, http.StatusGone, http.StatusConflict:
		return refused.Reason, true
	}
	return "", false
}

// revalidateTimeout bounds the start-up confirmation of the registrations.
const revalidateTimeout = 15 * time.Second

// revalidate confirms, at start, the registrations the user's registrations
// file names and adopts the floor of the newest confirmed one whose sandbox
// runs, or of the newest confirmed one when none runs (GAP-0693); it
// returns the revoked ones. The file is the user's own: an edited floor is
// never adopted for a registration the gateway does not answer for. A
// confirmation replaces the entire cached floor with the gateway's floor.
func (d *SandboxDaemon) revalidate(ctx context.Context) []daemonRegistration {
	ctx, cancel := context.WithTimeout(ctx, revalidateTimeout)
	defer cancel()
	revoked := d.pollRegistrations(ctx, false)
	d.adoptMu.Lock()
	defer d.adoptMu.Unlock()
	phases, _ := d.sandboxPhases(ctx)
	floor := d.regs.newestFloor(func(name string) bool { return sandboxMayRun(phases[name]) })
	if floor == nil {
		floor = d.regs.newestFloor(nil)
	}
	if floor == nil {
		return revoked
	}
	// Only the closed floor is replaced: a status's re-confirmation
	// (confirmIfClosed) must not put back an older registration's floor
	// over the one a create or a start just adopted.
	d.floorMu.Lock()
	closed := d.floor == nil
	if closed {
		d.floor = floor
	}
	d.floorMu.Unlock()
	if closed {
		d.reloadConfig()
		// The manager loaded its sandbox records under the closed floor
		// before Run called revalidate. A poll sees this same floor and does
		// not refresh those records again, so refresh them at adoption.
		d.rt.manager.RefreshPolicies()
	}
	return revoked
}

// confirmIfClosed confirms the registrations again when the manager still
// judges against the closed start-up floor (no confirmed registration was
// adopted: the managed gateway did not answer revalidate when the daemon
// started, a restart after an upgrade, say) and a live registration could
// open it: one that waits for its confirmation, or one a poll or a failed
// start confirmed without adopting its floor (a stopped sandbox's). A
// sandbox's status and list are judged against that floor, which denies
// every sandbox: they said "your organization does not let you run
// sandboxes" and a strict, deny-all policy for a sandbox the organization
// allows (GAP-0462). The managed gateway is asked again before the floor
// opens; one that does not answer leaves the confirmations it gave, and a
// revoked registration's sandbox is stopped, as at start.
//
// A confirmed floor re-resolves every sandbox's policy at once: the views
// are built from the policies resolved before, which the configuration
// check re-resolves only on its next tick, so the first status after the
// confirmation still showed the closed floor's deny. A revoked
// registration's stop has its own bound, apart from the view's: a stop cut
// short left a revoked registration's sandbox running, which no poll stops
// again.
func (d *SandboxDaemon) confirmIfClosed(ctx context.Context) {
	if !d.awaitingConfirmation() {
		return
	}
	vctx, cancel := context.WithTimeout(ctx, managedViewTimeout)
	revoked := d.revalidate(vctx)
	cancel()
	if len(revoked) == 0 {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revalidateTimeout)
	defer cancel()
	for _, r := range revoked {
		d.stopRevoked(sctx, r)
	}
}

// floorClosed reports whether the manager still judges against the closed
// start-up floor: no confirmed registration's floor was adopted.
func (d *SandboxDaemon) floorClosed() bool {
	d.floorMu.Lock()
	defer d.floorMu.Unlock()
	return d.floor == nil
}

// awaitingConfirmation reports the closed floor in force while a live
// registration could open it. Keyed on unconfirmed registrations only, it
// skipped one a poll had confirmed for a stopped sandbox, and that
// sandbox's status kept the closed floor's deny (GAP-0462).
func (d *SandboxDaemon) awaitingConfirmation() bool {
	return d.floorClosed() && slices.ContainsFunc(d.regs.list(), func(r daemonRegistration) bool { return !r.Revoked })
}

// registrationUnconfirmed is a live registration the managed gateway has
// not confirmed since the daemon started.
func registrationUnconfirmed(r daemonRegistration) bool { return !r.Revoked && !r.Confirmed }

// sandboxConfirmingNote is what a sandbox's status and list say while its
// registration waits for the managed gateway's confirmation on the closed
// floor (GAP-0462), in place of that floor's deny.
const sandboxConfirmingNote = "DefenseClaw is confirming this sandbox's policy with your organization's gateway after a restart; " +
	"try again in a moment. Until then it has no web egress, and the policy shown is the one it was created with"

// confirmingView makes v say its policy is being confirmed (Manager.ConfirmingView)
// while its registration waits for that on the closed floor. A sandbox
// whose registration the managed gateway revoked shows, on the closed
// floor, the policy it was created with and no note: judged against that
// floor, the list of a sandbox a regroup had stopped read profile strict
// and network deny after a daemon restart, instead of its balanced
// allowlist (GAP-0079). Its Stopped row says why it stopped; the floor
// stays closed, so this changes only what the views show.
func (c *managedSandboxController) confirmingView(v *sandboxapi.Sandbox) {
	if v == nil || !c.d.floorClosed() {
		return
	}
	r, ok := c.d.regs.get(v.Name)
	switch {
	case !ok:
	case registrationUnconfirmed(r):
		c.ConfirmingView(v, sandboxConfirmingNote)
	case r.Revoked:
		c.ConfirmingView(v, "")
	}
}

// confirmRunningView asks the managed gateway for the current policy of
// name's confirmed registration before a status of its running sandbox is
// shown, and reports whether the answer changed what the status shows. The
// daemon learned of a regroup only from a relayed hook or the minute's
// poll, so for up to a minute `sandbox status NAME` named the profile before
// the regroup while `sandbox policy explain` named the new one (GAP-0080).
// A changed answer is put in force first (the policies re-resolved, the
// settings read again for a new generation), as a connection's confirmation
// does (confirmOnce). An answer that ended the registration marks it
// revoked and stops the sandbox, as the poll does, so the status shows the
// stop and the organization's words for it. A managed gateway that does not
// answer within sandboxEgressConfirmTimeout changes nothing: the status
// shows the policy the daemon holds, which the relayed hooks and the
// sandbox's connections confirm on their own.
func (d *SandboxDaemon) confirmRunningView(ctx context.Context, name string) bool {
	r, ok := d.regs.get(name)
	if !ok || r.ID == "" || r.Revoked || !r.Confirmed {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
	ans := d.askPolicy(cctx, r, false, false)
	cancel()
	switch {
	case ans.gone:
		if d.regs.markRevokedText(r.Sandbox, ans.reason, ans.stopText) {
			r.Revoked, r.RevokedReason, r.StopText = true, ans.reason, ans.stopText
			sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), revalidateTimeout)
			d.stopRevoked(sctx, r)
			scancel()
		}
		return true
	case ans.err != nil || !ans.changed:
		return false
	}
	if ans.moved {
		sctx, scancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
		d.refreshSettings(sctx)
		scancel()
	}
	actx, acancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
	d.adoptApplied(actx, ans.moved)
	acancel()
	if ans.moved {
		// The other registrations follow at once.
		d.askPoll()
	}
	return true
}

// managedStopReason is the managed gateway's words for a revoke as the
// user's views show them: display-safe and bounded.
func managedStopReason(text string) string {
	text = strings.TrimSpace(sandboxapi.DisplayText(text))
	const limit = 512
	if len(text) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut]
	}
	return text
}

// registrationView adds to v what the daemon's registration of the sandbox
// says: the profile and digest of its current match, which a regroup moves
// (the manager's view has the pack and network profile it was resolved
// with), or, once the registration was revoked, the organization's words
// for the stop (#1199).
func (c *managedSandboxController) registrationView(v *sandboxapi.Sandbox) {
	if v == nil {
		return
	}
	r, ok := c.d.regs.get(v.Name)
	if !ok {
		return
	}
	if r.Revoked {
		v.StopReason = managedStopReason(r.StopText)
		return
	}
	v.OrganizationProfile, v.PolicyDigest, v.Provisional = sandboxapi.DisplayText(r.Profile), sandboxapi.DisplayText(r.Digest), r.Provisional
}

// notePolicyStop says in the activity feed why the organization's policy
// stopped r's sandbox, in the managed gateway's words, when it gave them:
// the feed said only that a hook call failed (403) and that the sandbox
// stopped (#1199).
func (d *SandboxDaemon) notePolicyStop(r daemonRegistration) {
	if text := managedStopReason(r.StopText); text != "" {
		d.rt.manager.Feed().Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: r.Sandbox,
			Reason: sandboxPolicyStopReason, Message: text})
	}
}

// sandboxPolicyStopReason is the feed reason of a stop the organization's
// policy made.
const sandboxPolicyStopReason = "policy_stop"

// stopRevoked stops a sandbox whose registration the managed gateway
// revoked; it never starts again from this registration.
func (d *SandboxDaemon) stopRevoked(ctx context.Context, r daemonRegistration) {
	if _, err := d.rt.manager.StopForPolicy(ctx, r.Sandbox); err != nil {
		d.logf("stop %s after its registration was revoked: %v", r.Sandbox, err)
		return
	}
	d.logf("stopped %s: its managed registration was revoked (%s)", r.Sandbox, r.RevokedReason)
	d.notePolicyStop(r)
	// A stop a re-match asked for (allowed false, a harness no longer
	// allowed) ends the registration at the gateway only when it hears the
	// sandbox stopped; the poll no longer reports a registration this daemon
	// marked revoked, so it stayed live there (GAP-0488).
	if _, err := d.relay.Report(ctx, r.ID, false); err != nil {
		if _, gone := registrationGone(err); !gone {
			d.logf("report %s stopped after its registration was revoked: %v", r.Sandbox, err)
		}
	}
}

// adoptFloor updates the daemon's current floor after a registration is
// confirmed and re-resolves every sandbox at once. The manager resolves
// each existing sandbox against its own confirmed registration; the current
// floor is used for a new run and the daemon's no-run configuration.
func (d *SandboxDaemon) adoptFloor(name string) {
	d.adoptMu.Lock()
	defer d.adoptMu.Unlock()
	r, ok := d.regs.get(name)
	if !ok || !r.Confirmed || r.Revoked {
		return
	}
	floor := r.Floor
	d.floorMu.Lock()
	d.floor = &floor
	d.floorMu.Unlock()
	d.reloadConfig()
	d.rt.manager.RefreshPolicies()
}

// ensureListeners binds the ingress and egress ports unless this daemon
// holds them already. A port another program holds refuses with the
// account-busy text: on a managed computer that is another account's
// sandbox daemon (D9).
func (d *SandboxDaemon) ensureListeners() error {
	d.listenMu.Lock()
	defer d.listenMu.Unlock()
	if d.listenCancel != nil {
		return nil
	}
	if d.runCtx == nil {
		return errors.New("sandbox daemon: not running")
	}
	ingressAddr := d.api.SandboxIngressAddr()
	ingress, err := net.Listen("tcp", ingressAddr)
	if err != nil {
		d.listenFailed.Store(&listenerFailure{part: "ingress", err: err})
		return sandboxListenError(err)
	}
	egressLn, err := egress.Listen(d.rt.egressAddr)
	if err != nil {
		_ = ingress.Close()
		d.listenFailed.Store(&listenerFailure{part: "egress", err: err})
		return sandboxListenError(err)
	}
	d.listenFailed.Store(nil)
	ctx, cancel := context.WithCancel(d.runCtx)
	done := make(chan struct{})
	d.listenCancel, d.listenDone = cancel, done
	// Held from here on: the manager's create sees them at once.
	d.rt.setListening("ingress", true)
	d.rt.setListening("egress", true)
	var wg sync.WaitGroup
	wg.Add(2)
	lost := make(chan listenerFailure, 2)
	go func() {
		defer wg.Done()
		defer d.rt.setListening("ingress", false)
		if err := d.api.RunSandboxIngressOn(ctx, ingress); err != nil && ctx.Err() == nil {
			d.logf("sandbox ingress: %v", err)
			failure := &listenerFailure{part: "ingress", err: err}
			d.listenFailed.Store(failure)
			lost <- *failure
		}
	}()
	go func() {
		defer wg.Done()
		if err := d.rt.serveEgressOn(ctx, egressLn, true); err != nil && ctx.Err() == nil {
			d.logf("sandbox egress: %v", err)
			failure := &listenerFailure{part: "egress", err: err}
			d.listenFailed.Store(failure)
			lost <- *failure
		}
	}()
	go func() {
		var failed *listenerFailure
		select {
		case failure := <-lost:
			// A listener died under running sandboxes. Once both are
			// released, keep containing until a create binds them again.
			failed = &failure
			cancel()
		case <-ctx.Done():
		}
		wg.Wait()
		close(done)
		d.listenMu.Lock()
		if d.listenDone == done {
			d.listenCancel, d.listenDone = nil, nil
		}
		d.listenMu.Unlock()
		if failed != nil {
			d.containLostListener(d.runCtx, failed.part)
		}
	}()
	return nil
}

// containLostListener retries the existing containment pass while this
// managed daemon owns neither listener. The lifecycle lock orders a pass
// with create and rebind, so a newly rebound listener cannot be followed
// by a stale stop attempt.
func (d *SandboxDaemon) containLostListener(ctx context.Context, part string) {
	every := d.rt.recheck
	if every <= 0 {
		every = sandboxListenerRecheck
	}
	unstoppable := map[string]bool{}
	for {
		if err := d.lockLifecycle(ctx); err != nil {
			return
		}
		if d.listening() {
			d.unlockLifecycle()
			return
		}
		stopSandboxesWithoutListener(ctx, d.rt.fleet, d.rt.publish, part, unstoppable)
		d.unlockLifecycle()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// policyFleet is the fleet the listener-loss containment stops through
// (buildSandboxRuntime, for the OSS sidecar and the managed daemon alike):
// that stop is DefenseClaw's own security response (another program may
// receive the sandbox's hooks and credentials), so a MicroVM whose disk
// sync fails is stopped all the same and the feed says what it may have
// lost (StopForPolicy), never held as a stop the user asked for is
// (GAP-1163).
type policyFleet struct{ policyStopper }

// policyStopper is what policyFleet needs: *manager.Manager.
type policyStopper interface {
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	StopForPolicy(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
}

// Stop is the policy stop.
func (f policyFleet) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	return f.StopForPolicy(ctx, name)
}

type listenerFailure struct {
	part string
	err  error
}

func (d *SandboxDaemon) lastListenerFailure() *listenerFailure {
	return d.listenFailed.Load()
}

// releaseListeners frees the ingress and egress ports.
//
// It holds listenMu until both listeners are closed, so a create that
// follows binds again instead of finding them half released.
func (d *SandboxDaemon) releaseListeners() {
	d.listenMu.Lock()
	defer d.listenMu.Unlock()
	cancel, done := d.listenCancel, d.listenDone
	if cancel == nil {
		return
	}
	cancel()
	<-done
	d.listenCancel, d.listenDone = nil, nil
}

// lockLifecycle takes the lifecycle (creates, starts, the release of the
// listeners), waiting while another holds it, unless ctx ends first.
func (d *SandboxDaemon) lockLifecycle(ctx context.Context) error {
	select {
	case d.lifecycle <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// tryLockLifecycle takes the lifecycle when nobody holds it.
func (d *SandboxDaemon) tryLockLifecycle() bool {
	select {
	case d.lifecycle <- struct{}{}:
		return true
	default:
		return false
	}
}

func (d *SandboxDaemon) unlockLifecycle() { <-d.lifecycle }

// releaseIfIdleLocked frees the ports after a create or start that failed,
// when no sandbox runs. The caller holds the lifecycle.
func (d *SandboxDaemon) releaseIfIdleLocked(ctx context.Context) {
	if n, err := d.runningSandboxes(context.WithoutCancel(ctx)); err == nil && n == 0 {
		d.releaseListeners()
	}
}

// listening reports whether the daemon holds its ports now (tests, status).
func (d *SandboxDaemon) listening() bool {
	d.listenMu.Lock()
	defer d.listenMu.Unlock()
	return d.listenCancel != nil
}

// sandboxListenError is the create refusal of a port the daemon could not
// bind.
func sandboxListenError(err error) error {
	if isAddrInUse(err) {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: sandboxAccountBusyMessage, Detail: SandboxAccountBusyReason}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: "the sandbox listeners could not start", Detail: err.Error()}
}

// managedStatus is Status.Managed: the caller's own policy and the
// daemon's OpenShell, with settings no older than sandboxDaemonSettingsTTL.
// Before any sandbox of the caller registered, the policy is the one the
// managed gateway names for a new run (GAP-0179).
func (d *SandboxDaemon) managedStatus(ctx context.Context) *sandboxapi.ManagedStatus {
	return d.managedStatusFor(ctx, d.freshSettings(ctx))
}

func (d *SandboxDaemon) managedStatusFor(ctx context.Context, s sandboxrelay.DaemonSettings) *sandboxapi.ManagedStatus {
	out := &sandboxapi.ManagedStatus{
		RequestAccess:    s.RequestAccess,
		InstallMode:      s.Enterprise.Install,
		Driver:           s.Enterprise.Driver,
		OpenShellVersion: s.Enterprise.Version,
		GatewayPort:      s.Enterprise.GatewayPort,
		PendingRestart:   d.pendingRestart.Load(),
		DriverFallback:   s.Enterprise.DriverFallback,
		NextDriver:       s.SelectedDriver,
	}
	if d.openShell != nil {
		out.OtherGateways = d.openShell.OtherGateways(ctx, s)
		out.RenderedConfigDrift = d.openShell.RenderedConfigDrift(s)
	}
	// A running sandbox keeps its driver. Without one, report the managed
	// gateway's refreshed choice for the next run. The last create's choice
	// may be stale after device access changes without a policy generation.
	if r, ok := d.regs.newest(); ok && r.Driver != "" {
		out.Driver, out.DriverReason = r.Driver, r.DriverReason
	} else if s.SelectedDriver != "" {
		out.Driver, out.DriverReason = s.SelectedDriver, s.DriverReason
	}
	switch {
	case !s.Enabled:
		out.Unavailable = "sandboxes are turned off by your organization"
	case !s.Available:
		out.Unavailable = s.Unavailable
	}
	registered := false
	if r, ok := d.regs.newest(); ok {
		out.Profile, out.Provisional, out.EffectiveDigest, out.UpdatedAt = r.Profile, r.Provisional, r.Digest, r.UpdatedAt
		registered = true
	}
	ctx, cancel := context.WithTimeout(ctx, managedViewTimeout)
	defer cancel()
	// Status and doctor describe whether the configured agents can run at
	// all. A default connector's permission cannot stand in for another's
	// connector-scoped profile (GAP-0534).
	harnesses := s.Operational.Harnesses
	if len(harnesses) == 0 {
		harnesses = []string{defaultManagedConnector}
	}
	seen := make(map[string]bool, len(harnesses))
	out.Allowed = true
	viewSet := false
	for _, name := range harnesses {
		connector := d.managedConnector(name)
		if seen[connector] {
			continue
		}
		seen[connector] = true
		me, _, err := d.managedExplain(ctx, sandboxapi.ExplainRequest{Harness: connector}, nil)
		if err != nil {
			out.Allowed = false
			continue
		}
		allowed := managedExplainAllowsHarness(me, connector) && managedPostureFatal(me) == nil
		if !allowed {
			out.Allowed = false
			out.DeniedHarnesses = append(out.DeniedHarnesses, connector)
		}
		if !registered && !viewSet {
			out.Profile, out.Description, out.Provisional, out.EffectiveDigest = me.Profile, me.Description, me.Provisional, me.PolicyDigest
			viewSet = true
		}
		if me.RequestAccess != "" && (!allowed || out.RequestAccess == "") {
			out.RequestAccess = me.RequestAccess
		}
	}
	return out
}

// managedViewTimeout bounds the managed gateway calls a status makes.
const managedViewTimeout = 5 * time.Second

// defaultManagedConnector is the connector a policy view that names no
// agent claims when the organization names no sandbox harness.
const defaultManagedConnector = "claudecode"

// managedConnector is the connector a managed gateway call claims for the
// harness name: its own, or, for a view that names none (`policy explain`
// of a run in this folder, `pack list`, status), the first harness the
// organization runs in sandboxes, else Claude Code. The gateway answers
// every policy view for one connector, whose profile it matches; without a
// claim it refuses the view, which left the user views on the daemon's
// closed floor (GAP-0179).
func (d *SandboxDaemon) managedConnector(name string) string {
	if name = strings.TrimSpace(name); name != "" {
		if spec, ok := harness.Get(config.NormalizeConnectorName(name)); ok {
			return spec.Name
		}
		return config.NormalizeConnectorName(name)
	}
	for _, h := range d.currentSettings().Operational.Harnesses {
		if spec, ok := harness.Get(config.NormalizeConnectorName(h)); ok {
			return spec.Name
		}
	}
	return defaultManagedConnector
}

// managedExplain asks the managed gateway for the caller's own policy, of
// one of the caller's sandboxes (req.Sandbox) or of a new run, and returns
// it with the floor to resolve it against: a confirmed registration's own
// floor, else the floor the answer names. Never the closed floor, which
// holds the manager until a create resolved: answering a run's preflight
// with it refused every valid user (GAP-0197). A gateway that does not
// answer fails the view with its reason. mcp are the caller's MCP servers
// a new run would bring along, which the answer judges.
func (d *SandboxDaemon) managedExplain(ctx context.Context, req sandboxapi.ExplainRequest, mcp []config.MCPServerEntry) (sandboxapi.ManagedExplain, config.OpenShellAdminConfig, error) {
	ereq := sandboxrelay.ExplainRequest{Connector: d.managedConnector(req.Harness), Sources: req.Sources}
	if claims := managedMCPClaims(mcp); len(claims) > 0 {
		ereq.MCP = claims
	}
	if strings.TrimSpace(req.Harness) != "" {
		// Only a named agent's explain is that agent's (its answer to
		// silent hooks, GAP-0477); without one the connector is a claim.
		ereq.Harness = ereq.Connector
	}
	var reg daemonRegistration
	registered := false
	if req.Sandbox != "" {
		if r, ok := d.regs.get(req.Sandbox); ok && !r.Revoked {
			reg, registered, ereq.Registration = r, true, r.ID
		}
	} else {
		if req.Project != "" && filepath.IsAbs(req.Project) {
			if real, err := filepath.EvalSymlinks(req.Project); err == nil {
				ereq.ProjectReal = real
			}
		}
		ereq.Flags = &sandboxrelay.RunFlags{Pack: req.Pack, Profile: req.Profile, Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo,
			Unmask: req.Unmask}
		overlay, pack, err := runFiles(ereq.ProjectReal, req.Pack)
		if err != nil {
			return sandboxapi.ManagedExplain{}, config.OpenShellAdminConfig{}, err
		}
		ereq.RepoOverlay, ereq.UserPack = overlay, pack
	}
	me, err := d.relay.Explain(ctx, ereq)
	if err != nil {
		return sandboxapi.ManagedExplain{}, config.OpenShellAdminConfig{}, managedRelayError(err)
	}
	if registered && reg.Confirmed {
		return me, reg.Floor, nil
	}
	return me, managedExplainFloor(me), nil
}

// managedExplainAllowsHarness applies both sandbox.allowed and the agent
// allowlist to a policy view. Resolve checks both before Create; Ready and
// status must make the same decision before an install or ready verdict.
func managedExplainAllowsHarness(me sandboxapi.ManagedExplain, name string) bool {
	if !me.Allowed {
		return false
	}
	if len(me.AllowedHarnesses) == 0 {
		return true
	}
	name = config.NormalizeConnectorName(name)
	return slices.ContainsFunc(me.AllowedHarnesses, func(h string) bool {
		return config.NormalizeConnectorName(h) == name
	})
}

// managedPostureFatal is the first fatal violation of the run a policy
// view resolves (ManagedExplain.Posture), nil without one: a run the
// organization's pack forbids (its harness.allowed leaves the agent out,
// for one) is refused at its create even when sandbox.allowed and the
// agent allowlist let it through, so ready and status must not call it
// allowed either (GAP-0812).
func managedPostureFatal(me sandboxapi.ManagedExplain) *sandboxapi.Violation {
	if me.Posture == nil {
		return nil
	}
	for i := range me.Posture.Violations {
		if me.Posture.Violations[i].Fatal {
			v := me.Posture.Violations[i]
			return &v
		}
	}
	return nil
}

// managedExplainFloor is the organization floor a managed explain names,
// in openshell.admin's terms. A setting the explain allows is left unset;
// the keys it does not carry (min_profile, required_pack, max_resources)
// are judged by the managed gateway when the run resolves.
func managedExplainFloor(me sandboxapi.ManagedExplain) config.OpenShellAdminConfig {
	off, on := false, true
	deny := func(allowed bool) *bool {
		if allowed {
			return nil
		}
		return &off
	}
	f := config.OpenShellAdminConfig{
		Allowed: deny(me.Allowed), RequiredFor: slices.Clone(me.RequiredFor), WhenUnavailable: me.WhenUnavailable,
		AllowedHarnesses: slices.Clone(me.AllowedHarnesses), AllowedCredentials: slices.Clone(me.AllowedCredentials),
		EgressAllowOnly: slices.Clone(me.EgressAllowOnly), EgressBlock: slices.Clone(me.EgressBlock),
		UserApprovals: me.UserApprovals, AllowUnblock: deny(me.AllowUnblock), AllowHostPorts: deny(me.AllowHostPorts),
		AllowYolo: deny(me.AllowYolo), OnSilence: me.OnSilence, MaxSilenceAfter: me.MaxSilenceAfter,
		DeleteStoppedAfter: me.DeleteStoppedAfter, RequestAccess: me.RequestAccess,
	}
	if me.ProcessTree {
		f.ProcessTree = &on
	}
	return f
}

// managedSandboxController is the daemon's SandboxController: the manager,
// with create and start resolved and registered at the managed gateway
// first and delete reported to it.
type managedSandboxController struct {
	*manager.Manager
	d *SandboxDaemon
}

var _ SandboxController = (*managedSandboxController)(nil)

// Status adds the managed part, with settings no older than
// sandboxDaemonSettingsTTL (managedStatus reads stale ones again).
func (c *managedSandboxController) Status(ctx context.Context) (*sandboxapi.Status, error) {
	st, err := c.Manager.Status(ctx)
	if st != nil {
		s := c.d.freshSettings(ctx)
		st.Managed = c.d.managedStatusFor(ctx, s)
		// The manager's runtime config can lag a driver switch. Enabled is
		// the organization's current choice, separate from readiness.
		st.Enabled = s.Enabled
		if !s.Enabled || !s.Available {
			st.Available, st.Reason = false, s.Unavailable
		}
		if st.Gateway != nil {
			c.d.driverInForce(st.Managed, st.Gateway.Driver)
		}
		c.d.neutralGatewayStatus(st)
		c.d.statusListenerAddresses(st)
		// The daemon's own resolution knows neither the caller's required
		// pack nor its profile minimum: the pack and profile are the
		// managed gateway's for the caller's newest sandbox, else for a
		// new run, and none when it does not answer (GAP-0179).
		st.Pack, st.Profile = "", ""
		req := sandboxapi.ExplainRequest{}
		if r, ok := c.d.regs.newest(); ok {
			req.Sandbox = r.Sandbox
		}
		vctx, cancel := context.WithTimeout(ctx, managedViewTimeout)
		if me, _, err := c.d.managedExplain(vctx, req, nil); err == nil && me.Posture != nil {
			st.Pack, st.Profile = me.Posture.Pack, me.Posture.Profile
		}
		cancel()
	}
	return st, err
}

// statusListenerAddresses keeps a failed bind or lost managed listener as
// the status cause until ensureListeners successfully binds again. The
// runtime still clears every address the daemon no longer holds.
func (d *SandboxDaemon) statusListenerAddresses(st *sandboxapi.Status) {
	if failure := d.lastListenerFailure(); st.Enabled && st.Available && failure != nil {
		st.Available = false
		st.Reason = fmt.Sprintf("the sandbox %s listener is not running in this process: %v; check openshell.%s_port, fix the listener error, then restart the DefenseClaw daemon",
			failure.part, failure.err, failure.part)
	}
	d.rt.statusListenerAddresses(st)
}

// driverInForce makes m name the compute driver the connected gateway runs
// (live) while a sandbox remains registered, not the one its record or setup
// asked for:
// after the organization switched drivers, the gateway restarts on the new
// one once the account's sandboxes stopped, while the registrations of the
// old driver's sandboxes still name the old one, and status, doctor and the
// run banner said so (GAP-0455). The reason stays while it is of that driver.
func (d *SandboxDaemon) driverInForce(m *sandboxapi.ManagedStatus, live string) {
	// An idle gateway may still be on the last sandbox's driver. For the
	// next run, the refreshed account availability is authoritative.
	if _, registered := d.regs.newest(); !registered || live == "" || m.Driver == live {
		return
	}
	s := d.currentSettings()
	reason := ""
	switch c := d.lastDriver.Load(); {
	case s.SelectedDriver == live:
		reason = s.DriverReason
	case c != nil && string(c.Driver) == live:
		reason = c.Reason
	case s.Enterprise.Driver == live:
		reason = openshell.DriverReasonConfigured
	}
	m.Driver, m.DriverReason = live, reason
}

// neutralGatewayStatus fills what a status says about the gateway port the
// daemon does not hold: the sandbox ports are bound only while a sandbox of
// the account runs (D3), and another account's OpenShell gateway on the
// gateway port is said as Q2's one-account-at-a-time text, which the run
// refuses with, not as certificates and CAs (GAP-0461). gateway_elsewhere
// names nobody ("another account").
func (d *SandboxDaemon) neutralGatewayStatus(st *sandboxapi.Status) {
	if !d.listening() {
		st.IngressAddr, st.EgressAddr = "", ""
	}
	if st.Available || st.Managed == nil {
		return
	}
	if uid, held := d.openShell.PortHolder(d.currentSettings()); held && uid != d.uid {
		st.GatewayElsewhere = "another account"
		st.Reason = sandboxAccountBusyMessage
	}
}

// Stop stops a sandbox, with the account's gateway started for it when the
// daemon had stopped it (GAP-0492); a sandbox the daemon knows is stopped
// while no gateway runs is answered as it is. The account's last running
// sandbox may have stopped: its gateway goes before the stop returns
// (GAP-0465). A stopped sandbox is reported stopped, so its registration
// authorizes no relayed call until it starts again (GAP-0505).
func (c *managedSandboxController) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	defer c.d.scheduleCheck(time.Second)
	c.d.stops.Add(1)
	defer c.d.stops.Add(-1)
	if _, held := c.d.openShell.PortHolder(c.d.currentSettings()); !held {
		if sb, err := c.Manager.Get(ctx, name); err == nil && sb != nil && audit.SandboxPhase(sb.Phase) == audit.SandboxPhaseStopped {
			c.d.reportStopped(context.WithoutCancel(ctx), name)
			c.d.handoverOpenShell(ctx)
			return sb, nil
		}
	}
	if err := c.d.openShellForKept(ctx, true); err != nil {
		return nil, err
	}
	sb, err := c.Manager.Stop(ctx, name)
	if err != nil {
		// The wait for the stop may have lost the gateway (a deferred
		// restart, the caller gone) after OpenShell stopped the sandbox:
		// the stop failed with "context canceled" and a refused connection
		// for a sandbox that stopped (GAP-0462). Its state decides; a
		// sandbox DefenseClaw does not know has none to read.
		if !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			if stopped := c.d.stoppedAfterFailedStop(ctx, name, c.Manager.Get); stopped != nil {
				c.d.logf("stop %s: the wait failed (%v), and the sandbox is stopped", name, err)
				c.d.reportStopped(context.WithoutCancel(ctx), name)
				c.d.handoverOpenShell(ctx)
				return stopped, nil
			}
		}
		return sb, err
	}
	c.d.reportStopped(context.WithoutCancel(ctx), name)
	c.d.handoverOpenShell(ctx)
	return sb, nil
}

// stopRecheckTimeout bounds the re-read of a sandbox whose stop failed.
const stopRecheckTimeout = 10 * time.Second

// stoppedAfterFailedStop reads name's sandbox again after its stop failed,
// with a bound of its own (the stop's context may be what ended), on the
// account's gateway readied again if the daemon can; it returns the
// sandbox when OpenShell says it is stopped, else nil.
func (d *SandboxDaemon) stoppedAfterFailedStop(ctx context.Context, name string,
	get func(context.Context, string) (*sandboxapi.Sandbox, error)) *sandboxapi.Sandbox {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopRecheckTimeout)
	defer cancel()
	_ = d.openShellForKept(rctx, false)
	sb, err := get(rctx, name)
	if err != nil || sb == nil || audit.SandboxPhase(sb.Phase) != audit.SandboxPhaseStopped {
		return nil
	}
	return sb
}

// List lists the account's sandboxes. A phase the gateway could not confirm
// (unknown: the gateway is not running) is asked again with the account's
// gateway started, when no other account holds its port (GAP-0492).
func (c *managedSandboxController) List(ctx context.Context) ([]sandboxapi.Sandbox, error) {
	c.d.confirmIfClosed(ctx)
	list, err := c.Manager.List(ctx)
	if err == nil && slices.ContainsFunc(list, unconfirmedSandbox) && c.mayReadyForRead() && c.d.openShellForKept(ctx, false) == nil {
		list, err = c.Manager.List(ctx)
	}
	for i := range list {
		c.confirmingView(&list[i])
		c.registrationView(&list[i])
	}
	return list, err
}

// Get is List for one sandbox. A status (sandboxPolicyConfirmAsked) of a
// running sandbox first confirms its policy (confirmRunningView).
func (c *managedSandboxController) Get(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	c.d.confirmIfClosed(ctx)
	sb, err := c.Manager.Get(ctx, name)
	if err == nil && sb != nil && unconfirmedSandbox(*sb) && c.mayReadyForRead() && c.d.openShellForKept(ctx, false) == nil {
		sb, err = c.Manager.Get(ctx, name)
	}
	if err == nil && sb != nil && sandboxPolicyConfirmAsked(ctx) && sandboxMayRun(sb.Phase) && c.d.confirmRunningView(ctx, name) {
		sb, err = c.Manager.Get(ctx, name)
	}
	if err == nil {
		c.confirmingView(sb)
		c.registrationView(sb)
	}
	return sb, err
}

// mayReadyForRead reports whether a read (List, Get) may start the account's
// OpenShell gateway to confirm a phase: not while the organization has
// sandboxes off, where the gateway cannot start without the managed setup
// and a kept sandbox's list waited out its start (GAP-1421, the GAP-0720
// class: a read-only view never waits for an unavailable gateway). The
// record's phase is the answer then.
func (c *managedSandboxController) mayReadyForRead() bool {
	return c.d.currentSettings().Enabled
}

// unconfirmedSandbox is a sandbox whose phase the gateway could not say.
func unconfirmedSandbox(sb sandboxapi.Sandbox) bool {
	return audit.SandboxPhase(sb.Phase) == audit.SandboxPhaseUnknown
}

// managedSettingsRefusal refuses a create or a ready the organization's
// settings do not allow: sandboxes off, or unavailable on this computer.
func managedSettingsRefusal(s sandboxrelay.DaemonSettings) error {
	if !s.Enabled {
		return sandboxapi.Errorf(sandboxapi.CodeDisabled, "sandboxes are turned off by your organization")
	}
	if !s.Available {
		if s.Unavailable == sandboxrelay.UnavailableSetupChanging {
			// A notice, no policy block: the CLI prints it without the
			// organization's exception contact (#1203).
			return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
				Message: s.Unavailable, Detail: sandboxrelay.DetailSetupChanging}
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: sandboxapi.AdminMessage, Detail: s.Unavailable}
	}
	return nil
}

// olderCLIReadyHarnesses are the agents a ready that names none may be for:
// the agent this daemon's managed configuration runs (managedConnector)
// first, then every other harness a create may run.
func (d *SandboxDaemon) olderCLIReadyHarnesses() []string {
	first := d.managedConnector("")
	out := []string{first}
	for _, name := range harness.Names() {
		if name != first {
			out = append(out, name)
		}
	}
	return out
}

// Ready asks the managed gateway at most readyViewsInFlight policy views at
// once. The gateway admits sandboxBudgetPolicy.InFlight (8) policy requests
// per account and answers more with 429; half leaves room for the account's
// other policy calls (a status view, the registrations' policy polls).
const readyViewsInFlight = 4

// A rate-limited policy view is asked again after readyViewRetryFirst,
// doubling up to readyViewRetryMax, within the view's own bound.
const (
	readyViewRetryFirst = 100 * time.Millisecond
	readyViewRetryMax   = time.Second
)

// readyPolicyRefusal refuses a ready unless the managed gateway's current
// policy allows one of the candidate agents, by both sandbox.allowed and the
// agent allowlist (managedExplainAllowsHarness). Ready has no run
// registration yet, so it asks before it installs OpenShell or starts its
// gateway: a forbidden profile must leave no runtime behind, including when
// Ready is called directly (GAP-0534). Profiles match per connector, so each
// candidate gets its own view (readyPolicyView). The views go in candidate
// order, readyViewsInFlight at a time, each within its own bound, so a view
// that is slow or unanswered neither holds up nor refuses a ready another
// agent's profile allows, and the asking stays inside the gateway's
// admission limit: the first allowed answer readies. With none allowed, a
// view the gateway did not answer fails the ready closed with its reason
// (the earliest candidate's, so the daemon's own agent's first); else the
// organization's refusal stands.
func (d *SandboxDaemon) readyPolicyRefusal(ctx context.Context, candidates []string, pack string) error {
	askCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		index     int
		allowed   bool
		sandboxes bool
		err       error
	}
	next := make(chan int, len(candidates))
	for index := range candidates {
		next <- index
	}
	close(next)
	answers := make(chan answer, len(candidates))
	for range min(readyViewsInFlight, len(candidates)) {
		go func() {
			for index := range next {
				if err := askCtx.Err(); err != nil {
					answers <- answer{index: index, err: err}
					continue
				}
				allowed, sandboxes, err := d.readyPolicyView(askCtx, candidates[index], pack)
				answers <- answer{index: index, allowed: allowed, sandboxes: sandboxes, err: err}
			}
		}()
	}
	errs := make([]error, len(candidates))
	sandboxesAllowed := false
	for range candidates {
		a := <-answers
		if a.allowed {
			return nil
		}
		errs[a.index] = a.err
		sandboxesAllowed = sandboxesAllowed || a.sandboxes
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	if sandboxesAllowed {
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
			Message: "Your organization doesn't allow this agent in a sandbox.", Detail: sandboxrelay.ReasonNotAllowed}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
		Message: "Your organization doesn't allow sandboxes for your account.", Detail: sandboxrelay.ReasonNotAllowed}
}

// readyPolicyView is whether the managed gateway's policy view of one agent
// allows it in a sandbox (managedExplainAllowsHarness), and whether it allows
// sandboxes at all, within one view's bound (managedViewTimeout). A view
// the gateway's admission limit refused (429) is asked again within that
// bound; when the bound ends first, the 429 is the view's error, which fails
// the ready closed unless another agent is allowed.
//
// The view decides only once it is settled. A provisional one (the
// caller's directory lookup had not finished, so the default profile
// answered) can still change, also to a group the organization denies, and
// the create's resolve waits for that lookup (sandboxrelay.
// ResolveIdentityWait): the ready asks again until the view is settled or
// that wait is over, and then goes by the view as the create would
// (GAP-0820). A view whose run the organization's pack forbids
// (managedPostureFatal) refuses the ready with that violation (GAP-0812).
func (d *SandboxDaemon) readyPolicyView(ctx context.Context, name, pack string) (allowed, sandboxes bool, err error) {
	settled := time.Now().Add(sandboxrelay.ResolveIdentityWait)
	for {
		view, err := d.readyPolicyViewOnce(ctx, name, pack)
		if err != nil {
			return false, false, err
		}
		if !view.Provisional || !time.Now().Before(settled) {
			allowed := managedExplainAllowsHarness(view, name)
			if v := managedPostureFatal(view); v != nil && allowed {
				return false, view.Allowed, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
					Message: firstNonEmpty(v.Message, "Your organization doesn't allow this agent in a sandbox."), Detail: v.Detail, Violation: v}
			}
			return allowed, view.Allowed, nil
		}
		timer := time.NewTimer(readyProvisionalPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, false, ctx.Err()
		case <-timer.C:
		}
	}
}

// readyProvisionalPoll paces readyPolicyView's asks while the view is
// provisional; the managed gateway's explain itself waits a moment for the
// lookup it runs.
var readyProvisionalPoll = 500 * time.Millisecond

// readyPolicyViewOnce is one policy view of the agent name for a ready,
// within one view's bound (managedViewTimeout). A view the gateway's
// admission limit refused (429) is asked again within that bound; when the
// bound ends first, the 429 is the view's error.
func (d *SandboxDaemon) readyPolicyViewOnce(ctx context.Context, name, pack string) (sandboxapi.ManagedExplain, error) {
	viewCtx, cancel := context.WithTimeout(ctx, managedViewTimeout)
	defer cancel()
	wait := readyViewRetryFirst
	for {
		// The run's own pack: an organization pack the run names may allow
		// an agent the default pack leaves out (GAP-1551).
		view, _, viewErr := d.managedExplain(viewCtx, sandboxapi.ExplainRequest{Harness: name, Pack: pack}, nil)
		if viewErr == nil {
			return view, nil
		}
		if sandboxapi.AsError(viewErr).Status != http.StatusTooManyRequests {
			return sandboxapi.ManagedExplain{}, viewErr
		}
		timer := time.NewTimer(wait)
		select {
		case <-viewCtx.Done():
			timer.Stop()
			return sandboxapi.ManagedExplain{}, viewErr
		case <-timer.C:
		}
		wait = min(2*wait, readyViewRetryMax)
	}
}

// Ready readies the account's OpenShell for a first run (readyOpenShell:
// setup mode installs the pinned release; both modes start and register the
// account's managed gateway) and answers the status. A run needs that before
// its create: its preflight reads the gateway's driver and runs the
// openshell CLI, and refused every run of an account whose OpenShell was not
// installed or started yet, before the create that readies it ran
// (GAP-0437, GAP-0441). The managed gateway's policy must allow sandboxes
// for the named agent first, and only its view is asked
// (readyPolicyRefusal). A request that names no agent, from a CLI of
// DefenseClaw 1.0.3 or older, does not say which agent it will run: it
// readies when the policy allows any agent a create may run
// (olderCLIReadyHarnesses), and the create judges the run's own agent, as a
// 1.0.3 daemon did. Kept through the 1.0.4 upgrade window.
func (c *managedSandboxController) Ready(ctx context.Context, req sandboxapi.ReadyRequest) (*sandboxapi.Status, error) {
	d := c.d
	candidates := []string{req.Harness}
	if strings.TrimSpace(req.Harness) == "" {
		candidates = d.olderCLIReadyHarnesses()
	} else if _, ok := harness.Get(config.NormalizeConnectorName(req.Harness)); !ok {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "a supported sandbox harness is required to ready OpenShell")
	}
	if err := d.lockLifecycle(ctx); err != nil {
		return nil, managedBusyError(err)
	}
	boundForReady := false
	s := d.freshSettings(ctx)
	err := managedSettingsRefusal(s)
	if err == nil {
		// Another account's gateway on the gateway port refuses at once,
		// before setup mode installs anything for a run that cannot start.
		if uid, held := d.openShell.PortHolder(s); held && uid != d.uid {
			err = accountBusyError()
		} else if err = d.readyPolicyRefusal(ctx, candidates, req.Pack); err == nil {
			// Status reports unavailable until this process holds both
			// listeners. Bind them before setup installs anything, so a
			// busy port refuses Ready without changing the account.
			wasListening := d.listening()
			if err = d.ensureListeners(); err == nil {
				boundForReady = !wasListening
				err = d.readyOpenShell(ctx, s, "")
			}
		}
	}
	if err != nil && boundForReady {
		// A failed Ready leaves a listener it found in place, but releases
		// listeners it bound itself even when the gateway cannot list boxes.
		d.releaseListeners()
	}
	if err != nil {
		d.unlockLifecycle()
		d.reportAccountBusy(ctx, "", err)
		return nil, err
	}
	// A supervisor pass may release idle listeners as soon as the lifecycle
	// unlocks. Report the readiness this call established while it still
	// holds that lock; Create will bind again if an idle pass follows.
	st, statusErr := c.Status(ctx)
	d.unlockLifecycle()
	return st, statusErr
}

// Create resolves the run at the managed gateway, creates the sandbox
// against the floor it answered and binds the registration to it. Any
// failure after the gateway registered the run deletes what was made.
//
// Managed creates and starts run one at a time (the lifecycle), so the
// supervision cannot release the listeners while one is under way. A create
// pins its own floor because a registration poll can change the default floor.
func (c *managedSandboxController) Create(ctx context.Context, req sandboxapi.CreateRequest) (_ *sandboxapi.Sandbox, err error) {
	d := c.d
	if err := d.lockLifecycle(ctx); err != nil {
		return nil, managedBusyError(err)
	}
	defer func() {
		if err != nil {
			d.releaseIfIdleLocked(ctx)
			d.reportAccountBusy(ctx, req.Harness, err)
		}
		d.unlockLifecycle()
	}()
	s, err := d.createSettings(ctx)
	if err != nil {
		return nil, err
	}
	if err := managedSettingsRefusal(s); err != nil {
		return nil, err
	}
	// The compute driver: chosen now, at sandbox start, by the user's own
	// KVM probe (never at login).
	choice, err := d.selectDriver(s)
	if err != nil {
		return nil, err
	}
	if err := d.dockerReady(ctx, s); err != nil {
		return nil, err
	}
	if err := d.ensureListeners(); err != nil {
		return nil, err
	}
	mcp := d.userMCPServers(req.Harness, req.NoMCP)
	resolveReq, err := d.resolveRequest(req, choice, mcp)
	if err != nil {
		return nil, err
	}
	resp, err := d.relay.Resolve(ctx, resolveReq)
	if err != nil {
		return nil, managedRelayError(err)
	}
	if resp.Refusal != nil {
		msg := resp.Refusal.Message
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
			Message: msg, Detail: resp.Refusal.Reason}
	}
	reg := resp.Registration.ID
	if reg == "" {
		return nil, managedPolicyUnloadable(errors.New("the managed gateway's answer has no registration"))
	}
	undo := func() {
		if err := d.relay.Deleted(context.WithoutCancel(ctx), reg); err != nil {
			d.logf("release registration %s: %v", reg, err)
		}
	}
	floor, err := managedResolveFloor(resp)
	if err == nil {
		_, err = useAuthorityPack(resp, floor)
	}
	if err != nil {
		d.logf("the managed gateway's policy answer can't be applied: %v", err)
		undo()
		return nil, managedPolicyUnloadable(err)
	}
	d.adoptMu.Lock()
	d.floorMu.Lock()
	d.floor = &floor
	d.floorMu.Unlock()
	d.reloadConfig()
	d.adoptMu.Unlock()
	if err := d.readyOpenShell(ctx, s, reg); err != nil {
		undo()
		return nil, err
	}

	// The user's OpenShell gateway must run the chosen driver (the manager
	// refuses the create otherwise); the record keeps the reason.
	createCtx := withManagedMCPJudge(manager.WithCreateConfig(manager.WithDriverChoice(ctx, choice), d.configWithFloor(floor)),
		fixedMCPJudge(resolveMCPDecision(resolveReq.Harness, mcp, resp)))
	// The sandbox this create reserves resolves under createCtx's floor
	// until its registration is kept (manager.EndCreate, GAP-0016).
	sb, err := c.Manager.Create(createCtx, req)
	if err != nil {
		undo()
		return nil, err
	}
	binding, err := d.rt.bindings.Lookup(sb.Name)
	if err == nil {
		_, err = d.relay.Bind(ctx, reg, sandboxrelay.BindRequest{SandboxID: sb.ID, SandboxName: sb.Name, BindingID: binding.ID,
			Driver: string(choice.Driver)})
	}
	if err == nil {
		err = d.regs.put(daemonRegistration{
			ID: reg, Sandbox: sb.Name, Profile: resp.Banner.Profile, Provisional: resp.Banner.Provisional,
			Digest: resp.Banner.PolicyDigest, Generation: resp.Generation, Floor: floor, UpdatedAt: time.Now().UTC(),
			Driver: string(choice.Driver), DriverReason: choice.Reason, Confirmed: true,
		})
	}
	if err != nil {
		// A sandbox the delete leaves behind has no registration: the
		// closed floor, not the create's.
		c.EndCreate(sb.Name, sb.ID)
		if _, delErr := c.Manager.Delete(context.WithoutCancel(ctx), sb.Name, sandboxapi.DeleteRequest{}); delErr != nil {
			d.logf("delete %s after its registration failed: %v", sb.Name, delErr)
		}
		undo()
		return nil, managedRelayError(err)
	}
	c.EndCreate(sb.Name, sb.ID)
	if fresh, err := c.Manager.Get(ctx, sb.Name); err == nil && fresh != nil {
		// The view under the registration just kept, not one a refresh
		// during the create judged against the closed floor (GAP-0016).
		sb = fresh
	}
	return sb, nil
}

// Start starts a stopped sandbox again under its live registration.
func (c *managedSandboxController) Start(ctx context.Context, name string, req sandboxapi.StartRequest) (_ *sandboxapi.Sandbox, err error) {
	d := c.d
	if err := d.lockLifecycle(ctx); err != nil {
		return nil, managedBusyError(err)
	}
	defer func() {
		if err != nil {
			d.releaseIfIdleLocked(ctx)
			d.reportAccountBusy(ctx, "", err)
		}
		d.unlockLifecycle()
	}()
	r, ok := d.regs.get(name)
	if !ok || r.Revoked {
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
			Message: "your organization's policy no longer covers sandbox " + name + "; delete it and start it again with defenseclaw sandbox run"}
	}
	// Reported running before the start, so the agent's first hooks are
	// admitted; a start that fails reports it stopped again. Its answer is
	// applied in the order of the registration's requests (applyOrdered).
	seq := d.regs.nextSeq()
	cp, err := d.relay.Report(ctx, r.ID, true)
	if err == nil {
		d.starting.Store(name, struct{}{})
		defer func() {
			d.starting.Delete(name)
			if err != nil {
				d.reportStopped(context.WithoutCancel(ctx), name)
				return
			}
			// Running once more: a poll that listed the sandbox stopped
			// before this start marked it may have reported it so since.
			if _, rerr := d.relay.Report(context.WithoutCancel(ctx), r.ID, true); rerr != nil {
				d.logf("report %s running: %v", name, rerr)
			}
		}()
	}
	if err != nil {
		// Only a registration the gateway ended for good is revoked; a
		// budget 429, a CSRF 403 or an outage leaves it for the next try.
		if reason, gone := registrationGone(err); gone {
			d.regs.markRevoked(name, reason)
		}
		return nil, managedRelayError(err)
	}
	if cp.Revoked {
		d.regs.markRevokedText(name, cp.RevokedReason, cp.RevokedReason)
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Status: http.StatusForbidden,
			Message: "your organization's policy no longer covers sandbox " + name + "; delete it and start it again with defenseclaw sandbox run"}
	}
	if cp.Floor == nil {
		return nil, managedPolicyUnloadable(errors.New("managed gateway omitted the complete sandbox policy floor"))
	}
	if err := useCurrentPack(cp); err != nil {
		return nil, managedPolicyUnloadable(err)
	}
	d.regs.applyOrdered(r, seq, cp)
	// A sandbox that starts again runs under the profile minimum of the
	// person's floor now, not the looser one it registered under (GAP-0224).
	d.regs.applyStartFloor(name, r.ID, cp)
	r, _ = d.regs.get(name)
	if err := d.ensureListeners(); err != nil {
		return nil, err
	}
	if err := d.readyOpenShell(ctx, d.currentSettings(), r.ID); err != nil {
		return nil, err
	}
	d.adoptFloor(name)
	// Its saved decisions as the floor now keeps them (GAP-0224).
	c.ReloadDecisions(ctx, r.ID)
	return c.Manager.Start(withManagedMCPJudge(ctx, d.startMCPJudge(r.ID)), name, req)
}

// userMCPServers are the caller's own MCP servers of harnessName (user
// scope, read as the caller), none with --no-mcp or when they can't be read.
func (d *SandboxDaemon) userMCPServers(harnessName string, noMCP bool) []config.MCPServerEntry {
	if noMCP || d.opts.mcpRead == nil {
		return nil
	}
	spec, ok := harness.Get(config.NormalizeConnectorName(harnessName))
	if !ok {
		return nil
	}
	entries, err := d.opts.mcpRead(spec.Name)
	if err != nil {
		return nil
	}
	return entries
}

// startMCPJudge asks the managed gateway, for a start of registration's
// sandbox, which of the caller's MCP servers it brings along now: the
// organization's block list and asset policy may have changed since the
// create. A failed answer fails the start.
func (d *SandboxDaemon) startMCPJudge(registration string) managedMCPJudge {
	return func(ctx context.Context, harnessName string) (*managedMCPDecision, error) {
		entries := d.userMCPServers(harnessName, false)
		claims := managedMCPClaims(entries)
		if len(claims) == 0 {
			return newManagedMCPDecision(harnessName, entries, nil, nil), nil
		}
		me, err := d.relay.Explain(ctx, sandboxrelay.ExplainRequest{Registration: registration, MCP: claims})
		if err != nil {
			return nil, managedRelayError(err)
		}
		return explainMCPDecision(harnessName, entries, me), nil
	}
}

// Delete deletes the sandbox and drops its registration at the gateway.
func (c *managedSandboxController) Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	// A kept sandbox is deleted on the account's gateway, started for it
	// when the daemon had stopped it (GAP-0492).
	defer c.d.scheduleCheck(time.Second)
	c.d.stops.Add(1)
	defer c.d.stops.Add(-1)
	ready := c.d.openShellForKept(ctx, true)
	resp, err := c.Manager.Delete(ctx, name, req)
	if err != nil {
		// A name the account has no sandbox of is that, whoever holds the
		// gateway: the busy text sent the person to wait for nothing
		// (GAP-0126).
		if ready != nil && !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			return nil, ready
		}
		return resp, err
	}
	if r, ok := c.d.regs.get(name); ok {
		if err := c.d.relay.Deleted(ctx, r.ID); err != nil {
			c.d.logf("drop the registration of %s: %v", name, err)
		}
		_ = c.d.regs.drop(name)
	}
	c.d.handoverOpenShell(ctx)
	return resp, nil
}

// Explain is the caller's own policy: the managed gateway's answer, and the
// posture resolved against the floor it names (managedExplain).
//
// For a new run the gateway also judges the caller's own MCP servers (the
// MCP row), and the run files the explain renders bring along those it
// kept, as a create would.
func (c *managedSandboxController) Explain(ctx context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	var mcp []config.MCPServerEntry
	connectorName := c.d.managedConnector(req.Harness)
	if req.Sandbox == "" {
		mcp = c.d.userMCPServers(connectorName, false)
	}
	me, floor, err := c.d.managedExplain(ctx, req, mcp)
	if err != nil {
		return nil, err
	}
	if me.Posture == nil {
		// The managed gateway could not resolve the run: its policy is
		// unknown here, and the daemon's own resolution (without the
		// administrator's packs) is not it.
		return nil, managedPolicyUnloadable(errors.New("the managed gateway's explain has no posture"))
	}
	if req.Sandbox == "" {
		ctx = withManagedMCPJudge(ctx, fixedMCPJudge(explainMCPDecision(connectorName, mcp, me)))
	}
	out, err := c.ExplainUnder(ctx, c.d.configWithFloor(floor), req)
	if err != nil {
		var apiErr *sandboxapi.Error
		if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodePackInvalid {
			return nil, err
		}
		// The daemon cannot read the administrator's packs; the
		// gateway's posture below is the answer.
		out = &sandboxapi.Explain{}
	}
	applyManagedPosture(out, me.Posture)
	me.Posture = nil
	if req.Sandbox == "" && req.Project != "" {
		// The project's own MCP servers, which only this process can read
		// as the caller: the MCP row counts them (#1200).
		project := req.Project
		if real, err := filepath.EvalSymlinks(project); err == nil {
			project = real
		}
		if spec, ok := harness.Get(connectorName); ok {
			me.MCPProjectCount = manager.ProjectMCPServerCount(spec.Name, project)
		}
		me.MCPProjectBlocked = true
		for _, s := range out.Settings {
			if s.Key == "mcp.project_servers" {
				me.MCPProjectBlocked = s.Value != packs.MCPProjectServersAllow
			}
		}
	}
	if me.Workspace != nil {
		// A new run's copy policy is the managed gateway's: the explain floor
		// leaves out the organization's pack, which the gateway resolves
		// (GAP-0478).
		out.Workspace = me.Workspace
	}
	out.Managed = &me
	return out, nil
}

// applyManagedPosture replaces the posture the daemon resolved itself in
// out with the managed gateway's (ManagedExplain.Posture): the pack and its
// chain, the profile and modes, every setting and the run's violations.
// The daemon's resolution lacks the caller's required pack and profile
// minimum (GAP-0179, GAP-0438); what only the daemon knows (the repository
// policy file it read, a MicroVM's first boot) stays.
func applyManagedPosture(out *sandboxapi.Explain, p *sandboxapi.ManagedPosture) {
	out.Pack, out.PackSource, out.PackDigest, out.PackChain = p.Pack, p.PackSource, p.PackDigest, p.PackChain
	out.Profile, out.NetworkMode, out.Approvals = p.Profile, p.NetworkMode, p.Approvals
	out.Settings, out.Violations = p.Settings, p.Violations
	if out.RepoPolicy != nil {
		out.RepoPolicy.Tightened = p.RepoTightened
	}
}

// PolicyTest judges destinations with a sandbox's policy or, naming none,
// with the caller's own policy for a new run in req.Project: resolved
// against the floor the managed gateway names, no sandbox needed
// (GAP-0228).
func (c *managedSandboxController) PolicyTest(ctx context.Context, req sandboxapi.PolicyTestRequest) (*sandboxapi.PolicyTestResult, error) {
	if req.Sandbox != "" {
		// Judged under the policy the sandbox's next connection meets: a
		// changed policy and its saved decisions are confirmed first, as
		// the egress proxy does, and while the proxy refuses the sandbox's
		// connections the test says so (GAP-0224).
		_, off := c.d.confirmEgressPolicy(ctx, egress.Principal{SandboxName: req.Sandbox})
		res, err := c.Manager.PolicyTest(ctx, req)
		if err != nil || off == nil {
			return res, err
		}
		for i := range res.Decisions {
			d := &res.Decisions[i]
			d.Allowed, d.Rule, d.Match, d.Source, d.Reason, d.Unblockable = false, string(off.Category), "", "", off.Reason, false
		}
		return res, nil
	}
	// The managed gateway judges them under the caller's floor, its
	// required pack and profile minimum included, which the daemon's own
	// resolution leaves out (GAP-0438).
	treq := sandboxrelay.PolicyTestRequest{Connector: c.d.managedConnector(req.Harness), Checks: req.Checks}
	if req.Project != "" && filepath.IsAbs(req.Project) {
		if real, err := filepath.EvalSymlinks(req.Project); err == nil {
			treq.ProjectReal = real
		}
	}
	overlay, _, err := runFiles(treq.ProjectReal, "")
	if err != nil {
		return nil, err
	}
	treq.RepoOverlay = overlay
	out, err := c.d.relay.PolicyTest(ctx, treq)
	if err != nil {
		return nil, managedRelayError(err)
	}
	return &out, nil
}

// runFiles are a new run's repository policy (<project>/.defenseclaw/
// sandbox.yaml) and --pack file as the daemon reads them, as the user, for
// the managed gateway to resolve: the gateway reads no file a user names.
func runFiles(project, pack string) (overlay, userPack []byte, err error) {
	if project != "" {
		overlay, err = readBounded(filepath.Join(project, ".defenseclaw", "sandbox.yaml"), sandboxrelay.MaxRepoOverlayBytes)
		if err != nil {
			return nil, nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "the repository policy: %v", err)
		}
	}
	if strings.ContainsRune(pack, '/') {
		if info, err := os.Stat(pack); err == nil && info.IsDir() {
			pack = filepath.Join(pack, "pack.yaml")
		}
		if userPack, err = readBounded(pack, sandboxrelay.MaxUserPackBytes); err != nil {
			return nil, nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "the pack: %v", err)
		}
	}
	return overlay, userPack, nil
}

// resolveRequest is what policy/resolve is told of a create: every field a
// claim the managed gateway judges, the user's MCP servers mcp among them
// (managedMCPClaims).
func (d *SandboxDaemon) resolveRequest(req sandboxapi.CreateRequest, choice openshell.DriverChoice, mcp []config.MCPServerEntry) (sandboxrelay.ResolveRequest, error) {
	name := config.NormalizeConnectorName(req.Harness)
	spec, ok := harness.Get(name)
	if !ok {
		return sandboxrelay.ResolveRequest{}, sandboxapi.Errorf(sandboxapi.CodeInvalid, "unknown harness %q (supported: %s)",
			req.Harness, strings.Join(harness.Names(), ", "))
	}
	project := ""
	if req.Project != "" {
		real, err := filepath.EvalSymlinks(req.Project)
		if err != nil {
			return sandboxrelay.ResolveRequest{}, sandboxapi.Errorf(sandboxapi.CodeInvalid, "project folder: %v", err)
		}
		project = real
	}
	s := d.currentSettings()
	version := spec.DefaultVersion
	if pin := s.Operational.Image.HarnessVersions[spec.Name]; pin != "" {
		version = pin
	}
	out := sandboxrelay.ResolveRequest{
		V: sandboxrelay.WireVersion, Harness: spec.Name, Connector: spec.Name, HarnessVersion: version,
		TamperTier: spec.TamperTier, ProjectReal: project,
		Flags: sandboxrelay.RunFlags{
			Pack: req.Pack, Profile: req.Profile, Copy: req.Copy, Safe: req.Safe, Yolo: req.Yolo,
			Unmask: req.Unmask, HostPorts: req.HostPorts, NoMCP: req.NoMCP, Learn: req.Learn,
			ProcessTree: req.ProcessTree, CPU: req.CPU, Memory: req.Memory,
		},
		Resources:    sandboxrelay.Resources{CPU: req.CPU, Memory: req.Memory},
		MCP:          managedMCPClaims(mcp),
		Driver:       string(choice.Driver),
		DriverReason: choice.Reason,
		OpenShell:    sandboxrelay.OpenShellFacts{Version: s.Enterprise.Version, InstallMode: s.Enterprise.Install},
	}
	overlay, pack, err := runFiles(project, req.Pack)
	if err != nil {
		return sandboxrelay.ResolveRequest{}, err
	}
	out.RepoOverlay, out.UserPack = overlay, pack
	return out, nil
}

// selectDriver picks the compute driver of a create at sandbox start: the
// organization's driver and the caller's own fallback (the managed
// settings), and on Linux the KVM probe, run now as the user. Where the
// MicroVM driver is required (driver_fallback: none) and can't run, the
// create is refused with the reason and the caller's request-access
// contact.
func (d *SandboxDaemon) selectDriver(s sandboxrelay.DaemonSettings) (openshell.DriverChoice, error) {
	choice, err := openshell.SelectDriver(d.opts.goos, s.Enterprise.Driver, s.Enterprise.DriverFallback,
		func() openshell.VMProbeResult { return d.opts.vmProbe(s) })
	var refused *openshell.DriverUnavailableError
	switch {
	case errors.As(err, &refused):
		d.logf("sandbox start refused: the MicroVM driver is required and can't run (%s)", refused.Reason)
		return openshell.DriverChoice{}, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: sandboxapi.DriverUnavailable(openshell.DriverReasonText(refused.Reason), s.RequestAccess),
			Detail:  "driver_unavailable: " + refused.Reason}
	case err != nil:
		return openshell.DriverChoice{}, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
			Message: sandboxapi.AdminMessage, Detail: err.Error()}
	}
	if choice.Fallback() {
		d.logf("sandbox start: docker fallback (%s)", choice.Reason)
	}
	d.lastDriver.Store(&choice)
	return choice, nil
}

// dockerReady refuses a create on a Mac whose Docker does not answer for the
// account, before anything is registered. The MicroVM driver boots the
// agent's image from the account's Docker, where DefenseClaw builds it, and
// a create without Docker failed later on a docker exec error (GAP-0443).
func (d *SandboxDaemon) dockerReady(ctx context.Context, s sandboxrelay.DaemonSettings) error {
	if d.opts.goos != "darwin" {
		return nil
	}
	err := d.opts.dockerEngine(ctx)
	if err == nil {
		return nil
	}
	d.logf("sandbox start refused: Docker does not answer: %v", err)
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: sandboxapi.DockerUnavailable(err.Error(), s.RequestAccess), Detail: "docker_unavailable"}
}

// daemonDockerEngine asks the account's Docker for its server version.
func daemonDockerEngine(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := (image.CLI{}).Run(ctx, nil, &out, &out, "version", "--format", "{{.Server.Version}}"); err != nil {
		if line := lastNonEmptyLine(out.String()); line != "" {
			return errors.New(line)
		}
		return err
	}
	return nil
}

// lastNonEmptyLine is the last line of s with text.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// daemonVMProbe is the user's own MicroVM probe at sandbox start: the CPU's
// virtualization flags, /dev/kvm opened read-write as the user (the test the
// driver itself meets), and openshell-driver-vm in the rendered driver_dir
// when set, or in the user's and system directories otherwise, followed by
// the executable listening on this account's managed gateway port, or the
// executable its unit will start when the port is still free.
func daemonVMProbe(s sandboxrelay.DaemonSettings) openshell.VMProbeResult {
	home, _ := os.UserHomeDir()
	return openshell.VMProbe{DriverDirs: daemonVMDriverDirs(s, home, openshell.GatewayExecutableOnPort(gatewayPort(s)))}.Run()
}

func daemonVMDriverDirs(s sandboxrelay.DaemonSettings, home, gatewayExecutable string) []string {
	dir := ""
	if path := s.Enterprise.GatewayConfigPath; path != "" {
		if data, err := readBounded(path, 1<<20); err == nil && data != nil {
			if rendered, err := openshell.ParseRenderedGateway(data, nil); err == nil {
				dir = rendered.DriverDir
			}
		}
	}
	if gatewayExecutable == "" {
		gatewayExecutable = newAccountOpenShell(runtime.GOOS, os.Geteuid(), home, nil).gatewayBinary(s)
	}
	return openshell.UserVMDriverDirs(home, dir, gatewayExecutable)
}

// readBounded reads a regular file of at most limit bytes; a missing file
// is nil.
func readBounded(path string, limit int) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

// managedRelayError maps a relay failure onto the sandbox API: a gateway
// refusal keeps its text, an unreachable gateway is unavailable.
func managedRelayError(err error) error {
	var apiErr *sandboxapi.Error
	if errors.As(err, &apiErr) {
		return err
	}
	var invalid *sandboxrelay.InvalidRequestError
	if errors.As(err, &invalid) {
		// The caller's own input, refused before the gateway was asked: not
		// an unreachable gateway (GAP-0579).
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Status: http.StatusBadRequest, Message: invalid.Message}
	}
	var refused *sandboxrelay.Error
	if errors.As(err, &refused) {
		msg := refused.Message
		if msg == "" {
			msg = sandboxapi.AdminMessage
		}
		status, code := refused.Status, sandboxapi.CodeAdminViolation
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		if status == http.StatusTooManyRequests || status >= 500 {
			code = sandboxapi.CodeUnavailable
		}
		return &sandboxapi.Error{Code: code, Status: status, Message: msg, Detail: refused.Reason}
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: "the managed DefenseClaw gateway is not reachable", Detail: err.Error()}
}

// managedBusyError is a create or start whose caller gave up while another
// one was under way.
func managedBusyError(err error) error {
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: "another sandbox of yours is being created or started; try again when it is up", Detail: err.Error()}
}

// managedPolicyUnloadable is a resolve answer the daemon cannot apply.
func managedPolicyUnloadable(err error) error {
	return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusServiceUnavailable,
		Message: "your organization's sandbox policy could not be loaded; contact your IT help desk",
		Detail:  sandboxrelay.ReasonPolicyUnloadable + ": " + err.Error()}
}

// daemonRegistration is one sandbox's managed registration as the daemon
// keeps it.
type daemonRegistration struct {
	ID          string                      `json:"id"`
	Sandbox     string                      `json:"sandbox"`
	Profile     string                      `json:"profile,omitempty"`
	Provisional bool                        `json:"provisional,omitempty"`
	Digest      string                      `json:"digest,omitempty"`
	Generation  uint64                      `json:"generation,omitempty"`
	Floor       config.OpenShellAdminConfig `json:"floor"`
	// Driver and DriverReason are the compute driver the sandbox was
	// created on and why (openshell.DriverReason*); it never switches.
	Driver        string `json:"driver,omitempty"`
	DriverReason  string `json:"driver_reason,omitempty"`
	Revoked       bool   `json:"revoked,omitempty"`
	RevokedReason string `json:"revoked_reason,omitempty"`
	// StopText is the managed gateway's words for the revoke, when its
	// policy answer said them (CurrentPolicy.RevokedReason): the user's
	// views and the activity feed give them (#1199).
	StopText  string    `json:"stop_text,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	// Confirmed is never persisted: the managed gateway answered for the
	// registration in this daemon's lifetime (a create, or policy/current),
	// so its floor may be adopted.
	Confirmed bool `json:"-"`
}

// daemonRegistrations is the daemon's registrations by sandbox name, kept
// in a 0600 file in its state directory so a restarted daemon relays the
// hooks of the sandboxes it left running.
type daemonRegistrations struct {
	path   string
	mu     sync.Mutex
	byName map[string]daemonRegistration
	// seq numbers the policy requests (nextSeq); applied is, by
	// registration id, the newest request whose answer was applied
	// (applyOrdered, under mu); changes counts the changes applyLive made
	// (changeCount).
	seq     atomic.Uint64
	applied map[string]uint64
	changes atomic.Uint64
}

func loadDaemonRegistrations(path string) (*daemonRegistrations, error) {
	r := &daemonRegistrations{path: path, byName: map[string]daemonRegistration{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sandbox daemon: read %s: %w", path, err)
	}
	var doc struct {
		V             int                  `json:"v"`
		Registrations []daemonRegistration `json:"registrations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.V != 1 {
		return nil, fmt.Errorf("sandbox daemon: %s is not a registrations file", path)
	}
	for _, reg := range doc.Registrations {
		if reg.ID != "" && reg.Sandbox != "" {
			// The file belongs to the account. Keep only the registration
			// identity until policy/current confirms its complete floor.
			reg.Floor = config.OpenShellAdminConfig{}
			r.byName[reg.Sandbox] = reg
		}
	}
	return r, nil
}

func (r *daemonRegistrations) get(name string) (daemonRegistration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byName[name]
	return reg, ok
}

// byID is the registration with id.
func (r *daemonRegistrations) byID(id string) (daemonRegistration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, reg := range r.byName {
		if reg.ID == id {
			return reg, true
		}
	}
	return daemonRegistration{}, false
}

func (r *daemonRegistrations) list() []daemonRegistration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]daemonRegistration, 0, len(r.byName))
	for _, reg := range r.byName {
		out = append(out, reg)
	}
	return out
}

// newest is the most recently updated live registration.
func (r *daemonRegistrations) newest() (daemonRegistration, bool) {
	var best daemonRegistration
	found := false
	for _, reg := range r.list() {
		if !reg.Revoked && (!found || reg.UpdatedAt.After(best.UpdatedAt)) {
			best, found = reg, true
		}
	}
	return best, found
}

// newestFloor is the floor of the newest live registration the managed
// gateway confirmed whose sandbox runs (runs nil: any sandbox), or nil.
func (r *daemonRegistrations) newestFloor(runs func(sandbox string) bool) *config.OpenShellAdminConfig {
	var best *daemonRegistration
	for _, reg := range r.list() {
		if reg.Revoked || !reg.Confirmed || (runs != nil && !runs(reg.Sandbox)) {
			continue
		}
		if best == nil || reg.UpdatedAt.After(best.UpdatedAt) {
			reg := reg
			best = &reg
		}
	}
	if best == nil {
		return nil
	}
	floor := best.Floor
	return &floor
}

// put records reg; a registration the file could not keep is not kept in
// memory either.
func (r *daemonRegistrations) put(reg daemonRegistration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, had := r.byName[reg.Sandbox]
	r.byName[reg.Sandbox] = reg
	err := r.saveLocked()
	if err != nil {
		if had {
			r.byName[reg.Sandbox] = prev
		} else {
			delete(r.byName, reg.Sandbox)
		}
	}
	return err
}

func (r *daemonRegistrations) drop(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byName, name)
	return r.saveLocked()
}

func (r *daemonRegistrations) markRevoked(name, reason string) { r.markRevokedText(name, reason, "") }

// markRevokedText is markRevoked with the managed gateway's words for the
// revoke (daemonRegistration.StopText), "" when it gave none.
// It reports whether this call marked it: a registration another path
// marked first is that path's to stop.
func (r *daemonRegistrations) markRevokedText(name, reason, text string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byName[name]
	if !ok || reg.Revoked {
		return false
	}
	reg.Revoked, reg.RevokedReason, reg.StopText, reg.UpdatedAt = true, reason, text, time.Now().UTC()
	r.byName[name] = reg
	_ = r.saveLocked()
	return true
}

// applyLive replaces the floor from a policy/current answer, marks the
// registration confirmed, and reports whether anything changed (a first
// confirmation included). The registration's UpdatedAt becomes the answer's
// policy time, so the status
// shows when the policy last changed, also for a change of a field that is
// not live (GAP-0690); that alone is not a change the floor adopts.
func (r *daemonRegistrations) applyLive(name string, cp sandboxrelay.CurrentPolicy) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyLiveLocked(name, cp)
}

// applyStartFloor gives the registration id of sandbox name the min_profile
// of a policy/current answer its start asked for (CurrentPolicy.MinProfile).
// The profile minimum is not live: a running sandbox keeps the one it
// started with, and its next start takes the floor's now, so a sandbox
// stopped under a looser profile never runs under it again (GAP-0224). An
// answer without it changes nothing.
func (r *daemonRegistrations) applyStartFloor(name, id string, cp sandboxrelay.CurrentPolicy) {
	if cp.MinProfile == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byName[name]
	if !ok || reg.ID != id || reg.Floor.MinProfile == *cp.MinProfile {
		return
	}
	reg.Floor.MinProfile = *cp.MinProfile
	r.byName[name] = reg
	_ = r.saveLocked()
	r.changes.Add(1)
}

// unconfirm puts registration id of sandbox name back on the closed floor
// (configForSandbox) until an answer confirms it again (applyLive), and
// reports whether it was confirmed. It counts as a change, so the next
// adoption re-resolves the sandbox's policy.
func (r *daemonRegistrations) unconfirm(name, id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byName[name]
	if !ok || reg.ID != id || !reg.Confirmed {
		return false
	}
	reg.Confirmed = false
	r.byName[name] = reg
	r.changes.Add(1)
	return true
}

// nextSeq numbers a policy request of a registration, taken before it is
// sent (applyOrdered).
func (r *daemonRegistrations) nextSeq() uint64 { return r.seq.Add(1) }

// changeCount is how many changes applyLive made so far: a registration's
// floor, digest, profile, generation, policy time or first confirmation,
// any of which can move the floor the manager resolves against
// (adoptApplied).
func (r *daemonRegistrations) changeCount() uint64 { return r.changes.Load() }

// applyOrdered is applyLive for the answer to the policy request of reg
// numbered seq (nextSeq). An answer to a request older than one already
// applied for the registration, or for a registration its sandbox's name no
// longer holds, changes nothing: a late answer never undoes a newer one, so
// a tightening a confirmation applied stays (GAP-0172).
func (r *daemonRegistrations) applyOrdered(reg daemonRegistration, seq uint64, cp sandboxrelay.CurrentPolicy) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.byName[reg.Sandbox]; !ok || cur.ID != reg.ID || seq < r.applied[reg.ID] {
		return false
	}
	if r.applied == nil {
		r.applied = map[string]uint64{}
	}
	r.applied[reg.ID] = seq
	return r.applyLiveLocked(reg.Sandbox, cp)
}

// pruneApplied forgets the request order of the registrations not in regs.
func (r *daemonRegistrations) pruneApplied(regs []daemonRegistration) {
	live := make(map[string]bool, len(regs))
	for _, reg := range regs {
		live[reg.ID] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.applied {
		if !live[id] {
			delete(r.applied, id)
		}
	}
}

// applyLiveLocked is applyLive under r.mu.
func (r *daemonRegistrations) applyLiveLocked(name string, cp sandboxrelay.CurrentPolicy) bool {
	reg, ok := r.byName[name]
	if !ok || cp.Floor == nil {
		return false
	}
	digest := cp.Digest
	confirmed := !reg.Confirmed
	reg.Confirmed = true
	policyAt := cp.UpdatedAt.UTC()
	moved := !cp.UpdatedAt.IsZero() && !policyAt.Equal(reg.UpdatedAt)
	if moved {
		reg.UpdatedAt = policyAt
	}
	// The generation the confirmed floor is now of, which a relayed answer's is
	// compared with (observeGeneration).
	if cp.Generation != 0 && cp.Generation != reg.Generation {
		reg.Generation, moved = cp.Generation, true
	}
	before := reg.Floor
	reg.Floor = *cp.Floor
	// The profile and provisional state of the same match as the digest: a
	// regroup re-matched the registration, or the directory answered again
	// after a provisional create (#1199).
	profile := strings.TrimSpace(cp.Profile)
	provisional := reg.Provisional
	if cp.Provisional != nil {
		provisional = *cp.Provisional
	}
	changed := !reflect.DeepEqual(before, reg.Floor) || (digest != "" && digest != reg.Digest) || (profile != "" && profile != reg.Profile) ||
		provisional != reg.Provisional
	if profile != "" {
		reg.Profile = profile
	}
	reg.Provisional = provisional
	if !changed {
		r.byName[name] = reg
		if moved {
			_ = r.saveLocked()
		}
		if moved || confirmed {
			r.changes.Add(1)
		}
		return confirmed
	}
	if digest != "" {
		reg.Digest = digest
	}
	if cp.UpdatedAt.IsZero() {
		reg.UpdatedAt = time.Now().UTC()
	}
	r.byName[name] = reg
	_ = r.saveLocked()
	r.changes.Add(1)
	return true
}

func (r *daemonRegistrations) saveLocked() error {
	doc := struct {
		V             int                  `json:"v"`
		Registrations []daemonRegistration `json:"registrations"`
	}{V: 1}
	for _, reg := range r.byName {
		doc.Registrations = append(doc.Registrations, reg)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := writeDaemonFileAtomic(r.path, append(raw, '\n')); err != nil {
		return fmt.Errorf("sandbox daemon: save registrations: %w", err)
	}
	return nil
}

// writeRegistrationsTemp writes the new registrations into the temporary
// file; a seam for tests (a full disk).
var writeRegistrationsTemp = func(f *os.File, data []byte) error {
	_, err := f.Write(data)
	return err
}

// writeDaemonFileAtomic replaces path with a 0600 file holding data: a temporary
// file in the same directory, written and synced, renamed over path, then
// the directory synced (off Windows, see syncDaemonDir). Any failure leaves
// path as it was.
func writeDaemonFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = tmp.Chmod(0o600)
	if err == nil {
		err = writeRegistrationsTemp(tmp, data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDaemonDir(dir)
}

// syncDaemonDir makes a rename in dir durable. Windows cannot flush a
// directory handle (FlushFileBuffers on it is "Access is denied"), and NTFS
// journals the rename itself, so there it does nothing, as the connector
// files and the device identity do.
func syncDaemonDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
