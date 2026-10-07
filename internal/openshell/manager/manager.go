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

// Package manager is the DefenseClaw daemon's OpenShell sandbox controller.
//
// It is the single writer of everything a sandbox owns outside the project
// folder: the ingress binding (sandboxauth), the OpenShell providers that
// deliver the binding token and the harness credentials as placeholders,
// the egress proxy credential, the sandbox itself, its policy approvals and
// its egress unblocks. Create resolves the effective pack and admin policy,
// selects a hook-verified overlay image, mints the binding, plans the live
// project mount, renders the policy and creates the sandbox, and rolls every
// step back when a later one fails. A watcher per sandbox maps the
// WatchSandbox stream onto the v8 sandbox telemetry, feeds draft proposals
// to triage and detects harness activity without hook traffic.
package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Defaults.
const (
	// DefaultSettleDelay covers OpenShell's first settings poll after a
	// start, which closes in-flight connections ~10-12 s in (FINDINGS P1).
	DefaultSettleDelay       = 15 * time.Second
	DefaultReconcileInterval = 5 * time.Minute
	DefaultTriageInterval    = 30 * time.Second
	defaultConnectRetry      = 30 * time.Second
	// connectBackoff bounds how often API requests redial a gateway that
	// just failed.
	connectBackoff   = 5 * time.Second
	defaultOpTimeout = 5 * time.Minute
	// defaultCreateTimeout bounds a create, which may build an image.
	defaultCreateTimeout = 45 * time.Minute
	rollbackTimeout      = 2 * time.Minute
	// undoTimeout bounds an undo: the stop, the restore and the restart.
	undoTimeout = 3 * defaultOpTimeout
)

// detached is ctx without its cancellation, bounded by timeout: for work
// that must run to its end once started (a delete's cleanup, an undo's
// restore), which a caller going away would otherwise cut short. It keeps
// ctx's values.
func detached(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// HostUser is the account the sandbox runs as in mount mode.
type HostUser struct {
	UID  int
	GID  int
	Name string
}

// ProxyControl is the running egress proxy. *egress.Proxy satisfies it.
// Each sandbox's proxy credential carries the sandbox's own decider; the
// manager sets the default after re-registering them (refreshEgress). The
// proxy decides a tunnel when it opens, so whenever the manager revokes or
// re-registers a credential it rechecks that binding's open tunnels
// (recheckEgress).
type ProxyControl interface {
	SetDecider(d *egress.Decider) error
	Recheck(bindingID string) int
	Counter() *egress.Counter
}

// Options configure a Manager.
type Options struct {
	// DataDir is the DefenseClaw data directory. Required.
	DataDir string
	// Owner labels the sandboxes this data dir owns (image.Store.Owner), so
	// two data dirs sharing a gateway never reconcile each other's. A
	// sandbox the data dir recorded under an earlier owner id keeps that
	// one (see loadRecords).
	Owner string
	// Config returns the current configuration snapshot. Required.
	Config func() *config.Config
	// Connect opens the OpenShell gateway connection. Required.
	Connect Connector
	// Bindings is the ingress binding store. Required.
	Bindings Bindings
	// Images selects overlay images. Required for Create.
	Images Images
	// Workspace defaults to DefaultWorkspace.
	Workspace Workspace
	// Profiles imports missing provider profiles; nil refuses to create a
	// sandbox whose profiles are not imported yet.
	Profiles ProfileImporter
	// MCP lists the user's MCP servers a run may bring along; nil brings
	// none (every sandbox still gets the per-run MCP lockdown).
	MCP MCPInventory
	// Telemetry receives the v8 sandbox records; nil drops them.
	Telemetry audit.SandboxTelemetry
	// Persist keeps "always" decisions in config.yaml; nil refuses them.
	Persist triage.Persister
	// Quiesce is the ingress in-flight tracker approvals wait on.
	Quiesce triage.Quiescer
	// ForgetBinding drops the ingress's per-binding state after a revoke.
	ForgetBinding func(bindingID string)
	// IngressPort and EgressPort are the DefenseClaw listeners (required);
	// APIPort is the main API, zero meaning config.DefaultGatewayAPIPort.
	IngressPort int
	EgressPort  int
	APIPort     int
	// IngressAddr and EgressAddr are reported by Status.
	IngressAddr string
	EgressAddr  string
	// HostUser defaults to the current user.
	HostUser *HostUser
	// Watch defaults to StreamWatch.
	Watch WatchFunc
	// Resolver resolves the destination names of approvals for the egress
	// proxy's dial-time checks; nil uses net.DefaultResolver.
	Resolver egress.Resolver
	// DefenseClawVersion is part of the image content hash.
	DefenseClawVersion string
	// GatewayResources reads the cpu and memory every sandbox gets on a
	// gateway whose compute driver sets no per-sandbox limits
	// (openshell.Driver.SandboxLimits false): the vm driver's gateway-wide
	// [openshell.drivers.vm] vcpus and mem_mib, its defaults included, from
	// the gateway's configuration, which the daemon's user owns. Nil, or an
	// error, leaves them unknown: an openshell.admin.max_resources then
	// refuses every such sandbox, since it cannot be judged.
	GatewayResources func() (packs.Resources, error)
	// VMDiskFree reports, on a gateway whose compute driver prepares a disk
	// from each image it boots (openshell.Driver.ImageCache: the vm
	// driver's), where it keeps them and the free space there, which the
	// daemon's user shares with the gateway. A create whose image has no
	// disk prepared yet is refused when the room for one is missing
	// (openshell.VMDiskShortage). Nil, or an error, skips that check.
	VMDiskFree func() (dir string, free uint64, err error)
	// SettleDelay waits for the first settings poll after a start
	// (DefaultSettleDelay); negative skips it.
	SettleDelay       time.Duration
	ReconcileInterval time.Duration
	// HookReachWindow is how long a session's harness may work before its
	// first authenticated hook is overdue and the session is flagged as
	// not reaching DefenseClaw (DefaultHookReachWindow; see reach.go).
	HookReachWindow time.Duration
	// ConnectRetry paces gateway reconnects.
	ConnectRetry time.Duration
	// TriageInterval paces the draft poll of ready sandboxes
	// (DefaultTriageInterval).
	TriageInterval time.Duration
	// Now overrides the clock.
	Now func() time.Time
	// Logf receives operational messages; nil writes to stderr.
	Logf func(format string, args ...any)
	// OnGateway is told about every gateway connection attempt: nil once
	// connected, the error when the gateway is unavailable.
	OnGateway func(err error)
	// Listeners reports whether this process holds the sandbox ingress and
	// egress listeners. OpenShell relays host.openshell.internal:<port> to
	// whatever listens on that host port, handing it the sandbox's ingress
	// token, so while it returns an error Create and Start are refused.
	// Nil assumes the caller holds them.
	Listeners func() error
	// Guard runs the nested-repository guard of a mounted project while
	// its sandbox is ready (default: package nestguard). GuardGitlinks
	// lists a project's index gitlinks (default: the host git through
	// gitsafe).
	Guard         GuardFunc
	GuardGitlinks func(ctx context.Context, root string) ([]string, error)
}

// Manager implements the gateway's SandboxController.
type Manager struct {
	opts Options
	// startedAt is when this daemon's manager was made: OpenShell records
	// from before it are replays (see ocsfEvent).
	startedAt time.Time
	ws        Workspace
	tel       *telemetryGuard
	records   recordStore
	now       func() time.Time
	logf      func(string, ...any)
	host      HostUser

	feed *Feed
	// egressFeed paces each sandbox's egress events onto the shared feed
	// (publishEgress).
	egressFeed *rateGate
	creds      *egress.CredentialStore
	unblocks   *egress.MemoryUnblocks
	batcher    *triage.Batcher
	sink       *egressSink
	// refusals keeps each binding's recent CONNECT refusals for its agent
	// (EgressRefusals).
	refusals  *refusalMemory
	toolCalls *hookTamperTracker
	// signatures is the AI signature catalog of the sandbox discoveries.
	signatures discoveryCatalog
	// tamperStops tracks the stops hook tamper started.
	tamperStops sync.WaitGroup

	runMu  sync.Mutex
	runCtx context.Context

	gwMu sync.RWMutex
	gw   *Gateway
	// gwGone is closed when gw is dropped or closed: the watchers built on
	// its stream connection end then and follow the next connection.
	gwGone chan struct{}
	gwErr  error
	// gwErrAt paces reconnects: requests arriving within connectBackoff of
	// a failed attempt get its error instead of dialing again.
	gwErrAt time.Time
	// gwPort is the connected gateway's port, and gwDriver its compute
	// driver (nil until a gateway answered), readable while a connect is
	// in progress.
	gwPort   atomic.Int64
	gwDriver atomic.Pointer[openshell.Driver]
	// gwCheckedAt is when the connected gateway last said which driver it
	// runs (UnixNano; recheckDriver).
	gwCheckedAt atomic.Int64

	mu            sync.Mutex
	boxes         map[string]*box
	approvals     map[string]*approval
	proxy         ProxyControl
	lastReconcile time.Time
	// cfgSeen is the configuration the egress deciders were last built
	// from (refreshEgress); cfgEnforced the one configLoop last enforced
	// on approved rules (enforceAll). refreshEgress also runs after creates
	// and deletes, so it cannot tell configLoop what was enforced.
	cfgSeen     *config.Config
	cfgEnforced *config.Config
	reconcileMu sync.Mutex
	// profileMu serializes this daemon's provider profile imports, so
	// concurrent creates do not race each other to import the same one.
	profileMu sync.Mutex
	// destMu guards dests, each sandbox's destinations (destinations.go).
	// It is never taken with mu held, nor mu with it.
	destMu sync.Mutex
	dests  map[string]*destTable
	// catalog classifies destinations (destinationCatalog); procs gives
	// their lineage: the manager's own process tree (Lineage), which knows
	// a sandbox's processes only while its process tree is on.
	catalogOnce sync.Once
	catalog     *catalog.Catalog
	procs       ProcessLookup
	// procGate paces each sandbox's process and SSH records.
	procGate *rateGate
	// authFails paces the proxy's refusals of invalid credentials into
	// health records (authFailed).
	authFails authFailures

	// credentialGC keeps a delete from removing a --credential profile
	// between a create's import of it and the provider that uses it:
	// creates hold it shared from import to provider, the collection of
	// unused profiles exclusively.
	credentialGC sync.RWMutex
}

// New validates opts and returns a Manager. Run must be running for
// watchers, reconciliation, approvals and egress telemetry.
func New(opts Options) (*Manager, error) {
	switch {
	case opts.DataDir == "":
		return nil, errors.New("sandbox manager: a data directory is required")
	case opts.Config == nil:
		return nil, errors.New("sandbox manager: a configuration source is required")
	case opts.Connect == nil:
		return nil, errors.New("sandbox manager: a gateway connector is required")
	case opts.Bindings == nil:
		return nil, errors.New("sandbox manager: a binding store is required")
	case opts.IngressPort <= 0 || opts.EgressPort <= 0:
		return nil, errors.New("sandbox manager: ingress and egress ports are required")
	}
	if opts.Owner == "" {
		return nil, errors.New("sandbox manager: an owner id is required")
	}
	if opts.APIPort <= 0 {
		opts.APIPort = config.DefaultGatewayAPIPort
	}
	if opts.Workspace == nil {
		opts.Workspace = DefaultWorkspace{}
	}
	if opts.Watch == nil {
		opts.Watch = StreamWatch
	}
	if opts.Guard == nil {
		opts.Guard = runNestGuard
	}
	if opts.SettleDelay == 0 {
		opts.SettleDelay = DefaultSettleDelay
	}
	if opts.ReconcileInterval <= 0 {
		opts.ReconcileInterval = DefaultReconcileInterval
	}
	if opts.HookReachWindow <= 0 {
		opts.HookReachWindow = DefaultHookReachWindow
	}
	if opts.ConnectRetry <= 0 {
		opts.ConnectRetry = defaultConnectRetry
	}
	if opts.TriageInterval <= 0 {
		opts.TriageInterval = DefaultTriageInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[sandbox] "+format+"\n", args...)
		}
	}
	host, err := resolveHostUser(opts.HostUser)
	if err != nil {
		return nil, err
	}
	unblocks, _ := egress.NewMemoryUnblocks()
	m := &Manager{
		opts:       opts,
		ws:         opts.Workspace,
		tel:        newTelemetryGuard(opts.Telemetry, host, opts.Logf, opts.Now),
		records:    newRecordStore(opts.DataDir),
		now:        opts.Now,
		logf:       opts.Logf,
		host:       host,
		feed:       NewFeed(DefaultFeedSize, opts.Now),
		egressFeed: newRateGate(feedBurst, feedRate),
		creds:      egress.NewCredentialStore(),
		unblocks:   unblocks,
		refusals:   newRefusalMemory(),
		toolCalls:  newHookTamperTracker(),
		boxes:      map[string]*box{},
		approvals:  map[string]*approval{},
		startedAt:  opts.Now(),
		dests:      map[string]*destTable{},
		procGate:   newRateGate(activityBurst, activityRate),
	}
	m.procs = m
	m.sink = newEgressSink(m)
	debounce := time.Duration(config.DefaultOpenShellApprovalDebounceMs) * time.Millisecond
	if cfg := opts.Config(); cfg != nil && cfg.OpenShell.Approvals.DebounceMs > 0 {
		debounce = time.Duration(cfg.OpenShell.Approvals.DebounceMs) * time.Millisecond
	}
	m.batcher = triage.NewBatcher(triage.BatcherOptions{
		Apply:    batchApplier{m: m},
		Quiesce:  opts.Quiesce,
		Tunnels:  proxyTunnels{m: m},
		Debounce: debounce,
		OnResult: m.approvalsApplied,
		Recheck:  m.recheckApproval,
	})
	if err := m.loadRecords(); err != nil {
		return nil, err
	}
	return m, nil
}

func resolveHostUser(h *HostUser) (HostUser, error) {
	if h != nil {
		if h.UID <= 0 || h.GID <= 0 {
			return HostUser{}, errors.New("sandbox manager: sandboxes never run as root")
		}
		return *h, nil
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 {
		return HostUser{}, errors.New("sandbox manager: the DefenseClaw daemon must not run as root to manage sandboxes")
	}
	out := HostUser{UID: uid, GID: gid}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		// The bare account: a binding refuses SSSD's alice@realm form.
		out.Name = useridentity.BareAccountName(u.Username)
	}
	return out, nil
}

// Feed returns the activity feed.
func (m *Manager) Feed() *Feed { return m.feed }

// EgressAuthenticator is the proxy credential store the egress proxy
// authenticates sandboxes with.
func (m *Manager) EgressAuthenticator() egress.Authenticator { return m.creds }

// EgressSink receives the proxy's events for telemetry and the feed.
func (m *Manager) EgressSink() egress.EventSink { return m.sink }

// proxyTunnels reports the attached egress proxy's traffic per binding to
// the approval batcher (triage.TunnelActivity), so a policy reload waits
// for the sandbox's proxied transfers; nothing while no proxy that reports
// it is attached.
type proxyTunnels struct{ m *Manager }

func (t proxyTunnels) BindingActivity(bindingID string) (int, int64) {
	t.m.mu.Lock()
	p := t.m.proxy
	t.m.mu.Unlock()
	if a, ok := p.(triage.TunnelActivity); ok {
		return a.BindingActivity(bindingID)
	}
	return 0, 0
}

// AttachProxy connects the running egress proxy, whose decider the manager
// rebuilds when the configuration or the set of sandboxes changes.
func (m *Manager) AttachProxy(p ProxyControl) {
	m.mu.Lock()
	m.proxy = p
	m.mu.Unlock()
	m.refreshEgress()
}

// Run connects to the gateway, reconciles, and serves watchers, approvals
// and egress telemetry until ctx ends.
func (m *Manager) Run(ctx context.Context) error {
	m.runMu.Lock()
	if m.runCtx != nil {
		m.runMu.Unlock()
		return errors.New("sandbox manager is already running")
	}
	m.runCtx = ctx
	m.runMu.Unlock()
	defer func() {
		m.stopWatchers()
		m.closeGateway()
		m.runMu.Lock()
		m.runCtx = nil
		m.runMu.Unlock()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(3)
	go func() { defer wg.Done(); _ = m.batcher.Run(ctx) }()
	go func() { defer wg.Done(); m.sink.run(ctx) }()
	go func() { defer wg.Done(); m.configLoop(ctx) }()

	startup := true
	reconcile := time.NewTimer(0)
	defer reconcile.Stop()
	silence := time.NewTicker(hookSilenceInterval)
	defer silence.Stop()
	reach := time.NewTicker(hookReachInterval)
	defer reach.Stop()
	drafts := time.NewTicker(m.opts.TriageInterval)
	defer drafts.Stop()
	destinations := time.NewTicker(destinationFlushEvery)
	defer destinations.Stop()
	defer m.flushDestinations("")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-destinations.C:
			m.flushDestinations("")
		case <-silence.C:
			m.checkHookSilence(ctx)
			m.pruneToolCalls()
		case <-reach.C:
			m.checkHookReach(ctx)
		case <-drafts.C:
			if m.gatewayUp() {
				m.triageSweep()
			}
		case <-reconcile.C:
			if _, err := m.gateway(ctx); err != nil {
				reconcile.Reset(m.opts.ConnectRetry)
				continue
			}
			if err := m.reconcile(ctx, startup); err != nil {
				m.logf("reconcile: %v", err)
				reconcile.Reset(m.opts.ConnectRetry)
				continue
			}
			startup = false
			reconcile.Reset(m.opts.ReconcileInterval)
		}
	}
}

// gateway returns the live connection, connecting when there is none.
func (m *Manager) gateway(ctx context.Context) (*Gateway, error) {
	gw, _, err := m.connection(ctx)
	return gw, err
}

// connection is gateway with a channel that is closed once the connection
// is dropped (dropGateway) or closed (closeGateway), for the work that
// lives on it, such as a watcher's stream.
func (m *Manager) connection(ctx context.Context) (*Gateway, <-chan struct{}, error) {
	m.gwMu.RLock()
	gw, gone := m.gw, m.gwGone
	m.gwMu.RUnlock()
	if gw != nil {
		return gw, gone, nil
	}
	m.gwMu.Lock()
	defer m.gwMu.Unlock()
	if m.gw != nil {
		return m.gw, m.gwGone, nil
	}
	if m.gwErr != nil && m.now().Sub(m.gwErrAt) < connectBackoff {
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the OpenShell gateway is not available: %v", m.gwErr)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	gw, err := m.opts.Connect(cctx)
	if err != nil {
		if m.gwErr == nil || m.gwErr.Error() != err.Error() {
			m.logf("OpenShell gateway unavailable: %v", err)
			m.health(ctx, audit.SandboxHealthDegraded, gatewaylog.ErrCodeOpenShellUnavailable, err.Error())
		}
		m.gwErr, m.gwErrAt = err, m.now()
		if m.opts.OnGateway != nil {
			m.opts.OnGateway(err)
		}
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the OpenShell gateway is not available: %v", err)
	}
	if m.gwErr != nil {
		m.health(ctx, audit.SandboxHealthRestored, "", "")
	} else {
		m.health(ctx, audit.SandboxHealthReady, "", "")
	}
	m.gw, m.gwGone, m.gwErr = gw, make(chan struct{}), nil
	if m.opts.OnGateway != nil {
		m.opts.OnGateway(nil)
	}
	m.gwPort.Store(int64(gw.Port))
	driver := gw.Driver
	m.gwDriver.Store(&driver)
	m.gwCheckedAt.Store(m.now().UnixNano())
	return gw, m.gwGone, nil
}

// driverRecheck is how long Status trusts the compute driver the
// connected gateway last reported before it asks again.
const driverRecheck = 5 * time.Second

// driverGateway is gateway for the work that depends on the compute driver
// the gateway runs (create, start, reconcile): it asks the gateway again
// which driver it runs (recheckDriver).
func (m *Manager) driverGateway(ctx context.Context) (*Gateway, error) {
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	return m.recheckDriver(ctx, gw)
}

// recheckDriver asks a connection's gateway which compute driver it runs
// now. A connection outlives a restart of its gateway (gRPC dials again on
// its own), and `sandbox setup` or `sandbox doctor --fix` restart the
// gateway on another driver: a connection whose gateway now runs another
// driver, or does not say which, is dropped, and the connection that
// replaces it reads the driver the gateway runs.
func (m *Manager) recheckDriver(ctx context.Context, gw *Gateway) (*Gateway, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	d, err := connectedDriver(cctx, gw.Client)
	cancel()
	if err == nil && d.Name == gw.Driver.Name {
		m.gwCheckedAt.Store(m.now().UnixNano())
		return gw, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil {
		err = fmt.Errorf("the OpenShell gateway now runs the %s compute driver, not %s", d.Name, gw.Driver.Name)
		m.logf("%v; connecting to it again", err)
	}
	m.forgetGateway(gw, err)
	return m.gateway(ctx)
}

// gatewayUp reports whether a gateway connection is held, without dialing.
func (m *Manager) gatewayUp() bool {
	m.gwMu.RLock()
	defer m.gwMu.RUnlock()
	return m.gw != nil
}

// dropGateway forgets a connection that failed, so the next call redials.
func (m *Manager) dropGateway(gw *Gateway, err error) {
	if gw == nil || !openshell.IsUnavailable(err) {
		return
	}
	m.forgetGateway(gw, err)
}

// forgetGateway forgets a connection, so the next call dials again at once.
func (m *Manager) forgetGateway(gw *Gateway, err error) {
	m.gwMu.Lock()
	if m.gw == gw {
		m.gw, m.gwErr, m.gwErrAt = nil, err, time.Time{}
		m.goneLocked()
		if gw.Close != nil {
			_ = gw.Close()
		}
	}
	m.gwMu.Unlock()
}

func (m *Manager) closeGateway() {
	m.gwMu.Lock()
	defer m.gwMu.Unlock()
	if m.gw != nil && m.gw.Close != nil {
		_ = m.gw.Close()
	}
	m.gw = nil
	m.goneLocked()
}

// goneLocked tells the work living on the connection that was just
// dropped or closed that it is gone. Callers hold gwMu.
func (m *Manager) goneLocked() {
	if m.gwGone != nil {
		close(m.gwGone)
		m.gwGone = nil
	}
}

func (m *Manager) health(ctx context.Context, state audit.SandboxHealthState, code gatewaylog.ErrorCode, summary string) {
	m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{
		State: state, ErrorCode: errorToken(code), ErrorSummary: truncate(summary, 512), Timestamp: m.now(),
	})
}

// errorToken is a gateway error code as audit records carry it: a stable
// token, which is lower case (OPENSHELL_UNAVAILABLE is recorded as
// openshell_unavailable). The recorder refuses the upper-case form.
func errorToken(code gatewaylog.ErrorCode) string {
	return strings.ToLower(string(code))
}

// Reason codes of the sandbox policy records (audit.SandboxPolicyEvent
// Reason): stable tokens, as the recorder refuses anything else.
const (
	// policyReasonApproval: an approved proposal was merged.
	policyReasonApproval = "approval"
	// policyReasonUnblock: an egress unblock was added.
	policyReasonUnblock = "egress_unblock"
	// policyReasonAdmin: an approved rule the organization's policy now
	// refuses was removed.
	policyReasonAdmin = "admin_policy"
	// policyReasonAdminRefused: the organization's policy refused the
	// request (a create, start, unblock or approval); nothing changed.
	policyReasonAdminRefused = "admin_refused"
	// policyReasonBlocklist: an approved rule to a destination a block list
	// or the blocklist feed now refuses was removed.
	policyReasonBlocklist = "egress_blocklist"
	// policyReasonResolvesToHost: an approved rule whose destination now
	// resolves to this machine was removed.
	policyReasonResolvesToHost = "rule_resolves_to_host"
	// policyReasonUnresolved: an approved rule was removed because no
	// policy, not even the organization's, can be resolved for the sandbox.
	policyReasonUnresolved = "policy_unresolved"
	// policyReasonApprovalRequired: a rule DefenseClaw approved on its own
	// was removed because the policy now leaves it to the user.
	policyReasonApprovalRequired = "approval_required"
)

// listenersReady refuses a create or start while this process does not
// hold its sandbox listeners (Options.Listeners): another program on the
// ingress or egress port would receive the sandbox's hooks, token and
// traffic.
func (m *Manager) listenersReady() error {
	if m.opts.Listeners == nil {
		return nil
	}
	if err := m.opts.Listeners(); err != nil {
		return &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
			Message: "DefenseClaw does not hold its sandbox listeners, so a sandbox's hooks and egress could reach another program; run `defenseclaw sandbox doctor`",
			Detail:  err.Error()}
	}
	return nil
}

func (m *Manager) config() *config.Config {
	cfg := m.opts.Config()
	if cfg == nil {
		cfg = &config.Config{}
	}
	return cfg
}

// keepIgnored is what a mounted project's undo point keeps a copy of
// (openshell.workdir.undo_ignored): the directory names and the cap on the
// copies, or nothing while the key is off.
func (m *Manager) keepIgnored() ([]string, int64) {
	u := m.config().OpenShell.Workdir.UndoIgnored
	if !u.Enabled {
		return nil, 0
	}
	return u.EffectiveDirs(), u.EffectiveMaxBytes()
}

// configLoop re-resolves policies and the egress decider when the
// configuration snapshot changes (a ConfigManager reload publishes a new
// one).
func (m *Manager) configLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg := m.opts.Config()
			m.mu.Lock()
			refresh, enforce := cfg != m.cfgSeen, cfg != m.cfgEnforced
			m.mu.Unlock()
			if refresh {
				m.refreshEgress()
			}
			// Approved rules bypass the egress proxy, so a change must reach
			// them even when a create or delete rebuilt the deciders first.
			// While the gateway is down the reconcile after it reconnects
			// enforces, and so does the next tick here.
			if enforce && m.gatewayUp() && m.enforceAll(ctx) {
				m.mu.Lock()
				m.cfgEnforced = cfg
				m.mu.Unlock()
			}
		}
	}
}

// running reports the manager's Run context, for goroutines that outlive
// a request.
func (m *Manager) running() context.Context {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	return m.runCtx
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence, so
// valid text stays valid in the telemetry, feed and API fields it bounds.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > 0 && i > n-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return s[:n]
}
