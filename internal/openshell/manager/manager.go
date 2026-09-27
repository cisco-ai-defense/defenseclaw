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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// Defaults.
const (
	// DefaultSettleDelay covers OpenShell's first settings poll after a
	// start, which closes in-flight connections ~10-12 s in (FINDINGS P1).
	DefaultSettleDelay       = 15 * time.Second
	DefaultReconcileInterval = 5 * time.Minute
	DefaultHookSilence       = 10 * time.Minute
	DefaultTriageInterval    = 30 * time.Second
	defaultConnectRetry      = 30 * time.Second
	// connectBackoff bounds how often API requests redial a gateway that
	// just failed.
	connectBackoff   = 5 * time.Second
	defaultOpTimeout = 5 * time.Minute
	// defaultCreateTimeout bounds a create, which may build an image.
	defaultCreateTimeout = 45 * time.Minute
	rollbackTimeout      = 2 * time.Minute
)

// HostUser is the account the sandbox runs as in mount mode.
type HostUser struct {
	UID  int
	GID  int
	Name string
}

// ProxyControl is the running egress proxy. *egress.Proxy satisfies it.
// Each sandbox's proxy credential carries the sandbox's own decider; the
// manager sets the default after re-registering them (refreshEgress).
type ProxyControl interface {
	SetDecider(d *egress.Decider) error
	Counter() *egress.Counter
}

// Options configure a Manager.
type Options struct {
	// DataDir is the DefenseClaw data directory. Required.
	DataDir string
	// Owner labels the sandboxes this data dir owns (image.Store.Owner), so
	// two data dirs sharing a gateway never reconcile each other's.
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
	// SettleDelay waits for the first settings poll after a start
	// (DefaultSettleDelay); negative skips it.
	SettleDelay       time.Duration
	ReconcileInterval time.Duration
	// HookSilence is how long a harness may be active without hook
	// traffic before a hook_silence finding (DefaultHookSilence).
	HookSilence time.Duration
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
	// Guard runs the nested-repository guard of a mounted project while
	// its sandbox is ready (default: package nestguard). GuardGitlinks
	// lists a project's index gitlinks (default: the host git through
	// gitsafe).
	Guard         GuardFunc
	GuardGitlinks func(ctx context.Context, root string) ([]string, error)
}

// Manager implements the gateway's SandboxController.
type Manager struct {
	opts    Options
	ws      Workspace
	tel     audit.SandboxTelemetry
	records recordStore
	now     func() time.Time
	logf    func(string, ...any)
	host    HostUser

	feed      *Feed
	creds     *egress.CredentialStore
	unblocks  *egress.MemoryUnblocks
	batcher   *triage.Batcher
	sink      *egressSink
	toolCalls *hookTamperTracker
	// tamperStops tracks the stops hook tamper started.
	tamperStops sync.WaitGroup

	runMu  sync.Mutex
	runCtx context.Context

	gwMu  sync.RWMutex
	gw    *Gateway
	gwErr error
	// gwErrAt paces reconnects: requests arriving within connectBackoff of
	// a failed attempt get its error instead of dialing again.
	gwErrAt time.Time
	// gwPort is the connected gateway's port, readable while a connect is
	// in progress.
	gwPort atomic.Int64

	mu            sync.Mutex
	boxes         map[string]*box
	approvals     map[string]*approval
	proxy         ProxyControl
	lastReconcile time.Time
	cfgSeen       *config.Config
	reconcileMu   sync.Mutex
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
	if opts.HookSilence <= 0 {
		opts.HookSilence = DefaultHookSilence
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
		opts:      opts,
		ws:        opts.Workspace,
		tel:       opts.Telemetry,
		records:   newRecordStore(opts.DataDir),
		now:       opts.Now,
		logf:      opts.Logf,
		host:      host,
		feed:      NewFeed(DefaultFeedSize, opts.Now),
		creds:     egress.NewCredentialStore(),
		unblocks:  unblocks,
		toolCalls: newHookTamperTracker(),
		boxes:     map[string]*box{},
		approvals: map[string]*approval{},
	}
	if m.tel == nil {
		m.tel = nopTelemetry{}
	}
	m.sink = newEgressSink(m)
	debounce := time.Duration(config.DefaultOpenShellApprovalDebounceMs) * time.Millisecond
	if cfg := opts.Config(); cfg != nil && cfg.OpenShell.Approvals.DebounceMs > 0 {
		debounce = time.Duration(cfg.OpenShell.Approvals.DebounceMs) * time.Millisecond
	}
	m.batcher = triage.NewBatcher(triage.BatcherOptions{
		Apply:    batchApplier{m: m},
		Quiesce:  opts.Quiesce,
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
		out.Name = u.Username
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
	silence := time.NewTicker(minDuration(m.opts.HookSilence/4, time.Minute))
	defer silence.Stop()
	drafts := time.NewTicker(m.opts.TriageInterval)
	defer drafts.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-silence.C:
			m.checkHookSilence(ctx)
			m.pruneToolCalls()
		case <-drafts.C:
			if m.gatewayUp() {
				m.triageSweep(ctx)
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

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 || a > b {
		return b
	}
	return a
}

// gateway returns the live connection, connecting when there is none.
func (m *Manager) gateway(ctx context.Context) (*Gateway, error) {
	m.gwMu.RLock()
	gw := m.gw
	m.gwMu.RUnlock()
	if gw != nil {
		return gw, nil
	}
	m.gwMu.Lock()
	defer m.gwMu.Unlock()
	if m.gw != nil {
		return m.gw, nil
	}
	if m.gwErr != nil && m.now().Sub(m.gwErrAt) < connectBackoff {
		return nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the OpenShell gateway is not available: %v", m.gwErr)
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
		return nil, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the OpenShell gateway is not available: %v", err)
	}
	if m.gwErr != nil {
		m.health(ctx, audit.SandboxHealthRestored, "", "")
	} else {
		m.health(ctx, audit.SandboxHealthReady, "", "")
	}
	m.gw, m.gwErr = gw, nil
	if m.opts.OnGateway != nil {
		m.opts.OnGateway(nil)
	}
	m.gwPort.Store(int64(gw.Port))
	return gw, nil
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
	m.gwMu.Lock()
	if m.gw == gw {
		m.gw, m.gwErr, m.gwErrAt = nil, err, time.Time{}
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
}

func (m *Manager) health(ctx context.Context, state audit.SandboxHealthState, code gatewaylog.ErrorCode, summary string) {
	_ = m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{
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
	// policyReasonResolvesToHost: an approved rule whose destination now
	// resolves to this machine was removed.
	policyReasonResolvesToHost = "rule_resolves_to_host"
	// policyReasonUnresolved: an approved rule was removed because no
	// policy, not even the organization's, can be resolved for the sandbox.
	policyReasonUnresolved = "policy_unresolved"
)

func (m *Manager) config() *config.Config {
	cfg := m.opts.Config()
	if cfg == nil {
		cfg = &config.Config{}
	}
	return cfg
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
			changed := cfg != m.cfgSeen
			m.mu.Unlock()
			if changed {
				m.refreshEgress()
				m.enforceAll(ctx)
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

type nopTelemetry struct{}

func (nopTelemetry) RecordSandboxLifecycle(context.Context, audit.SandboxLifecycleEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxEgress(context.Context, audit.SandboxEgressEvent) error { return nil }
func (nopTelemetry) RecordSandboxApproval(context.Context, audit.SandboxApprovalEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxPolicy(context.Context, audit.SandboxPolicyEvent) error { return nil }
func (nopTelemetry) RecordSandboxHealth(context.Context, audit.SandboxHealthEvent) error { return nil }
func (nopTelemetry) RecordSandboxFinding(context.Context, audit.SandboxFindingEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxWorkspace(context.Context, audit.SandboxWorkspaceEvent) error {
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
