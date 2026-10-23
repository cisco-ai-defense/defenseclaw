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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"gopkg.in/yaml.v3"
)

// The sandbox manager is the SandboxController the REST API drives.
var _ SandboxController = (*manager.Manager)(nil)

// sandboxListenerHost is where the sandbox ingress and egress proxy
// listen: OpenShell relays host.openshell.internal to host loopback.
const sandboxListenerHost = "127.0.0.1"

// sandboxRuntime is the OpenShell sandbox subsystem the API owns while
// openshell.enabled: the hook ingress, the egress proxy and the manager.
// It restarts with the API, whose restart rules cover the listener ports.
type sandboxRuntime struct {
	api        *APIServer
	manager    *manager.Manager
	proxy      *egress.Proxy
	egressAddr string
	health     *SidecarHealth
	// bindings is the sandbox binding store the manager mints into.
	bindings *sandboxauth.FileStore

	// report marks one part of the subsystem healthy (nil) or not; run
	// installs it.
	reportMu sync.Mutex
	report   func(part string, err error)

	// listening records the sandbox listeners (ingress, egress) this
	// process holds right now.
	listenMu  sync.Mutex
	listening map[string]bool

	// fleet, publish and tel are what containing a lost listener uses
	// (the manager, its activity feed and the sandbox telemetry recorder);
	// listenBudget bounds the egress bind retries (30s when zero) and
	// recheck paces the containment (sandboxListenerRecheck when zero).
	fleet        sandboxFleet
	publish      func(sandboxapi.ActivityEvent)
	tel          sandboxHealthRecorder
	listenBudget time.Duration
	recheck      time.Duration
}

// sandboxFleet is what containing a lost sandbox listener needs from the
// manager.
type sandboxFleet interface {
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
}

// sandboxHealthRecorder records durable sandbox subsystem health.
type sandboxHealthRecorder interface {
	RecordSandboxHealth(ctx context.Context, input audit.SandboxHealthEvent) error
}

// sandboxListenerRecheck is how often, while this process does not hold a
// sandbox listener, it looks for running sandboxes to stop.
const sandboxListenerRecheck = 15 * time.Second

// setListening records whether this process holds one sandbox listener.
func (rt *sandboxRuntime) setListening(part string, up bool) {
	rt.listenMu.Lock()
	defer rt.listenMu.Unlock()
	if rt.listening == nil {
		rt.listening = map[string]bool{}
	}
	rt.listening[part] = up
}

// listenersReady reports whether this process holds both sandbox
// listeners (manager.Options.Listeners). OpenShell relays
// host.openshell.internal:<port> to whatever listens on that host port, and
// hands it the sandbox's real ingress token: while another program holds
// one of them, no sandbox may be created or started.
func (rt *sandboxRuntime) listenersReady() error {
	rt.listenMu.Lock()
	defer rt.listenMu.Unlock()
	var missing []string
	for _, part := range []string{"ingress", "egress"} {
		if !rt.listening[part] {
			missing = append(missing, part)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the sandbox %s listener is not running in this process", strings.Join(missing, " and "))
	}
	return nil
}

// gatewayState reports the OpenShell gateway connection as the "openshell"
// part of the sandbox subsystem health.
func (rt *sandboxRuntime) gatewayState(err error) {
	rt.reportMu.Lock()
	report := rt.report
	rt.reportMu.Unlock()
	if report != nil {
		report("openshell", err)
	}
}

// sandboxRecorder returns the process's single sandbox telemetry recorder
// (the active-sandbox gauge is derived from its state).
func (s *Sidecar) sandboxTelemetry() *audit.SandboxRecorder {
	s.sandboxRecorderOnce.Do(func() {
		s.sandboxRecorder = audit.NewSandboxRecorder(s.logger)
	})
	return s.sandboxRecorder
}

// newSandboxRuntime prepares the sandbox subsystem for api, or returns nil
// when sandboxes are off or unsupported here (reported through health).
//
// A managed_enterprise gateway never runs sandboxes itself: it is the
// policy authority. On a standalone managed computer each user's sandbox
// daemon runs them under the user's own account (newSandboxDaemonRuntime)
// and relays their hooks to this gateway's hook socket.
func (s *Sidecar) newSandboxRuntime(api *APIServer) (*sandboxRuntime, error) {
	cfg := s.currentConfig()
	if cfg == nil || !cfg.OpenShell.Enabled {
		return nil, nil
	}
	if err := openshell.CheckHost(runtime.GOOS, runtime.GOARCH); err != nil {
		s.health.SetSandbox(StateDisabled, err.Error(), nil)
		return nil, nil
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		s.health.SetSandbox(StateDisabled, managedGatewaySandboxNote(cfg), nil)
		return nil, nil
	}
	mcp := &sandboxMCPInventory{config: s.currentConfig}
	mcp.policy = enforce.NewPolicyEngine(api.store).WithConfig(s.currentConfig)
	return buildSandboxRuntime(api, sandboxRuntimeDeps{
		config:           s.currentConfig,
		health:           s.health,
		telemetry:        s.sandboxTelemetry(),
		mcp:              mcp,
		persist:          sandboxConfigPersister{api: api},
		syncConfig:       api.syncSandboxConfig,
		discoveryRemoved: func(string) { api.rescanAIDiscovery() },
	}, RuntimeOptions{})
}

// managedGatewaySandboxNote is the managed gateway's sandbox health detail.
func managedGatewaySandboxNote(cfg *config.Config) string {
	if cfg.StandaloneEnterprise() {
		return "sandboxes run in each user's own sandbox daemon on this managed computer, not in the managed gateway"
	}
	return "OpenShell sandboxes are not available in this managed deployment"
}

// sandboxRuntimeDeps are what a sandbox runtime takes from its host process:
// the per-user gateway (newSandboxRuntime) or a managed host's per-user
// sandbox daemon (newSandboxDaemonRuntime).
type sandboxRuntimeDeps struct {
	// config is the configuration the manager reads: config.yaml for the
	// per-user gateway, the managed gateway's settings for the daemon.
	config           func() *config.Config
	configForSandbox func(string) *config.Config
	health           *SidecarHealth
	// telemetry records the v8 sandbox records: the per-user gateway's
	// recorder, or a managed daemon's relay to the managed gateway
	// (daemonRelayTelemetry). nil drops them.
	telemetry audit.SandboxTelemetry
	// mcp lists the user's MCP servers; nil brings none.
	mcp manager.MCPInventory
	// persist keeps "always" decisions; nil refuses them.
	persist    triage.Persister
	syncConfig func(context.Context) error
	// confirmPolicy is a managed daemon's manager.Options.ConfirmPolicy;
	// nil for the per-user gateway, whose policy is local.
	confirmPolicy func(context.Context, string)
	// hostUser is the account sandboxes run as; nil is this process's.
	hostUser         *manager.HostUser
	discoveryRemoved func(string)
	// registration and onGeneration are forwarding mode's
	// (SandboxIngressConfig.Registration, OnGeneration).
	registration func(sandboxauth.Binding) (string, bool)
	onGeneration func(string, uint64)
	// egressRefresh brings a sandbox's policy up to date before its egress
	// proxy decides a new connection (egress.Options.Refresh): a managed
	// daemon's; nil for the per-user gateway, whose policy is local.
	egressRefresh func(context.Context, egress.Principal) *egress.Decision
}

// buildSandboxRuntime prepares the hook ingress, the egress proxy and the
// manager. RuntimeOptions{} is the per-user gateway's runtime; Managed is a
// managed host's per-user daemon, whose ingress forwards every call to the
// managed gateway through opts.Relay (forwarding mode).
func buildSandboxRuntime(api *APIServer, deps sandboxRuntimeDeps, opts RuntimeOptions) (*sandboxRuntime, error) {
	cfg := deps.config()
	if cfg == nil {
		return nil, errors.New("sandbox runtime: no configuration")
	}
	if opts.Managed && (opts.Relay == nil || opts.Settings == nil || deps.registration == nil) {
		return nil, errors.New("sandbox runtime: a managed runtime needs the managed gateway relay, its settings and the registrations")
	}
	dataDir := cfg.DataDir
	store, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(dataDir))
	if err != nil {
		return nil, fmt.Errorf("open the sandbox binding store: %w", err)
	}
	images := image.NewStore(dataDir)
	owner, err := images.Owner()
	if err != nil {
		return nil, fmt.Errorf("sandbox image store: %w", err)
	}
	ingressPort, egressPort := cfg.OpenShellIngressPort(), cfg.OpenShellEgressPort()
	ingressAddr := net.JoinHostPort(sandboxListenerHost, strconv.Itoa(ingressPort))
	egressAddr := net.JoinHostPort(sandboxListenerHost, strconv.Itoa(egressPort))
	inflight := sandboxauth.NewInFlight(nil)
	rt := &sandboxRuntime{api: api, egressAddr: egressAddr, health: deps.health, bindings: store}
	telemetry := deps.telemetry
	discoveryRemoved := deps.discoveryRemoved
	if discoveryRemoved == nil {
		discoveryRemoved = func(string) {}
	}

	// A managed daemon also stops what the account's other registered
	// OpenShell gateways run (GAP-0678).
	var otherGateways func(context.Context, *manager.Gateway) []*manager.Gateway
	if opts.Managed {
		otherGateways = manager.OtherRegisteredGateways(openshell.DiscoverOptions{},
			openshell.ClientOptions{Workspace: cfg.OpenShell.Gateway.Workspace})
	}
	mgr, err := manager.New(manager.Options{
		DataDir:          dataDir,
		Owner:            owner,
		Config:           deps.config,
		ConfigForSandbox: deps.configForSandbox,
		Connect: manager.DiscoverConnector(
			openshell.DiscoverOptions{Gateway: cfg.OpenShell.Gateway.Name},
			openshell.ClientOptions{Workspace: cfg.OpenShell.Gateway.Workspace},
		),
		Bindings: store,
		Images: manager.BuilderImages{Builder: &image.Builder{
			Docker: image.CLI{}, Store: images, Log: io.Discard,
		}},
		Profiles: manager.CLIProfileImporter{BinaryFunc: func() string {
			if c := deps.config(); c != nil {
				return c.OpenShell.EffectiveBinary()
			}
			return cfg.OpenShell.EffectiveBinary()
		}},
		MCP:                deps.mcp,
		Telemetry:          telemetry,
		Persist:            deps.persist,
		SyncConfig:         deps.syncConfig,
		ConfirmPolicy:      deps.confirmPolicy,
		Quiesce:            inflight,
		ForgetBinding:      api.ForgetSandboxBinding,
		IngressPort:        ingressPort,
		EgressPort:         egressPort,
		APIPort:            cfg.Gateway.APIPort,
		IngressAddr:        ingressAddr,
		EgressAddr:         egressAddr,
		HostUser:           deps.hostUser,
		DefenseClawVersion: manager.ImageVersion(),
		GatewayResources:   manager.GatewayConfigResources(""),
		VMDiskFree:         manager.GatewayVMDiskFree(""),
		StartLock:          func() (func(), error) { return openshell.LockSandboxStart("") },
		MigrateBootstrap:   dockerBootstrapMigrator(opts.Managed),
		OnGateway:          rt.gatewayState,
		Listeners:          rt.listenersReady,
		DiscoveryRemoved:   discoveryRemoved,
		ManagedAccount:     opts.Managed,
		OtherGateways:      otherGateways,
	})
	if err != nil {
		return nil, err
	}
	ingress := SandboxIngressConfig{
		Addr: ingressAddr, Bindings: store, InFlight: inflight,
		OnRequest:   mgr.ObserveIngress,
		OnListening: func() { rt.setListening("ingress", true) },
		OnHookDecision: func(d SandboxHookDecision) {
			mgr.ObserveHookDecision(manager.HookDecision{
				BindingID: d.BindingID, SandboxName: d.SandboxName, Connector: d.Connector,
				Event: d.Event, Tool: d.Tool, ToolUseID: d.ToolUseID,
				SessionID: d.SessionID, ToolInput: d.ToolInput, ResultStatus: d.ResultStatus,
				Action: d.Action, WouldBlock: d.WouldBlock, Severity: d.Severity, Reason: d.Reason,
				ModelError: d.ModelError, ModelStatus: d.ModelStatus, CallRef: d.CallRef, AlertsLow: d.AlertsLow,
			})
		},
		OnHookFailure: func(f SandboxHookFailure) {
			mgr.ObserveHookFailure(manager.HookFailure{BindingID: f.BindingID, SandboxName: f.SandboxName, Status: f.Status})
		},
		EgressUnblock: func(b sandboxauth.Binding, host string) (string, bool) {
			return mgr.EgressUnblock(b.ID, b.SandboxName, host)
		},
		EgressRefusals: func(b sandboxauth.Binding) []SandboxEgressRefusal {
			return sandboxEgressRefusalsOf(mgr.EgressRefusals(b.ID, b.SandboxName))
		},
	}
	if opts.Managed {
		ingress.Relay, ingress.Registration, ingress.OnGeneration = opts.Relay, deps.registration, deps.onGeneration
		// The managed gateway tells the agent (#1192): the daemon sends the
		// untold refusals with each hook call and marks the ones it told.
		ingress.EgressRefusals = func(b sandboxauth.Binding) []SandboxEgressRefusal {
			return sandboxEgressRefusalsOf(mgr.PendingEgressRefusals(b.ID, b.SandboxName))
		}
		ingress.EgressRefusalsTold = func(b sandboxauth.Binding, told []SandboxEgressRefusal) {
			out := make([]manager.EgressRefusal, 0, len(told))
			for _, r := range told {
				out = append(out, manager.EgressRefusal{Host: r.Host, Port: r.Port, Category: r.Category, Note: r.Note})
			}
			mgr.EgressRefusalsTold(b.ID, b.SandboxName, out)
		}
	}
	if err := api.SetSandboxIngress(ingress); err != nil {
		return nil, err
	}
	decider, err := mgr.Decider()
	if err != nil {
		_ = api.SetSandboxIngress(SandboxIngressConfig{})
		return nil, fmt.Errorf("egress policy: %w", err)
	}
	// The counter's threshold is only the default: each sandbox's proxy
	// credential carries its resolved policy's threshold and large-upload
	// block (egress.block_large_uploads), so no block is set counter-wide.
	proxy, err := egress.New(egress.Options{
		Auth: mgr.EgressAuthenticator(), Decider: decider, Sink: mgr.EgressSink(),
		Counter: egress.NewCounter(egress.CounterOptions{LargeUploadBytes: mgr.LargeUploadBytes()}),
		Refresh: deps.egressRefresh,
	})
	if err != nil {
		_ = api.SetSandboxIngress(SandboxIngressConfig{})
		return nil, fmt.Errorf("egress proxy: %w", err)
	}
	mgr.AttachProxy(proxy)
	api.SetSandboxController(mgr)
	rt.manager, rt.proxy = mgr, proxy
	feed := mgr.Feed()
	rt.fleet = mgr
	if deps.telemetry != nil {
		rt.tel = deps.telemetry
	}
	rt.publish = func(ev sandboxapi.ActivityEvent) { feed.Publish(ev) }
	return rt, nil
}

// run serves the API together with the sandbox listeners and manager until
// ctx ends or the API stops. A sandbox listener that cannot start, or
// stops, degrades the sandbox subsystem and stops the running sandboxes
// (containListenerLoss), but never stops the API.
func (rt *sandboxRuntime) run(ctx context.Context, serveAPI func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var problemsMu sync.Mutex
	problems := map[string]string{}
	report := func(part string, err error) {
		problemsMu.Lock()
		defer problemsMu.Unlock()
		if err != nil {
			problems[part] = err.Error()
		} else {
			delete(problems, part)
		}
		if len(problems) == 0 {
			rt.health.SetSandbox(StateRunning, "", map[string]interface{}{
				"ingress": rt.api.SandboxIngressAddr(), "egress": rt.egressAddr,
			})
			return
		}
		parts := make([]string, 0, len(problems))
		for k, v := range problems {
			parts = append(parts, k+": "+v)
		}
		slices.Sort(parts)
		rt.health.SetSandbox(StateDegraded, strings.Join(parts, "; "), nil)
	}
	report("", nil)
	rt.reportMu.Lock()
	rt.report = report
	rt.reportMu.Unlock()
	defer func() {
		rt.reportMu.Lock()
		rt.report = nil
		rt.reportMu.Unlock()
	}()

	if active, ok := rt.tel.(sandboxActiveExporter); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exportSandboxActive(ctx, active, audit.SandboxActiveExportInterval)
		}()
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer rt.setListening("ingress", false)
		if err := rt.api.RunSandboxIngress(ctx); err != nil && ctx.Err() == nil {
			rt.listenerLost(ctx, "ingress", err, report)
		}
	}()
	go func() {
		defer wg.Done()
		if err := rt.serveEgress(ctx); err != nil && ctx.Err() == nil {
			rt.listenerLost(ctx, "egress", err, report)
		}
	}()
	go func() {
		defer wg.Done()
		if err := rt.manager.Run(ctx); err != nil && ctx.Err() == nil {
			report("manager", err)
		}
	}()
	err := serveAPI(ctx)
	cancel()
	wg.Wait()
	rt.api.SetSandboxController(nil)
	rt.health.SetSandbox(StateStopped, "", nil)
	return err
}

// sandboxActiveExporter is the recorder that exports the active-sandbox
// gauge (audit.SandboxRecorder).
type sandboxActiveExporter interface {
	RecordActiveSandboxes(ctx context.Context) error
}

// exportSandboxActive exports the active-sandbox gauge every interval until
// ctx ends: lifecycle records export it only when a phase changes, and a
// running sandbox must not read as none once Prometheus marks the last point
// stale (#1241).
func exportSandboxActive(ctx context.Context, active sandboxActiveExporter, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := active.RecordActiveSandboxes(ctx); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[sandbox] %s: export the active-sandbox gauge: %v\n", gatewaylog.ErrCodeOpenShellTelemetryFailed, err)
			}
		}
	}
}

// sandboxEgressRefusalsOf is the manager's refusals as the ingress tells
// them.
func sandboxEgressRefusalsOf(refused []manager.EgressRefusal) []SandboxEgressRefusal {
	if len(refused) == 0 {
		return nil
	}
	out := make([]SandboxEgressRefusal, 0, len(refused))
	for _, r := range refused {
		out = append(out, SandboxEgressRefusal{Host: r.Host, Port: r.Port, Category: r.Category, What: r.What, Remedy: r.Remedy,
			Cut: r.Cut, Sent: r.Sent, Note: r.Note})
	}
	return out
}

// listenerLost handles the loss of the sandbox listener part (ingress or
// egress): it reports the subsystem degraded, records the failure, and
// contains it until ctx ends (containListenerLoss).
func (rt *sandboxRuntime) listenerLost(ctx context.Context, part string, cause error, report func(string, error)) {
	fmt.Fprintf(os.Stderr, "[sandbox] %s: %v\n", gatewaylog.ErrCodeOpenShellListenerFailed, cause)
	report(part, fmt.Errorf("%w (running sandboxes are stopped until DefenseClaw holds this port again)", cause))
	if rt.tel != nil {
		if err := rt.tel.RecordSandboxHealth(context.WithoutCancel(ctx), audit.SandboxHealthEvent{
			State:        audit.SandboxHealthFailed,
			ErrorCode:    strings.ToLower(string(gatewaylog.ErrCodeOpenShellListenerFailed)),
			ErrorSummary: "the sandbox " + part + " listener is not running: " + cause.Error(),
			Timestamp:    time.Now(),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "[sandbox] %s: record the lost %s listener: %v\n", gatewaylog.ErrCodeOpenShellTelemetryFailed, part, err)
		}
	}
	if rt.fleet == nil {
		<-ctx.Done()
		return
	}
	every := rt.recheck
	if every <= 0 {
		every = sandboxListenerRecheck
	}
	serving := func() bool { return rt.health == nil || rt.health.Snapshot().API.State == StateRunning }
	containListenerLoss(ctx, rt.fleet, rt.publish, part, every, serving)
}

// containListenerLoss stops every sandbox that may be running, and does so
// again every interval, until ctx ends, while this process does not hold
// the sandbox listener part.
//
// OpenShell relays host.openshell.internal:<port> to whatever listens on
// that host port, and nothing on the relay authenticates DefenseClaw: a
// sandbox's hooks go there with its real ingress token, and its egress
// with its proxy credential. While another program may hold one of the
// ports, a running sandbox would ask that program for its verdicts, so it
// is stopped. None can start meanwhile (listenersReady), a sandbox adopted
// later is caught by the next pass, and starting one again rotates its
// ingress token, so a token the other program saw is useless. The runtime
// binds its listeners again when it restarts with the API.
//
// A pass runs only while serving reports that this process serves its
// API: a second DefenseClaw daemon started by mistake finds every port
// taken, the running daemon's listeners among them, and must not stop the
// sandboxes that daemon serves.
func containListenerLoss(ctx context.Context, fleet sandboxFleet, publish func(sandboxapi.ActivityEvent),
	part string, every time.Duration, serving func() bool) {
	if publish == nil {
		publish = func(sandboxapi.ActivityEvent) {}
	}
	unstoppable := map[string]bool{}
	for {
		if serving == nil || serving() {
			stopSandboxesWithoutListener(ctx, fleet, publish, part, unstoppable)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// stopSandboxesWithoutListener is one containListenerLoss pass. A sandbox
// that does not stop is reported once and tried again on the next pass.
func stopSandboxesWithoutListener(ctx context.Context, fleet sandboxFleet, publish func(sandboxapi.ActivityEvent),
	part string, unstoppable map[string]bool) {
	sandboxes, err := fleet.List(ctx)
	if err != nil {
		return
	}
	why := "⚠ DefenseClaw is not holding its sandbox " + part + " port, so another program may receive this " +
		"sandbox's hooks and credentials"
	for _, sb := range sandboxes {
		if ctx.Err() != nil {
			return
		}
		switch audit.SandboxPhase(sb.Phase) {
		case audit.SandboxPhaseProvisioning, audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseUnknown:
		default:
			continue
		}
		if _, err := fleet.Stop(ctx, sb.Name); err != nil {
			if ctx.Err() != nil {
				return
			}
			if !unstoppable[sb.Name] {
				unstoppable[sb.Name] = true
				fmt.Fprintf(os.Stderr, "[sandbox] %s: stop %s: %v\n", gatewaylog.ErrCodeOpenShellListenerFailed, sb.Name, err)
				publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: sb.Name, Severity: "CRITICAL",
					Reason: sandboxListenerLostReason, Message: why + ", and DefenseClaw could not stop it: stop it yourself"})
			}
			continue
		}
		delete(unstoppable, sb.Name)
		fmt.Fprintf(os.Stderr, "[sandbox] %s: stopped %s: the %s listener is not running\n",
			gatewaylog.ErrCodeOpenShellListenerFailed, sb.Name, part)
		publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityFinding, Sandbox: sb.Name, Severity: "CRITICAL",
			Reason: sandboxListenerLostReason, Message: why + "; DefenseClaw stopped it. Free the port, run " +
				"defenseclaw-gateway restart, then start the sandbox again"})
	}
}

// sandboxListenerLostReason is the activity feed reason of a sandbox
// stopped because a sandbox listener was lost.
const sandboxListenerLostReason = "listener_lost"

// serveEgress listens on the egress port (retrying briefly while a
// previous listener releases it) and serves the proxy until ctx ends.
func (rt *sandboxRuntime) serveEgress(ctx context.Context) error {
	addr := rt.egressAddr
	var ln net.Listener
	budget := rt.listenBudget
	if budget <= 0 {
		budget = 30 * time.Second
	}
	deadline := time.Now().Add(budget)
	for {
		var err error
		ln, err = egress.Listen(addr)
		if err == nil {
			break
		}
		if !isAddrInUse(err) || time.Now().After(deadline) {
			return fmt.Errorf("sandbox egress proxy: listen %s: %w", addr, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return rt.serveEgressOn(ctx, ln, false)
}

// serveEgressOn serves the proxy on ln, which it owns, until ctx ends. The
// proxy is shut down then, unless keep: the managed sandbox daemon releases
// its port when no sandbox runs and serves the same proxy on a new listener
// at the next create, so only the listener closes.
func (rt *sandboxRuntime) serveEgressOn(ctx context.Context, ln net.Listener, keep bool) error {
	fmt.Fprintf(os.Stderr, "[sandbox-egress] listening on %s\n", ln.Addr())
	rt.setListening("egress", true)
	defer rt.setListening("egress", false)
	errCh := make(chan error, 1)
	go func() { errCh <- rt.proxy.Serve(ln) }()
	select {
	case err := <-errCh:
		_ = ln.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		if keep {
			_ = ln.Close()
		} else {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rt.proxy.Shutdown(shutdownCtx)
			_ = ln.Close()
		}
		<-errCh
		return nil
	}
}

// sandboxConfigPersister keeps "always" sandbox decisions in config.yaml
// (openshell.egress.unblocked / block) through the same write transaction
// the guardrail config API uses, so the ConfigManager reloads them. Always
// approvals and unblocks never go to openshell.egress.allow: an allow entry
// lets its name resolve to private addresses, an unblock does not.
type sandboxConfigPersister struct {
	api *APIServer
}

func (p sandboxConfigPersister) AllowAlways(ctx context.Context, host string) error {
	return p.api.appendSandboxConfigList(ctx, "openshell.egress.unblocked", host)
}

func (p sandboxConfigPersister) BlockAlways(ctx context.Context, host string) error {
	return p.api.appendSandboxConfigList(ctx, "openshell.egress.block", host)
}

// syncSandboxConfig reloads config.yaml through the central reload
// transaction, so a sandbox decision sees a change the CLI wrote a moment
// ago instead of waiting for the reload watcher (manager.Options.SyncConfig).
func (a *APIServer) syncSandboxConfig(ctx context.Context) error {
	if a.configReloader == nil {
		return nil
	}
	return a.configReloader(ctx, "sandbox_decision")
}

func (a *APIServer) appendSandboxConfigList(ctx context.Context, key, host string) error {
	if a.configReloader == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the daemon cannot write its configuration")
	}
	a.configWriteMu.Lock()
	defer a.configWriteMu.Unlock()
	current := a.runtimeConfigSnapshot()
	if current == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "configuration not available")
	}
	if key != "openshell.egress.unblocked" && key != "openshell.egress.block" {
		return fmt.Errorf("sandbox decisions cannot be saved to %s", key)
	}
	// The list comes from the file the write replaces, not from the applied
	// generation, which lags it (debounce, a rejected reload, another
	// writer): the CAS below then covers the whole read-modify-write.
	path := configFilePathForSnapshot(current)
	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		OpenShell struct {
			Egress struct {
				Unblocked []string `yaml:"unblocked"`
				Block     []string `yaml:"block"`
			} `yaml:"egress"`
		} `yaml:"openshell"`
	}
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	list := doc.OpenShell.Egress.Unblocked
	if key == "openshell.egress.block" {
		list = doc.OpenShell.Egress.Block
	}
	for _, have := range list {
		if strings.EqualFold(strings.TrimSpace(have), host) {
			return nil
		}
	}
	next := append(append([]string{}, list...), host)
	actor := configwrite.ActorPrefixSandbox + host
	written, err := configwrite.Apply(ctx, path, []configwrite.Change{{Path: key, Value: next}}, configwrite.Options{
		Actor:        actor,
		Reason:       "sandbox always decision",
		ExpectSHA256: configwrite.SHA256Hex(original),
	})
	if errors.Is(err, configwrite.ErrManaged) {
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
			Detail: "the configuration is administrator-owned; decisions cannot be kept for future sandboxes"}
	}
	if err != nil {
		return fmt.Errorf("save %s: %w", key, err)
	}
	if err := a.configReloader(ctx, "sandbox_always_decision"); err != nil {
		_, rollbackErr := configwrite.ReplaceDocument(ctx, path, original, configwrite.Options{
			Actor: actor, Reason: "sandbox always decision rollback", ExpectSHA256: written.SHA256,
		})
		if rollbackErr == nil {
			rollbackErr = a.configReloader(ctx, "sandbox_always_decision_rollback")
		}
		if rollbackErr != nil {
			err = fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
		}
		return err
	}
	return nil
}

// dockerBootstrapMigrator is the sandbox manager's MigrateBootstrap: the
// account's OpenShell gateway keeps its Docker sandboxes' bootstrap in its
// state folder, and the migration moves the sandbox's files in the first
// folder that gateway may use (gatewayStateHomes, the gateway's own first)
// that keeps it. Another folder is not read once one keeps the sandbox. A
// folder that cannot be listed is not known to keep it and is passed over:
// it never refuses a start, which then goes to OpenShell as before the
// migration existed (a bootstrap it cannot read still fails there, and
// legacyBootstrapRefusal says why). A file of the sandbox's own that cannot
// be moved refuses it.
func dockerBootstrapMigrator(managedAccount bool) func(string) ([]string, error) {
	return func(sandboxID string) ([]string, error) {
		homes, err := gatewayStateHomes(managedAccount)
		if err != nil {
			return nil, err
		}
		for _, stateHome := range homes {
			moved, kept, err := openshell.MigrateDockerBootstrap(stateHome, sandboxID)
			if errors.Is(err, openshell.ErrDockerStateUnreadable) {
				continue
			}
			if err != nil || kept {
				return moved, err
			}
		}
		return nil, nil
	}
}

// sandboxAccountHomeDir is the home of the account a managed daemon runs as,
// the one its exec shim starts the gateway in; a seam for tests.
var sandboxAccountHomeDir = func() string { return accountHome(os.Getuid()) }

// gatewayStateHomes are the state folders the account's OpenShell gateway
// may keep its state in, the one it runs with first. A managed daemon's
// gateway is the exec shim's, which starts it with HOME and no
// XDG_STATE_HOME: openshell.DefaultStateHome of the account's home,
// whatever $XDG_STATE_HOME the daemon itself has.
// The per-user gateway's OpenShell is one the person started: under
// $XDG_STATE_HOME (openshell.UserStateHome, as the daemon's environment
// says), or, as a fallback, ~/.local/state when it started without one.
func gatewayStateHomes(managedAccount bool) ([]string, error) {
	if managedAccount {
		home := sandboxAccountHomeDir()
		if home == "" {
			return nil, errors.New("the account has no home directory for its OpenShell gateway's state")
		}
		return []string{openshell.DefaultStateHome(home)}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	homes := []string{openshell.UserStateHome(os.Getenv, home)}
	if def := openshell.DefaultStateHome(home); filepath.Clean(def) != filepath.Clean(homes[0]) {
		homes = append(homes, def)
	}
	return homes, nil
}
