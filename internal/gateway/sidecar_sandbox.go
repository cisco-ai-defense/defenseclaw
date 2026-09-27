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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
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

	// report marks one part of the subsystem healthy (nil) or not; run
	// installs it.
	reportMu sync.Mutex
	report   func(part string, err error)

	// listening records the sandbox listeners (ingress, egress) this
	// process holds right now.
	listenMu  sync.Mutex
	listening map[string]bool
}

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
func (s *Sidecar) newSandboxRuntime(api *APIServer) (*sandboxRuntime, error) {
	cfg := s.currentConfig()
	if cfg == nil || !cfg.OpenShell.Enabled {
		return nil, nil
	}
	if err := openshell.CheckPlatform(runtime.GOOS); err != nil {
		s.health.SetSandbox(StateDisabled, err.Error(), nil)
		return nil, nil
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		msg := "OpenShell sandboxes are not supported in managed_enterprise deployments yet"
		s.health.SetSandbox(StateDisabled, msg, nil)
		return nil, nil
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
	rt := &sandboxRuntime{api: api, egressAddr: egressAddr, health: s.health}
	mcp := &sandboxMCPInventory{config: s.currentConfig}
	if api.store != nil {
		mcp.policy = enforce.NewPolicyEngine(api.store)
	}

	mgr, err := manager.New(manager.Options{
		DataDir: dataDir,
		Owner:   owner,
		Config:  s.currentConfig,
		Connect: manager.DiscoverConnector(
			openshell.DiscoverOptions{Gateway: cfg.OpenShell.Gateway.Name},
			openshell.ClientOptions{Workspace: cfg.OpenShell.Gateway.Workspace},
		),
		Bindings: store,
		Images: manager.BuilderImages{Builder: &image.Builder{
			Docker: image.CLI{}, Store: images, Log: io.Discard,
		}},
		Profiles:           manager.CLIProfileImporter{Binary: cfg.OpenShell.EffectiveBinary()},
		MCP:                mcp,
		Telemetry:          s.sandboxTelemetry(),
		Persist:            sandboxConfigPersister{api: api},
		Quiesce:            inflight,
		ForgetBinding:      api.ForgetSandboxBinding,
		IngressPort:        ingressPort,
		EgressPort:         egressPort,
		APIPort:            cfg.Gateway.APIPort,
		IngressAddr:        ingressAddr,
		EgressAddr:         egressAddr,
		DefenseClawVersion: manager.ImageVersion(),
		OnGateway:          rt.gatewayState,
		Listeners:          rt.listenersReady,
	})
	if err != nil {
		return nil, err
	}
	if err := api.SetSandboxIngress(SandboxIngressConfig{
		Addr: ingressAddr, Bindings: store, InFlight: inflight,
		OnRequest:   mgr.ObserveIngress,
		OnListening: func() { rt.setListening("ingress", true) },
		OnHookDecision: func(d SandboxHookDecision) {
			mgr.ObserveHookDecision(manager.HookDecision{
				BindingID: d.BindingID, SandboxName: d.SandboxName, Event: d.Event, Tool: d.Tool, ToolUseID: d.ToolUseID,
				Action: d.Action, WouldBlock: d.WouldBlock, Severity: d.Severity, Reason: d.Reason,
			})
		},
	}); err != nil {
		return nil, err
	}
	decider, err := mgr.Decider()
	if err != nil {
		_ = api.SetSandboxIngress(SandboxIngressConfig{})
		return nil, fmt.Errorf("egress policy: %w", err)
	}
	proxy, err := egress.New(egress.Options{
		Auth: mgr.EgressAuthenticator(), Decider: decider, Sink: mgr.EgressSink(),
		Counter: egress.NewCounter(egress.CounterOptions{LargeUploadBytes: mgr.LargeUploadBytes()}),
	})
	if err != nil {
		_ = api.SetSandboxIngress(SandboxIngressConfig{})
		return nil, fmt.Errorf("egress proxy: %w", err)
	}
	mgr.AttachProxy(proxy)
	api.SetSandboxController(mgr)
	rt.manager, rt.proxy = mgr, proxy
	return rt, nil
}

// run serves the API together with the sandbox listeners and manager until
// ctx ends or the API stops. A sandbox listener that cannot start degrades
// the sandbox subsystem (hooks fail closed) but never stops the API.
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

	wg.Add(3)
	go func() {
		defer wg.Done()
		defer rt.setListening("ingress", false)
		if err := rt.api.RunSandboxIngress(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sandbox] %s: %v\n", gatewaylog.ErrCodeOpenShellListenerFailed, err)
			report("ingress", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := rt.serveEgress(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sandbox] %s: %v\n", gatewaylog.ErrCodeOpenShellListenerFailed, err)
			report("egress", err)
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

// serveEgress listens on the egress port (retrying briefly while a
// previous listener releases it) and serves the proxy until ctx ends.
func (rt *sandboxRuntime) serveEgress(ctx context.Context) error {
	addr := rt.egressAddr
	var ln net.Listener
	deadline := time.Now().Add(30 * time.Second)
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
	fmt.Fprintf(os.Stderr, "[sandbox-egress] listening on %s\n", ln.Addr())
	rt.setListening("egress", true)
	defer rt.setListening("egress", false)
	errCh := make(chan error, 1)
	go func() { errCh <- rt.proxy.Serve(ln) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.proxy.Shutdown(shutdownCtx)
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
	if managed.IsManagedEnterprise(current.DeploymentMode) {
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
			Detail: "the configuration is administrator-owned; decisions cannot be kept for future sandboxes"}
	}
	var list []string
	switch key {
	case "openshell.egress.unblocked":
		list = current.OpenShell.Egress.Unblocked
	case "openshell.egress.block":
		list = current.OpenShell.Egress.Block
	default:
		return fmt.Errorf("sandbox decisions cannot be saved to %s", key)
	}
	for _, have := range list {
		if strings.EqualFold(strings.TrimSpace(have), host) {
			return nil
		}
	}
	next := append(append([]string{}, list...), host)
	path := configFilePathForSnapshot(current)
	original, err := captureConfigFileState(path)
	if err != nil {
		return err
	}
	if err := config.PatchYAMLFile(path, map[string]any{key: next}); err != nil {
		return err
	}
	if _, err := config.LoadRuntimeV8File(path); err != nil {
		_ = restoreConfigFileState(path, original)
		return fmt.Errorf("the updated %s is invalid: %w", key, err)
	}
	if err := a.configReloader(ctx, "sandbox_always_decision"); err != nil {
		rollbackErr := restoreConfigFileState(path, original)
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
