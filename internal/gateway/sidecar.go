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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// Sidecar is the long-running process that connects to the OpenClaw gateway,
// watches for skill installs, and exposes a local REST API.
type Sidecar struct {
	cfg    *config.Config
	client *Client
	router *EventRouter
	store  *audit.Store
	logger *audit.Logger
	health *SidecarHealth
	shell  *sandbox.OpenShell
	otel   *telemetry.Provider
	notify *NotificationQueue

	alertCtx    context.Context
	alertCancel context.CancelFunc
	alertWg     sync.WaitGroup
}

// NewSidecar creates a sidecar instance ready to connect.
func NewSidecar(cfg *config.Config, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, otel *telemetry.Provider) (*Sidecar, error) {
	fmt.Fprintf(os.Stderr, "[sidecar] initializing client (host=%s port=%d device_key=%s)\n",
		cfg.Gateway.Host, cfg.Gateway.Port, cfg.Gateway.DeviceKeyFile)

	// In standalone sandbox mode the veth link is point-to-point;
	// TLS is not needed and OpenClaw serves plain WS.
	if !cfg.Gateway.RequiresTLSWithMode(&cfg.OpenShell) {
		cfg.Gateway.NoTLS = true
	}

	client, err := NewClient(&cfg.Gateway)
	if err != nil {
		return nil, fmt.Errorf("sidecar: create client: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[sidecar] device identity loaded (id=%s)\n", client.device.DeviceID)

	notify := NewNotificationQueue()

	router := NewEventRouter(client, store, logger, cfg.Gateway.AutoApprove, otel)
	router.notify = notify
	client.OnEvent = router.Route

	alertCtx, alertCancel := context.WithCancel(context.Background())

	return &Sidecar{
		cfg:         cfg,
		client:      client,
		router:      router,
		store:       store,
		logger:      logger,
		health:      NewSidecarHealth(),
		shell:       shell,
		otel:        otel,
		notify:      notify,
		alertCtx:    alertCtx,
		alertCancel: alertCancel,
	}, nil
}

// Run starts all subsystems as independent goroutines. Each subsystem runs
// in its own goroutine so that a gateway disconnect does not stop the watcher
// or API server. Run blocks until ctx is cancelled, then shuts everything down.
func (s *Sidecar) Run(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "[sidecar] starting subsystems (auto_approve=%v watcher=%v api_port=%d guardrail=%v)\n",
		s.cfg.Gateway.AutoApprove, s.cfg.Gateway.Watcher.Enabled, s.cfg.Gateway.APIPort, s.cfg.Guardrail.Enabled)
	_ = s.logger.LogAction("sidecar-start", "", "starting all subsystems")

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	// Goroutine 1: Gateway connection loop (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runGatewayLoop(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] gateway loop exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 2: Skill/MCP watcher (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runWatcher(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] watcher exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 3: REST API server (always runs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runAPI(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] api server exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Goroutine 4: guardrail proxy (opt-in via config)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.runGuardrail(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] guardrail exited with error: %v\n", err)
			errCh <- err
		}
	}()

	// Report telemetry (OTel) health — not a goroutine, just state
	s.reportTelemetryHealth()
	if s.otel != nil {
		s.otel.EmitStartupSpan(ctx)
	}

	// Report Splunk HEC health — not a goroutine, just state
	s.reportSplunkHealth()

	// Report sandbox health — only present when standalone mode is active
	s.reportSandboxHealth(ctx)

	// Wait for context cancellation (signal handler in CLI layer)
	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "[sidecar] context cancelled, waiting for subsystems to stop ...\n")
	wg.Wait()

	s.alertCancel()
	s.alertWg.Wait()

	_ = s.logger.LogAction("sidecar-stop", "", "all subsystems stopped")
	_ = s.client.Close()

	// Return the first non-nil error if any subsystem failed before shutdown
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// runGatewayLoop connects to the gateway and reconnects on disconnect,
// running indefinitely until ctx is cancelled.
func (s *Sidecar) runGatewayLoop(ctx context.Context) error {
	for {
		s.health.SetGateway(StateReconnecting, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] connecting to %s:%d ...\n", s.cfg.Gateway.Host, s.cfg.Gateway.Port)

		err := s.client.ConnectWithRetry(ctx)
		if err != nil {
			if ctx.Err() != nil {
				s.health.SetGateway(StateStopped, "", nil)
				return nil
			}
			s.health.SetGateway(StateError, err.Error(), nil)
			fmt.Fprintf(os.Stderr, "[sidecar] connect failed: %v (will keep retrying)\n", err)
			continue
		}

		hello := s.client.Hello()
		s.logHello(hello)
		_ = s.logger.LogAction("sidecar-connected", "",
			fmt.Sprintf("protocol=%d", hello.Protocol))
		s.health.SetGateway(StateRunning, "", map[string]interface{}{
			"protocol": hello.Protocol,
		})

		s.subscribeToSessions(ctx)

		fmt.Fprintf(os.Stderr, "[sidecar] event loop running, waiting for events ...\n")

		select {
		case <-ctx.Done():
			s.health.SetGateway(StateStopped, "", nil)
			return nil
		case <-s.client.Disconnected():
			fmt.Fprintf(os.Stderr, "[sidecar] gateway connection lost, reconnecting ...\n")
			_ = s.logger.LogAction("sidecar-disconnected", "", "connection lost, reconnecting")
			s.health.SetGateway(StateReconnecting, "connection lost", nil)
		}
	}
}

// runWatcher starts the skill/MCP install watcher if enabled in config.
func (s *Sidecar) runWatcher(ctx context.Context) error {
	wcfg := s.cfg.Gateway.Watcher

	if !wcfg.Enabled {
		s.health.SetWatcher(StateDisabled, "", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] watcher disabled (set gateway.watcher.enabled=true to enable)\n")
		<-ctx.Done()
		return nil
	}

	// Resolve skill dirs: explicit config overrides autodiscovery
	var skillDirs []string
	if wcfg.Skill.Enabled {
		if len(wcfg.Skill.Dirs) > 0 {
			skillDirs = wcfg.Skill.Dirs
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using configured skill dirs: %v\n", skillDirs)
		} else {
			skillDirs = s.cfg.SkillDirs()
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: autodiscovered skill dirs: %v\n", skillDirs)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill watching disabled\n")
	}

	// Plugin dirs: explicit config overrides autodiscovery from claw mode
	var pluginDirs []string
	if wcfg.Plugin.Enabled {
		if len(wcfg.Plugin.Dirs) > 0 {
			pluginDirs = wcfg.Plugin.Dirs
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: using configured plugin dirs: %v\n", pluginDirs)
		} else {
			pluginDirs = s.cfg.PluginDirs()
			fmt.Fprintf(os.Stderr, "[sidecar] watcher: autodiscovered plugin dirs: %v\n", pluginDirs)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin watching disabled\n")
	}

	if len(skillDirs) == 0 && len(pluginDirs) == 0 {
		s.health.SetWatcher(StateError, "no directories configured", nil)
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: no directories to watch\n")
		<-ctx.Done()
		return nil
	}

	s.health.SetWatcher(StateStarting, "", map[string]interface{}{
		"skill_dirs":         len(skillDirs),
		"plugin_dirs":        len(pluginDirs),
		"skill_take_action":  wcfg.Skill.TakeAction,
		"plugin_take_action": wcfg.Plugin.TakeAction,
	})

	var opa *policy.Engine
	if s.cfg.PolicyDir != "" {
		regoDir := s.cfg.PolicyDir
		if engine, err := policy.New(regoDir); err == nil {
			if compileErr := engine.Compile(); compileErr == nil {
				opa = engine
				fmt.Fprintf(os.Stderr, "[sidecar] OPA policy engine loaded from %s\n", regoDir)
			} else {
				fmt.Fprintf(os.Stderr, "[sidecar] OPA compile error (falling back to built-in): %v\n", compileErr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] OPA init skipped (falling back to built-in): %v\n", err)
		}
	}

	w := watcher.New(s.cfg, skillDirs, pluginDirs, s.store, s.logger, s.shell, opa, s.otel, func(r watcher.AdmissionResult) {
		s.handleAdmissionResult(r)
	})
	if s.otel != nil {
		w.SetOTelProvider(s.otel)
	}

	fmt.Fprintf(os.Stderr, "[sidecar] watcher starting (%d skill dirs, %d plugin dirs, skill_take_action=%v, plugin_take_action=%v)\n",
		len(skillDirs), len(pluginDirs), wcfg.Skill.TakeAction, wcfg.Plugin.TakeAction)

	s.health.SetWatcher(StateRunning, "", map[string]interface{}{
		"skill_dirs":         len(skillDirs),
		"plugin_dirs":        len(pluginDirs),
		"skill_take_action":  wcfg.Skill.TakeAction,
		"plugin_take_action": wcfg.Plugin.TakeAction,
	})

	err := w.Run(ctx)
	s.health.SetWatcher(StateStopped, "", nil)
	return err
}

// handleAdmissionResult processes watcher verdicts. For blocked/rejected skills
// and plugins, it also disables them at the gateway level when take_action is enabled.
func (s *Sidecar) handleAdmissionResult(r watcher.AdmissionResult) {
	fmt.Fprintf(os.Stderr, "[sidecar] watcher verdict: %s %s — %s (%s)\n",
		r.Event.Type, r.Event.Name, r.Verdict, r.Reason)

	if r.Verdict != watcher.VerdictBlocked && r.Verdict != watcher.VerdictRejected {
		return
	}

	switch r.Event.Type {
	case watcher.InstallSkill:
		s.handleSkillAdmission(r)
	case watcher.InstallPlugin:
		s.handlePluginAdmission(r)
	default:
		if s.logger != nil {
			_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
				fmt.Sprintf("type=%s verdict=%s (no handler)", r.Event.Type, r.Verdict))
		}
	}
}

func (s *Sidecar) handleSkillAdmission(r watcher.AdmissionResult) {
	if !s.cfg.Gateway.Watcher.Skill.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: skill %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
			fmt.Sprintf("verdict=%s (take_action disabled, no gateway action)", r.Verdict))
		return
	}

	var actions []string

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.client.DisableSkill(ctx, r.Event.Name); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disable skill %s failed: %v\n",
			r.Event.Name, err)
	} else {
		actions = append(actions, "disabled")
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disabled skill %s\n", r.Event.Name)
		_ = s.logger.LogAction("sidecar-watcher-disable", r.Event.Name,
			fmt.Sprintf("auto-disabled skill via gateway after verdict=%s", r.Verdict))
	}

	if strings.Contains(r.Reason, "quarantine") || strings.Contains(r.Reason, "block") {
		actions = append(actions, "quarantined", "blocked")
	}

	s.alertWg.Add(1)
	go func() {
		defer s.alertWg.Done()
		s.sendEnforcementAlert(r.Event.Name, r.MaxSeverity, r.FindingCount, actions, r.Reason)
	}()
}

// sendEnforcementAlert sends a security notification to all active sessions
// via the gateway's sessions.send RPC so each chat learns about the enforcement.
// Runs in a goroutine to avoid blocking the watcher callback.
func (s *Sidecar) sendEnforcementAlert(skillName, severity string, findings int, actions []string, reason string) {
	parent := s.alertCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()

	msg := formatEnforcementMessage(skillName, severity, findings, actions, reason)

	sessionKeys := s.router.ActiveSessionKeys()
	if len(sessionKeys) == 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: no active sessions tracked, falling back to guardrail injection\n")
		s.notify.Push(SecurityNotification{
			SkillName: skillName,
			Severity:  severity,
			Findings:  findings,
			Actions:   actions,
			Reason:    reason,
		})
		return
	}

	sent := 0
	for _, key := range sessionKeys {
		sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.client.SessionsSend(sendCtx, key, msg); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: send to session %s failed: %v\n", key, err)
		} else {
			sent++
			fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert sent to session %s\n", key)
		}
		sendCancel()
	}

	if sent == 0 {
		fmt.Fprintf(os.Stderr, "[sidecar] enforcement alert: all sessions.send failed, falling back to guardrail injection\n")
		s.notify.Push(SecurityNotification{
			SkillName: skillName,
			Severity:  severity,
			Findings:  findings,
			Actions:   actions,
			Reason:    reason,
		})
	}
}

// formatEnforcementMessage builds a human-readable security alert for chat.
func formatEnforcementMessage(skillName, severity string, findings int, actions []string, reason string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[DefenseClaw Security Alert] Skill %q was blocked.\n", skillName)
	fmt.Fprintf(&sb, "Severity: %s", severity)
	if findings > 0 {
		fmt.Fprintf(&sb, " (%d security finding(s))", findings)
	}
	sb.WriteString("\n")
	if len(actions) > 0 {
		fmt.Fprintf(&sb, "Actions taken: %s\n", strings.Join(actions, ", "))
	}
	if reason != "" {
		fmt.Fprintf(&sb, "Reason: %s\n", reason)
	}
	sb.WriteString("The skill was NOT installed. Do not use it or confirm its installation.")
	return sb.String()
}

func (s *Sidecar) handlePluginAdmission(r watcher.AdmissionResult) {
	if !s.cfg.Gateway.Watcher.Plugin.TakeAction {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher: plugin %s verdict=%s (take_action=false, logging only)\n",
			r.Event.Name, r.Verdict)
		_ = s.logger.LogAction("sidecar-watcher-verdict", r.Event.Name,
			fmt.Sprintf("verdict=%s (plugin take_action disabled, no gateway action)", r.Verdict))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.client.DisablePlugin(ctx, r.Event.Name); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disable plugin %s failed: %v\n",
			r.Event.Name, err)
	} else {
		fmt.Fprintf(os.Stderr, "[sidecar] watcher→gateway disabled plugin %s\n", r.Event.Name)
		_ = s.logger.LogAction("sidecar-watcher-disable-plugin", r.Event.Name,
			fmt.Sprintf("auto-disabled plugin via gateway after verdict=%s", r.Verdict))
	}
}

// runGuardrail starts the Go guardrail proxy when guardrail is enabled.
func (s *Sidecar) runGuardrail(ctx context.Context) error {
	proxy, err := NewGuardrailProxy(
		&s.cfg.Guardrail,
		&s.cfg.CiscoAIDefense,
		s.logger,
		s.health,
		s.otel,
		s.store,
		s.cfg.DataDir,
		s.cfg.PolicyDir,
		s.notify,
	)
	if err != nil {
		s.health.SetGuardrail(StateError, err.Error(), nil)
		fmt.Fprintf(os.Stderr, "[guardrail] init error: %v\n", err)
		if !s.cfg.Guardrail.Enabled {
			s.health.SetGuardrail(StateDisabled, "", nil)
			<-ctx.Done()
			return nil
		}
		<-ctx.Done()
		return err
	}
	return proxy.Run(ctx)
}

// runAPI starts the REST API server.
func (s *Sidecar) runAPI(ctx context.Context) error {
	bind := "127.0.0.1"
	if s.cfg.Gateway.APIBind != "" {
		bind = s.cfg.Gateway.APIBind
	} else if s.cfg.OpenShell.IsStandalone() && s.cfg.Guardrail.Host != "" && s.cfg.Guardrail.Host != "localhost" {
		bind = s.cfg.Guardrail.Host
	}
	addr := fmt.Sprintf("%s:%d", bind, s.cfg.Gateway.APIPort)
	api := NewAPIServer(addr, s.health, s.client, s.store, s.logger, s.cfg)
	api.SetOTelProvider(s.otel)
	return api.Run(ctx)
}

// subscribeToSessions lists active sessions and subscribes to each one
// so we receive session.tool events for tool call/result tracing.
func (s *Sidecar) subscribeToSessions(ctx context.Context) {
	subCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	raw, err := s.client.SessionsList(subCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] sessions.list failed (will still receive agent events): %v\n", err)
		return
	}

	// OpenClaw returns sessions as either an array or an object keyed by
	// session ID. Try both formats.
	type sessionEntry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var sessions []sessionEntry

	if err := json.Unmarshal(raw, &sessions); err != nil {
		// Try object format: {"sessionId": {id, name, ...}, ...}
		var sessMap map[string]json.RawMessage
		if err2 := json.Unmarshal(raw, &sessMap); err2 != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] parse sessions list: %v\n", err)
			return
		}
		for k, v := range sessMap {
			var entry sessionEntry
			if json.Unmarshal(v, &entry) == nil {
				if entry.ID == "" {
					entry.ID = k
				}
				sessions = append(sessions, entry)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[sidecar] found %d active sessions, subscribing for tool events...\n", len(sessions))

	for _, sess := range sessions {
		subCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		if err := s.client.SessionsSubscribe(subCtx2, sess.ID); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] subscribe to session %s failed: %v\n", sess.ID, err)
		} else {
			fmt.Fprintf(os.Stderr, "[sidecar] subscribed to session %s (%s)\n", sess.ID, sess.Name)
		}
		cancel2()
	}
}

func (s *Sidecar) logHello(h *HelloOK) {
	fmt.Fprintf(os.Stderr, "[sidecar] connected to gateway (protocol v%d)\n", h.Protocol)
	if h.Features != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] methods: %s\n", strings.Join(h.Features.Methods, ", "))
		fmt.Fprintf(os.Stderr, "[sidecar] events:  %s\n", strings.Join(h.Features.Events, ", "))
	}
}

// reportTelemetryHealth sets the OTel telemetry subsystem health based on
// whether the provider was initialized and which signals are active.
func (s *Sidecar) reportTelemetryHealth() {
	if s.otel == nil || !s.otel.Enabled() {
		s.health.SetTelemetry(StateDisabled, "", nil)
		return
	}

	details := map[string]interface{}{}
	if s.cfg.OTel.Endpoint != "" {
		details["endpoint"] = s.cfg.OTel.Endpoint
	}

	var signals []string
	if s.cfg.OTel.Traces.Enabled {
		signals = append(signals, "traces")
	}
	if s.cfg.OTel.Metrics.Enabled {
		signals = append(signals, "metrics")
	}
	if s.cfg.OTel.Logs.Enabled {
		signals = append(signals, "logs")
	}
	if len(signals) > 0 {
		details["signals"] = strings.Join(signals, ", ")
	}

	if ep := s.cfg.OTel.Traces.Endpoint; ep != "" {
		details["traces_endpoint"] = ep
	}

	s.health.SetTelemetry(StateRunning, "", details)
}

// reportSandboxHealth sets the sandbox subsystem health when standalone mode is active.
// It starts a background goroutine that probes the sandbox endpoint and
// transitions the state to running once reachable, or error on timeout.
func (s *Sidecar) reportSandboxHealth(ctx context.Context) {
	if !s.cfg.OpenShell.IsStandalone() {
		return
	}

	details := map[string]interface{}{
		"sandbox_ip":    s.cfg.Gateway.Host,
		"openclaw_port": s.cfg.Gateway.Port,
	}
	s.health.SetSandbox(StateStarting, "", details)

	go s.probeSandbox(ctx, details)
}

// probeSandbox tries to TCP-dial the sandbox endpoint with back-off.
// On success it transitions sandbox health to running; on context
// cancellation or too many failures it transitions to error/stopped.
func (s *Sidecar) probeSandbox(ctx context.Context, details map[string]interface{}) {
	addr := net.JoinHostPort(s.cfg.Gateway.Host, fmt.Sprintf("%d", s.cfg.Gateway.Port))
	const maxAttempts = 20
	backoff := 500 * time.Millisecond

	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			s.health.SetSandbox(StateStopped, "context cancelled", details)
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			fmt.Fprintf(os.Stderr, "[sidecar] sandbox probe succeeded (%s reachable)\n", addr)
			s.health.SetSandbox(StateRunning, "", details)
			return
		}

		fmt.Fprintf(os.Stderr, "[sidecar] sandbox probe attempt %d/%d failed: %v\n", i+1, maxAttempts, err)

		select {
		case <-ctx.Done():
			s.health.SetSandbox(StateStopped, "context cancelled", details)
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff = backoff * 3 / 2
		}
	}

	s.health.SetSandbox(StateError, fmt.Sprintf("sandbox unreachable after %d probes (%s)", maxAttempts, addr), details)
}

// reportSplunkHealth sets the Splunk HEC subsystem health based on config.
func (s *Sidecar) reportSplunkHealth() {
	if !s.cfg.Splunk.Enabled {
		s.health.SetSplunk(StateDisabled, "", nil)
		return
	}

	details := map[string]interface{}{
		"hec_endpoint": s.cfg.Splunk.HECEndpoint,
		"index":        s.cfg.Splunk.Index,
	}

	bridgeEnv := readDotEnvFile(filepath.Join(s.cfg.DataDir, "splunk-bridge", "env"))
	if bridgeEnv == nil {
		bridgeEnv = readDotEnvFile(s.cfg.DataDir)
	}
	if bridgeEnv["SPLUNK_PASSWORD"] != "" {
		details["web_url"] = "http://127.0.0.1:8000"
		details["web_user"] = "admin"
		details["web_password_set"] = true
	}
	if user := bridgeEnv["DEFENSECLAW_LOCAL_USERNAME"]; user != "" {
		details["username"] = user
	}
	if bridgeEnv["DEFENSECLAW_LOCAL_PASSWORD"] != "" {
		details["password_set"] = true
	}

	s.health.SetSplunk(StateRunning, "", details)
}

// readDotEnvFile reads KEY=VALUE pairs from the .env (or .env.example) file in dataDir.
func readDotEnvFile(dataDir string) map[string]string {
	path := filepath.Join(dataDir, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		path = filepath.Join(dataDir, ".env.example")
		data, err = os.ReadFile(path)
		if err != nil {
			return nil
		}
	}
	env := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		env[k] = v
	}
	return env
}

// Client returns the underlying gateway client for direct RPC calls.
func (s *Sidecar) Client() *Client {
	return s.client
}

// Health returns the shared health tracker.
func (s *Sidecar) Health() *SidecarHealth {
	return s.health
}
