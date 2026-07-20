// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func readinessSnapshot(guardrailState, gatewayState gateway.SubsystemState) gateway.HealthSnapshot {
	return gateway.HealthSnapshot{
		API:       gateway.SubsystemHealth{State: gateway.StateRunning},
		Gateway:   gateway.SubsystemHealth{State: gatewayState},
		Watcher:   gateway.SubsystemHealth{State: gateway.StateDisabled},
		Guardrail: gateway.SubsystemHealth{State: guardrailState},
		Telemetry: gateway.SubsystemHealth{State: gateway.StateDisabled},
	}
}

func TestDefaultStartReadinessTimeoutCoversColdWindowsStartup(t *testing.T) {
	if defaultStartReadinessTimeout != 60*time.Second {
		t.Fatalf("default start readiness timeout = %s, want 60s", defaultStartReadinessTimeout)
	}
}

func TestLoadDaemonConfigMatchesGatewayDynamicConfigResolution(t *testing.T) {
	defaultDataDir := t.TempDir()
	resolvedDataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	const (
		secretEnv = "DC_TEST_DAEMON_DYNAMIC_AUTH"
		secret    = "dynamic-daemon-fixture-secret"
	)
	t.Setenv("DEFENSECLAW_HOME", defaultDataDir)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	t.Setenv(secretEnv, "")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	raw := fmt.Sprintf(`config_version: 8
data_dir: %s
gateway:
  api_bind: 127.0.0.1
  api_port: %d
observability:
  destinations:
    - name: dynamic-fixture
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        Authorization: {env: %s}
`, filepath.ToSlash(resolvedDataDir), apiPort, secretEnv)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resolvedDataDir, ".env"), []byte(secretEnv+"="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadDaemonConfig(nil)
	if err != nil {
		t.Fatalf("loadDaemonConfig() error = %v", err)
	}
	if cfg.Gateway.APIBind != "127.0.0.1" || cfg.Gateway.APIPort != apiPort {
		t.Fatalf("daemon endpoint = %s:%d, want dynamic endpoint 127.0.0.1:%d", cfg.Gateway.APIBind, cfg.Gateway.APIPort, apiPort)
	}
	if got := os.Getenv(secretEnv); got != secret {
		t.Fatalf("resolved daemon secret = %q, want dotenv value", got)
	}
}

func TestDaemonReadinessRequirementsExpectCanonicalV8Telemetry(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.OTel.Enabled = false

	requirements := daemonReadinessRequirementsFromConfig(cfg, time.Time{})
	if !requirements.telemetryEnabled {
		t.Fatal("schema-v8 observability runtime was treated as disabled telemetry")
	}
}

func TestRotationRequiredConnectorNamesUsesEnabledConfiguredRoster(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {},
		"claudecode": {},
	}
	if got := strings.Join(rotationRequiredConnectorNames(cfg), ","); got != "claudecode,codex" {
		t.Fatalf("rotation required connectors = %q, want claudecode,codex", got)
	}

	disabled := false
	cfg.Guardrail.Connectors["claudecode"] = config.PerConnectorGuardrailConfig{Enabled: &disabled}
	if got := strings.Join(rotationRequiredConnectorNames(cfg), ","); got != "codex" {
		t.Fatalf("rotation required connectors with Claude disabled = %q, want codex", got)
	}

	cfg.Guardrail.Enabled = false
	if got := rotationRequiredConnectorNames(cfg); len(got) != 0 {
		t.Fatalf("disabled guardrail rotation required connectors = %v, want none", got)
	}
}

func TestGatewaySnapshotReadyRotationRequiresEveryConfiguredConnector(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Connectors = []gateway.ConnectorHealth{{Name: "codex", State: gateway.StateRunning}}

	ready, err := gatewaySnapshotReady(snap, daemonReadinessRequirements{
		guardrailEnabled:   true,
		requiredConnectors: []string{"claudecode", "codex"},
	})
	if err == nil || !strings.Contains(err.Error(), "claudecode") {
		t.Fatalf("gatewaySnapshotReady() error = %v, want missing Claude convergence failure", err)
	}
	if ready {
		t.Fatal("gatewaySnapshotReady() ready = true with only one of two required connectors")
	}

	ready, err = gatewaySnapshotReady(snap, daemonReadinessRequirements{guardrailEnabled: true})
	if err != nil || !ready {
		t.Fatalf("ordinary readiness changed by rotation-only roster gate: ready=%v error=%v", ready, err)
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationUsesScopedCredentials(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	tokens := map[connector.OTLPPathTokenScope]string{
		connector.OTLPScopeCodex:     strings.Repeat("c", 64),
		connector.OTLPScopeClaude:    strings.Repeat("d", 64),
		connector.OTLPScopeGeminiCLI: strings.Repeat("e", 64),
	}
	loadRotationOTLPPathToken = func(_ string, scope connector.OTLPPathTokenScope) (string, error) {
		return tokens[scope], nil
	}

	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("probe method = %s, want GET", r.Method)
		}
		source := r.Header.Get("X-DefenseClaw-Source")
		switch {
		case r.URL.Path == "/v1/logs" && (source == "codex" || source == "claudecode"):
			scope, _ := connector.OTLPPathTokenScopeForConnector(source)
			if got, want := r.Header.Get("Authorization"), "Bearer "+tokens[scope]; got != want {
				t.Errorf("%s authorization did not use its scoped credential", source)
			}
			seen[source]++
		case r.URL.Path == "/otlp/geminicli/"+tokens[connector.OTLPScopeGeminiCLI]+"/v1/logs":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("geminicli path-token probe sent an Authorization header")
			}
			seen["geminicli"]++
		default:
			t.Errorf("unexpected convergence probe path %q source %q", r.URL.Path, source)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	err := verifyRotationConnectorOTLPAuthentication(
		srv.Client(), srv.URL+"/status", "D:\\fixture-data", []string{"claudecode", "codex", "geminicli"},
	)
	if err != nil {
		t.Fatalf("verifyRotationConnectorOTLPAuthentication() error = %v", err)
	}
	for _, name := range []string{"claudecode", "codex", "geminicli"} {
		if seen[name] != 1 {
			t.Fatalf("%s auth probes = %d, want 1", name, seen[name])
		}
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationFailsClosedWithoutLeakingCredential(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	credential := strings.Repeat("f", 64)
	loadRotationOTLPPathToken = func(_ string, _ connector.OTLPPathTokenScope) (string, error) {
		return credential, nil
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := verifyRotationConnectorOTLPAuthentication(
		srv.Client(), srv.URL+"/status", "D:\\fixture-data", []string{"claudecode"},
	)
	if err == nil || !strings.Contains(err.Error(), "claudecode") {
		t.Fatalf("authentication error = %v, want connector-scoped failure", err)
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatal("authentication error leaked the connector-scoped credential")
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationRefusesNonLoopbackEndpoint(t *testing.T) {
	err := verifyRotationConnectorOTLPAuthentication(
		&http.Client{}, "http://collector.example.test/status", "D:\\fixture-data", []string{"claudecode"},
	)
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("non-loopback authentication probe error = %v, want fail-closed refusal", err)
	}
}

func TestWaitForGatewayReadinessWaitsForDelayedGuardrailRunning(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		state := gateway.StateDisabled
		if probes.Add(1) >= 3 {
			state = gateway.StateRunning
		}
		_ = json.NewEncoder(w).Encode(readinessSnapshot(state, gateway.StateDisabled))
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("waitForGatewayReadiness() error = %v", err)
	}
	if !ready {
		t.Fatal("waitForGatewayReadiness() ready = false, want true")
	}
	if snap.Guardrail.State != gateway.StateRunning {
		t.Fatalf("guardrail state = %q, want %q", snap.Guardrail.State, gateway.StateRunning)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("health probes = %d, want 3", got)
	}
}

func TestWaitForGatewayReadinessFailsWhenSlowLiveProcessMissesDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		50*time.Millisecond,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "remained STARTING") {
		t.Fatalf("waitForGatewayReadiness() error = %v, want readiness timeout", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
	if snap.Guardrail.State != gateway.StateDisabled {
		t.Fatalf("guardrail state = %q, want %q", snap.Guardrail.State, gateway.StateDisabled)
	}
}

type fakeReadinessProcess struct {
	running    bool
	pid        int
	stopCalls  int
	stopErr    error
	stoppedPID int
}

type fakeStrongReadinessProcess struct {
	*fakeReadinessProcess
	identityOK bool
}

func (p *fakeStrongReadinessProcess) HasManagedProcessIdentity(int) bool {
	return p.identityOK
}

func (p *fakeReadinessProcess) IsRunning() (bool, int) {
	return p.running, p.pid
}

func (p *fakeReadinessProcess) Stop(time.Duration) error {
	p.stopCalls++
	return p.stopErr
}

func (p *fakeReadinessProcess) StopStarted(pid int, _ time.Duration) error {
	p.stopCalls++
	p.stoppedPID = pid
	return p.stopErr
}

func TestWaitForStartedDaemonStopsSlowLiveProcessAfterDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer srv.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		25*time.Millisecond,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
	)
	if err == nil || !strings.Contains(err.Error(), "remained STARTING") || ready {
		t.Fatalf("waitForStartedDaemon() ready = %v, error = %v, want timeout", ready, err)
	}
	if process.stopCalls != 1 {
		t.Fatalf("scoped stop calls = %d, want 1", process.stopCalls)
	}
	if process.stoppedPID != 42 {
		t.Fatalf("StopStarted() PID = %d, want only launched PID 42", process.stoppedPID)
	}
}

func TestWaitForStartedDaemonStopsProcessOnFatalReadinessError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateError, LastError: "bind failed"},
		})
	}))
	defer srv.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
	)
	if err == nil || !strings.Contains(err.Error(), "bind failed") || ready {
		t.Fatalf("waitForStartedDaemon() ready = %v, error = %v, want fatal bind error", ready, err)
	}
	if process.stopCalls != 1 {
		t.Fatalf("scoped stop calls = %d, want 1 for a fatal readiness error", process.stopCalls)
	}
	if process.stoppedPID != 42 {
		t.Fatalf("StopStarted() PID = %d, want only launched PID 42", process.stoppedPID)
	}
}

func TestWaitForStartedDaemonRejectsReadyProcessWithoutStrongIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateRunning, gateway.StateDisabled))
	}))
	defer srv.Close()

	base := &fakeReadinessProcess{running: true, pid: 42}
	process := &fakeStrongReadinessProcess{fakeReadinessProcess: base}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
	)
	if err == nil || !strings.Contains(err.Error(), "process start identity") || ready {
		t.Fatalf("waitForStartedDaemon() ready = %v, error = %v, want strong identity failure", ready, err)
	}
	if base.stopCalls != 1 || base.stoppedPID != 42 {
		t.Fatalf("scoped cleanup = (%d calls, PID %d), want (1, 42)", base.stopCalls, base.stoppedPID)
	}
}

func TestWaitForStartedDaemonRotationRejectsPartialConnectorRosterAndStopsB(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Connectors = []gateway.ConnectorHealth{{Name: "codex", State: gateway.StateRunning}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	base := &fakeReadinessProcess{running: true, pid: 42}
	process := &fakeStrongReadinessProcess{fakeReadinessProcess: base, identityOK: true}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{
			guardrailEnabled:   true,
			requiredConnectors: []string{"claudecode", "codex"},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "claudecode") || ready {
		t.Fatalf("partial rotation readiness = %v, error = %v, want Claude convergence failure", ready, err)
	}
	if base.stopCalls != 1 || base.stoppedPID != 42 {
		t.Fatalf("B cleanup = (%d calls, PID %d), want (1, 42)", base.stopCalls, base.stoppedPID)
	}
}

func TestWaitForStartedDaemonRotationStopsBWhenScopedAuthIsRejected(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	loadRotationOTLPPathToken = func(_ string, _ connector.OTLPPathTokenScope) (string, error) {
		return strings.Repeat("a", 64), nil
	}
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Connectors = []gateway.ConnectorHealth{{Name: "claudecode", State: gateway.StateRunning}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/logs" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	base := &fakeReadinessProcess{running: true, pid: 42}
	process := &fakeStrongReadinessProcess{fakeReadinessProcess: base, identityOK: true}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL+"/status",
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{
			guardrailEnabled:    true,
			requiredConnectors:  []string{"claudecode"},
			verifyConnectorOTLP: true,
			expectedDataDir:     "D:\\fixture-data",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "scoped OTLP authentication") || ready {
		t.Fatalf("rejected scoped auth readiness = %v, error = %v, want convergence failure", ready, err)
	}
	if base.stopCalls != 1 || base.stoppedPID != 42 {
		t.Fatalf("B cleanup = (%d calls, PID %d), want (1, 42)", base.stopCalls, base.stoppedPID)
	}
}

func TestPrintDaemonStartResultOnlyRendersReadySuccess(t *testing.T) {
	out := captureStdout(t, func() {
		printDaemonStartResult(42, readinessSnapshot(gateway.StateRunning, gateway.StateDisabled))
	})
	if !strings.Contains(out, "OK (PID 42)") || strings.Contains(out, "STARTING") {
		t.Fatalf("output = %q, want READY-only success rendering", out)
	}
}

func TestWaitForGatewayReadinessFailsFastWhenProcessExits(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
		func() bool { return false },
	)
	if err == nil || !strings.Contains(err.Error(), "exited before readiness") {
		t.Fatalf("error = %v, want process-exit diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("health probes = %d, want 0 after confirmed process exit", got)
	}
}

func TestWaitForGatewayReadinessFailsFastOnAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{
				State:     gateway.StateError,
				LastError: "bind failed",
			},
		})
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("error = %v, want API startup diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
}

func TestWaitForGatewayReadinessFailsFastOnGuardrailError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateError, gateway.StateDisabled)
		snap.Guardrail.LastError = "connector setup failed"
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "connector setup failed") {
		t.Fatalf("error = %v, want guardrail failure diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
}

func TestWaitForGatewayReadinessAcceptsConfiguredDisabledGuardrail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateRunning))
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: false},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("disabled guardrail readiness = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessAcceptsRunningHooksWithProxyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateRunning, gateway.StateDisabled))
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: false},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("connector-native hook readiness = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessWaitsForDisabledGuardrailFinalization(t *testing.T) {
	startedAt := time.Now()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)
		snap.StartedAt = startedAt
		snap.Guardrail.Since = startedAt
		if probes.Add(1) >= 2 {
			snap.Guardrail.Since = startedAt.Add(time.Millisecond)
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: false},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("disabled guardrail finalization readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestWaitForGatewayReadinessAcceptsHookOnlyGatewayDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateRunning, gateway.StateDisabled))
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("hook-only gateway disabled readiness = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessRejectsPreviousProcessGeneration(t *testing.T) {
	startAttemptedAt := time.Now()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
		if probes.Add(1) < 3 {
			snap.StartedAt = startAttemptedAt.Add(-time.Minute)
		} else {
			snap.StartedAt = startAttemptedAt.Add(time.Millisecond)
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{
			guardrailEnabled: true,
			startedNotBefore: startAttemptedAt,
		},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("new process generation readiness = %v, error = %v", ready, err)
	}
	if snap.StartedAt.Before(startAttemptedAt) {
		t.Fatalf("accepted stale started_at %s before %s", snap.StartedAt, startAttemptedAt)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("health probes = %d, want 3", got)
	}
}

func TestWaitForGatewayReadinessWaitsForConfiguredWatcher(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
		snap.Watcher.State = gateway.StateStarting
		if probes.Add(1) >= 2 {
			snap.Watcher.State = gateway.StateRunning
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, watcherEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("configured watcher readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestWaitForGatewayReadinessAllowsRecoveringGatewayError(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateError)
		snap.Gateway.LastError = "upstream unavailable"
		if probes.Add(1) >= 2 {
			snap.Gateway = gateway.SubsystemHealth{State: gateway.StateRunning}
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("recovering gateway readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestFetchSidecarHealthParsesLargeMultiConnectorDocument(t *testing.T) {
	want := gateway.HealthSnapshot{
		Gateway: gateway.SubsystemHealth{
			State: gateway.StateRunning,
			Details: map[string]interface{}{
				"inventory": strings.Repeat("x", 2200),
			},
		},
		API: gateway.SubsystemHealth{State: gateway.StateRunning},
		Connectors: []gateway.ConnectorHealth{
			{Name: "codex", State: gateway.StateRunning},
			{Name: "claudecode", State: gateway.StateRunning},
		},
	}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 2000 {
		t.Fatalf("fixture length = %d, want > 2000", len(payload))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	got, err := fetchSidecarHealth(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchSidecarHealth() error = %v", err)
	}
	if got.API.State != gateway.StateRunning {
		t.Fatalf("API state = %q, want %q", got.API.State, gateway.StateRunning)
	}
	if len(got.Connectors) != 2 {
		t.Fatalf("connectors = %d, want 2", len(got.Connectors))
	}
}

func TestFetchSidecarHealthRejectsOversizedDocument(t *testing.T) {
	payload := []byte(`{"padding":"` + strings.Repeat("x", gatewayHealthDocumentMaxBytes) + `"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	_, err := fetchSidecarHealth(srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want bounded-document diagnostic", err)
	}
}
