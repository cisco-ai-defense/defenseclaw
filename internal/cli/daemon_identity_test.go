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

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

type fakeDaemonState struct {
	running bool
	pid     int
}

func (f fakeDaemonState) IsRunning() (bool, int) { return f.running, f.pid }

type fakeStrongDaemonState struct {
	fakeDaemonState
	identityOK bool
}

func (f fakeStrongDaemonState) HasManagedProcessIdentity(int) bool { return f.identityOK }

type fakeUpgradeDaemonState struct {
	fakeStrongDaemonState
	startedAt    time.Time
	generationOK bool
}

func (f fakeUpgradeDaemonState) ManagedProcessStartedAt(int) (time.Time, bool) {
	return f.startedAt, f.generationOK
}

func startupTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Gateway.APIBind = "127.0.0.1"
	cfg.Gateway.APIPort = 18970
	cfg.Gateway.Token = "unit-test-token"
	return cfg
}

func withStartupListenerInspector(t *testing.T, fn func(string, int) (int, error)) {
	t.Helper()
	oldRequired := requireStartupListenerOwnership
	oldInspector := startupListenerOwner
	requireStartupListenerOwnership = true
	startupListenerOwner = fn
	t.Cleanup(func() {
		requireStartupListenerOwnership = oldRequired
		startupListenerOwner = oldInspector
	})
}

func authenticatedStatusServer(t *testing.T, token string, status gatewayStatusEnvelope) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-DefenseClaw-Token") != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(status)
	}))
}

func TestUpgradeReadinessBindsStrictStateGenerationAndCandidateVersion(t *testing.T) {
	token := strings.Repeat("u", 32)
	cfg := startupTestConfig(t)
	t.Setenv("DEFENSECLAW_HOME", cfg.DataDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", token)
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Enabled = true
	cfg.Gateway.Watcher.Enabled = false

	generation := time.Now().Add(-time.Second)
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.StartedAt = generation.Add(100 * time.Millisecond)
	if cfg.ConfigVersion == config.ObservabilityV8ConfigVersion {
		snap.Telemetry.State = gateway.StateRunning
	}
	status := gatewayStatusEnvelope{Health: snap}
	status.Provenance.BinaryVersion = "0.9.0"
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	server := authenticatedStatusServer(t, token, status)
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })

	state := fakeUpgradeDaemonState{
		fakeStrongDaemonState: fakeStrongDaemonState{
			fakeDaemonState: fakeDaemonState{running: true, pid: 42},
			identityOK:      true,
		},
		startedAt:    generation,
		generationOK: true,
	}
	if err := waitForUpgradeGatewayReadiness(
		state,
		cfg,
		server.Client(),
		"0.9.0",
		time.Second,
		5*time.Millisecond,
	); err != nil {
		t.Fatalf("strict upgrade readiness: %v", err)
	}
}

func TestUpgradeReadinessRejectsVersionAndGenerationDrift(t *testing.T) {
	token := strings.Repeat("u", 32)
	cfg := startupTestConfig(t)
	t.Setenv("DEFENSECLAW_HOME", cfg.DataDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", token)
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Enabled = true

	generation := time.Now()
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.StartedAt = generation.Add(-10 * time.Second)
	if cfg.ConfigVersion == config.ObservabilityV8ConfigVersion {
		snap.Telemetry.State = gateway.StateRunning
	}
	status := gatewayStatusEnvelope{Health: snap}
	status.Provenance.BinaryVersion = "0.8.5"
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	server := authenticatedStatusServer(t, token, status)
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })

	state := fakeUpgradeDaemonState{
		fakeStrongDaemonState: fakeStrongDaemonState{
			fakeDaemonState: fakeDaemonState{running: true, pid: 42},
			identityOK:      true,
		},
		startedAt:    generation,
		generationOK: true,
	}
	err := waitForUpgradeGatewayReadiness(state, cfg, server.Client(), "0.9.0", time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "authenticated gateway version") {
		t.Fatalf("version drift error = %v, want authenticated version mismatch", err)
	}

	status.Provenance.BinaryVersion = "0.9.0"
	generationServer := authenticatedStatusServer(t, token, status)
	defer generationServer.Close()
	host, port = splitHostPortForTest(t, strings.TrimPrefix(generationServer.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	err = waitForUpgradeGatewayReadiness(
		state,
		cfg,
		generationServer.Client(),
		"0.9.0",
		25*time.Millisecond,
		5*time.Millisecond,
	)
	if err == nil || !strings.Contains(err.Error(), "STARTING") {
		t.Fatalf("generation drift error = %v, want readiness timeout", err)
	}

	for _, subsystem := range []string{"guardrail", "telemetry"} {
		t.Run(subsystem+" still starting", func(t *testing.T) {
			subsystemStatus := status
			subsystemStatus.Health.StartedAt = generation.Add(time.Millisecond)
			switch subsystem {
			case "guardrail":
				subsystemStatus.Health.Guardrail.State = gateway.StateStarting
			case "telemetry":
				subsystemStatus.Health.Telemetry.State = gateway.StateStarting
			}
			subsystemServer := authenticatedStatusServer(t, token, subsystemStatus)
			defer subsystemServer.Close()
			host, port := splitHostPortForTest(t, strings.TrimPrefix(subsystemServer.URL, "http://"))
			cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
			err := waitForUpgradeGatewayReadiness(
				state,
				cfg,
				subsystemServer.Client(),
				"0.9.0",
				25*time.Millisecond,
				5*time.Millisecond,
			)
			if err == nil || !strings.Contains(err.Error(), "STARTING") {
				t.Fatalf("subsystem readiness error = %v, want strict subsystem timeout", err)
			}
		})
	}

	state.generationOK = false
	err = waitForUpgradeGatewayReadiness(state, cfg, http.DefaultClient, "0.9.0", time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "launch generation") {
		t.Fatalf("missing generation error = %v, want fail-closed generation check", err)
	}
}

func TestRotationStopReadinessAuthenticatesPIDDataDirAndListener(t *testing.T) {
	token := strings.Repeat("r", 32)
	cfg := startupTestConfig(t)
	t.Setenv("DEFENSECLAW_HOME", cfg.DataDir)
	t.Setenv("DEFENSECLAW_DATA_DIR", cfg.DataDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", token)
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Enabled = true
	cfg.Gateway.Watcher.Enabled = false

	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	if cfg.ConfigVersion == config.ObservabilityV8ConfigVersion {
		snap.Telemetry.State = gateway.StateRunning
	}
	status := gatewayStatusEnvelope{Health: snap}
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	server := authenticatedStatusServer(t, token, status)
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })

	state := fakeStrongDaemonState{
		fakeDaemonState: fakeDaemonState{running: true, pid: 42},
		identityOK:      true,
	}
	if err := waitForRunningDaemonReadiness(
		state,
		42,
		server.Client(),
		cfg,
		time.Second,
		5*time.Millisecond,
	); err != nil {
		t.Fatalf("rotation stop readiness: %v", err)
	}
}

func TestRotationStopReadinessTimeoutLeavesOldDaemonRunning(t *testing.T) {
	token := strings.Repeat("r", 32)
	cfg := startupTestConfig(t)
	t.Setenv("DEFENSECLAW_HOME", cfg.DataDir)
	t.Setenv("DEFENSECLAW_DATA_DIR", cfg.DataDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", token)
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Enabled = true
	cfg.Gateway.Watcher.Enabled = false

	snap := readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)
	status := gatewayStatusEnvelope{Health: snap}
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	server := authenticatedStatusServer(t, token, status)
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })

	state := fakeStrongDaemonState{
		fakeDaemonState: fakeDaemonState{running: true, pid: 42},
		identityOK:      true,
	}
	err := waitForRunningDaemonReadiness(
		state,
		42,
		server.Client(),
		cfg,
		25*time.Millisecond,
		5*time.Millisecond,
	)
	if err == nil || !strings.Contains(err.Error(), "STARTING") {
		t.Fatalf("rotation stop timeout error = %v, want readiness timeout", err)
	}
	if running, pid := state.IsRunning(); !running || pid != 42 {
		t.Fatalf("old daemon state changed after readiness timeout: running=%v pid=%d", running, pid)
	}
}

func TestRotationCleanupAuthenticatesStartingPIDDataDirAndListener(t *testing.T) {
	token := strings.Repeat("r", 32)
	cfg := startupTestConfig(t)
	t.Setenv("DEFENSECLAW_HOME", cfg.DataDir)
	t.Setenv("DEFENSECLAW_DATA_DIR", cfg.DataDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", token)
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN="+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Guardrail.Enabled = true
	cfg.Gateway.Watcher.Enabled = false

	snap := readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)
	status := gatewayStatusEnvelope{Health: snap}
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	server := authenticatedStatusServer(t, token, status)
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })

	state := fakeStrongDaemonState{
		fakeDaemonState: fakeDaemonState{running: true, pid: 42},
		identityOK:      true,
	}
	running, pid, err := inspectRotationStopTarget(
		state,
		cfg,
		server.Client(),
		true,
		25*time.Millisecond,
		5*time.Millisecond,
	)
	if err != nil || !running || pid != 42 {
		t.Fatalf("rotation cleanup target: running=%v pid=%d error=%v", running, pid, err)
	}
}

func TestInspectConfiguredListenerRejectsForeignCollisionAndStalePID(t *testing.T) {
	cfg := startupTestConfig(t)
	withStartupListenerInspector(t, func(string, int) (int, error) { return 9001, nil })
	for _, state := range []fakeDaemonState{{running: false}, {running: true, pid: 42}} {
		_, _, err := inspectConfiguredListener(state, cfg, http.DefaultClient)
		if err == nil || !strings.Contains(err.Error(), "foreign process PID 9001") {
			t.Fatalf("state %#v: error = %v, want foreign collision", state, err)
		}
	}
}

func TestInspectConfiguredListenerAcceptsAuthenticatedExpectedInstance(t *testing.T) {
	cfg := startupTestConfig(t)
	status := gatewayStatusEnvelope{}
	status.Runtime.PID = 42
	status.Runtime.DataDir = cfg.DataDir
	srv := authenticatedStatusServer(t, cfg.Gateway.Token, status)
	defer srv.Close()
	// Point the status URL at the disposable authenticated server.
	cfg.Gateway.APIBind = strings.TrimPrefix(srv.URL, "http://")
	host, port := splitHostPortForTest(t, cfg.Gateway.APIBind)
	cfg.Gateway.APIBind = host
	cfg.Gateway.APIPort = port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })
	running, pid, err := inspectConfiguredListener(fakeDaemonState{running: true, pid: 42}, cfg, srv.Client())
	if err != nil || !running || pid != 42 {
		t.Fatalf("inspect = (%v, %d, %v), want authenticated PID 42", running, pid, err)
	}
}

func TestInspectConfiguredListenerRejectsAuthMismatch(t *testing.T) {
	cfg := startupTestConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(srv.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })
	_, _, err := inspectConfiguredListener(fakeDaemonState{running: true, pid: 42}, cfg, srv.Client())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error = %v, want authentication failure", err)
	}
}

func TestInspectConfiguredListenerRejectsLegacyOrReusedPIDIdentity(t *testing.T) {
	cfg := startupTestConfig(t)
	withStartupListenerInspector(t, func(string, int) (int, error) { return 42, nil })
	state := fakeStrongDaemonState{fakeDaemonState: fakeDaemonState{running: true, pid: 42}}
	_, _, err := inspectConfiguredListener(state, cfg, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "process start identity") {
		t.Fatalf("error = %v, want strong process-identity failure", err)
	}
}

func TestInspectConfiguredListenerFailsClosedOnAccessDenied(t *testing.T) {
	cfg := startupTestConfig(t)
	withStartupListenerInspector(t, func(string, int) (int, error) {
		return 0, errors.New("listener ownership access denied")
	})
	_, _, err := inspectConfiguredListener(fakeDaemonState{}, cfg, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("error = %v, want access-denied failure", err)
	}
}

func TestInspectConfiguredListenerRejectsManagedPIDWithoutListener(t *testing.T) {
	cfg := startupTestConfig(t)
	withStartupListenerInspector(t, func(string, int) (int, error) { return 0, daemon.ErrNoListener })
	_, _, err := inspectConfiguredListener(fakeDaemonState{running: true, pid: 42}, cfg, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "no listener") {
		t.Fatalf("error = %v, want managed-PID-without-listener failure", err)
	}
}

func TestWaitForConfiguredPortFreeRetriesRestartRelease(t *testing.T) {
	cfg := startupTestConfig(t)
	var probes atomic.Int32
	withStartupListenerInspector(t, func(string, int) (int, error) {
		if probes.Add(1) < 3 {
			return 42, nil
		}
		return 0, daemon.ErrNoListener
	})
	if err := waitForConfiguredPortFree(cfg, 42, time.Second, time.Millisecond); err != nil {
		t.Fatalf("waitForConfiguredPortFree: %v", err)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("listener probes = %d, want 3", got)
	}
}

func TestWaitForConfiguredPortFreeKeepsForeignCollisionTerminal(t *testing.T) {
	cfg := startupTestConfig(t)
	var probes atomic.Int32
	withStartupListenerInspector(t, func(string, int) (int, error) {
		probes.Add(1)
		return 99, nil
	})
	err := waitForConfiguredPortFree(cfg, 42, time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "occupied by PID 99") {
		t.Fatalf("error = %v, want occupied-port failure", err)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("foreign-listener probes = %d, want immediate failure after 1", got)
	}
}

func TestVerifyGatewayRuntimeIdentityRejectsConfigHomeMismatch(t *testing.T) {
	status := gatewayStatusEnvelope{}
	status.Runtime.PID = 42
	status.Runtime.DataDir = t.TempDir()
	err := verifyGatewayRuntimeIdentity(status, 42, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("error = %v, want configuration-home mismatch", err)
	}
}

func TestWaitForGatewayReadinessRequiresAuthRuntimeAndListenerIdentity(t *testing.T) {
	dataDir := t.TempDir()
	started := time.Now().Add(time.Millisecond)
	status := gatewayStatusEnvelope{Health: readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)}
	status.Health.StartedAt = started
	status.Runtime.PID = 77
	status.Runtime.DataDir = dataDir
	srv := authenticatedStatusServer(t, "secret", status)
	defer srv.Close()
	requirements := daemonReadinessRequirements{
		guardrailEnabled: true,
		startedNotBefore: started.Add(-time.Millisecond),
		expectedPID:      77,
		expectedDataDir:  dataDir,
		token:            func() string { return "secret" },
		listenerHost:     "127.0.0.1",
		listenerPort:     18970,
		listenerOwner:    func(string, int) (int, error) { return 77, nil },
		requireOwnership: true,
	}
	_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, time.Second, time.Millisecond, requirements, func() bool { return true })
	if err != nil || !ready {
		t.Fatalf("ready = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessIdentityProvenButStartingAtDeadlineFails(t *testing.T) {
	dataDir := t.TempDir()
	status := gatewayStatusEnvelope{Health: readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)}
	status.Runtime.PID = 77
	status.Runtime.DataDir = dataDir
	srv := authenticatedStatusServer(t, "secret", status)
	defer srv.Close()
	requirements := daemonReadinessRequirements{
		guardrailEnabled: true,
		expectedPID:      77,
		expectedDataDir:  dataDir,
		token:            func() string { return "secret" },
		listenerHost:     "127.0.0.1",
		listenerPort:     18970,
		listenerOwner:    func(string, int) (int, error) { return 77, nil },
		requireOwnership: true,
	}
	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		25*time.Millisecond,
		5*time.Millisecond,
		requirements,
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "remained STARTING") || ready {
		t.Fatalf("ready = %v, error = %v, want terminal timeout after identity proof", ready, err)
	}
}

func TestWaitForGatewayReadinessRejectsPIDReuseAndForeignListener(t *testing.T) {
	for _, tc := range []struct {
		name        string
		runtimePID  int
		listenerPID int
	}{
		{name: "authenticated PID mismatch", runtimePID: 78, listenerPID: 77},
		{name: "listener PID mismatch", runtimePID: 77, listenerPID: 78},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			status := gatewayStatusEnvelope{Health: readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)}
			status.Runtime.PID = tc.runtimePID
			status.Runtime.DataDir = dataDir
			srv := authenticatedStatusServer(t, "secret", status)
			defer srv.Close()
			req := daemonReadinessRequirements{
				guardrailEnabled: true, expectedPID: 77, expectedDataDir: dataDir,
				token: func() string { return "secret" }, listenerOwner: func(string, int) (int, error) { return tc.listenerPID, nil }, requireOwnership: true,
			}
			_, _, err := waitForGatewayReadiness(srv.Client(), srv.URL, time.Second, time.Millisecond, req, func() bool { return true })
			if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
				t.Fatalf("error = %v, want identity mismatch", err)
			}
		})
	}
}

func TestWaitForGatewayReadinessRetriesMissingListenerAndDetectsChildExitAfterBind(t *testing.T) {
	dataDir := t.TempDir()
	status := gatewayStatusEnvelope{Health: readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)}
	status.Runtime.PID, status.Runtime.DataDir = 77, dataDir
	srv := authenticatedStatusServer(t, "secret", status)
	defer srv.Close()
	var listenerProbes atomic.Int32
	var processProbes atomic.Int32
	req := daemonReadinessRequirements{
		guardrailEnabled: true, expectedPID: 77, expectedDataDir: dataDir,
		token: func() string { return "secret" }, requireOwnership: true,
		listenerOwner: func(string, int) (int, error) {
			if listenerProbes.Add(1) == 1 {
				return 0, daemon.ErrNoListener
			}
			return 77, nil
		},
	}
	_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, time.Second, time.Millisecond, req, func() bool {
		return processProbes.Add(1) < 3
	})
	if err == nil || ready || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("ready = %v, error = %v, want child-exit failure", ready, err)
	}
}

func TestSidecarURLsNormalizeWildcardAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		bind, health, status string
	}{
		{"0.0.0.0", "http://127.0.0.1:18970/health", "http://127.0.0.1:18970/status"},
		{"::", "http://[::1]:18970/health", "http://[::1]:18970/status"},
		{"::0", "http://[::1]:18970/health", "http://[::1]:18970/status"},
		{"0:0:0:0:0:0:0:0", "http://[::1]:18970/health", "http://[::1]:18970/status"},
		{"::1", "http://[::1]:18970/health", "http://[::1]:18970/status"},
	} {
		cfg := config.DefaultConfig()
		cfg.Gateway.APIBind = tc.bind
		if got := sidecarHealthURL(cfg); got != tc.health {
			t.Errorf("bind %q health = %q, want %q", tc.bind, got, tc.health)
		}
		if got := sidecarStatusURL(cfg); got != tc.status {
			t.Errorf("bind %q status = %q, want %q", tc.bind, got, tc.status)
		}
	}
}

func TestDaemonGatewayTokenReadsDisposableHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=disposable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Gateway.Token = ""
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	if got := daemonGatewayToken(cfg); got != "disposable" {
		t.Fatalf("token = %q, want disposable home token", got)
	}
}

func TestDaemonGatewayTokenMatchesChildDotenvPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=installed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "stale-parent")
	cfg := config.DefaultConfig()
	cfg.Gateway.Token = "stale-inline"

	if got := daemonGatewayToken(cfg); got != "installed" {
		t.Fatalf("token = %q, want child dotenv token", got)
	}
}

func TestDaemonGatewayTokenPreservesCustomEnvironmentPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=installed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTOM_GATEWAY_TOKEN", "managed-override")
	cfg := config.DefaultConfig()
	cfg.Gateway.TokenEnv = "CUSTOM_GATEWAY_TOKEN"
	cfg.Gateway.Token = "stale-inline"

	if got := daemonGatewayToken(cfg); got != "managed-override" {
		t.Fatalf("token = %q, want custom environment token", got)
	}
}

func TestDaemonGatewayTokenMatchesWindowsCaseInsensitiveChildPrecedence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows environment names are case-insensitive")
	}
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("defenseclaw_gateway_token=installed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DeFeNsEcLaW_GaTeWaY_ToKeN", "stale-parent")
	cfg := config.DefaultConfig()
	cfg.Gateway.TokenEnv = "dEfEnSeClAw_GaTeWaY_tOkEn"
	cfg.Gateway.Token = "stale-inline"

	if got := daemonGatewayToken(cfg); got != "installed" {
		t.Fatalf("token = %q, want mixed-case child dotenv token", got)
	}
}

func splitHostPortForTest(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, ok := strings.Cut(address, ":")
	if !ok {
		t.Fatalf("address %q has no port", address)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return host, port
}
