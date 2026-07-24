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

func TestUpgradeControllerReadinessDelegationIsExactAndNeverWeakensRotation(t *testing.T) {
	for _, tc := range []struct {
		name                string
		value               string
		rotationTransaction bool
		want                bool
	}{
		{name: "ordinary direct start"},
		{name: "false-like value", value: "0"},
		{name: "word-like value", value: "true"},
		{name: "fresh upgrade controller", value: "1", want: true},
		{name: "rotation remains synchronous", value: "1", rotationTransaction: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(upgradeFreshProcessEnv, tc.value)
			if got := upgradeControllerOwnsGatewayStartReadiness(tc.rotationTransaction); got != tc.want {
				t.Fatalf(
					"upgradeControllerOwnsGatewayStartReadiness(rotation=%v, value=%q) = %v, want %v",
					tc.rotationTransaction,
					tc.value,
					got,
					tc.want,
				)
			}
		})
	}
}

func TestFreshProcessMarkerIsHiddenFromGatewayAndWatchdogChildren(t *testing.T) {
	for _, value := range []string{"1", "unexpected"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(upgradeFreshProcessEnv, value)
			restore, err := isolateUpgradeFreshProcessMarkerFromChildren()
			if err != nil {
				t.Fatalf("isolate marker: %v", err)
			}
			if observed, present := os.LookupEnv(upgradeFreshProcessEnv); present {
				t.Fatalf("gateway/watchdog child environment retained marker %q", observed)
			}
			restore()
			if observed := os.Getenv(upgradeFreshProcessEnv); observed != value {
				t.Fatalf("restored management marker = %q, want %q", observed, value)
			}
		})
	}
}

func TestUpgradeWaitReadyCommandIsHiddenAndFailsClosedBeforeConfigLoading(t *testing.T) {
	if !upgradeWaitReadyCmd.Hidden {
		t.Fatal("upgrade readiness bridge must remain hidden")
	}
	if upgradeWaitReadyCmd.PersistentPreRunE == nil {
		t.Fatal("upgrade readiness bridge would inherit the sidecar root pre-run")
	}
	if err := upgradeWaitReadyCmd.PersistentPreRunE(upgradeWaitReadyCmd, nil); err != nil {
		t.Fatalf("upgrade readiness no-op pre-run: %v", err)
	}

	oldVersion := appVersion
	oldTimeout, _ := upgradeWaitReadyCmd.Flags().GetDuration(upgradeWaitReadyTimeoutFlag)
	oldExpected, _ := upgradeWaitReadyCmd.Flags().GetString(upgradeWaitReadyVersionFlag)
	t.Cleanup(func() {
		appVersion = oldVersion
		_ = upgradeWaitReadyCmd.Flags().Set(upgradeWaitReadyTimeoutFlag, oldTimeout.String())
		_ = upgradeWaitReadyCmd.Flags().Set(upgradeWaitReadyVersionFlag, oldExpected)
	})
	_ = upgradeWaitReadyCmd.Flags().Set(upgradeWaitReadyTimeoutFlag, "60s")
	_ = upgradeWaitReadyCmd.Flags().Set(upgradeWaitReadyVersionFlag, "0.9.0")

	for _, marker := range []string{"", "0"} {
		t.Setenv(upgradeFreshProcessEnv, marker)
		if err := runUpgradeWaitReady(upgradeWaitReadyCmd, nil); err == nil || !strings.Contains(err.Error(), "fresh-process controller marker") {
			t.Fatalf("marker %q error = %v, want exact handoff refusal", marker, err)
		}
	}

	t.Setenv(upgradeFreshProcessEnv, "1")
	appVersion = "0.8.5"
	if err := runUpgradeWaitReady(upgradeWaitReadyCmd, nil); err == nil || !strings.Contains(err.Error(), "control binary version") {
		t.Fatalf("control binary mismatch error = %v, want candidate-version refusal", err)
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

func TestDaemonReadinessRequirementsUseEffectiveGuardrailPosture(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = ""
	cfg.Guardrail.Connectors = nil
	cfg.Claw.Mode = ""

	requirements := daemonReadinessRequirementsFromConfig(cfg, time.Time{})
	if requirements.guardrailEnabled {
		t.Fatal("enabled guardrail without a configured connector was treated as running")
	}

	cfg.Guardrail.Connector = "codex"
	requirements = daemonReadinessRequirementsFromConfig(cfg, time.Time{})
	if !requirements.guardrailEnabled {
		t.Fatal("enabled configured connector was not treated as a running guardrail")
	}

	disabled := false
	cfg.Guardrail.Connector = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Enabled: &disabled},
	}
	requirements = daemonReadinessRequirementsFromConfig(cfg, time.Time{})
	if requirements.guardrailEnabled {
		t.Fatal("individually disabled connector was treated as a running guardrail")
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

func TestRotationConnectorStateRejectsFallbackPolicyDrift(t *testing.T) {
	expected := rotationConnectorState{
		Version: 1,
		Connectors: []rotationConnectorPolicy{
			{Name: "claudecode", Mode: "action", HookFailMode: "closed", Enabled: true},
			{Name: "codex", Mode: "action", HookFailMode: "closed", Enabled: true},
		},
	}
	fallback := config.DefaultConfig()
	fallback.Guardrail.Mode = "observe"
	fallback.Guardrail.HookFailMode = "open"
	fallback.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Mode: "action", HookFailMode: "closed"},
		"codex":      {},
	}
	if err := verifyRotationConfigState(fallback, expected); err == nil || !strings.Contains(err.Error(), "codex mode changed from action to observe") {
		t.Fatalf("fallback config verification error = %v, want exact Codex action -> observe drift", err)
	}

	fallback.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{Mode: "action", HookFailMode: "closed"}
	if err := verifyRotationConfigState(fallback, expected); err != nil {
		t.Fatalf("exact dual action/closed state rejected: %v", err)
	}

	mixed := expected
	mixed.Connectors = append([]rotationConnectorPolicy(nil), expected.Connectors...)
	mixed.Connectors[0].Mode = "observe"
	mixed.Connectors[0].HookFailMode = "open"
	fallback.Guardrail.Connectors["claudecode"] = config.PerConnectorGuardrailConfig{Mode: "observe", HookFailMode: "open"}
	if err := verifyRotationConfigState(fallback, mixed); err != nil {
		t.Fatalf("exact mixed connector state rejected: %v", err)
	}
}

func TestParseRotationConnectorStateIsStrict(t *testing.T) {
	valid := `{"connectors":[{"enabled":true,"hook_fail_mode":"closed","mode":"action","name":"codex"}],"version":1}`
	if _, err := parseRotationConnectorState(valid); err != nil {
		t.Fatalf("valid connector state rejected: %v", err)
	}
	for _, raw := range []string{
		``,
		`{"connectors":null,"version":1}`,
		`{"connectors":[],"version":2}`,
		`{"connectors":[{"enabled":true,"hook_fail_mode":"closed","mode":"action","name":"Codex"}],"version":1}`,
		`{"connectors":[{"enabled":true,"hook_fail_mode":"closed","mode":"action","name":"codex"},{"enabled":true,"hook_fail_mode":"open","mode":"observe","name":"codex"}],"version":1}`,
		`{"connectors":[],"unexpected":true,"version":1}`,
	} {
		if _, err := parseRotationConnectorState(raw); err == nil {
			t.Fatalf("invalid connector state accepted: %q", raw)
		}
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

func TestGatewaySnapshotReadyRotationRejectsUnexpectedConnector(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Connectors = []gateway.ConnectorHealth{
		{Name: "claudecode", State: gateway.StateRunning},
		{Name: "codex", State: gateway.StateRunning},
		{Name: "cursor", State: gateway.StateRunning},
	}
	ready, err := gatewaySnapshotReady(snap, daemonReadinessRequirements{
		guardrailEnabled:            true,
		requiredConnectors:          []string{"claudecode", "codex"},
		requireExactConnectorRoster: true,
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected ready connector: cursor") || ready {
		t.Fatalf("unexpected connector readiness = %v, error = %v", ready, err)
	}
}

func testClaudeRotationProbes(baseURL, credential string) []connector.ClaudeCodeNativeOTLPProbe {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+credential)
	headers.Set("X-DefenseClaw-Client", "claudecode-otel/1.0")
	headers.Set("X-DefenseClaw-Source", "claudecode")
	return []connector.ClaudeCodeNativeOTLPProbe{
		{Signal: connector.NativeOTLPSignalLogs, Endpoint: baseURL + "/v1/logs", Headers: headers.Clone()},
		{Signal: connector.NativeOTLPSignalMetrics, Endpoint: baseURL + "/v1/metrics", Headers: headers.Clone()},
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationUsesScopedCredentials(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	originalClaudeLoader := loadRotationClaudeNativeOTLPProbes
	t.Cleanup(func() { loadRotationClaudeNativeOTLPProbes = originalClaudeLoader })
	tokens := map[connector.OTLPPathTokenScope]string{
		connector.OTLPScopeCodex:     strings.Repeat("c", 64),
		connector.OTLPScopeClaude:    strings.Repeat("d", 64),
		connector.OTLPScopeGeminiCLI: strings.Repeat("e", 64),
	}
	loadRotationOTLPPathToken = func(_ string, scope connector.OTLPPathTokenScope) (string, error) {
		return tokens[scope], nil
	}

	seen := map[string]int{}
	var srv *httptest.Server
	loadRotationClaudeNativeOTLPProbes = func() ([]connector.ClaudeCodeNativeOTLPProbe, error) {
		return testClaudeRotationProbes(srv.URL, tokens[connector.OTLPScopeClaude]), nil
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("probe method = %s, want GET", r.Method)
		}
		source := r.Header.Get("X-DefenseClaw-Source")
		switch {
		case (r.URL.Path == "/v1/logs" || r.URL.Path == "/v1/metrics") && (source == "codex" || source == "claudecode"):
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
	for name, want := range map[string]int{"claudecode": 2, "codex": 1, "geminicli": 1} {
		if seen[name] != want {
			t.Fatalf("%s auth probes = %d, want %d", name, seen[name], want)
		}
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationFailsClosedWithoutLeakingCredential(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	originalClaudeLoader := loadRotationClaudeNativeOTLPProbes
	t.Cleanup(func() { loadRotationClaudeNativeOTLPProbes = originalClaudeLoader })
	credential := strings.Repeat("f", 64)
	loadRotationOTLPPathToken = func(_ string, _ connector.OTLPPathTokenScope) (string, error) {
		return credential, nil
	}
	var srv *httptest.Server
	loadRotationClaudeNativeOTLPProbes = func() ([]connector.ClaudeCodeNativeOTLPProbe, error) {
		return testClaudeRotationProbes(srv.URL, credential), nil
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestVerifyRotationConnectorOTLPAuthenticationUsesPersistedClaudeHeaderLiterally(t *testing.T) {
	originalTokenLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalTokenLoader })
	originalClaudeLoader := loadRotationClaudeNativeOTLPProbes
	t.Cleanup(func() { loadRotationClaudeNativeOTLPProbes = originalClaudeLoader })

	credential := strings.Repeat("a", 64)
	loadRotationOTLPPathToken = func(_ string, _ connector.OTLPPathTokenScope) (string, error) {
		t.Fatal("Claude convergence synthesized a credential from the token file")
		return "", fmt.Errorf("unreachable")
	}
	var receivedAuthorization string
	var srv *httptest.Server
	loadRotationClaudeNativeOTLPProbes = func() ([]connector.ClaudeCodeNativeOTLPProbe, error) {
		probes := testClaudeRotationProbes(srv.URL, credential)
		for index := range probes {
			probes[index].Headers.Set("Authorization", "Bearer%20"+credential)
		}
		return probes, nil
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := verifyRotationConnectorOTLPAuthentication(
		srv.Client(), srv.URL+"/status", "D:\\fixture-data", []string{"claudecode"},
	)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("encoded persisted Claude auth error = %v, want HTTP 401 convergence failure", err)
	}
	if receivedAuthorization != "Bearer%20"+credential {
		t.Fatal("Claude convergence did not send the persisted Authorization value literally")
	}
	if strings.Contains(err.Error(), credential) {
		t.Fatal("Claude convergence error leaked the persisted credential")
	}
}

func TestVerifyRotationConnectorOTLPAuthenticationLoadsExactPersistedClaudeCredentials(t *testing.T) {
	originalSettingsOverride := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = ""
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = originalSettingsOverride })

	logsCredential := strings.Repeat("l", 64)
	metricsCredential := strings.Repeat("m", 64)

	for _, tc := range []struct {
		name           string
		rejectedSignal connector.NativeOTLPSignal
		wantError      bool
	}{
		{name: "both signals accepted"},
		{name: "logs rejected", rejectedSignal: connector.NativeOTLPSignalLogs, wantError: true},
		{name: "metrics rejected", rejectedSignal: connector.NativeOTLPSignalMetrics, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configDir := t.TempDir()
			fallbackHome := t.TempDir()
			t.Setenv("HOME", fallbackHome)
			t.Setenv("USERPROFILE", fallbackHome)
			t.Setenv("CLAUDE_CONFIG_DIR", configDir)

			var logsSeen atomic.Int32
			var metricsSeen atomic.Int32
			var requestMismatch atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var signal connector.NativeOTLPSignal
				var expectedAuthorization string
				var seen *atomic.Int32
				switch r.URL.Path {
				case "/v1/logs":
					signal = connector.NativeOTLPSignalLogs
					expectedAuthorization = "Bearer " + logsCredential
					seen = &logsSeen
				case "/v1/metrics":
					signal = connector.NativeOTLPSignalMetrics
					expectedAuthorization = "Bearer " + metricsCredential
					seen = &metricsSeen
				default:
					requestMismatch.Store(true)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				seen.Add(1)
				if r.Method != http.MethodGet ||
					r.Header.Get("Authorization") != expectedAuthorization ||
					r.Header.Get("X-DefenseClaw-Client") != "claudecode-otel/1.0" ||
					r.Header.Get("X-DefenseClaw-Source") != "claudecode" {
					requestMismatch.Store(true)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if tc.rejectedSignal == signal {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
			}))
			defer server.Close()

			literalHeaders := func(credential string) string {
				return "authorization=Bearer " + credential +
					",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
			}
			settings := map[string]interface{}{
				"env": map[string]interface{}{
					"CLAUDE_CODE_ENABLE_TELEMETRY":        "1",
					"OTEL_LOGS_EXPORTER":                  "otlp",
					"OTEL_METRICS_EXPORTER":               "otlp",
					"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL":    "http/json",
					"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "http/json",
					"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    server.URL + "/v1/logs",
					"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": server.URL + "/v1/metrics",
					"OTEL_EXPORTER_OTLP_LOGS_HEADERS":     literalHeaders(logsCredential),
					"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  literalHeaders(metricsCredential),
				},
			}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatalf("marshal Claude settings fixture: %v", err)
			}
			if err := os.WriteFile(filepath.Join(configDir, "settings.json"), data, 0o600); err != nil {
				t.Fatalf("write Claude settings fixture: %v", err)
			}

			err = verifyRotationConnectorOTLPAuthentication(
				server.Client(), server.URL+"/status", t.TempDir(), []string{"claudecode"},
			)
			if requestMismatch.Load() {
				t.Fatal("Claude convergence probe did not preserve an exact persisted endpoint or header value")
			}
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "claudecode") || !strings.Contains(err.Error(), "401") {
					t.Fatalf("rejected Claude %s probe error = %v, want redacted HTTP 401 failure", tc.rejectedSignal, err)
				}
				for _, credential := range []string{logsCredential, metricsCredential} {
					if strings.Contains(err.Error(), credential) {
						t.Fatalf("rejected Claude %s probe error leaked a persisted credential", tc.rejectedSignal)
					}
				}
				if tc.rejectedSignal == connector.NativeOTLPSignalLogs && logsSeen.Load() != 1 {
					t.Fatal("rejected persisted Claude logs credential was not probed")
				}
				if tc.rejectedSignal == connector.NativeOTLPSignalMetrics && metricsSeen.Load() != 1 {
					t.Fatal("rejected persisted Claude metrics credential was not probed")
				}
				return
			}
			if err != nil {
				t.Fatalf("persisted Claude convergence probes failed: %v", err)
			}
			if logsSeen.Load() != 1 || metricsSeen.Load() != 1 {
				t.Fatalf("persisted Claude probes: logs=%d metrics=%d, want one each", logsSeen.Load(), metricsSeen.Load())
			}
		})
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

func TestVerifyRotationConnectorOTLPAuthenticationRefusesMismatchedClaudeExporterEndpoint(t *testing.T) {
	originalClaudeLoader := loadRotationClaudeNativeOTLPProbes
	t.Cleanup(func() { loadRotationClaudeNativeOTLPProbes = originalClaudeLoader })
	credential := strings.Repeat("a", 64)
	loadRotationClaudeNativeOTLPProbes = func() ([]connector.ClaudeCodeNativeOTLPProbe, error) {
		return testClaudeRotationProbes("http://collector.example.test", credential), nil
	}

	err := verifyRotationConnectorOTLPAuthentication(
		&http.Client{}, "http://127.0.0.1:18970/status", "D:\\fixture-data", []string{"claudecode"},
	)
	if err == nil || !strings.Contains(err.Error(), "does not match the gateway") {
		t.Fatalf("mismatched Claude exporter endpoint error = %v, want fail-closed refusal", err)
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

func TestVerifyDelegatedGatewayStartReturnsBeforeFrozenControllerTimeout(t *testing.T) {
	base := &fakeReadinessProcess{running: true, pid: 42}
	process := &fakeStrongReadinessProcess{fakeReadinessProcess: base, identityOK: true}

	started := time.Now()
	err := verifyDelegatedGatewayStart(process, 42)
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("delegated launch verification took %s, want well below frozen controller's 30s timeout", elapsed)
	}
	if err != nil {
		t.Fatalf("strong live delegated launch rejected: %v", err)
	}
	if base.stopCalls != 0 {
		t.Fatalf("slow-but-live delegated gateway was stopped %d times", base.stopCalls)
	}
}

func TestVerifyDelegatedGatewayStartFailsClosedBeforeReadinessDelegation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		running    bool
		pid        int
		identityOK bool
	}{
		{name: "process exited", pid: 42, identityOK: true},
		{name: "PID changed", running: true, pid: 43, identityOK: true},
		{name: "strong identity missing", running: true, pid: 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &fakeReadinessProcess{running: tc.running, pid: tc.pid}
			process := &fakeStrongReadinessProcess{fakeReadinessProcess: base, identityOK: tc.identityOK}

			err := verifyDelegatedGatewayStart(process, 42)
			if err == nil || !strings.Contains(err.Error(), "process start identity") {
				t.Fatalf("delegated launch error = %v, want strong live identity failure", err)
			}
			if base.stopCalls != 1 || base.stoppedPID != 42 {
				t.Fatalf("scoped cleanup = (%d calls, PID %d), want (1, 42)", base.stopCalls, base.stoppedPID)
			}
		})
	}
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

func TestWaitForStartedDaemonRotationRequiresExactConnectorPosture(t *testing.T) {
	dual := rotationConnectorState{
		Version: 1,
		Connectors: []rotationConnectorPolicy{
			{Name: "claudecode", Mode: "action", HookFailMode: "closed", Enabled: true},
			{Name: "codex", Mode: "action", HookFailMode: "closed", Enabled: true},
		},
	}
	dualModes := []gatewayConnectorModeSnapshot{
		{Connector: "claudecode", GuardrailMode: "action", HookFailMode: "closed", Enabled: true},
		{Connector: "codex", GuardrailMode: "action", HookFailMode: "closed", Enabled: true},
	}
	mixed := dual
	mixed.Connectors = append([]rotationConnectorPolicy(nil), dual.Connectors...)
	mixed.Connectors[0].Mode = "observe"
	mixed.Connectors[0].HookFailMode = "open"
	mixedModes := append([]gatewayConnectorModeSnapshot(nil), dualModes...)
	mixedModes[0].GuardrailMode = "observe"
	mixedModes[0].HookFailMode = "open"

	cases := []struct {
		name     string
		expected rotationConnectorState
		modes    []gatewayConnectorModeSnapshot
		wantErr  string
	}{
		{name: "dual action closed", expected: dual, modes: dualModes},
		{name: "mixed exact", expected: mixed, modes: mixedModes},
		{name: "omission", expected: dual, modes: dualModes[1:], wantErr: "claudecode is missing"},
		{name: "addition", expected: dual, modes: append(append([]gatewayConnectorModeSnapshot(nil), dualModes...), gatewayConnectorModeSnapshot{Connector: "cursor", GuardrailMode: "observe", HookFailMode: "open", Enabled: true}), wantErr: "unexpected connector cursor was added"},
		{name: "mode drift", expected: dual, modes: []gatewayConnectorModeSnapshot{dualModes[0], {Connector: "codex", GuardrailMode: "observe", HookFailMode: "closed", Enabled: true}}, wantErr: "codex mode changed"},
		{name: "fail mode drift", expected: dual, modes: []gatewayConnectorModeSnapshot{dualModes[0], {Connector: "codex", GuardrailMode: "action", HookFailMode: "open", Enabled: true}}, wantErr: "codex hook fail mode changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
			snap.Connectors = []gateway.ConnectorHealth{
				{Name: "claudecode", State: gateway.StateRunning},
				{Name: "codex", State: gateway.StateRunning},
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"health":          snap,
					"connector_modes": tc.modes,
					"runtime": map[string]interface{}{
						"pid":      42,
						"data_dir": dataDir,
					},
				})
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
					guardrailEnabled:            true,
					requiredConnectors:          []string{"claudecode", "codex"},
					expectedConnectorState:      tc.expected,
					verifyConnectorState:        true,
					requireExactConnectorRoster: true,
					expectedPID:                 42,
					expectedDataDir:             dataDir,
					token:                       func() string { return "fixture" },
				},
			)
			if tc.wantErr == "" {
				if err != nil || !ready || base.stopCalls != 0 {
					t.Fatalf("exact posture readiness = %v, error = %v, stop calls = %d", ready, err, base.stopCalls)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || ready {
				t.Fatalf("drift readiness = %v, error = %v, want %q", ready, err, tc.wantErr)
			}
			if base.stopCalls != 1 || base.stoppedPID != 42 {
				t.Fatalf("B cleanup = (%d calls, PID %d), want (1, 42)", base.stopCalls, base.stoppedPID)
			}
		})
	}
}

func TestWaitForStartedDaemonRotationStopsBWhenScopedAuthIsRejected(t *testing.T) {
	originalLoader := loadRotationOTLPPathToken
	t.Cleanup(func() { loadRotationOTLPPathToken = originalLoader })
	originalClaudeLoader := loadRotationClaudeNativeOTLPProbes
	t.Cleanup(func() { loadRotationClaudeNativeOTLPProbes = originalClaudeLoader })
	credential := strings.Repeat("a", 64)
	loadRotationOTLPPathToken = func(_ string, _ connector.OTLPPathTokenScope) (string, error) {
		return credential, nil
	}
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Connectors = []gateway.ConnectorHealth{{Name: "claudecode", State: gateway.StateRunning}}
	var srv *httptest.Server
	loadRotationClaudeNativeOTLPProbes = func() ([]connector.ClaudeCodeNativeOTLPProbe, error) {
		return testClaudeRotationProbes(srv.URL, credential), nil
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if err == nil || !strings.Contains(err.Error(), "native OTLP authentication") || ready {
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
