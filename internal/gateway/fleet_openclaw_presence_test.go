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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// stubOpenClawBinary makes the binary probe answer installed for the test so
// results do not depend on whether this host has an openclaw executable.
// Callers must not run in parallel: the probe is a package variable.
func stubOpenClawBinary(t *testing.T, installed bool) {
	t.Helper()
	previous := openClawBinaryInstalled
	openClawBinaryInstalled = func() bool { return installed }
	t.Cleanup(func() { openClawBinaryInstalled = previous })
}

// withoutOpenClaw points the OpenClaw paths at an empty temp home and stubs
// the binary probe to "not installed".
func withoutOpenClaw(t *testing.T, cfg *config.Config) {
	t.Helper()
	home := t.TempDir()
	cfg.Claw.HomeDir = filepath.Join(home, ".openclaw")
	cfg.Claw.ConfigFile = filepath.Join(home, ".openclaw", "openclaw.json")
	stubOpenClawBinary(t, false)
}

// withConfiguredOpenClaw writes an openclaw.json into a temp OpenClaw home so
// the config reads as an OpenClaw install.
func withConfiguredOpenClaw(t *testing.T, cfg *config.Config) {
	t.Helper()
	withoutOpenClaw(t, cfg)
	if err := os.MkdirAll(cfg.Claw.HomeDir, 0o700); err != nil {
		t.Fatalf("mkdir openclaw home: %v", err)
	}
	if err := os.WriteFile(cfg.Claw.ConfigFile, []byte(`{"gateway":{"mode":"local"}}`), 0o600); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}
}

// clawModeDefaultConfig is what a sandbox-only or hook-only install that never
// picked a connector loads: claw.mode keeps init's openclaw default, no
// guardrail.connector, the loopback default host and fleet_mode "auto".
func clawModeDefaultConfig() *config.Config {
	return &config.Config{
		Claw:    config.ClawConfig{Mode: config.ClawOpenClaw},
		Gateway: config.GatewayConfig{Host: "127.0.0.1", Port: 18789, FleetMode: "auto"},
	}
}

// TestGatewayShouldConnect_OpenClawNotInstalled pins #958: the claw.mode
// default without OpenClaw on the machine no longer dials, while every other
// OpenClaw shape keeps dialing. The watchdog (RequiresFleetGateway) and the
// fleet RPC gate must agree with the dial loop.
func TestGatewayShouldConnect_OpenClawNotInstalled(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(t *testing.T, cfg *config.Config)
		notInstalls bool // openClawImpliedButNotInstalled
		dial        bool // gatewayShouldConnectForConfiguredConnector
	}{
		{"claw_mode_default_auto", func(t *testing.T, cfg *config.Config) {}, true, false},
		{"claw_mode_default_empty_fleet_mode", func(t *testing.T, cfg *config.Config) { cfg.Gateway.FleetMode = "" }, true, false},
		{"claw_mode_default_auto_mixed_case", func(t *testing.T, cfg *config.Config) { cfg.Gateway.FleetMode = " AUTO " }, true, false},
		{"claw_mode_default_empty_host", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "" }, true, false},
		{"claw_mode_default_localhost", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "localhost" }, true, false},
		{"claw_mode_default_ipv6_loopback", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "[::1]" }, true, false},
		// Hook connectors in guardrail.connectors do not name OpenClaw.
		{"connectors_map_without_openclaw", func(t *testing.T, cfg *config.Config) {
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}, "hermes": {}}
		}, true, false},

		// Every other shape keeps today's behaviour.
		{"openclaw_json_at_config_file", func(t *testing.T, cfg *config.Config) { withConfiguredOpenClaw(t, cfg) }, false, true},
		{"openclaw_json_in_home_dir_only", func(t *testing.T, cfg *config.Config) {
			withConfiguredOpenClaw(t, cfg)
			cfg.Claw.ConfigFile = filepath.Join(t.TempDir(), "elsewhere.json")
		}, false, true},
		{"openclaw_binary_installed", func(t *testing.T, cfg *config.Config) { stubOpenClawBinary(t, true) }, false, true},
		{"explicit_guardrail_connector", func(t *testing.T, cfg *config.Config) { cfg.Guardrail.Connector = "openclaw" }, false, true},
		{"openclaw_in_connectors_map", func(t *testing.T, cfg *config.Config) {
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"OpenClaw": {}}
		}, false, true},
		{"remote_host", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "10.0.0.5" }, false, true},
		{"bind_all_host", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "0.0.0.0" }, false, true},
		{"fqdn_host", func(t *testing.T, cfg *config.Config) { cfg.Gateway.Host = "gw.example.com" }, false, true},
		{"fleet_mode_enabled", func(t *testing.T, cfg *config.Config) { cfg.Gateway.FleetMode = "enabled" }, false, true},
		{"fleet_mode_typo_falls_through_to_dial", func(t *testing.T, cfg *config.Config) { cfg.Gateway.FleetMode = "enabledd" }, false, true},
		{"fleet_mode_disabled", func(t *testing.T, cfg *config.Config) { cfg.Gateway.FleetMode = "disabled" }, false, false},
		{"zeptoclaw_claw_mode", func(t *testing.T, cfg *config.Config) { cfg.Claw.Mode = "zeptoclaw" }, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := clawModeDefaultConfig()
			withoutOpenClaw(t, cfg)
			tc.mutate(t, cfg)

			if got := openClawImpliedButNotInstalled(cfg); got != tc.notInstalls {
				t.Errorf("openClawImpliedButNotInstalled = %v, want %v", got, tc.notInstalls)
			}
			if got := gatewayShouldConnectForConfiguredConnector(cfg); got != tc.dial {
				t.Errorf("gatewayShouldConnectForConfiguredConnector = %v, want %v", got, tc.dial)
			}
			if got := RequiresFleetGateway(cfg); got != tc.dial {
				t.Errorf("RequiresFleetGateway = %v, want %v (must match the dial predicate)", got, tc.dial)
			}
			if got := (&Sidecar{cfg: cfg}).fleetRPCsEnabled(); got != tc.dial {
				t.Errorf("fleetRPCsEnabled = %v, want %v (must match the dial predicate)", got, tc.dial)
			}
		})
	}

	t.Run("nil_config", func(t *testing.T) {
		if openClawImpliedButNotInstalled(nil) {
			t.Error("openClawImpliedButNotInstalled(nil) = true, want false")
		}
	})

	// An OpenClaw home that cannot be inspected counts as installed, so the
	// gateway keeps dialing instead of guessing.
	t.Run("uninspectable_config_path_counts_as_present", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows maps a file used as a directory to not-exist")
		}
		cfg := clawModeDefaultConfig()
		withoutOpenClaw(t, cfg)
		blocker := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatalf("write blocker: %v", err)
		}
		cfg.Claw.ConfigFile = filepath.Join(blocker, "openclaw.json")
		cfg.Claw.HomeDir = blocker
		if openClawImpliedButNotInstalled(cfg) {
			t.Error("an OpenClaw path that fails with ENOTDIR was treated as absent")
		}
	})
}

// TestRunGatewayLoop_OpenClawNotInstalledReportsOff runs the real fleet client
// against a loopback listener on the fleet port. With the claw.mode default and
// no OpenClaw the loop publishes DISABLED with the "not installed" summary and
// never dials; the control with an openclaw.json proves the listener sees the
// dial when OpenClaw is configured.
func TestRunGatewayLoop_OpenClawNotInstalledReportsOff(t *testing.T) {
	run := func(t *testing.T, configured bool) (bool, SubsystemHealth) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		conns := make(chan struct{}, 8)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				conns <- struct{}{}
				_ = c.Close()
			}
		}()
		_, portText, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portText)

		cfg := clawModeDefaultConfig()
		cfg.Gateway.Port = port
		if configured {
			withConfiguredOpenClaw(t, cfg)
		} else {
			withoutOpenClaw(t, cfg)
		}
		dataDir := testenv.PrivateTempDir(t)
		cfg.DataDir = dataDir
		cfg.Gateway.Token = "listener-check-token"
		cfg.Gateway.DeviceKeyFile = filepath.Join(dataDir, "device.key")
		client, err := NewClient(&cfg.Gateway, dataDir)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		s := &Sidecar{cfg: cfg, client: client, health: NewSidecarHealth()}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.runGatewayLoop(ctx) }()
		accepted := false
		select {
		case <-conns:
			accepted = true
		case <-time.After(750 * time.Millisecond):
		}
		health := s.health.Snapshot().Gateway
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runGatewayLoop did not return after cancel")
		}
		return accepted, health
	}

	t.Run("not_installed_is_off", func(t *testing.T) {
		accepted, health := run(t, false)
		if accepted {
			t.Fatal("gateway dialed the loopback fleet port although OpenClaw is not installed")
		}
		if health.State != StateDisabled {
			t.Fatalf("gateway state = %q, want %q", health.State, StateDisabled)
		}
		if got, _ := health.Details["summary"].(string); got != fleetOffSummaryOpenClawNotInstalled {
			t.Errorf("summary = %q, want %q", got, fleetOffSummaryOpenClawNotInstalled)
		}
		if got, _ := health.Details["reason"].(string); got != fleetOffReasonOpenClawNotInstalled {
			t.Errorf("reason = %q, want %q", got, fleetOffReasonOpenClawNotInstalled)
		}
		hint, _ := health.Details["hint"].(string)
		if !strings.Contains(hint, "restart the gateway") || !strings.Contains(hint, "gateway.fleet_mode: enabled") {
			t.Errorf("hint = %q, want the restart and fleet_mode escape hatches", hint)
		}
	})
	t.Run("configured_openclaw_dials", func(t *testing.T) {
		accepted, health := run(t, true)
		if !accepted {
			t.Fatal("control: a configured OpenClaw did not dial the listener; the test cannot detect a regression")
		}
		if health.State == StateDisabled {
			t.Errorf("gateway state = %q with OpenClaw configured, want the dial loop", health.State)
		}
	})
}
