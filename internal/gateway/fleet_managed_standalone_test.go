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
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// managedStandaloneFleetConfig is the shape an administrator writes for a
// managed standalone host: connectors come from guardrail.connectors, no
// single guardrail.connector, and claw.mode keeps the loader default.
func managedStandaloneFleetConfig(host string, port int, fleetMode string) *config.Config {
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Claw:           config.ClawConfig{Mode: "openclaw"},
		Guardrail: config.GuardrailConfig{
			Enabled: true,
			Connectors: map[string]config.PerConnectorGuardrailConfig{
				"claudecode": {}, "codex": {}, "copilot": {},
				"opencode": {}, "hermes": {}, "openhands": {},
			},
		},
		Gateway: config.GatewayConfig{Host: host, Port: port, FleetMode: fleetMode},
	}
}

// TestGatewayShouldConnect_ManagedStandaloneNeedsExplicitRemoteFleet pins the
// fix for the managed standalone gateway dialing the OpenClaw fleet port on
// loopback. The fleet client sends the gateway's API token, and any local
// account can bind a loopback port, so a managed standalone deployment dials
// only when the administrator set fleet_mode enabled and a non-loopback host.
func TestGatewayShouldConnect_ManagedStandaloneNeedsExplicitRemoteFleet(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		host      string
		fleetMode string
		want      bool
	}{
		{"connectors_map_default_loopback", "", "127.0.0.1", "", false},
		{"explicit_enabled_loopback", "", "127.0.0.1", "enabled", false},
		// A bind-all address reaches a listener on this machine too.
		{"explicit_enabled_unspecified_ipv6_bracketed", "", "[::]", "enabled", false},
		{"auto_remote_needs_explicit_enable", "", "10.0.0.5", "auto", false},
		{"explicit_enabled_remote", "", "10.0.0.5", "enabled", true},
		{"explicit_on_remote_fqdn", "", "fleet.example.internal", " On ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := managedStandaloneFleetConfig(tc.host, 18789, tc.fleetMode)
			cfg.Guardrail.Connector = tc.connector
			if !cfg.StandaloneEnterprise() {
				t.Fatalf("test config is not a managed standalone deployment")
			}
			if got := gatewayShouldConnectForConfiguredConnector(cfg); got != tc.want {
				t.Errorf("gatewayShouldConnectForConfiguredConnector(managed standalone, connector=%q host=%q fleet_mode=%q) = %v, want %v",
					tc.connector, tc.host, tc.fleetMode, got, tc.want)
			}
			if got := RequiresFleetGateway(cfg); got != tc.want {
				t.Errorf("RequiresFleetGateway = %v, want %v (must match the dial predicate)", got, tc.want)
			}
			s := &Sidecar{cfg: cfg}
			if got := s.fleetRPCsEnabled(); got != tc.want {
				t.Errorf("fleetRPCsEnabled = %v, want %v (must match the dial predicate)", got, tc.want)
			}
		})
	}

	// The same connectors-map shape outside a managed deployment keeps the
	// historical claw.mode derivation, so unmanaged OpenClaw installs still
	// dial their local daemon. OpenClaw is configured here (openclaw.json
	// exists): without it the claw.mode default no longer dials (#958).
	t.Run("unmanaged_control_keeps_claw_mode_derivation", func(t *testing.T) {
		cfg := managedStandaloneFleetConfig("127.0.0.1", 18789, "")
		cfg.DeploymentMode = ""
		cfg.Enterprise = config.EnterpriseConfig{}
		withConfiguredOpenClaw(t, cfg)
		if !gatewayShouldConnectForConfiguredConnector(cfg) {
			t.Errorf("unmanaged connectors map with claw.mode=openclaw: predicate = false, want true")
		}
	})
}

// TestRunGatewayLoop_ManagedStandaloneSendsNothingToLoopbackListener runs the
// real fleet client against a listener that stands in for another local
// account on the fleet port. The managed standalone gateway must publish
// DISABLED and never connect; the unmanaged control proves the listener sees
// the dial when the predicate allows it.
func TestRunGatewayLoop_ManagedStandaloneSendsNothingToLoopbackListener(t *testing.T) {
	run := func(t *testing.T, managedDeployment bool) (accepted bool, state SubsystemState) {
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

		cfg := managedStandaloneFleetConfig("127.0.0.1", port, "")
		if !managedDeployment {
			cfg.DeploymentMode = ""
			cfg.Enterprise = config.EnterpriseConfig{}
			withConfiguredOpenClaw(t, cfg)
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
		select {
		case <-conns:
			accepted = true
		case <-time.After(750 * time.Millisecond):
		}
		state = s.health.Snapshot().Gateway.State
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("runGatewayLoop did not return after cancel")
		}
		return accepted, state
	}

	t.Run("managed_standalone", func(t *testing.T) {
		accepted, state := run(t, true)
		if accepted {
			t.Fatal("managed standalone gateway connected to the loopback fleet port; it must never dial it")
		}
		if state != StateDisabled {
			t.Errorf("gateway state = %q, want %q", state, StateDisabled)
		}
	})
	t.Run("unmanaged_control_dials", func(t *testing.T) {
		accepted, _ := run(t, false)
		if !accepted {
			t.Fatal("control: unmanaged openclaw config did not dial the listener; the test cannot detect a regression")
		}
	})
}
