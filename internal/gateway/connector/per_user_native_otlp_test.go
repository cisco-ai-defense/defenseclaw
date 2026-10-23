// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"slices"
	"testing"
)

// A native exporter cannot authenticate the account behind a loopback TCP
// listener. When the user's gateway stops, another account may bind its port.
// The agent must not retain a direct OTLP endpoint or a bearer for that port.
func TestPerUserNativeOTLPHasNoUnverifiedTCPDestination(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			opts := SetupOpts{GOOS: goos, APIAddr: "127.0.0.1:19081", OTLPPathToken: "test scoped token"}
			if spec := NewCodexConnector().HookProfile(opts).NativeOTLP; spec != nil {
				t.Fatalf("Codex per-user exporter can send telemetry and its bearer to an unverified listener: %+v", spec.Kind)
			}
			if spec := NewClaudeCodeConnector().HookProfile(opts).NativeOTLP; spec != nil {
				t.Fatalf("Claude Code per-user exporter can send telemetry to an unverified listener: %+v", spec.Kind)
			}
			for _, conn := range []ConnectorCapabilityProvider{NewCodexConnector(), NewClaudeCodeConnector()} {
				caps := conn.Capabilities(opts).Telemetry
				if caps.NativeOTLP || len(caps.NativeSignals) != 0 || slices.Contains(caps.SourceModes, "native") || caps.EndpointTemplate != "" {
					t.Fatalf("per-user capability still advertises an unverified native exporter: %+v", caps)
				}
			}
		})
	}
}
