// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// Codex and Claude Code cannot inspect the peer of their native OTLP HTTP
// connection. A managed service account does not stop another local user from
// holding its unprivileged loopback port during an outage, so Setup must not
// hand either exporter a bearer or telemetry endpoint for that listener.
func TestManagedNativeOTLPHasNoUnverifiedLoopbackExporter(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, profileName := range []string{"standalone", "secure-client"} {
			t.Run(goos+"/"+profileName, func(t *testing.T) {
				opts := SetupOpts{GOOS: goos, ManagedEnterprise: true, APIAddr: "127.0.0.1:18970", OTLPPathToken: strings.Repeat("a", 64)}
				opts.SecureClientHookDelivery = profileName == "secure-client"
				if profile := (&CodexConnector{}).HookProfile(opts); profile.NativeOTLP != nil {
					t.Error("Codex configured an unverified native OTLP listener")
				}
				if profile := (&ClaudeCodeConnector{}).HookProfile(opts); profile.NativeOTLP != nil {
					t.Error("Claude Code configured an unverified native OTLP listener")
				}
				env := buildClaudeCodeOtelEnv(opts)
				if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "0" || env["OTEL_LOGS_EXPORTER"] != "none" || env["OTEL_METRICS_EXPORTER"] != "none" {
					t.Error("Claude Code managed env still exports to an unverified listener")
				}
			})
		}
	}
}
