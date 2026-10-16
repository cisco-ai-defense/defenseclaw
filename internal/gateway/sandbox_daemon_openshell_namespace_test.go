// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0566: every managed docker gateway keeps its sandboxes in one
// namespace, and a docker gateway's start force-removes the supervisors of
// that namespace. One managed port kept two accounts' gateways apart, but
// while account A's gateway_port switch waits for A's sandboxes to stop, A's
// gateway still runs on the old port and the new one is free: account B's
// daemon started B's gateway there and its start ended A's sandboxes. A
// managed gateway of another account, on any port, now refuses the start
// with the neutral account-busy text.
func TestManagedGatewayStartWaitsForAnotherAccountsManagedGatewayOnAnyPort(t *testing.T) {
	const cfg = "/etc/defenseclaw/openshell/gateway.toml"
	settings := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{
		Install: "prerequisite", Driver: "docker", GatewayPort: 17670, GatewayConfigPath: cfg}}
	for _, tc := range []struct {
		name    string
		procs   string
		refused bool
	}{
		{"another account's managed gateway on the old port", "5002 4242 /usr/bin/openshell-gateway --config " + cfg + "\n5001 77 /bin/bash\n", true},
		{"another account's managed docker fallback (setup mode binary)", "5003 4243 /home/b/.local/bin/openshell-gateway --config /etc/defenseclaw/openshell/gateway-docker.toml\n", true},
		// The 1.0.1 upgrade bridge's gateways share OpenShell's default namespace (GAP-0587).
		{"another account's gateway on the 1.0.1 upgrade bridge", "5004 4246 /usr/bin/openshell-gateway --config /etc/defenseclaw/openshell/gateway-docker-default-namespace.toml\n", true},
		{"another account's own gateway (not the managed configuration)", "5002 4244 /usr/bin/openshell-gateway --config /home/b/.config/openshell/gateway.toml\n", false},
		{"this account's own managed gateway", "5001 4245 /usr/bin/openshell-gateway --config " + cfg + "\n", false},
		{"no other gateway", "1 1 /sbin/init\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fastGatewayWaits(t)
			r := newOpenShellRig(t, "linux")
			r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
			r.o.hostProcs = func(context.Context) (string, error) { return tc.procs, nil }
			// The port is free until this account's gateway starts on it.
			r.holder = func(call int) int {
				if call <= 2 {
					return 0
				}
				return 5001
			}
			_, err := r.o.Prepare(context.Background(), settings)
			started := strings.Contains(strings.Join(r.ran(), "\n"), "systemctl --user start ")
			if !tc.refused {
				if !started {
					t.Fatalf("the gateway was not started: %v (commands %v)", err, r.ran())
				}
				return
			}
			var apiErr *sandboxapi.Error
			if !errors.As(err, &apiErr) || apiErr.Message != sandboxAccountBusyMessage {
				t.Fatalf("start beside another account's managed gateway = %v, want the account-busy refusal", err)
			}
			if started {
				t.Fatalf("the gateway was started beside another account's managed gateway: %v", r.ran())
			}
		})
	}
}
