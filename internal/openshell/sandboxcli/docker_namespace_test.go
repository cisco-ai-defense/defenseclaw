// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// GAP-0579: the per-user docker gateways of two accounts on one Linux host
// shared OpenShell's default sandbox namespace, and one account's gateway
// start ended the other's running sandboxes. Setup gives the account's
// gateway a namespace of its own in the same plan as its other changes, and
// leaves a gateway that keeps sandboxes in the default namespace on it, with
// a note (the gateway lists only its namespace's sandboxes).
func TestSetupGivesTheGatewayADockerNamespaceOfItsOwn(t *testing.T) {
	run := func(t *testing.T, prepare func(ta *testApp)) *testApp {
		t.Helper()
		ta := setupApp(t, "", "", false)
		ta.IO.TTY = false
		ta.Cfg.OpenShell.Enabled = false
		useGateway(ta)
		if prepare != nil {
			prepare(ta)
		}
		ta.ok(t, ta.Setup(bg, SetupOptions{NonInteractive: true, Yes: true}))
		return ta
	}
	t.Run("no sandbox in the default namespace", func(t *testing.T) {
		ta := run(t, nil)
		if len(ta.gateway.planned) != 1 || ta.gateway.planned[0].DockerNamespace != openshell.AccountDockerNamespace(1000) || ta.gateway.applied != 1 {
			t.Fatalf("gateway plans = %+v, applied %d", ta.gateway.planned, ta.gateway.applied)
		}
	})
	t.Run("a gateway that keeps sandboxes in the default namespace stays on it", func(t *testing.T) {
		ta := run(t, func(ta *testApp) {
			dir := filepath.Join(ta.home, ".local", "state", "openshell", "docker-sandbox-tokens", openshell.DefaultDockerNamespace, "sbx-1111")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		})
		if len(ta.gateway.planned) != 1 || ta.gateway.planned[0].DockerNamespace != "" {
			t.Fatalf("gateway plans = %+v", ta.gateway.planned)
		}
		has(t, ta.output(), "your OpenShell gateway keeps its sandboxes in OpenShell's default Docker sandbox namespace")
	})
	t.Run("a gateway with a namespace of its own keeps it", func(t *testing.T) {
		ta := run(t, func(ta *testApp) { ta.gateway.state.DockerNamespace = "team-a" })
		if len(ta.gateway.planned) != 1 || ta.gateway.planned[0].DockerNamespace != "" {
			t.Fatalf("gateway plans = %+v", ta.gateway.planned)
		}
	})
}
