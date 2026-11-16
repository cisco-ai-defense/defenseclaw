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

package enterpriseunix

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

var keptDockerSettings = map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671}

// requireDefaultNamespaceBridge checks that the account's kept 1.0.1
// sandboxes stay reachable: the bridge render is in place next to the
// managed render, the applied record carries the bridge, and nothing was
// switched (GAP-0666).
func requireDefaultNamespaceBridge(t *testing.T, h *osHost, changes []string) {
	t.Helper()
	bridge := h.read(h.env.renderedBridgeTOMLPath())
	if !strings.Contains(bridge, "compute_driver = 'docker'") || strings.Contains(bridge, "sandbox_label") {
		t.Fatalf("the bridge is not the 1.0.1 docker render:\n%s", bridge)
	}
	state := h.env.loadOpenShellState()
	if state.Applied == nil || !state.Applied.DefaultNamespaceBridge || state.Applied.DockerNamespace != openshell.ManagedDockerNamespace {
		t.Fatalf("applied record = %+v, want the bridge and the managed namespace", state.Applied)
	}
	if containsLine(changes, "switched the sandbox setup") {
		t.Fatalf("the reinstall switched the kept sandboxes: %v", changes)
	}
	if physicalExists(h.env.openshellKeptStatePath()) {
		t.Error("the adopted kept record is still there")
	}
}

// A non-purge uninstall then a reinstall keeps the 1.0.1 upgrade bridge of
// an account that kept default-namespace sandboxes: directly with the
// administrator's config, and through the package's first ensure on the
// default config (sandboxes off) followed by the administrator's config
// (GAP-0666).
func TestKeptOpenShellSetupReinstallKeepsTheDefaultNamespaceBridge(t *testing.T) {
	t.Run("admin config", func(t *testing.T) {
		h := keptDockerHost(t, "linux", true)
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		r := ensureKeptHost(t, h, keptDockerSettings)
		requireOK(t, r)
		requireDefaultNamespaceBridge(t, h, r.Changes)
	})
	t.Run("default config first", func(t *testing.T) {
		h := keptDockerHost(t, "linux", true)
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		h.ops.status[h.alice.UID] = SandboxStatus{}
		off := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", false, nil))})
		requireOK(t, off)
		state := h.env.loadOpenShellState()
		if state.Applied == nil || state.Applied.Enabled || !state.Applied.DefaultNamespaceBridge {
			t.Fatalf("the sandboxes-off reinstall recorded %+v, want a disabled record that keeps the bridge", state.Applied)
		}
		r := ensureKeptHost(t, h, keptDockerSettings)
		requireOK(t, r)
		requireDefaultNamespaceBridge(t, h, r.Changes)
	})
	t.Run("purge ends it", func(t *testing.T) {
		h := keptDockerHost(t, "linux", true)
		requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
		r := ensureKeptHost(t, h, keptDockerSettings)
		requireOK(t, r)
		if _, err := os.Lstat(h.env.P(h.env.renderedBridgeTOMLPath())); !os.IsNotExist(err) {
			t.Fatalf("a reinstall after a purge rendered the bridge: %v", err)
		}
	})
}

// A fresh ensure after a non-purge uninstall that kept sandboxes can fail
// activation and roll back. The retry adopts the kept state without
// --adopt-existing, and the kept setup record with it (GAP-0631).
func TestKeptOpenShellSetupRetryAfterRolledBackEnsure(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			homeRecord, store, key := retrySandboxPaths(h)
			h.healthy = false
			requireError(t, ensureKeptHost(t, h, keptDockerSettings), codeActivate)
			if !physicalExists(h.env.openshellKeptStatePath()) || !physicalExists(store) || !physicalExists(key) || !physicalExists(homeRecord) {
				t.Fatal("the rolled-back ensure lost the kept sandbox state")
			}
			if marker := retainedMarkerPath(h.env.P(h.env.Layout.DataDir)); !physicalExists(marker) {
				t.Fatal("the rolled-back ensure removed the retained-state marker")
			} else if uid, _, err := h.env.OwnerOf(marker); err != nil || uid != 0 {
				t.Fatalf("the rolled-back ensure gave the retained-state marker to uid %d (%v)", uid, err)
			}
			h.healthy = true
			r := ensureKeptHost(t, h, keptDockerSettings)
			requireOK(t, r)
			if !physicalExists(store) || !physicalExists(key) || !physicalExists(homeRecord) {
				t.Fatalf("the retry lost the kept sandbox state: %v", r.Changes)
			}
			if physicalExists(h.env.openshellKeptStatePath()) {
				t.Error("the retry did not adopt the kept setup record")
			}
			if goos == "linux" {
				requireDefaultNamespaceBridge(t, h, r.Changes)
			}
			if physicalExists(h.env.retainedStatePath()) || physicalExists(retainedMarkerPath(h.env.P(h.env.Layout.DataDir))) {
				t.Error("the committed retry kept the retained-state record")
			}
		})
	}
}

// The kept record names the inode of the gateway binary the uninstall
// removed. Its adoption forgets it, so the reinstalled binary reloads the
// kept accounts' LaunchAgents even when it reuses that inode.
func TestKeptOpenShellSetupAdoptionForgetsTheGatewayIdentity(t *testing.T) {
	h := keptDockerHost(t, "darwin", true)
	state := h.env.loadOpenShellState()
	state.GatewayIdentity = "sample-inode-of-the-removed-gateway"
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if kept := h.env.loadKeptOpenShellState(); kept == nil || kept.GatewayIdentity == "" {
		t.Fatalf("the kept record = %+v, want the identity as the uninstall left it", kept)
	}
	adopted, ok := (&lifecycle{env: h.env, result: &enterprisestatus.Result{}}).openShellStateForSettle()
	if !ok || adopted.Applied == nil || adopted.GatewayIdentity != "" {
		t.Fatalf("adopted %+v (kept %t), want the applied setup without the old gateway identity", adopted, ok)
	}
}
