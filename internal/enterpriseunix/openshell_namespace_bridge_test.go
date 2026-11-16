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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// packagedDockerHost is a Linux host with the administrator's OpenShell and
// docker installed.
func packagedDockerHost(t *testing.T) *osHost {
	t.Helper()
	h := newOSHost(t, "linux")
	for _, p := range []string{"/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker", "/usr/sbin/mke2fs"} {
		if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.runner.replies = map[string]fakeReply{"rpm -q --qf %{VERSION} openshell": {result: CommandResult{Stdout: []byte("0.1.5")}}}
	return h
}

// GAP-0587, replayed from the rc.5 failure (TST-5462, TST-5464): 1.0.1
// rendered the managed docker gateway without a sandbox_label, so the
// sandboxes its accounts kept are in OpenShell's default namespace, and a
// gateway lists only its own namespace's. rc.5 made the move to the managed
// namespace a switch: at the account's next gateway start the kept sandboxes
// went to ComputeResourceMissing, the next ensure applied the switch and
// OpenShell dropped them with their unpulled work. With the 1.0.1 upgrade
// bridge the upgrade is a plain restart for every account: the lifecycle
// renders the 1.0.1 docker configuration as well, which the exec shim starts
// an account's gateway on while it keeps a sandbox in the default namespace
// (TestPlanSandboxOpenShellExecDefaultNamespaceBridge), so nothing is
// switched, stopped beyond the restart, or reported lost; the bridge stays on
// the next upgrades and ends with the docker driver.
func TestUpgradeFrom101KeepsTheDefaultNamespaceBridge(t *testing.T) {
	h := packagedDockerHost(t)
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, GID: h.alice.GID, Home: "/home/bob"}
	if err := os.MkdirAll(h.env.P(bob.Home), 0o755); err != nil {
		t.Fatal(err)
	}
	h.ops.accounts = append(h.ops.accounts, bob)
	cfg := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "gateway_port": 17671})
	ensureWith := func(cfg []byte, payload string) *enterprisestatus.Result {
		t.Helper()
		return h.run(Options{Action: ActionEnsure, PayloadDir: payload, ConfigFile: writeTempConfig(t, cfg)})
	}
	requireOK(t, h.ensure(cfg))
	bridgePath := h.env.renderedBridgeTOMLPath()
	if _, err := os.Lstat(h.env.P(bridgePath)); !os.IsNotExist(err) {
		t.Fatalf("a host that was never on 1.0.1 got the bridge: %v", err)
	}

	// The record as 1.0.1 left it: no docker namespace, and the daemon
	// inputs of its render.
	state := h.env.loadOpenShellState()
	state.Applied.DockerNamespace, state.Applied.DefaultNamespaceBridge = "", false
	state.Applied.DaemonInputs = "sha256:inputs-of-a-render-without-sandbox_label"
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(h.env.openshellStatePath()); err != nil || strings.Contains(string(raw), "docker_namespace") {
		t.Fatalf("the 1.0.1 record names a namespace: %s %v", raw, err)
	}
	// alice (eng1) kept sandboxes and runs one now; bob never used sandboxes.
	if err := os.MkdirAll(h.env.P(filepath.Join(h.alice.Home, h.env.daemonStateRel())), 0o700); err != nil {
		t.Fatal(err)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}

	// rpm -U: the upgrade renders the bridge next to the managed render and
	// waits for alice's sandbox with a restart, not a switch.
	upgraded := h.payload("1.0.2")
	r := ensureWith(cfg, upgraded)
	requireOK(t, r)
	bridge := h.read(bridgePath)
	if !strings.Contains(bridge, "compute_driver = 'docker'") || strings.Contains(bridge, "sandbox_label") ||
		!strings.Contains(bridge, "enable_bind_mounts = true") {
		t.Fatalf("the bridge is not the 1.0.1 docker render:\n%s", bridge)
	}
	if toml := h.read(h.env.renderedTOMLPath()); !strings.Contains(toml, "sandbox_label = '"+openshell.ManagedDockerNamespace+"'") {
		t.Fatalf("gateway.toml lost the managed namespace:\n%s", toml)
	}
	state = h.env.loadOpenShellState()
	entry, waiting := state.Pending[strconv.Itoa(h.alice.UID)]
	if !waiting || entry.Kind != "restart" {
		t.Fatalf("alice's pending change = %+v (waiting %t), want a restart", entry, waiting)
	}
	if !state.Applied.DefaultNamespaceBridge || state.Applied.DockerNamespace != openshell.ManagedDockerNamespace {
		t.Fatalf("applied record = %+v, want the bridge and the managed namespace", state.Applied)
	}
	for _, w := range r.Warnings {
		if strings.Contains(w.Message, "namespace") || strings.Contains(w.Message, "pending switch") {
			t.Errorf("the upgrade warns of a namespace switch: %s", w.Message)
		}
	}
	if len(h.ops.stopped()) != 0 {
		t.Fatalf("a running sandbox was not waited for: stops %v", h.ops.stopped())
	}

	// alice stops her sandbox (`sandbox stop --yes`) and the next ensure
	// runs: her daemon restarts on the new inputs, nothing is switched, and
	// no change line says her sandboxes cannot start or are dropped.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	r = ensureWith(cfg, upgraded)
	requireOK(t, r)
	changes := strings.Join(r.Changes, "\n")
	if strings.Contains(changes, "switched") || strings.Contains(changes, "cannot start") || strings.Contains(changes, "of bob") {
		t.Fatalf("changes = %v", r.Changes)
	}
	if got := strings.Join(h.ops.stopped(), ","); got != "alice:daemon" {
		t.Errorf("stops = %s, want only alice's daemon restart", got)
	}
	if state = h.env.loadOpenShellState(); len(state.Pending) != 0 {
		t.Fatalf("pending after the restart: %+v", state.Pending)
	}

	// The next upgrade keeps the bridge (the record carries it now).
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
	requireOK(t, ensureWith(cfg, h.payload("1.0.3")))
	if state = h.env.loadOpenShellState(); !state.Applied.DefaultNamespaceBridge {
		t.Fatalf("the next upgrade dropped the bridge: %+v", state.Applied)
	}
	if entry, waiting := state.Pending[strconv.Itoa(h.alice.UID)]; waiting && entry.Kind == "switch" {
		t.Fatalf("an upgrade on the bridge is a switch: %+v", entry)
	}
	if _, err := os.Lstat(h.env.P(bridgePath)); err != nil {
		t.Fatalf("the bridge is gone after the next upgrade: %v", err)
	}
}

// The bridge holds for a 1.0.1 docker record (no docker namespace) and for a
// record that carries it, while the render still starts docker gateways on
// Linux (or sandboxes are off, to be turned on again); a record of this
// release, a setup without docker gateways and macOS never get it.
func TestDockerBridgeHolds(t *testing.T) {
	docker := openshellSettings{Enabled: true, Driver: "docker"}
	vmFallback := openshellSettings{Enabled: true, Driver: "vm", Fallback: "docker"}
	vmOnly := openshellSettings{Enabled: true, Driver: "vm", Fallback: "none"}
	off := openshellSettings{Driver: "docker"}
	rec101 := &openshellApplied{Enabled: true, Driver: "docker"}
	rec101VM := &openshellApplied{Enabled: true, Driver: "vm", Fallback: "docker"}
	bridged := &openshellApplied{Enabled: true, Driver: "docker", DockerNamespace: openshell.ManagedDockerNamespace, DefaultNamespaceBridge: true}
	current := &openshellApplied{Enabled: true, Driver: "docker", DockerNamespace: openshell.ManagedDockerNamespace}
	for _, tc := range []struct {
		name string
		goos string
		s    openshellSettings
		prev *openshellApplied
		want bool
	}{
		{"1.0.1 docker record", "linux", docker, rec101, true},
		{"1.0.1 MicroVM record with the docker fallback", "linux", vmFallback, rec101VM, true},
		{"a record that carries the bridge", "linux", docker, bridged, true},
		{"sandboxes turned off keep it", "linux", off, bridged, true},
		{"a record of this release", "linux", docker, current, false},
		{"a fresh host", "linux", docker, nil, false},
		{"the docker driver goes", "linux", vmOnly, bridged, false},
		{"a 1.0.1 MicroVM record without docker", "linux", docker, &openshellApplied{Enabled: true, Driver: "vm", Fallback: "none"}, false},
		{"macOS", "darwin", docker, rec101, false},
	} {
		if got := dockerBridgeHolds(tc.goos, tc.s, tc.prev); got != tc.want {
			t.Errorf("%s: bridge %t, want %t", tc.name, got, tc.want)
		}
	}
	// The docker namespace is no part of a switch any more: 1.0.1's record
	// and this release's switch nothing, and a fallback that comes is the
	// fallback's change only.
	if rec101.switchKey() != current.switchKey() {
		t.Errorf("the 1.0.1 record switches: %q -> %q", rec101.switchKey(), current.switchKey())
	}
	from := &openshellApplied{Enabled: true, Install: "prerequisite", Driver: "vm", Fallback: "none", GatewayPort: 17670}
	to := &openshellApplied{Enabled: true, Install: "prerequisite", Driver: "vm", Fallback: "docker", GatewayPort: 17670, DockerNamespace: openshell.ManagedDockerNamespace}
	if !fallbackOnlySwitch(from, to) || describeSwitch(from, to) != "driver_fallback none -> docker" {
		t.Errorf("a fallback that comes: fallback-only %t, %q", fallbackOnlySwitch(from, to), describeSwitch(from, to))
	}
}
