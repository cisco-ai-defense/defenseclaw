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
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func physicalExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func physicalMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func keptDockerHost(t *testing.T, goos string, sandbox bool) *osHost {
	t.Helper()
	h := newOSHost(t, goos)
	cfg := sandboxConfig(t, goos, true, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671})
	requireOK(t, h.ensure(cfg))
	state := h.env.loadOpenShellState()
	if state.Applied == nil {
		t.Fatal("initial install did not record the sandbox setup")
	}
	// A 1.0.1/rc record did not have docker_namespace. Its gateways used
	// OpenShell's default namespace.
	state.Applied.DockerNamespace = ""
	state.Applied.DaemonInputs = "sha256:old-render-without-sandbox-label"
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(h.env.openshellStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "docker_namespace") {
		t.Fatal("the old record unexpectedly names the managed namespace")
	}
	if sandbox {
		writeHostFile(t, h.testHost, filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", "sb-kept", "record.json"), "{}\n")
		writeHostFile(t, h.testHost, filepath.Join(h.env.Layout.DataDir, "sandbox", "registrations", strconv.Itoa(h.alice.UID)+".json"), "{}\n")
		writeHostFile(t, h.testHost, filepath.Join(h.env.Layout.DataDir, "redaction-correlation.key"), "sample-key\n")
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	return h
}

func ensureKeptHost(t *testing.T, h *osHost, settings map[string]any) *enterprisestatus.Result {
	t.Helper()
	cfg := sandboxConfig(t, h.env.GOOS, true, settings)
	return h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), ConfigFile: writeTempConfig(t, cfg)})
}

func sandboxSwitchLine(t *testing.T, r *enterprisestatus.Result) string {
	t.Helper()
	for _, line := range r.Changes {
		if strings.HasPrefix(line, "switched the sandbox setup of alice (") {
			return line
		}
	}
	t.Fatalf("no sandbox switch in changes: %v", r.Changes)
	return ""
}

func TestKeptOpenShellSetupSwitchEqualsDirectSwitch(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name     string
			settings map[string]any
			want     string
		}{
			{"docker port", map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17672}, "gateway port 17671 -> 17672"},
			{"docker to vm and port", map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5", "gateway_port": 17672}, "driver docker -> vm"},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				direct := keptDockerHost(t, goos, true)
				directResult := ensureKeptHost(t, direct, tc.settings)
				requireOK(t, directResult)
				wantLine := sandboxSwitchLine(t, directResult)
				if !strings.Contains(wantLine, tc.want) || !strings.Contains(wantLine, sandboxSwitchLeftovers) {
					t.Fatalf("direct switch = %q", wantLine)
				}
				kept := keptDockerHost(t, goos, true)
				before, err := os.ReadFile(kept.env.openshellStatePath())
				if err != nil {
					t.Fatal(err)
				}
				uninstall := kept.run(Options{Action: ActionUninstall})
				requireOK(t, uninstall)
				if physicalExists(kept.env.openshellStatePath()) || !physicalExists(kept.env.openshellKeptStatePath()) {
					t.Fatalf("uninstall did not move the active sandbox record: changes %v", uninstall.Changes)
				}
				after, err := os.ReadFile(kept.env.openshellKeptStatePath())
				if err != nil || !bytes.Equal(after, before) {
					t.Errorf("kept record content changed on move: %v", err)
				}
				if got := physicalMode(t, kept.env.openshellKeptStatePath()); got != 0o600 {
					t.Errorf("kept record mode = %04o", got)
				}
				if uid, _, err := kept.env.OwnerOf(kept.env.openshellKeptStatePath()); err != nil || uid != 0 {
					t.Errorf("kept record owner = %d, %v", uid, err)
				}
				if !containsLine(uninstall.Changes, "removed the machine state: ") ||
					!strings.Contains(strings.Join(uninstall.Changes, "\n"), "except the record of the sandbox setup the kept sandboxes were made under") {
					t.Errorf("uninstall summary omitted the kept record: %v", uninstall.Changes)
				}
				kept.ops.stops = nil
				reactivated := ensureKeptHost(t, kept, tc.settings)
				requireOK(t, reactivated)
				if got := sandboxSwitchLine(t, reactivated); got != wantLine {
					t.Errorf("reactivated switch = %q\ndirect switch = %q", got, wantLine)
				}
				if got := strings.Join(kept.ops.stopped(), ","); got != "alice:daemon+socket,alice:daemon+gateway" {
					t.Errorf("switch stopped %q, want the daemon and its socket, then daemon and gateway", got)
				}
				if physicalExists(kept.env.openshellKeptStatePath()) {
					t.Error("successful adoption left the kept record")
				}
			})
		}
	}
}

func TestKeptOpenShellSetupWaitsForRunningSandbox(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			settings := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5", "gateway_port": 17671}
			direct := keptDockerHost(t, goos, true)
			direct.ops.status[direct.alice.UID] = SandboxStatus{Active: true, Running: 1}
			requireOK(t, ensureKeptHost(t, direct, settings))
			want, ok := direct.env.loadOpenShellState().Pending[strconv.Itoa(direct.alice.UID)]
			if !ok || want.Kind != "switch" {
				t.Fatalf("direct switch did not wait: %+v", want)
			}
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			h.ops.stops = nil
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
			r := ensureKeptHost(t, h, settings)
			requireOK(t, r)
			entry, ok := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]
			if !ok || entry.Kind != "switch" || !strings.Contains(entry.Reason, "driver docker -> vm") || entry.Sandboxes != 1 {
				t.Fatalf("pending switch = %+v, present %t", entry, ok)
			}
			if entry.Reason != want.Reason || entry.From == nil || want.From == nil || entry.From.switchKey() != want.From.switchKey() {
				t.Errorf("reactivated pending switch = %+v, direct switch = %+v", entry, want)
			}
			if len(h.ops.stopped()) != 0 || containsLine(r.Changes, "switched the sandbox setup") {
				t.Errorf("running sandbox was switched: stops %v, changes %v", h.ops.stopped(), r.Changes)
			}
			if physicalExists(h.env.openshellKeptStatePath()) {
				t.Error("saved pending switch left the kept record")
			}
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
			r = ensureKeptHost(t, h, settings)
			requireOK(t, r)
			if !strings.Contains(sandboxSwitchLine(t, r), sandboxSwitchLeftovers) || len(h.env.loadOpenShellState().Pending) != 0 {
				t.Errorf("idle account did not finish the switch: changes %v", r.Changes)
			}
		})
	}
}

func TestKeptOpenShellSetupUninstallModes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			noSandbox := keptDockerHost(t, goos, false)
			r := noSandbox.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			layout := noSandbox.env.Layout
			wantSummary := "removed the machine state: the managed config and secrets (" + layout.ConfigDir + "), the gateway and guardian state (" + layout.DataDir + ", " + layout.GuardianAuthDir + "), the logs (" + layout.LogDir + "), the lifecycle state (" + layout.LifecycleDir + ") and the service account " + layout.ServiceUser
			if !containsLine(r.Changes, wantSummary) {
				t.Errorf("no-sandbox summary changed: %v", r.Changes)
			}
			if physicalExists(noSandbox.env.openshellStatePath()) || physicalExists(noSandbox.env.openshellKeptStatePath()) ||
				strings.Contains(strings.Join(r.Changes, "\n"), "record of the sandbox setup the kept sandboxes") {
				t.Errorf("no-sandbox uninstall kept a setup record: %v", r.Changes)
			}
			reactivated := ensureKeptHost(t, noSandbox, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671})
			requireOK(t, reactivated)
			fresh := newOSHost(t, goos)
			first := ensureKeptHost(t, fresh, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671})
			requireOK(t, first)
			if got, want := sandboxResultLines(reactivated), sandboxResultLines(first); !reflect.DeepEqual(got, want) {
				t.Errorf("no-sandbox reactivation = %v, first-time-on = %v", got, want)
			}
			if containsLine(reactivated.Changes, "switched the sandbox setup") {
				t.Errorf("no-sandbox reactivation reported a switch: %v", reactivated.Changes)
			}

			kept := keptDockerHost(t, goos, true)
			requireOK(t, kept.run(Options{Action: ActionUninstall}))
			if !physicalExists(kept.env.openshellKeptStatePath()) {
				t.Fatal("non-purge uninstall left no kept record")
			}
			purged := kept.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, purged)
			if physicalExists(kept.env.openshellKeptStatePath()) || len(kept.ops.teardowns) != 0 {
				t.Errorf("purge of uninstalled deployment used the hidden record: teardowns %v", kept.ops.teardowns)
			}
			firstPurge := keptDockerHost(t, goos, true)
			requireOK(t, firstPurge.run(Options{Action: ActionUninstall, Purge: true}))
			if physicalExists(firstPurge.env.openshellKeptStatePath()) {
				t.Error("first-uninstall purge kept the record")
			}
			requireOK(t, firstPurge.run(Options{Action: ActionUninstall}))
			if physicalExists(firstPurge.env.openshellKeptStatePath()) {
				t.Error("non-purge uninstall after purge resurrected the record")
			}
			keepState := keptDockerHost(t, goos, true)
			r = keepState.run(Options{Action: ActionUninstall, KeepState: true})
			requireOK(t, r)
			if !physicalExists(keepState.env.openshellKeptStatePath()) || physicalExists(keepState.env.openshellStatePath()) ||
				!strings.Contains(strings.Join(r.Changes, "\n"), "kept the record of the sandbox setup") {
				t.Errorf("--keep-state lost or omitted the kept setup record: %v", r.Changes)
			}
		})
	}
}

func sandboxResultLines(r *enterprisestatus.Result) []string {
	var lines []string
	for _, line := range r.Changes {
		if strings.Contains(line, "sandbox") || strings.Contains(line, "OpenShell") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestKeptOpenShellSetupAdoptionHygiene(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name   string
			mutate func(t *testing.T, h *osHost)
		}{
			{"malformed", func(t *testing.T, h *osHost) {
				t.Helper()
				if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"wrong version", func(t *testing.T, h *osHost) {
				t.Helper()
				if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte(`{"version":2,"applied":{"enabled":true,"install":"setup","driver":"docker","gateway_port":17671}}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"unknown field", func(t *testing.T, h *osHost) {
				t.Helper()
				if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte(`{"version":1,"applied":{"enabled":true,"install":"setup","driver":"docker","gateway_port":17671},"unexpected":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"oversize", func(t *testing.T, h *osHost) {
				t.Helper()
				if err := os.Truncate(h.env.openshellKeptStatePath(), maxInputBytes+1); err != nil {
					t.Fatal(err)
				}
			}},
			{"symlink", func(t *testing.T, h *osHost) {
				t.Helper()
				path := h.env.openshellKeptStatePath()
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "state.json")
				if err := os.WriteFile(target, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}},
			{"non-root owner", func(t *testing.T, h *osHost) {
				t.Helper()
				h.owners[h.env.openshellKeptStatePath()] = [2]int{2000, 2000}
			}},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				h := keptDockerHost(t, goos, true)
				requireOK(t, h.run(Options{Action: ActionUninstall}))
				if !physicalExists(h.env.openshellKeptStatePath()) {
					t.Fatal("uninstall did not keep the sandbox setup record")
				}
				tc.mutate(t, h)
				r := ensureKeptHost(t, h, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671})
				requireOK(t, r)
				if containsLine(r.Changes, "switched the sandbox setup") || physicalExists(h.env.openshellKeptStatePath()) {
					t.Errorf("invalid kept record was adopted or left after save: %v", r.Changes)
				}
			})
		}
		t.Run(goos+"/stale active state", func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !physicalExists(h.env.openshellKeptStatePath()) {
				t.Fatal("uninstall did not keep the sandbox setup record")
			}
			active := h.env.loadOpenShellState()
			active.Applied = &openshellApplied{Enabled: true, Install: "setup", Driver: "docker", Version: "0.1.5", GatewayPort: 17671, DockerNamespace: openshell.ManagedDockerNamespace}
			if err := h.env.saveOpenShellState(active); err != nil {
				t.Fatal(err)
			}
			r := ensureKeptHost(t, h, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17671})
			requireOK(t, r)
			if containsLine(r.Changes, "switched the sandbox setup") || physicalExists(h.env.openshellKeptStatePath()) {
				t.Errorf("stale kept record influenced an active setup: %v", r.Changes)
			}
		})
		t.Run(goos+"/rollback", func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			h.healthy = false
			settings := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5", "gateway_port": 17671}
			requireError(t, ensureKeptHost(t, h, settings), codeActivate)
			if !physicalExists(h.env.openshellKeptStatePath()) {
				t.Fatal("rollback removed the kept setup record")
			}
			if kept := h.env.loadKeptOpenShellState(); kept == nil || kept.Applied == nil || kept.Applied.Driver != "docker" {
				t.Errorf("rollback did not leave a readable record for a later attempt: %+v", kept)
			}
		})
		t.Run(goos+"/no save leaves invalid record", func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !physicalExists(h.env.openshellKeptStatePath()) {
				t.Fatal("uninstall did not keep the sandbox setup record")
			}
			if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := sandboxConfig(t, goos, false, nil)
			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), ConfigFile: writeTempConfig(t, cfg)})
			requireOK(t, r)
			if !physicalExists(h.env.openshellKeptStatePath()) {
				t.Error("an early return with no state save removed the kept file")
			}
		})
	}
}

func TestKeptOpenShellSetupCarriesPendingRestart(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			state := h.env.loadOpenShellState()
			state.Pending[strconv.Itoa(h.alice.UID)] = pending{User: h.alice.Name, UID: h.alice.UID, Home: h.alice.Home, Kind: "restart", Reason: "old unit inputs changed", Since: "2026-10-14T00:00:00Z"}
			if err := h.env.saveOpenShellState(state); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			// The uninstall stopped the daemon. Its pending restart needs no stop.
			h.ops.status[h.alice.UID] = SandboxStatus{}
			r := ensureKeptHost(t, h, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17672})
			requireOK(t, r)
			if len(h.env.loadOpenShellState().Pending) != 0 || !containsLine(r.Changes, "switched the sandbox setup") {
				t.Errorf("kept pending entry blocked the new switch: %v", r.Changes)
			}
		})
	}
}

// A record that cannot be kept (its mode was changed by hand) must not stop
// the uninstall or a package removal: the uninstall warns, removes the
// record as it did before kept sandboxes carried one, and goes on.
func TestKeptOpenShellSetupRecordProblemWarnsAndUninstallGoesOn(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			if err := os.Chmod(h.env.openshellStatePath(), 0o644); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			if !hasWarning(r, codeOpenShell) {
				t.Errorf("no warning for the record that could not be kept: %+v", r.Warnings)
			}
			if physicalExists(h.env.openshellStatePath()) || physicalExists(h.env.openshellKeptStatePath()) {
				t.Error("a record that could not be kept stayed behind")
			}
			if strings.Contains(strings.Join(r.Changes, "\n"), "record of the sandbox setup the kept sandboxes") {
				t.Errorf("the summary claims a kept record: %v", r.Changes)
			}
			// The kept sandboxes themselves stay, as before.
			if len(h.ops.teardowns) != 0 {
				t.Errorf("a non-purge uninstall tore down sandboxes: %v", h.ops.teardowns)
			}
		})
	}
}
