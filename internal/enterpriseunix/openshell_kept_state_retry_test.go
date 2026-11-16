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
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func failedUninstallWithKeptSandbox(t *testing.T, goos string) *osHost {
	t.Helper()
	h := keptDockerHost(t, goos, true)
	h.services.failReloadOnce = true
	requireError(t, h.run(Options{Action: ActionUninstall}), codeUninstall)
	store := h.env.P(filepath.Join(h.env.Layout.DataDir, "sandbox", "registrations", strconv.Itoa(h.alice.UID)+".json"))
	key := h.env.P(filepath.Join(h.env.Layout.DataDir, "redaction-correlation.key"))
	if !physicalExists(h.env.deploymentPath()) || !physicalExists(h.env.openshellKeptStatePath()) ||
		physicalExists(h.env.openshellStatePath()) || !physicalExists(store) || !physicalExists(key) {
		t.Fatalf("failed uninstall did not leave the deployment, kept setup, store and key for retry")
	}
	return h
}

func retrySandboxPaths(h *osHost) (homeRecord, store, key string) {
	homeRecord = h.env.P(filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", "sb-kept", "record.json"))
	store = h.env.P(filepath.Join(h.env.Layout.DataDir, "sandbox", "registrations", strconv.Itoa(h.alice.UID)+".json"))
	key = h.env.P(filepath.Join(h.env.Layout.DataDir, "redaction-correlation.key"))
	return
}

func TestKeptOpenShellSetupRetryPlainUninstallKeepsSandboxState(t *testing.T) {
	settings := map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5", "gateway_port": 17672}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			direct := keptDockerHost(t, goos, true)
			directResult := ensureKeptHost(t, direct, settings)
			requireOK(t, directResult)
			wantSwitch := sandboxSwitchLine(t, directResult)
			if !strings.Contains(wantSwitch, "gateway port 17671 -> 17672") {
				t.Fatalf("direct switch = %q", wantSwitch)
			}

			h := failedUninstallWithKeptSandbox(t, goos)
			if accounts := (&lifecycle{env: h.env}).sandboxAccounts(context.Background()); len(accounts) != 1 || accounts[0].Name != "alice" {
				t.Fatalf("failed uninstall retry found accounts %v", accounts)
			}
			homeRecord, store, key := retrySandboxPaths(h)
			r := h.run(Options{Action: ActionUninstall})
			requireOK(t, r)
			if !physicalExists(h.env.openshellKeptStatePath()) || !physicalExists(store) || !physicalExists(key) || !physicalExists(homeRecord) {
				t.Fatalf("plain retry lost kept sandbox state: changes %v", r.Changes)
			}
			changes := strings.Join(r.Changes, "\n")
			for _, want := range []string{"kept the sandboxes of alice", filepath.Join(h.env.Layout.DataDir, "sandbox"), filepath.Join(h.env.Layout.DataDir, "redaction-correlation.key"), "except the record of the sandbox setup the kept sandboxes were made under, " + filepath.Join(h.env.Layout.LifecycleDir, "openshell-state.kept.json")} {
				if !strings.Contains(changes, want) {
					t.Errorf("plain retry summary omitted %q: %v", want, r.Changes)
				}
			}
			if len(h.ops.teardowns) != 0 {
				t.Errorf("plain retry tore down sandboxes: %v", h.ops.teardowns)
			}
			if physicalExists(h.env.deploymentPath()) {
				t.Error("successful retry left the deployment record")
			}
			reactivated := ensureKeptHost(t, h, settings)
			requireOK(t, reactivated)
			if got := sandboxSwitchLine(t, reactivated); got != wantSwitch {
				t.Errorf("retry switch = %q, direct switch = %q", got, wantSwitch)
			}
			if physicalExists(h.env.openshellKeptStatePath()) {
				t.Error("successful ensure left the adopted kept setup")
			}
		})
	}
}

func TestKeptOpenShellSetupRetryPurgeTearsDownSandboxes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, failTeardown := range []bool{false, true} {
			name := "teardown succeeds"
			if failTeardown {
				name = "teardown warns"
			}
			t.Run(goos+"/"+name, func(t *testing.T) {
				h := failedUninstallWithKeptSandbox(t, goos)
				if failTeardown {
					h.ops.teardownErr = errors.New("sandbox launcher is unavailable")
				}
				homeRecord, store, key := retrySandboxPaths(h)
				r := h.run(Options{Action: ActionUninstall, Purge: true})
				requireOK(t, r)
				if !reflect.DeepEqual(h.ops.teardowns, []string{"alice"}) {
					t.Errorf("purge retry teardowns = %v", h.ops.teardowns)
				}
				warning := messagesOf(r.Warnings, codeSandboxUserState)
				if failTeardown && !strings.Contains(warning, "sandbox teardown did not finish for user alice") {
					t.Errorf("failed teardown warning = %q", warning)
				}
				if !failTeardown && strings.Contains(warning, "sandbox teardown did not finish") {
					t.Errorf("successful teardown warned: %q", warning)
				}
				if physicalExists(h.env.openshellKeptStatePath()) || physicalExists(store) || physicalExists(key) || physicalExists(homeRecord) {
					t.Errorf("purge retry left local sandbox state: changes %v", r.Changes)
				}
			})
		}
	}
}

func TestKeptOpenShellSetupRetryControls(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos+"/completed uninstall purge ignores kept setup", func(t *testing.T) {
			h := keptDockerHost(t, goos, true)
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if physicalExists(h.env.deploymentPath()) || !physicalExists(h.env.openshellKeptStatePath()) {
				t.Fatal("completed uninstall did not leave only the kept setup")
			}
			requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
			if len(h.ops.teardowns) != 0 || physicalExists(h.env.openshellKeptStatePath()) {
				t.Errorf("completed uninstall purge read the kept setup: teardowns %v", h.ops.teardowns)
			}
		})

		for _, tc := range []struct {
			name   string
			mutate func(*testing.T, *osHost)
		}{
			{"malformed", func(t *testing.T, h *osHost) {
				if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"empty", func(t *testing.T, h *osHost) {
				if err := os.WriteFile(h.env.openshellKeptStatePath(), []byte(`{"version":1,"pending":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"non-root owner", func(_ *testing.T, h *osHost) {
				h.owners[h.env.openshellKeptStatePath()] = [2]int{2000, 2000}
			}},
			{"symlink", func(t *testing.T, h *osHost) {
				path := h.env.openshellKeptStatePath()
				target := filepath.Join(t.TempDir(), "setup.json")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
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
		} {
			t.Run(goos+"/invalid kept setup/"+tc.name, func(t *testing.T) {
				h := failedUninstallWithKeptSandbox(t, goos)
				tc.mutate(t, h)
				_, store, key := retrySandboxPaths(h)
				requireOK(t, h.run(Options{Action: ActionUninstall}))
				if physicalExists(h.env.openshellKeptStatePath()) || physicalExists(store) || physicalExists(key) || len(h.ops.teardowns) != 0 {
					t.Errorf("invalid kept setup affected retry: teardowns %v", h.ops.teardowns)
				}
			})
		}

		t.Run(goos+"/populated active setup wins", func(t *testing.T) {
			h := failedUninstallWithKeptSandbox(t, goos)
			active := h.env.loadOpenShellState()
			active.Applied = &openshellApplied{Enabled: true, Install: "setup", Driver: "docker", Version: "0.1.5", GatewayPort: 17671, DockerNamespace: openshell.ManagedDockerNamespace}
			if err := h.env.saveOpenShellState(active); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			kept := h.env.loadKeptOpenShellState()
			if kept == nil || kept.Applied == nil || kept.Applied.DockerNamespace != openshell.ManagedDockerNamespace {
				t.Errorf("stale kept setup took precedence over active setup: %+v", kept)
			}
		})

		t.Run(goos+"/no sandbox remains", func(t *testing.T) {
			h := failedUninstallWithKeptSandbox(t, goos)
			for _, rel := range []string{h.env.daemonStateRel(), installStateRel, openshellVMStateRel} {
				if err := os.RemoveAll(h.env.P(filepath.Join(h.alice.Home, rel))); err != nil {
					t.Fatal(err)
				}
			}
			_, store, key := retrySandboxPaths(h)
			if err := os.Remove(store); err != nil {
				t.Fatal(err)
			}
			if h.env.hasHomeSandboxState(h.alice) {
				t.Fatal("test account still has sandbox state")
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if physicalExists(h.env.openshellKeptStatePath()) || physicalExists(key) || len(h.ops.teardowns) != 0 {
				t.Errorf("retry with no sandbox kept state: teardowns %v", h.ops.teardowns)
			}
		})
	}
}
