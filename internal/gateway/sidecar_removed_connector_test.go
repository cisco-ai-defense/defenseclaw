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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// retiredExampleConnector is a made-up connector name that no build ships.
// It stands in for any connector an older release registered.
const retiredExampleConnector = "retired-example"

// stageRetiredExampleLock records a lock entry for retiredExampleConnector
// and returns the path of a host hook file that must never be touched.
func stageRetiredExampleLock(t *testing.T, dataDir string) (hookPath string, hookBody []byte) {
	t.Helper()
	hookPath = filepath.Join(testenv.PrivateTempDir(t), "agent-hooks.json")
	hookBody = []byte("{\"hooks\":{\"pre\":[{\"command\":\"/opt/old/hook.sh\"}]}}\n")
	if err := os.WriteFile(hookPath, hookBody, 0o600); err != nil {
		t.Fatal(err)
	}
	stub := &bootStubConnector{
		stubConnector: stubConnector{name: retiredExampleConnector},
		artifactPath:  hookPath,
	}
	opts := connector.SetupOpts{DataDir: dataDir, HookFailMode: "closed", GuardrailMode: "action"}
	if err := connector.SaveFreshHookContractLockEntry(
		dataDir,
		connector.NewHookContractLockEntry(opts, stub, "0.8.10"),
	); err != nil {
		t.Fatalf("stage lock entry: %v", err)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, retiredExampleConnector); got.Connector == "" {
		t.Fatal("fixture did not record a lock entry")
	}
	return hookPath, hookBody
}

func TestOrphanLockDropsUnregisteredConnector(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	hookPath, hookBody := stageRetiredExampleLock(t, dataDir)
	priorRoster := []string{"claudecode", "codex"}
	if err := connector.SaveActiveConnectors(dataDir, priorRoster); err != nil {
		t.Fatal(err)
	}

	var audited []string
	resolveCalls := 0
	err := reconcileOrphanedConnectorRegistrations(
		context.Background(),
		connector.NewDefaultRegistry(),
		dataDir,
		priorRoster,
		orphanConnectorReconcileOps{
			resolveOpts: func(connector.Connector) (connector.SetupOpts, error) {
				resolveCalls++
				return connector.SetupOpts{}, nil
			},
			clearLock: connector.ClearHookContractLockEntry,
			audit:     func(name string) { audited = append(audited, name) },
		},
	)
	if err != nil {
		t.Fatalf("an unregistered lock-only connector must not block boot: %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("resolveOpts called %d times for a connector with no teardown owner", resolveCalls)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, retiredExampleConnector); got.Connector != "" {
		t.Fatalf("lock entry survived: %+v", got)
	}
	if body, readErr := os.ReadFile(hookPath); readErr != nil || !reflect.DeepEqual(body, hookBody) {
		t.Fatalf("host hook file = %q, %v; want untouched %q", body, readErr, hookBody)
	}
	if got := connector.LoadActiveConnectors(dataDir); !reflect.DeepEqual(got, priorRoster) {
		t.Fatalf("active roster = %v, want %v", got, priorRoster)
	}
	if !reflect.DeepEqual(audited, []string{retiredExampleConnector}) {
		t.Fatalf("audited = %v, want [%s]", audited, retiredExampleConnector)
	}
}

func TestTeardownRemovedConnectorsDropsUnregistered(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	hookPath, hookBody := stageRetiredExampleLock(t, dataDir)
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "hooks", retiredExampleConnector+"-hook.sh"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	codex := &recordingConnector{stubConnector: stubConnector{name: "codex"}}
	reg := newRecordingRegistry(codex)

	failed, dropped := teardownRemovedConnectorsReport(
		reg,
		[]string{retiredExampleConnector, "codex"},
		nil,
		connector.SetupOpts{DataDir: dataDir},
		context.Background(),
	)
	if len(failed) != 0 {
		t.Fatalf("failed = %v, want none: an unregistered name is dropped, not retried", failed)
	}
	if !reflect.DeepEqual(dropped, []string{retiredExampleConnector}) {
		t.Fatalf("dropped = %v, want [%s]", dropped, retiredExampleConnector)
	}
	if codex.teardownCalls != 1 {
		t.Fatalf("registered connector teardownCalls = %d, want 1", codex.teardownCalls)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, retiredExampleConnector); got.Connector != "" {
		t.Fatalf("lock entry survived: %+v", got)
	}
	if body, readErr := os.ReadFile(hookPath); readErr != nil || !reflect.DeepEqual(body, hookBody) {
		t.Fatalf("host hook file = %q, %v; want untouched %q", body, readErr, hookBody)
	}

	// DefenseClaw's own hook script for the dropped name is gone.
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks", retiredExampleConnector+"-hook.sh")); !os.IsNotExist(err) {
		t.Fatalf("hook script for the dropped connector survived: %v", err)
	}

	// The compatibility wrapper keeps its historical return value.
	if got := teardownRemovedConnectors(reg, []string{retiredExampleConnector}, nil, connector.SetupOpts{DataDir: dataDir}, context.Background()); len(got) != 0 {
		t.Fatalf("teardownRemovedConnectors failed = %v, want none", got)
	}
}

// registryWithFailedPluginDiscovery returns a registry whose plugin discovery
// reported an error, so any unresolved name may still be a plugin.
func registryWithFailedPluginDiscovery(t *testing.T, conns ...*recordingConnector) *connector.Registry {
	t.Helper()
	reg := newRecordingRegistry(conns...)
	notADir := filepath.Join(testenv.PrivateTempDir(t), "plugins")
	if err := os.WriteFile(notADir, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reg.DiscoverPlugins(notADir); err == nil {
		t.Fatal("plugin discovery on a regular file must fail")
	}
	return reg
}

// A lock-only name that a plugin may still provide (discovery failed) keeps
// the strict behaviour: boot reports it instead of forgetting its state.
func TestOrphanLockKeepsNameWhenPluginDiscoveryFailed(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	stageRetiredExampleLock(t, dataDir)
	err := reconcileOrphanedConnectorRegistrations(
		context.Background(),
		registryWithFailedPluginDiscovery(t),
		dataDir,
		nil,
		orphanConnectorReconcileOps{
			resolveOpts: func(connector.Connector) (connector.SetupOpts, error) { return connector.SetupOpts{}, nil },
			clearLock:   connector.ClearHookContractLockEntry,
		},
	)
	if err == nil {
		t.Fatal("a lock-only name a plugin may provide must not be dropped silently")
	}
	if got := connector.LoadHookContractLockEntry(dataDir, retiredExampleConnector); got.Connector == "" {
		t.Fatal("lock entry was dropped although plugin discovery failed")
	}
}

// A removed name that a plugin may still provide is retained for a later
// teardown retry and none of its files are removed.
func TestTeardownRemovedConnectorsRetainsNameWhenPluginDiscoveryFailed(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	stageRetiredExampleLock(t, dataDir)
	script := filepath.Join(dataDir, "hooks", retiredExampleConnector+"-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	failed, dropped := teardownRemovedConnectorsReport(
		registryWithFailedPluginDiscovery(t),
		[]string{retiredExampleConnector},
		nil,
		connector.SetupOpts{DataDir: dataDir},
		context.Background(),
	)
	if !reflect.DeepEqual(failed, []string{retiredExampleConnector}) || len(dropped) != 0 {
		t.Fatalf("failed=%v dropped=%v; want the name retained for retry", failed, dropped)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, retiredExampleConnector); got.Connector == "" {
		t.Fatal("lock entry was dropped although plugin discovery failed")
	}
	if _, err := os.Lstat(script); err != nil {
		t.Fatalf("hook script removed although plugin discovery failed: %v", err)
	}
}
