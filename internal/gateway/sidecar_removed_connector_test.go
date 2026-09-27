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

	// The compatibility wrapper keeps its historical return value.
	if got := teardownRemovedConnectors(reg, []string{retiredExampleConnector}, nil, connector.SetupOpts{DataDir: dataDir}, context.Background()); len(got) != 0 {
		t.Fatalf("teardownRemovedConnectors failed = %v, want none", got)
	}
}
