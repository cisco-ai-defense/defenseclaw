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

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const hermesAdmissionTestRawVersion = "Hermes Agent v0.20.0 (2026.8.3)"

func prepareHermesSetupAdmissionFixture(t *testing.T, opts SetupOpts) SetupOpts {
	t.Helper()
	if runtime.GOOS != "windows" {
		return opts
	}
	if err := ensureManagedBackupDirRestricted(opts.DataDir); err != nil {
		t.Fatalf("protect Hermes admission data directory: %v", err)
	}
	executable := filepath.Join(opts.DataDir, "managed-hermes", "hermes-agent", "venv", "Scripts", "hermes.exe")
	if err := atomicWriteFile(executable, []byte("MZ Hermes v0.20 admission fixture"), 0o700); err != nil {
		t.Fatalf("write Hermes admission executable: %v", err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok {
		t.Fatal("hash Hermes admission executable")
	}
	now := time.Now().UTC()
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		UpdatedAt:     now.Format(time.RFC3339),
		Selections: map[string]agentSelectionEvidence{
			// The peer proves Hermes admission accepts the generic integrator's
			// merged multi-connector receipt without rewriting or consuming it.
			"codex": {
				Connector:         "codex",
				Source:            "setup-selected",
				Executable:        filepath.Join(opts.DataDir, "peer", "codex.exe"),
				RawVersion:        "codex-cli 0.142.4",
				NormalizedVersion: "0.142.4",
				SHA256:            "1111111111111111111111111111111111111111111111111111111111111111",
				SelectedAt:        now.Add(-time.Second).Format(time.RFC3339),
				ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
			},
			"hermes": {
				Connector:         "hermes",
				Source:            "setup-selected",
				Executable:        stablePath,
				RawVersion:        hermesAdmissionTestRawVersion,
				NormalizedVersion: "0.20.0",
				SHA256:            digest,
				SelectedAt:        now.Add(-time.Second).Format(time.RFC3339),
				ExpiresAt:         now.Add(10 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(opts.DataDir, agentSelectionFile), append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write protected Hermes selection receipt: %v", err)
	}
	if _, ok := loadSetupAgentSelection(opts.DataDir, "hermes"); !ok {
		t.Fatal("Hermes admission fixture did not produce a valid protected receipt")
	}
	previousResolver := hermesManagedExecutablePathResolver
	previousProbe := hermesAgentVersionProbe
	hermesManagedExecutablePathResolver = func() string { return stablePath }
	hermesAgentVersionProbe = func(_ context.Context, probed string) (string, error) {
		if !sameCodexExecutablePath(probed, stablePath) {
			return "", fmt.Errorf("unexpected Hermes probe target")
		}
		return hermesAdmissionTestRawVersion, nil
	}
	t.Cleanup(func() {
		hermesManagedExecutablePathResolver = previousResolver
		hermesAgentVersionProbe = previousProbe
	})
	opts.AgentExecutable = stablePath
	opts.AgentVersion = hermesAdmissionTestRawVersion
	opts.HookContractID = "hermes-hooks-v1"
	return opts
}

func hermesAdmissionMutationTargets(opts SetupOpts, configPath string) []string {
	return []string{
		configPath,
		filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName),
		filepath.Join(opts.DataDir, activeConnectorFile),
		filepath.Join(opts.DataDir, hookContractLockFile),
		filepath.Join(opts.DataDir, ".hermes-lifecycle.lock"),
		filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh"),
		filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName),
		managedFileBackupPath(opts.DataDir, "hermes", "config"),
		managedFileBackupPath(opts.DataDir, "hermes", "config.yaml"),
		managedFileBackupPath(opts.DataDir, "hermes", hermesAllowlistLogicalName),
	}
}

func snapshotHermesAdmissionTargets(t *testing.T, paths []string) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			snapshot[path] = nil
			continue
		}
		if err != nil {
			t.Fatalf("snapshot %s: %v", path, err)
		}
		snapshot[path] = append([]byte(nil), body...)
	}
	return snapshot
}

func assertHermesAdmissionTargetsUnchanged(t *testing.T, snapshot map[string][]byte) {
	t.Helper()
	for path, want := range snapshot {
		got, err := os.ReadFile(path)
		if want == nil {
			if !os.IsNotExist(err) {
				t.Fatalf("admission failure created %s: %v", path, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("read unchanged target %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("admission failure mutated %s", path)
		}
	}
}
