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
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// managedSetupSelectionLifetime keeps a guardian-written receipt well inside
// agentSelectionMaxLifetime; the guardian consumes it in the same reconcile.
const managedSetupSelectionLifetime = 10 * time.Minute

// ProtectedSetupSelectionConnector reports whether a connector binds its
// setup and contract publication to a protected, setup-selected executable on
// this OS.
func ProtectedSetupSelectionConnector(connectorName string) bool {
	return protectedSetupSelectionConnectorForOS(connectorName, runtime.GOOS)
}

// WriteManagedSetupAgentSelection records the executable that the managed
// enterprise guardian discovered and hashed for one per-user connector, in
// the same protected agent_selection.json receipt an explicit per-user setup
// writes. The connector's executable admission and its contract publication
// then bind to that exact image. In managed mode the guardian is the
// selecting authority; the receipt only carries its choice into the connector.
func WriteManagedSetupAgentSelection(dataDir, connectorName, executable, rawVersion string) error {
	connectorName = normalizeConnectorName(connectorName)
	if !ProtectedSetupSelectionConnector(connectorName) {
		return fmt.Errorf("connector %q does not use a protected executable selection", connectorName)
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return errors.New("managed selection state directory is not an absolute normalized path")
	}
	rawVersion = strings.TrimSpace(rawVersion)
	resolution := ResolveHookContract(connectorName, rawVersion)
	if resolution.Status != HookCompatibilityKnown {
		return fmt.Errorf("agent version %q is not verified against a known hook contract", rawVersion)
	}
	stable, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok || !sameCodexExecutablePath(stable, executable) {
		return errors.New("selected executable is missing or changed during stable hashing")
	}
	now := time.Now().UTC()
	receipt := agentSelectionReceipt{
		SchemaVersion: agentSelectionSchemaVersion,
		Selections:    map[string]agentSelectionEvidence{},
	}
	if data, exists := readStablePrivateStateFile(dataDir, agentSelectionFile, agentSelectionMaxBytes); exists {
		var existing agentSelectionReceipt
		if json.Unmarshal(data, &existing) == nil && existing.SchemaVersion == agentSelectionSchemaVersion {
			for name, selection := range existing.Selections {
				if name != connectorName {
					receipt.Selections[name] = selection
				}
			}
		}
	}
	receipt.Selections[connectorName] = agentSelectionEvidence{
		Connector:         connectorName,
		Source:            "setup-selected",
		Executable:        stable,
		RawVersion:        rawVersion,
		NormalizedVersion: resolution.NormalizedVersion,
		SHA256:            digest,
		SelectedAt:        now.Format(time.RFC3339),
		ExpiresAt:         now.Add(managedSetupSelectionLifetime).Format(time.RFC3339),
	}
	receipt.UpdatedAt = now.Format(time.RFC3339)
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, agentSelectionFile)
	return withFileLockMode(path, true, func() error {
		return hookRuntimeFileWriter(true)(path, append(data, '\n'), 0o600)
	})
}
