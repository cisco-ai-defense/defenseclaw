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

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const managedSelectionAmpVersion = "0.0.1785875347-gbc402f"

func managedSelectionFixture(t *testing.T) (dataDir, executable string) {
	t.Helper()
	dataDir = filepath.Join(testenv.PrivateTempDir(t), "data")
	if err := ensureManagedBackupDirRestricted(dataDir); err != nil {
		t.Fatalf("prepare protected state: %v", err)
	}
	executable = filepath.Join(testenv.PrivateTempDir(t), "amp.exe")
	if err := atomicWriteFile(executable, []byte("guardian-selected native Amp image"), 0o700); err != nil {
		t.Fatalf("write Amp executable fixture: %v", err)
	}
	return dataDir, executable
}

func TestManagedSetupSelectionAdmitsGuardianSelectedAmpImage(t *testing.T) {
	dataDir, executable := managedSelectionFixture(t)
	if err := WriteManagedSetupAgentSelection(dataDir, "amp", executable, managedSelectionAmpVersion); err != nil {
		t.Fatalf("write managed selection: %v", err)
	}
	resolution := ResolveHookContract("amp", managedSelectionAmpVersion)
	opts := SetupOpts{
		DataDir:         dataDir,
		AgentExecutable: executable,
		AgentVersion:    managedSelectionAmpVersion,
		HookContractID:  resolution.Contract.ContractID,
	}
	if err := validateAmpWindowsSetupAdmission(opts); err != nil {
		t.Fatalf("admission with guardian selection: %v", err)
	}

	// A replaced image after selection must still be refused.
	if err := atomicWriteFile(executable, []byte("replacement bytes"), 0o700); err != nil {
		t.Fatalf("replace executable: %v", err)
	}
	if err := validateAmpWindowsSetupAdmission(opts); err == nil ||
		!strings.Contains(err.Error(), "digest does not match protected evidence") {
		t.Fatalf("admission after replacement error=%v, want digest rejection", err)
	}
}

func TestManagedSetupSelectionPreservesOtherConnectorSelections(t *testing.T) {
	dataDir, executable := managedSelectionFixture(t)
	other := filepath.Join(testenv.PrivateTempDir(t), "codex.exe")
	if err := atomicWriteFile(other, []byte("codex image"), 0o700); err != nil {
		t.Fatalf("write codex fixture: %v", err)
	}
	if err := WriteManagedSetupAgentSelection(dataDir, "amp", executable, managedSelectionAmpVersion); err != nil {
		t.Fatalf("first selection: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dataDir, agentSelectionFile))
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var receipt agentSelectionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	receipt.Selections["codex"] = agentSelectionEvidence{Connector: "codex", Source: "setup-selected", Executable: other}
	merged, _ := json.Marshal(receipt)
	if err := hookRuntimeFileWriter(true)(filepath.Join(dataDir, agentSelectionFile), merged, 0o600); err != nil {
		t.Fatalf("seed second selection: %v", err)
	}
	if err := WriteManagedSetupAgentSelection(dataDir, "amp", executable, managedSelectionAmpVersion); err != nil {
		t.Fatalf("second selection: %v", err)
	}
	data, _ = os.ReadFile(filepath.Join(dataDir, agentSelectionFile))
	receipt = agentSelectionReceipt{}
	_ = json.Unmarshal(data, &receipt)
	if _, ok := receipt.Selections["codex"]; !ok {
		t.Fatalf("managed selection dropped another connector's selection: %s", data)
	}
}

func TestManagedSetupSelectionRefusesUnknownContractsAndUnprotectedConnectors(t *testing.T) {
	dataDir, executable := managedSelectionFixture(t)
	if err := WriteManagedSetupAgentSelection(dataDir, "amp", executable, "not-a-version"); err == nil ||
		!strings.Contains(err.Error(), "known hook contract") {
		t.Fatalf("unknown version error=%v, want contract refusal", err)
	}
	if err := WriteManagedSetupAgentSelection(dataDir, "copilot", executable, "1.0.88"); err == nil {
		t.Fatalf("copilot has no protected executable selection; expected refusal")
	}
	if _, err := os.Stat(filepath.Join(dataDir, agentSelectionFile)); !os.IsNotExist(err) {
		t.Fatalf("refused selections must not write a receipt: %v", err)
	}
}
