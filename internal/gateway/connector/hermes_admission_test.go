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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const hermesAdmissionTestRawVersion = "Hermes Agent v0.21.5 (2026.9.24)"

func TestFirstHermesVersionLineAcceptsCurrentMultilineBanner(t *testing.T) {
	output := "\r\nHermes Agent v0.21.5 (2026.9.24)\r\n" +
		"Install directory: C:\\Users\\tester\\AppData\\Local\\hermes\\hermes-agent\r\n" +
		"Python: 3.11.15\r\nOpenAI SDK: 2.24.0\r\n"

	got, err := firstHermesVersionLine(output, "")
	if err != nil {
		t.Fatalf("parse current Hermes banner: %v", err)
	}
	if got != hermesAdmissionTestRawVersion {
		t.Fatalf("first Hermes version line = %q, want %q", got, hermesAdmissionTestRawVersion)
	}
}

func TestFirstHermesVersionLineFallsBackToStderr(t *testing.T) {
	got, err := firstHermesVersionLine(" \r\n\t\r\n", hermesAdmissionTestRawVersion+"\r\nPython: 3.11")
	if err != nil {
		t.Fatalf("parse Hermes stderr banner: %v", err)
	}
	if got != hermesAdmissionTestRawVersion {
		t.Fatalf("first Hermes stderr version line = %q, want %q", got, hermesAdmissionTestRawVersion)
	}
}

func TestFirstHermesVersionLineRejectsEmptyOrNULOutput(t *testing.T) {
	for name, stdout := range map[string]string{
		"empty": " \r\n\t\r\n",
		"NUL":   hermesAdmissionTestRawVersion + "\r\nPython: 3.11\x00",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := firstHermesVersionLine(stdout, ""); err == nil {
				t.Fatalf("unsafe Hermes output parsed as %q", got)
			}
		})
	}
}

func prepareHermesSetupAdmissionFixture(t *testing.T, opts SetupOpts) SetupOpts {
	t.Helper()
	if runtime.GOOS != "windows" {
		return opts
	}
	// Verify runs the registered command's execution probe. A per-user
	// install (no HookExecutable) registers the packaged launcher, which a
	// test binary does not have: give it one that answers, unless the test
	// pinned its own first (GAP-1069).
	if strings.TrimSpace(opts.HookExecutable) == "" && os.Getenv(testHermesProbeLauncherEnv) == "" {
		answerHermesProbeForTest(t)
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
				NormalizedVersion: "0.21.5",
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
	opts.HookContractID = "hermes-hooks-v2"
	return opts
}

// os/exec copies a command stream with io.Copy, which prefers the
// destination's ReadFrom. The bound must hold on that path too.
func TestHermesBoundedCommandBufferHoldsThroughIOCopy(t *testing.T) {
	const limit = 16
	buffer := &hermesBoundedCommandBuffer{limit: limit}
	source := strings.NewReader(strings.Repeat("x", 8<<20))
	copied, err := io.Copy(buffer, source)
	if err == nil {
		t.Fatalf("io.Copy of 8 MiB into a %d-byte bound succeeded (%d bytes)", limit, copied)
	}
	if got := len(buffer.String()); got != limit {
		t.Fatalf("buffer kept %d bytes; want %d", got, limit)
	}
	if _, isReaderFrom := any(buffer).(io.ReaderFrom); isReaderFrom {
		t.Fatal("bounded buffer exposes ReadFrom, which bypasses its Write bound")
	}
}
