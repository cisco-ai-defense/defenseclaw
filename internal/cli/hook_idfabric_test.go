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

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/idfabric"
)

// spoolEntries lists the records written to a spool directory.
func spoolEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestCaptureIdentityFabricTelemetryDisabledLeavesStdinAlone(t *testing.T) {
	home := t.TempDir()
	spoolDir := filepath.Join(home, "spool")
	t.Setenv(idfabric.SpoolDirEnv, spoolDir)
	t.Setenv(idfabric.EnableEnv, "")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")

	original := strings.NewReader(`{"session_id":"s1"}`)
	opts := hookexec.Options{Home: home, Stdin: original}

	captureIdentityFabricTelemetry(&opts, "codex", "session_start", false)

	if opts.Stdin != io.Reader(original) {
		t.Error("stdin was replaced while capture is disabled")
	}
	if names := spoolEntries(t, spoolDir); len(names) != 0 {
		t.Errorf("wrote %v, want no records while disabled", names)
	}
}

func TestCaptureIdentityFabricTelemetryReplaysStdinByteForByte(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	spoolDir := filepath.Join(home, "spool")
	t.Setenv(idfabric.SpoolDirEnv, spoolDir)
	t.Setenv(idfabric.EnableEnv, "1")

	payload := `{"session_id":"s1","model":"gpt-5","tool_name":"Bash"}`
	opts := hookexec.Options{Home: home, Stdin: strings.NewReader(payload)}

	captureIdentityFabricTelemetry(&opts, "codex", "session_start", false)

	replayed, err := io.ReadAll(opts.Stdin)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(replayed) != payload {
		t.Errorf("replayed stdin = %q, want %q", replayed, payload)
	}
	if names := spoolEntries(t, spoolDir); len(names) != 2 {
		t.Errorf("wrote %v, want the event and inventory records", names)
	}
}

func TestCaptureIdentityFabricTelemetryPreservesOversizedPayloadDetection(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv(idfabric.SpoolDirEnv, filepath.Join(home, "spool"))
	t.Setenv(idfabric.EnableEnv, "1")

	// hookexec detects an oversized payload by reading one byte past its cap,
	// so the replayed reader must still be able to supply that byte.
	const cap = 16
	payload := strings.Repeat("x", cap*4)
	opts := hookexec.Options{Home: home, Stdin: strings.NewReader(payload), MaxBody: cap}

	captureIdentityFabricTelemetry(&opts, "codex", "session_start", false)

	replayed, err := io.ReadAll(opts.Stdin)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(replayed) != cap+1 {
		t.Errorf("replayed %d bytes, want %d so the overflow check still trips", len(replayed), cap+1)
	}
}

func TestCaptureIdentityFabricTelemetryNilOptionsIsSafe(t *testing.T) {
	t.Setenv(idfabric.EnableEnv, "1")
	captureIdentityFabricTelemetry(nil, "codex", "session_start", false)
}

// setTestHome points user-home lookup at a scratch directory so connector
// account probing cannot read the developer's real credentials.
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("CODEX_HOME", filepath.Join(dir, ".codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(dir, ".claude"))
}
