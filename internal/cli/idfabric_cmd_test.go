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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/idfabric"
)

// runIDFabricCapture executes the capture subcommand with payload on stdin and
// returns the spool directory it wrote to.
func runIDFabricCapture(t *testing.T, payload string, args ...string) (string, error) {
	t.Helper()
	spoolDir := filepath.Join(t.TempDir(), "spool")
	t.Setenv(idfabric.SpoolDirEnv, spoolDir)

	stdinPath := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(stdinPath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	stdin, err := os.Open(stdinPath)
	if err != nil {
		t.Fatalf("open payload: %v", err)
	}
	defer func() { _ = stdin.Close() }()

	original := os.Stdin
	os.Stdin = stdin
	defer func() { os.Stdin = original }()

	cmd := newIDFabricCaptureCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return spoolDir, cmd.Execute()
}

func spooledRecords(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read spool dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestIDFabricCaptureWritesRecordsFromStdin covers the entrypoint the Unix
// hooks use. Without it the .sh hooks, which curl the gateway and never run
// the native hook command, produce no telemetry at all.
func TestIDFabricCaptureWritesRecordsFromStdin(t *testing.T) {
	payload := `{"hook_event_name":"sessionStart","session_id":"s-1","cursor_version":"3.10.17","user_email":"user@example.com"}`
	spoolDir, err := runIDFabricCapture(t, payload,
		"--connector", "cursor", "--event", "sessionStart", "--enterprise-managed")
	if err != nil {
		t.Fatalf("capture returned an error: %v", err)
	}

	names := spooledRecords(t, spoolDir)
	if len(names) == 0 {
		t.Fatal("capture wrote no records")
	}
	var sawEvent, sawInventory bool
	for _, name := range names {
		switch {
		case filepath.Ext(name) != ".json":
			t.Errorf("unexpected spool entry %q", name)
		case len(name) > 10 && name[:10] == "agentevent":
			sawEvent = true
		default:
			sawInventory = true
		}
	}
	if !sawEvent {
		t.Error("capture wrote no session_start event record")
	}
	if !sawInventory {
		t.Error("capture wrote no inventory record")
	}
}

// TestIDFabricCaptureIsInertWhenDisabled pins the gate. An unmanaged endpoint
// must not accumulate records, so the disabled path must not even create the
// spool directory.
func TestIDFabricCaptureIsInertWhenDisabled(t *testing.T) {
	t.Setenv(idfabric.EnableEnv, "")
	payload := `{"hook_event_name":"sessionStart","session_id":"s-1"}`
	spoolDir, err := runIDFabricCapture(t, payload, "--connector", "cursor", "--event", "sessionStart")
	if err != nil {
		t.Fatalf("capture returned an error: %v", err)
	}
	if names := spooledRecords(t, spoolDir); len(names) != 0 {
		t.Errorf("disabled capture wrote %v", names)
	}
}

// TestIDFabricCaptureSucceedsOnUnusablePayload keeps telemetry from becoming a
// guardrail failure. The shell backgrounds this next to a fail-closed hook, so
// a nonzero exit on a payload the record cannot describe would be a far worse
// outcome than a missing record.
func TestIDFabricCaptureSucceedsOnUnusablePayload(t *testing.T) {
	for _, payload := range []string{
		"",
		"not json at all",
		`{"hook_event_name":"anEventNobodySupports"}`,
		`{"hook_event_name":{"nested":"wrong type"}}`,
	} {
		spoolDir, err := runIDFabricCapture(t, payload,
			"--connector", "cursor", "--enterprise-managed")
		if err != nil {
			t.Errorf("payload %q returned an error: %v", payload, err)
		}
		// Records are optional here; not failing is the contract.
		_ = spoolDir
	}
}

// TestIDFabricCaptureSucceedsOnUnsupportedConnector covers a hook shipped
// ahead of connector support in idfabric.
func TestIDFabricCaptureSucceedsOnUnsupportedConnector(t *testing.T) {
	payload := `{"hook_event_name":"sessionStart","session_id":"s-1"}`
	spoolDir, err := runIDFabricCapture(t, payload,
		"--connector", "someconnectorwedonotmodel", "--enterprise-managed")
	if err != nil {
		t.Fatalf("capture returned an error: %v", err)
	}
	if names := spooledRecords(t, spoolDir); len(names) != 0 {
		t.Errorf("unsupported connector wrote %v", names)
	}
}
