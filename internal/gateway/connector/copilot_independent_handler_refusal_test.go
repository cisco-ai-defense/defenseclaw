// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2372: an independent handler the operator added on a bound event of
// DefenseClaw's own Copilot hook file is the operator's choice. Setup cannot
// restore that event without dropping it, so it refuses before it changes
// anything, as an agent setting that turns the hooks off does
// (ErrAgentConfigRefusal): a gateway start then keeps every other connector
// instead of failing for all of them, and the refusal names the move.
func TestCopilotIndependentHandlerIsAnAgentSettingsRefusal(t *testing.T) {
	copilotHome := t.TempDir()
	t.Setenv("COPILOT_HOME", copilotHome)
	dataDir := t.TempDir()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok"}
	conn := NewCopilotConnector()
	path := conn.configPath(opts)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	field := "bash"
	if runtime.GOOS == "windows" {
		field = "powershell"
	}
	own := copilotHookRegistration(runtime.GOOS, "preToolUse", conn.hookCommand(opts))
	write := func(entries ...interface{}) []byte {
		t.Helper()
		if err := writeJSONObject(path, map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"preToolUse": entries}}); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	write(own)
	if err := CheckAgentSettings(conn, opts); err != nil {
		t.Fatalf("DefenseClaw's own handler alone: %v", err)
	}

	before := write(own, map[string]interface{}{"type": "command", field: "bash /opt/operator/retired-open.sh --event preToolUse"})
	err := CheckAgentSettings(conn, opts)
	if !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), "move it to another hook file") ||
		!strings.Contains(err.Error(), `"preToolUse"`) {
		t.Fatalf("CheckAgentSettings = %v; want the agent-settings refusal that names the move", err)
	}
	err = NewCopilotConnector().Setup(context.Background(), opts)
	if !errors.Is(err, ErrSetupRefusedUnchanged) || !errors.Is(err, ErrAgentConfigRefusal) {
		t.Fatalf("Setup = %v; want the refusal before any change", err)
	}
	if after, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(after, before) {
		t.Fatalf("Setup changed the hook file: %q (%v)", after, readErr)
	}
	entries, readErr := os.ReadDir(dataDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".lock") {
			t.Errorf("Setup wrote %s into the data dir before refusing", entry.Name())
		}
	}
}
