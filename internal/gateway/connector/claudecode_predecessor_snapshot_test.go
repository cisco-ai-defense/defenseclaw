// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// An upgrade can take the exact settings.json snapshot from a file an
// earlier release still managed, while the env backup holds the operator's
// real env. Uninstall must not put that release's values back (SWEEP-14).
func TestClaudeCode_TeardownDropsEarlierReleaseEnvFromExactSnapshot(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })

	operatorEnv := map[string]interface{}{"AWS_REGION": "us-east-1", "PATH": "/operator/bin"}
	data, err := json.Marshal(map[string]interface{}{"env": operatorEnv})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{
		DataDir:       dir,
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
		HookFailMode:  "closed",
	}
	c := NewClaudeCodeConnector()
	// The earlier release: fail closed and prompt capture on at the source.
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("earlier Setup: %v", err)
	}
	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings["env"].(map[string]interface{})["OTEL_LOG_USER_PROMPTS"] = "1"
	if data, err = json.Marshal(settings); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// The upgrade lost the exact snapshot, so the next Setup takes it from
	// the file the earlier release still manages.
	if err := os.Remove(managedFileBackupPath(dir, c.Name(), "settings.json")); err != nil {
		t.Fatal(err)
	}
	opts.HookFailMode = "open"
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	settings = map[string]interface{}{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if got := settings["env"]; !reflect.DeepEqual(got, operatorEnv) {
		t.Fatalf("env after teardown = %v, want only the operator env %v", got, operatorEnv)
	}
}
