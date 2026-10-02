// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// GAP-1926: after a rollback the earlier release's gateway registers
// DefenseClaw's hooks again, and this release's setup then backs up that
// file as the operator's. Teardown restores it and must still remove
// DefenseClaw's own hooks from it.
func TestHookOnlyTeardownRemovesOwnHooksFromRestoredBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook commands")
	}
	for _, conn := range []*hookOnlyConnector{NewCopilotConnector(), NewOpenHandsConnector()} {
		t.Run(conn.Name(), func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, conn.Name(), "hooks.json")
			ptr := &OpenHandsHooksPathOverride
			if conn.Name() == "copilot" {
				cfgPath = filepath.Join(dir, conn.Name(), "defenseclaw.json")
				ptr = &CopilotHooksPathOverride
			}
			prev := *ptr
			*ptr = cfgPath
			t.Cleanup(func() { *ptr = prev })
			opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir()}
			if conn.Name() == "openhands" {
				opts = prepareOpenHandsSetupAdmissionFixture(t, opts)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			registered, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := os.WriteFile(cfgPath, registered, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup over the re-registered file: %v", err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if err := conn.VerifyClean(opts); err != nil {
				t.Fatalf("VerifyClean: %v", err)
			}
			if _, err := os.Stat(cfgPath); conn.Name() == "copilot" && !os.IsNotExist(err) {
				t.Fatalf("DefenseClaw's own Copilot hooks file survived teardown: %v", err)
			}
		})
	}
}

// GAP-1917: the four OTLP endpoints DefenseClaw writes, left on a dead
// loopback gateway port without the capture pins, are DefenseClaw's and go;
// one operator endpoint stays.
func TestClaudeCode_TeardownDropsOrphanedDefenseClawEndpointSet(t *testing.T) {
	for name, tc := range map[string]struct {
		pristine string
		want     map[string]interface{}
	}{
		"orphaned endpoint set": {
			pristine: `{"env":{"AWS_REGION":"us-east-1",` +
				`"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19030",` +
				`"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"http://127.0.0.1:19030/v1/logs",` +
				`"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://127.0.0.1:19030/v1/metrics",` +
				`"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":"http://127.0.0.1:19030/v1/traces"}}`,
			want: map[string]interface{}{"AWS_REGION": "us-east-1"},
		},
		"operator endpoint": {
			pristine: `{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:4318"}}`,
			want:     map[string]interface{}{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(settingsPath, []byte(tc.pristine), 0o600); err != nil {
				t.Fatal(err)
			}
			ClaudeCodeSettingsPathOverride = settingsPath
			t.Cleanup(func() { ClaudeCodeSettingsPathOverride = "" })
			c := NewClaudeCodeConnector()
			opts := SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18984", APIToken: "test-token"}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			data, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			var settings map[string]interface{}
			if err := json.Unmarshal(data, &settings); err != nil {
				t.Fatal(err)
			}
			if got := settings["env"]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("env after teardown = %v, want %v", got, tc.want)
			}
		})
	}
}
