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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

func TestRetiredConnectorResolvesOnlyTheRetiredID(t *testing.T) {
	for _, name := range []string{"devin", "cursor", "", "retired-example"} {
		if _, ok := RetiredConnector(name); ok {
			t.Fatalf("RetiredConnector(%q) resolved", name)
		}
	}
	conn, ok := RetiredConnector(strings.ToUpper(legacyconnector.RetiredDesktopID))
	if !ok || conn.Name() != legacyconnector.RetiredDesktopID {
		t.Fatalf("RetiredConnector did not resolve the retired ID: %v %v", conn, ok)
	}
	if IsKnownBuiltinConnector(conn.Name()) {
		t.Fatal("the retired ID must not be a registered built-in")
	}
	if _, registered := NewDefaultRegistry().Get(conn.Name()); registered {
		t.Fatal("the retired ID must not be reachable through the registry")
	}
	if conn.Authenticate(nil) {
		t.Fatal("a retired connector must never authenticate hook traffic")
	}
}

func TestRetiredConnectorRefusesSetup(t *testing.T) {
	conn, _ := RetiredConnector(legacyconnector.RetiredDesktopID)
	err := conn.Setup(context.Background(), SetupOpts{DataDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "defenseclaw setup "+legacyconnector.Replacement) {
		t.Fatalf("Setup error = %v, want a pointer to %s", err, legacyconnector.Replacement)
	}
}

func TestRetiredConnectorTeardownAndVerify(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	restore, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()

	scripts := legacyconnector.OwnedHookScripts(dataDir)
	for _, script := range scripts {
		if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	backup := legacyconnector.BackupDir(dataDir)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooksPath := legacyconnector.CascadeUserHooksPath(home)
	doc := map[string]interface{}{"hooks": map[string]interface{}{
		"pre_run_command": []interface{}{
			map[string]interface{}{"command": scripts[0], "show_output": true},
			map[string]interface{}{"command": "/opt/team/check.sh"},
		},
		"post_read_code": []interface{}{
			map[string]interface{}{"command": scripts[0], "show_output": true},
		},
	}}
	data, _ := json.Marshal(doc)
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	conn, _ := RetiredConnector(legacyconnector.RetiredDesktopID)
	opts := SetupOpts{DataDir: dataDir}
	if err := conn.VerifyClean(opts); err == nil {
		t.Fatal("VerifyClean passed while DefenseClaw entries remain")
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean after Teardown: %v", err)
	}
	report := conn.(RetiredCleanupReporter).LastCleanup()
	if report.RemovedEntries != 2 || report.HooksPath != hooksPath {
		t.Fatalf("cleanup report = %+v, want 2 entries from %s", report, hooksPath)
	}
	for _, script := range scripts {
		if _, err := os.Stat(script); !os.IsNotExist(err) {
			t.Fatalf("owned script %s survived: %v", script, err)
		}
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup dir survived: %v", err)
	}
	after, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "/opt/team/check.sh") || strings.Contains(string(after), scripts[0]) {
		t.Fatalf("hooks after teardown = %s", after)
	}

	// A second teardown is a no-op.
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
	if got := conn.(RetiredCleanupReporter).LastCleanup().RemovedEntries; got != 0 {
		t.Fatalf("second Teardown removed %d entries", got)
	}
}
