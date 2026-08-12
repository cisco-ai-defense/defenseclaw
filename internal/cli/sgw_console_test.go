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
	"bytes"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func TestSGWConsoleOpenCommandBypassesRootInitialization(t *testing.T) {
	wantDir := filepath.Join(t.TempDir(), "defenseclaw")
	var opened string
	cmd := newSGWConsoleOpenCommand(func(dataDir string) (gateway.SGWConsoleStatus, error) {
		opened = dataDir
		return gateway.SGWConsoleStatus{SchemaVersion: 1, Status: "opened"}, nil
	})
	if !cmd.Hidden || cmd.PersistentPreRunE == nil || cmd.PersistentPostRun == nil {
		t.Fatal("native s-gw console command does not own its lifecycle hooks")
	}
	if err := cmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("pre-run hook: %v", err)
	}
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--data-dir", wantDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if opened != wantDir {
		t.Fatalf("opened %q, want %q", opened, wantDir)
	}
	if output.String() != "{\"schema_version\":1,\"status\":\"opened\"}\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestSGWConsoleOpenCommandRejectsRelativeDataDir(t *testing.T) {
	cmd := newSGWConsoleOpenCommand(func(string) (gateway.SGWConsoleStatus, error) {
		t.Fatal("opener was called")
		return gateway.SGWConsoleStatus{}, nil
	})
	cmd.SetArgs([]string{"--data-dir", "relative"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("relative data directory was accepted")
	}
}
