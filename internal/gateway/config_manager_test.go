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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestConfigManagerReloadAppliesAndPublishesSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	mgr := NewConfigManager(path, initial, nil, nil, func(_ context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff) error {
		applied = true
		if oldCfg.Guardrail.Mode != "observe" || newCfg.Guardrail.Mode != "action" {
			t.Fatalf("apply saw mode %q -> %q", oldCfg.Guardrail.Mode, newCfg.Guardrail.Mode)
		}
		if !slices.Contains(diff.Changed, "guardrail") {
			t.Fatalf("diff changed = %v, want guardrail", diff.Changed)
		}
		return nil
	})

	writeConfigForManagerTest(t, path, dir, "action")
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !applied {
		t.Fatal("apply callback was not called")
	}
	if got := mgr.Current().Guardrail.Mode; got != "action" {
		t.Fatalf("current mode = %q, want action", got)
	}
}

func TestConfigManagerReloadRejectsInvalidAndKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	mgr := NewConfigManager(path, initial, nil, nil, func(context.Context, *config.Config, *config.Config, ConfigDiff) error {
		t.Fatal("apply callback must not run for invalid config")
		return nil
	})

	raw := "config_version: 6\n" +
		"data_dir: " + dir + "\n" +
		"deployment_mode: invalid\n" +
		"guardrail:\n" +
		"  mode: observe\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil {
		t.Fatal("reload succeeded with invalid deployment_mode")
	}
	if got := mgr.Current().Guardrail.Mode; got != "observe" {
		t.Fatalf("current mode changed to %q after failed reload", got)
	}
}

func TestDiffConfigsMarksStorageIdentityRestartRequired(t *testing.T) {
	oldCfg := &config.Config{
		DataDir:       "/old/data",
		AuditDB:       "/old/audit.db",
		JudgeBodiesDB: "/old/judge.db",
	}
	newCfg := &config.Config{
		DataDir:       "/new/data",
		AuditDB:       "/new/audit.db",
		JudgeBodiesDB: "/new/judge.db",
	}
	oldCfg.Gateway.DeviceKeyFile = "/old/device.pem"
	newCfg.Gateway.DeviceKeyFile = "/new/device.pem"

	diff := diffConfigs(oldCfg, newCfg)
	for _, want := range []string{"data_dir", "audit_db", "judge_bodies_db", "gateway.device_key_file"} {
		if !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("restart_required = %v, missing %s", diff.RestartRequired, want)
		}
	}
}

func writeConfigForManagerTest(t *testing.T, path, dataDir, mode string) {
	t.Helper()
	raw := "config_version: 6\n" +
		"data_dir: " + dataDir + "\n" +
		"guardrail:\n" +
		"  mode: " + mode + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
