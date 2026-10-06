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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// seedReleasedDesktopInstall writes the host state a 0.8.10 install of the
// retired Desktop connector left behind and returns the legacy hooks path.
func seedReleasedDesktopInstall(t *testing.T, home, dataDir string) string {
	t.Helper()
	scripts := legacyconnector.OwnedHookScripts(dataDir)
	if err := os.MkdirAll(filepath.Dir(scripts[0]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scripts[0], []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	backup := legacyconnector.BackupDir(dataDir)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	hooks := map[string]interface{}{}
	for _, event := range []string{"pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use", "pre_user_prompt"} {
		hooks[event] = []interface{}{map[string]interface{}{"command": scripts[0], "show_output": true}}
	}
	hooks["pre_run_command"] = append(hooks["pre_run_command"].([]interface{}),
		map[string]interface{}{"command": "/opt/team/foreign.sh"})
	data, _ := json.MarshalIndent(map[string]interface{}{"hooks": hooks}, "", "  ")
	hooksPath := legacyconnector.CascadeUserHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	retired, _ := connector.RetiredConnector(legacyconnector.RetiredDesktopID)
	entry := connector.NewHookContractLockEntry(connector.SetupOpts{DataDir: dataDir, HookFailMode: "closed"}, retired, "0.8.10")
	entry.Connector = legacyconnector.RetiredDesktopID
	if err := connector.SaveFreshHookContractLockEntry(dataDir, entry); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	if err := connector.SaveActiveConnectors(dataDir, []string{legacyconnector.RetiredDesktopID}); err != nil {
		t.Fatalf("seed active roster: %v", err)
	}
	return hooksPath
}

func TestBootMigratesRetiredConnectorToDevin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hook script fixture")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restoreHome()
	devinHooks := filepath.Join(home, ".config", "devin", "config.json")
	prevDevin := connector.DevinHooksPathOverride
	connector.DevinHooksPathOverride = devinHooks
	t.Cleanup(func() { connector.DevinHooksPathOverride = prevDevin })

	cascadeHooks := seedReleasedDesktopInstall(t, home, dataDir)

	t.Setenv("DEFENSECLAW_HOME", dataDir)
	cfgPath := filepath.Join(dataDir, config.DefaultConfigName)
	body := "config_version: 9\ndata_dir: " + dataDir + "\nclaw:\n  mode: " + legacyconnector.RetiredDesktopID +
		"\nguardrail:\n  enabled: true\n  mode: observe\n  connector: " + legacyconnector.RetiredDesktopID +
		"\n  connectors:\n    " + legacyconnector.RetiredDesktopID + ":\n      mode: observe\ngateway:\n  api_port: 18970\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Guardrail.Connector != "devin" || len(cfg.LegacyConnectorNotices) != 1 {
		t.Fatalf("config not migrated: connector=%q notices=%v", cfg.Guardrail.Connector, cfg.LegacyConnectorNotices)
	}

	s := &Sidecar{cfg: cfg, health: NewSidecarHealth(), router: routerWithDefaultRulePack(t)}
	registry := connector.NewDefaultRegistry()
	stderr := captureStderr(t, func() {
		s.migrateRetiredConnectorState(context.Background(), registry)
	})
	if got := strings.Count(stderr, legacyconnector.Headline); got != 1 {
		t.Fatalf("migration line printed %d times:\n%s", got, stderr)
	}
	for _, want := range []string{"removed 5 DefenseClaw hook entries from " + cascadeHooks, devinHooks, "Cascade conversations are not protected"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("migration line missing %q:\n%s", want, stderr)
		}
	}

	// Cascade entries are gone; the foreign one stays.
	after, err := os.ReadFile(cascadeHooks)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), legacyconnector.OwnedHookScripts(dataDir)[0]) || !strings.Contains(string(after), "/opt/team/foreign.sh") {
		t.Fatalf("legacy hooks after migration = %s", after)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, legacyconnector.RetiredDesktopID); got.Connector != "" {
		t.Fatalf("retired lock entry survived: %+v", got)
	}
	for _, name := range connector.LoadActiveConnectors(dataDir) {
		if legacyconnector.IsRetired(name) {
			t.Fatalf("retired ID still in the active roster: %v", connector.LoadActiveConnectors(dataDir))
		}
	}
	if _, err := os.Stat(legacyconnector.BackupDir(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("retired backup survived: %v", err)
	}

	// The replacement then installs through its normal Setup.
	devin, ok := registry.Get("devin")
	if !ok {
		t.Fatal("devin missing from registry")
	}
	opts := connector.SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "t", HookAPIToken: "h", HookFailMode: "closed", GuardrailMode: "observe"}
	if err := devin.Setup(context.Background(), opts); err != nil {
		t.Fatalf("devin setup after migration: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(devin, opts); err != nil || !present {
		t.Fatalf("devin hooks present=%v err=%v", present, err)
	}

	// A second boot with the host already clean and the config persisted
	// does nothing and prints nothing.
	cfg.LegacyConnectorNotices = nil
	again := captureStderr(t, func() {
		s.migrateRetiredConnectorState(context.Background(), registry)
	})
	if strings.Contains(again, legacyconnector.Headline) {
		t.Fatalf("migration repeated on a clean host:\n%s", again)
	}
}
