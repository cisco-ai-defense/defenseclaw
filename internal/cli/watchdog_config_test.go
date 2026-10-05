// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1310: a destination secret kept only in <data_dir>/.env made the
// watchdog commands fail to load the config (they skip the root pre-run), so
// 'watchdog start' timed out on a child that had exited and 'watchdog status'
// called the watchdog disabled.
func TestWatchdogConfigLoadsDestinationSecretsFromDotEnv(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	const secretEnv = "DC_TEST_WATCHDOG_DOTENV_AUTH"
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	t.Setenv(secretEnv, "")
	raw := fmt.Sprintf(`config_version: 8
data_dir: %s
observability:
  destinations:
    - name: dotenv-fixture
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        Authorization: {env: %s}
`, filepath.ToSlash(dataDir), secretEnv)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadRuntimeV8File(configPath); err == nil {
		t.Fatal("precondition: the config should not compile without the .env secret")
	}
	if err := os.WriteFile(filepath.Join(dataDir, ".env"), []byte(secretEnv+"=watchdog-fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadWatchdogConfig()
	if err != nil {
		t.Fatalf("loadWatchdogConfig() error = %v", err)
	}
	if !cfg.Gateway.Watchdog.Enabled {
		t.Fatal("watchdog should be enabled by default")
	}
}
