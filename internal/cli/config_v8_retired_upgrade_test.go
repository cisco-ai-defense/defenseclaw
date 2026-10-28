// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// until 1.1: the installer's upgrade check runs the staged gateway's
// `config-v8 validate` and `config migrate --to 9 --dry-run` on the live
// config.yaml before it swaps anything (cli/defenseclaw/migrations.py), and
// Windows Setup runs validateStandaloneGatewayConfig. A config a published
// release wrote with OpenHands or OmniGent set up was refused there ("target
// runtime did not retain the configured connector"), so the upgrade stopped
// before the retired-connector cleanup could run (GAP-0290). Each published
// shape must pass every check, and the staged runtime must keep exactly the
// surviving connectors. Delete with internal/config/retired_connector_upgrade.go.
func TestStagedUpgradeCheckAcceptsPublishedConfigsWithRemovedConnectors(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    []string
	}{
		{"1.0.2", []string{"claudecode", "codex", "copilot", "hermes", "opencode"}},
		{"1.0.2-retired-primary", []string{"codex"}},
		{"1.0.0-v8", []string{"codex"}},
		{"1.0.2-only-retired", nil},
		{"1.0.3-retired-everywhere", []string{"codex"}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("USERPROFILE", os.Getenv("HOME"))
			raw, err := os.ReadFile(filepath.Join("testdata", "retired-connector-upgrade", tc.fixture+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			source := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "@HOME@", filepath.ToSlash(home))
			path := filepath.Join(home, "config.yaml")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			// The rule pack init installed next to it.
			shipped := filepath.Join("..", "..", "policies", "guardrail", "default")
			if err := os.CopyFS(filepath.Join(home, "policies", "guardrail", "default"), os.DirFS(shipped)); err != nil {
				t.Fatal(err)
			}

			// The installer's check: the staged gateway's config-v8 validate.
			previousPath, previousDataDir := configV8ConfigPath, configV8DataDir
			previousOutput := configV8ValidateCmd.OutOrStdout()
			t.Cleanup(func() {
				configV8ConfigPath, configV8DataDir = previousPath, previousDataDir
				configV8ValidateCmd.SetOut(previousOutput)
			})
			configV8ConfigPath, configV8DataDir = path, home
			output := &strings.Builder{}
			configV8ValidateCmd.SetOut(output)
			if err := configV8ValidateCmd.RunE(configV8ValidateCmd, nil); err != nil {
				t.Fatalf("config-v8 validate refused the published config: %v\n%s", err, output)
			}
			var result configV8WireResponse
			if err := json.Unmarshal([]byte(output.String()), &result); err != nil || result.Valid == nil || !*result.Valid {
				t.Fatalf("config-v8 validate result = %s, %v", output, err)
			}

			// The installer's preview: config migrate --to 9 --dry-run.
			input, err := configMigrateV9Input(path)
			if err != nil {
				t.Fatalf("config migrate input: %v", err)
			}
			input.DryRun = true
			if _, err := config.MigrateV9(context.Background(), input); err != nil {
				t.Fatalf("config migrate --dry-run refused the published config: %v", err)
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != source {
				t.Fatalf("the checks changed config.yaml (%v)", err)
			}

			// Windows Setup's and the managed lifecycle's check.
			if err := validateStandaloneGatewayConfig(path, home, ""); err != nil {
				t.Fatalf("validateStandaloneGatewayConfig refused the published config: %v", err)
			}

			loaded, err := loadConfigV8File(path, home)
			if err != nil {
				t.Fatalf("loadConfigV8File: %v", err)
			}
			got := make([]string, 0, len(loaded.runtime.Guardrail.Connectors))
			for name := range loaded.runtime.Guardrail.Connectors {
				got = append(got, name)
			}
			sort.Strings(got)
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("staged runtime connectors = %v, want %v", got, tc.want)
			}
		})
	}
}

// The roster check drops a removed connector in every spelling the loader
// accepts, and still refuses a surviving connector the runtime lost.
func TestValidateRuntimeV8ConnectorRosterExpectsRemovedConnectorsDropped(t *testing.T) {
	document, err := config.ParseV8YAML("candidate.yaml", []byte(`config_version: 8
guardrail:
  connectors:
    codex: {}
    OpenHands: {}
    open_hands: {}
    " omnigent ": {}
observability: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	candidate := &config.Config{}
	candidate.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}}
	if err := validateRuntimeV8ConnectorRoster(document, candidate); err != nil {
		t.Fatalf("roster with removed connectors dropped: %v", err)
	}
	candidate.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{}
	if err := validateRuntimeV8ConnectorRoster(document, candidate); err == nil {
		t.Fatal("roster check accepted a runtime that lost codex")
	}
	candidate.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}, "openhands": {}}
	if err := validateRuntimeV8ConnectorRoster(document, candidate); err == nil {
		t.Fatal("roster check accepted a runtime that kept a removed connector")
	}
}
