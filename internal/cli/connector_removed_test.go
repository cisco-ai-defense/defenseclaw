// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	removedOmnigentOperatorConfig = "policy_modules:\n  - corp_policy\n"
	removedOmnigentPatchedConfig  = "policy_modules:\n  - corp_policy\n  - defenseclaw_omnigent_policy\n" +
		"policies:\n  defenseclaw_guardrail:\n    handler: defenseclaw_omnigent_policy.defenseclaw_policy\n"
)

// writeRemovedSetupRecord writes config.yaml as an older OmniGent setup left
// it, with the backup record of the file it found.
func writeRemovedSetupRecord(t *testing.T, dataDir, path string) {
	t.Helper()
	sum := func(data string) string {
		digest := sha256.Sum256([]byte(data))
		return hex.EncodeToString(digest[:])
	}
	record, err := json.Marshal(map[string]any{
		"version": 1, "connector": "omnigent", "logical_name": "config", "path": path,
		"existed": true, "mode": 0o600, "pristine_sha256": sum(removedOmnigentOperatorConfig),
		"pristine_bytes": []byte(removedOmnigentOperatorConfig), "post_sha256": sum(removedOmnigentPatchedConfig),
		"captured_at": "2026-10-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, body := range map[string]string{
		filepath.Join(dataDir, "connector_backups", "omnigent", "config.json"): string(record),
		path: removedOmnigentPatchedConfig,
	} {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// until 1.1: native Setup and uninstall tear down a removed connector with an
// explicit config home. The teardown changes only the policy module (the stub
// that denies every request) and the tokens; config.yaml stays as it is,
// whether or not it was edited, and the teardown lists it, with the module and
// the backups, as left for the user (JSON for Setup, text for a person).
// Teardown and verify succeed so uninstall and Setup go on.
func TestConnectorTeardownRemovedOmnigentHonoursConfigHome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edited bool
		json   bool
	}{{"unchanged since setup", false, true}, {"edited since setup", true, true}, {"text output", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			configHome := filepath.Join(testenv.PrivateTempDir(t), ".omnigent")
			configPath := filepath.Join(configHome, "config.yaml")
			writeRemovedSetupRecord(t, dataDir, configPath)
			want := removedOmnigentPatchedConfig
			if tc.edited {
				want = removedOmnigentPatchedConfig + "model: local\n"
				if err := os.WriteFile(configPath, []byte(want), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			module := filepath.Join(dataDir, "hooks", "defenseclaw_omnigent_policy.py")
			if err := os.MkdirAll(filepath.Dir(module), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(module, []byte("# defenseclaw-managed-policy v1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			defer withConnectorState(t, dataDir, "codex")()

			args := []string{"teardown", "--connector", "omnigent", "--config-home", configHome}
			if tc.json {
				args = append(args, "--json")
			}
			stdout, stderr, code := runConnectorCmd(t, args...)
			if code != 0 || strings.Contains(stderr, "unsupported") || strings.Contains(stderr, "unknown connector") {
				t.Fatalf("teardown exit=%d stderr=%s", code, stderr)
			}
			if tc.json {
				var payload struct {
					OK        bool `json:"ok"`
					Leftovers []struct{ Path, What, Step string }
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err != nil || !payload.OK {
					t.Fatalf("teardown JSON = %q, %v", stdout, err)
				}
				var paths []string
				for _, item := range payload.Leftovers {
					paths = append(paths, item.Path)
				}
				for _, path := range []string{configPath, module, filepath.Join(dataDir, "connector_backups", "omnigent")} {
					if !strings.Contains(strings.Join(paths, "\n"), path) {
						t.Fatalf("leftovers %v do not name %s", paths, path)
					}
				}
			} else if !strings.Contains(stdout, "OmniGent support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:") ||
				!strings.Contains(stdout, "  - "+configPath+": ") {
				t.Fatalf("teardown output = %q, want the leftovers with config.yaml", stdout)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != want {
				t.Fatalf("config.yaml after teardown = %q, want it untouched: %q", data, want)
			}
			if body, err := os.ReadFile(module); err != nil || !strings.Contains(string(body), `"DENY"`) {
				t.Fatalf("policy module after teardown = %q, %v; want the stub", body, err)
			}
			if _, stderr, code := runConnectorCmd(t, "verify", "--connector", "omnigent", "--config-home", configHome); code != 0 {
				t.Fatalf("verify exit=%d stderr=%s", code, stderr)
			}
		})
	}
}

// A removed connector can be torn down but never reconciled, and the
// selected refresh stays limited to the connectors native Setup refreshes.
func TestConnectorReconcileRefusesUnsupportedConnectors(t *testing.T) {
	for _, name := range []string{"omnigent", "openhands", "kiro"} {
		t.Run(name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			defer withConnectorState(t, dataDir, "codex")()
			_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", name, "--json")
			if !strings.Contains(stderr, "unknown connector") && !strings.Contains(stderr, "selected refresh is supported only") {
				t.Fatalf("reconcile %s stderr = %q, want a refusal", name, stderr)
			}
		})
	}
}
