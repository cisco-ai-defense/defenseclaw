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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

// until 1.1: native Setup, the installers and uninstall tear down OmniGent
// with an explicit config home. The teardown removes what DefenseClaw wrote:
// its policy_modules entry and policy in config.yaml (the operator's own
// entries stay, edited or not), the policy module and the setup receipts. It
// prints the one removal notice, lists nothing when nothing is left, and
// teardown and verify succeed.
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
			if tc.edited {
				if err := os.WriteFile(configPath, []byte(removedOmnigentPatchedConfig+"model: local\n"), 0o600); err != nil {
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
					OK        bool   `json:"ok"`
					Notice    string `json:"notice"`
					Leftovers []struct{ Path, What, Step string }
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err != nil || !payload.OK {
					t.Fatalf("teardown JSON = %q, %v", stdout, err)
				}
				if payload.Notice != connector.RemovedConnectorNotice || len(payload.Leftovers) != 0 {
					t.Fatalf("teardown JSON = %q, want the notice and no leftovers", stdout)
				}
			} else if !strings.Contains(stdout, connector.RemovedConnectorNotice) {
				t.Fatalf("teardown output = %q, want the removal notice", stdout)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			if strings.Contains(text, "defenseclaw_omnigent_policy") || !strings.Contains(text, "corp_policy") ||
				tc.edited != strings.Contains(text, "model: local") {
				t.Fatalf("config.yaml after teardown = %q, want only the operator's entries", text)
			}
			if _, err := os.Lstat(module); err == nil {
				t.Fatalf("policy module %s is still there", module)
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
