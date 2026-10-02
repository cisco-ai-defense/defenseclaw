// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestCodexPerUserWindowsSetupMovesHooksOutOfIgnoredManagedLayer covers the
// upgrade path of WIN2-U2-09: an earlier per-user Windows release registered
// the hook matrix in CODEX_HOME\managed_config.toml, which current Codex
// ignores. The upgraded gateway re-runs per-user Setup at boot; that Setup must
// leave no DefenseClaw hook in the ignored layer, keep the operator's entries
// there, and register a trusted matrix in config.toml.
func TestCodexPerUserWindowsSetupMovesHooksOutOfIgnoredManagedLayer(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(t *testing.T, conn *CodexConnector, managedPath, hooksDir string, legacy SetupOpts)
	}{
		{
			// The earlier release's Setup ran with this data dir, so its
			// managed-file backup is present.
			name: "with setup backup",
			seed: func(t *testing.T, conn *CodexConnector, _, _ string, legacy SetupOpts) {
				if err := conn.Setup(context.Background(), legacy); err != nil {
					t.Fatalf("seed Setup in the managed layer: %v", err)
				}
			},
		},
		{
			// No backup survived: the owned matrix is found by its command.
			name: "without setup backup",
			seed: func(t *testing.T, _ *CodexConnector, managedPath, hooksDir string, _ SetupOpts) {
				hooks := map[string]interface{}{}
				if err := mergeOwnedCodexHooks(
					hooks,
					managedPath,
					filepath.Join(hooksDir, "codex-hook.sh"),
					hooksDir,
					SetupOpts{},
					true,
					codexHookGroups,
				); err != nil {
					t.Fatalf("seed owned managed hooks: %v", err)
				}
				raw, err := toml.Marshal(map[string]interface{}{
					"operator_policy": map[string]interface{}{"mode": "strict"},
					"hooks":           hooks,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(managedPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "codex", "config.toml")
			managedPath := filepath.Join(filepath.Dir(configPath), codexManagedConfigLogicalName)
			dataDir := filepath.Join(dir, "defenseclaw")
			hooksDir := filepath.Join(dataDir, "hooks")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(managedPath, []byte("[operator_policy]\nmode = \"strict\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previousPath := CodexConfigPathOverride
			CodexConfigPathOverride = configPath
			t.Cleanup(func() { CodexConfigPathOverride = previousPath })
			previousInspector := codexPolicyInspector
			codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
				return codexEffectivePolicy{Source: "per-user migration test"}, nil
			}
			t.Cleanup(func() { codexPolicyInspector = previousInspector })
			setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))

			conn := NewCodexConnector()
			legacy := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", ManagedEnterprise: true}
			tc.seed(t, conn, managedPath, hooksDir, legacy)
			if err := verifyNoOwnedCodexHooks(readCASTOML(t, managedPath), hooksDir); err == nil {
				t.Fatal("seed left no DefenseClaw hooks in managed_config.toml")
			}

			perUser := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}
			if err := conn.Setup(context.Background(), perUser); err != nil {
				t.Fatalf("per-user Setup: %v", err)
			}

			managed := readCASTOML(t, managedPath)
			if err := verifyNoOwnedCodexHooks(managed, hooksDir); err != nil {
				t.Fatalf("per-user Setup left hooks in the ignored managed layer: %v", err)
			}
			if policy, _ := managed["operator_policy"].(map[string]interface{}); policy["mode"] != "strict" {
				t.Fatalf("per-user Setup changed unrelated managed config: %#v", managed)
			}
			config := readCASTOML(t, configPath)
			if config["model"] != "gpt-5" {
				t.Fatalf("per-user Setup changed unrelated user config: %#v", config)
			}
			hooks, ok := config["hooks"].(map[string]interface{})
			if !ok {
				t.Fatalf("config.toml has no hooks table: %#v", config)
			}
			if err := verifyTrustedCodexHookMatrix(hooks, configPath, hooksDir, perUser); err != nil {
				t.Fatalf("config.toml matrix is not trusted: %v", err)
			}
			if present, err := conn.ownedHookContractPresent(perUser); err != nil || !present {
				t.Fatalf("ownedHookContractPresent = %v, %v; want true", present, err)
			}
			if got := conn.HookCapabilities(perUser).ConfigPath; got != configPath {
				t.Fatalf("HookCapabilities ConfigPath = %q, want %q", got, configPath)
			}
		})
	}
}
