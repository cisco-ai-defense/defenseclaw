// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func windowsMCPInventoryFixture(t *testing.T, names ...string) (*config.Config, string, string) {
	t.Helper()
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	root := t.TempDir()
	cfg := &config.Config{DataDir: filepath.Join(root, "data"), DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	cfg.AIDiscovery.Enabled = true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{}
	home := filepath.Join(root, "profile-must-not-be-opened")
	sid := "S-1-5-21-1-2-3-1001"
	var targets []managedGuardianAuthorizationTarget
	for _, name := range names {
		cfg.Guardrail.Connectors[name] = config.PerConnectorGuardrailConfig{}
		targets = append(targets, managedGuardianAuthorizationTarget{
			User: "alice", UserHome: home, SID: sid, Connector: name, OK: true,
		})
		dir := enrolledMCPSpoolDir(cfg, name)
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		data, err := enterprisehooks.MarshalClaudeMCPSpoolRecord(sid, []config.MCPServerEntry{{
			Name: "openaiDeveloperDocs", URL: "https://developers.openai.com/mcp",
			Transport: "http", SourceScope: "user",
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeWindowsMCPInventoryAuthorization(t, cfg, managedGuardianAuthorization{
		Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339), OK: true,
		TargetCount: len(targets), SuccessCount: len(targets), ProtectedTargets: targets,
	})
	return cfg, home, sid
}

func writeWindowsMCPInventoryAuthorization(t *testing.T, cfg *config.Config, authorization managedGuardianAuthorization) {
	t.Helper()
	path := managed.HookGuardianAuthorizationPath(cfg.DataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readWindowsMCPInventoryFixture(t *testing.T, cfg *config.Config) ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
	t.Helper()
	return perConnectorMCPEntriesForOSWithHomeGuardStatus(cfg, nil, "windows", func(string) error {
		t.Fatal("Secure Client inventory attempted to inspect a user profile")
		return fmt.Errorf("profile forbidden")
	})
}

func TestWindowsSecureClientMCPInventoryPersistsObservedToolsFromSpool(t *testing.T) {
	for _, name := range []string{"codex", "claudecode"} {
		t.Run(name, func(t *testing.T) {
			cfg, home, sid := windowsMCPInventoryFixture(t, name)
			parents, status := readWindowsMCPInventoryFixture(t, cfg)
			if status.partial || len(parents) != 1 {
				t.Fatalf("parents=%+v status=%+v", parents, status)
			}
			parent := parents[0]
			if parent.userID != sid || parent.userName != "alice" || parent.agentConnector != name ||
				parent.mcpServerURL != "https://developers.openai.com" || parent.mcpTransport != "http" {
				t.Fatalf("spool metadata/owner lost: %+v", parent)
			}
			if _, err := os.Stat(home); !os.IsNotExist(err) {
				t.Fatalf("test profile unexpectedly exists: %v", err)
			}
			store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			tools := &mcpToolInventory{store: store}
			tools.refreshCompleteParents(parents, status.incompleteConnectors)
			api := &APIServer{store: store, mcpTools: tools}
			req := agentHookRequest{
				ConnectorName: name, ConnectorInstanceID: syntheticToolResourceConnectorID,
				ToolName: "mcp__openaiDeveloperDocs__search_openai_docs",
			}
			ctx := withAuthenticatedToolResource(withAuthenticatedHookConnector(context.Background(), name), req,
				[]byte(`{"tool_name":"mcp__openaiDeveloperDocs__search_openai_docs"}`))
			api.recordObservedMCPTool(ctx, req, time.Now())
			persisted, err := store.ListMCPObservedTools(t.Context())
			if err != nil || len(persisted) != 1 || persisted[0].ParentComponentID != parent.id ||
				persisted[0].ToolName != "search_openai_docs" {
				t.Fatalf("durable tools=%+v err=%v", persisted, err)
			}
			rows, partial := tools.components(parents, true, "observed")
			if partial || len(rows) != 1 || rows[0].mcpToolParentID != parent.id {
				t.Fatalf("exportable tool inventory=%+v partial=%v", rows, partial)
			}
		})
	}
}

func TestWindowsSecureClientMCPInventoryRejectsUnusableSpool(t *testing.T) {
	for _, failure := range []string{"missing", "unreadable", "wrong-sid", "untrusted", "stale-authorization", "missing-authorization"} {
		t.Run(failure, func(t *testing.T) {
			cfg, _, sid := windowsMCPInventoryFixture(t, "codex")
			path := filepath.Join(enrolledMCPSpoolDir(cfg, "codex"), sid+".json")
			switch failure {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				data, err := enterprisehooks.MarshalClaudeMCPSpoolUnreadable(sid, enterprisehooks.ClaudeStateUnreadable{Reason: "signed out", SignedOut: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "wrong-sid":
				data, err := enterprisehooks.MarshalClaudeMCPSpoolRecord("S-1-5-21-1-2-3-9999", nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "untrusted":
				validateManagedGuardianAuthorization = func(file, _ string) error {
					if file == path {
						return fmt.Errorf("untrusted spool")
					}
					return nil
				}
			case "stale-authorization":
				writeWindowsMCPInventoryAuthorization(t, cfg, managedGuardianAuthorization{Version: 1, UpdatedAt: "2000-01-01T00:00:00Z"})
			case "missing-authorization":
				if err := os.Remove(managed.HookGuardianAuthorizationPath(cfg.DataDir)); err != nil {
					t.Fatal(err)
				}
			}
			rows, status := readWindowsMCPInventoryFixture(t, cfg)
			if !status.partial || len(rows) != 0 {
				t.Fatalf("unusable record became authoritative: rows=%+v status=%+v", rows, status)
			}
		})
	}
}

func TestWindowsSecureClientMCPInventoryMissingConnectorKeepsCompleteSibling(t *testing.T) {
	cfg, _, sid := windowsMCPInventoryFixture(t, "codex", "claudecode")
	if err := os.Remove(filepath.Join(enrolledMCPSpoolDir(cfg, "codex"), sid+".json")); err != nil {
		t.Fatal(err)
	}
	rows, status := readWindowsMCPInventoryFixture(t, cfg)
	if !status.partial || len(rows) != 1 || rows[0].agentConnector != "claudecode" {
		t.Fatalf("complete sibling lost: rows=%+v status=%+v", rows, status)
	}
	tools := &mcpToolInventory{}
	tools.refreshCompleteParents(rows, status.incompleteConnectors)
	if _, ok := tools.resolveConfiguredServer("claudecode", "openaiDeveloperDocs"); !ok {
		t.Fatal("complete sibling did not establish parent")
	}
}

func TestWindowsSecureClientMCPInventoryAuthoritativeEmptySpool(t *testing.T) {
	cfg, _, sid := windowsMCPInventoryFixture(t, "codex")
	data, err := enterprisehooks.MarshalClaudeMCPSpoolRecord(sid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(enrolledMCPSpoolDir(cfg, "codex"), sid+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	rows, status := readWindowsMCPInventoryFixture(t, cfg)
	if status.partial || len(rows) != 0 {
		t.Fatalf("authoritative empty spool became partial: rows=%+v status=%+v", rows, status)
	}
}

func TestWindowsSecureClientMCPInventoryLeavesOtherModesUnchanged(t *testing.T) {
	for _, mode := range []string{"oss-windows", "standalone-windows", "secure-client-darwin", "secure-client-linux", "secure-client-discovery-off"} {
		t.Run(mode, func(t *testing.T) {
			cfg, home, _ := windowsMCPInventoryFixture(t, "codex")
			serviceHome := t.TempDir()
			t.Setenv("HOME", serviceHome)
			t.Setenv("USERPROFILE", serviceHome)
			cfg.AIDiscovery.HomeDirs = []string{home}
			goos := "windows"
			switch mode {
			case "oss-windows":
				cfg.DeploymentMode = "opensource"
			case "standalone-windows":
				cfg.Enterprise.Profile = managed.ProfileStandalone
			case "secure-client-darwin":
				goos = "darwin"
			case "secure-client-linux":
				goos = "linux"
			case "secure-client-discovery-off":
				cfg.AIDiscovery.Enabled = false
			}
			guardCalls := 0
			rows, status := perConnectorMCPEntriesForOSWithHomeGuardStatus(cfg, nil, goos, func(string) error {
				guardCalls++
				return fmt.Errorf("existing profile guard")
			})
			if guardCalls == 0 || !status.partial || len(rows) != 0 {
				t.Fatalf("other mode consumed Windows spool: calls=%d rows=%+v status=%+v", guardCalls, rows, status)
			}
		})
	}
}
