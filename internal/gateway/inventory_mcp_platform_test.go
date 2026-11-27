// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestMCPServerInventoryAdaptersProjectTheSameContract(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CODEX_HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("[mcp_servers.docs]\ncommand = 'node'\nargs = ['server.js']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := connector.NewRegistry()
	if err := registry.RegisterPlugin(&endpointInventoryPluginConnector{name: "codex", description: "test"}); err != nil {
		t.Fatal(err)
	}
	macConfig := &config.Config{AIDiscovery: config.AIDiscoveryConfig{HomeDirs: []string{home}}}
	macRows, macStatus := perConnectorMCPEntriesForOSWithHomeGuardStatus(macConfig, registry, "darwin", func(string) error { return nil })
	if macStatus.partial || len(macRows) != 1 {
		t.Fatalf("mac adapter rows=%+v status=%+v", macRows, macStatus)
	}

	dataDir := t.TempDir()
	sid := "S-1-5-21-1-2-3-1001"
	authorization := managedGuardianAuthorization{
		Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339), OK: true,
		TargetCount: 1, SuccessCount: 1,
		ProtectedTargets: []managedGuardianAuthorizationTarget{{
			User: "alice", UserHome: home, SID: sid, Connector: "codex", OK: true,
		}},
	}
	raw, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	authorizationDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(enterprisehooks.MCPSpoolDir(authorizationDir, "codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed.HookGuardianAuthorizationPath(dataDir), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := enterprisehooks.MarshalClaudeMCPSpoolRecord(sid, []config.MCPServerEntry{{
		Name: "docs", Command: "node", Args: []string{"server.js"}, Source: configPath, SourceScope: "user",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(enterprisehooks.MCPSpoolDir(authorizationDir, "codex"), sid+".json"), spool, 0o600); err != nil {
		t.Fatal(err)
	}
	previousTrust := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previousTrust })
	windowsConfig := &config.Config{
		DataDir: dataDir, DeploymentMode: string(config.DeploymentModeManagedEnterprise),
		Enterprise:  config.EnterpriseConfig{Profile: managed.ProfileSecureClient},
		AIDiscovery: config.AIDiscoveryConfig{Enabled: true, HomeDirs: []string{home}},
	}
	windowsRows, windowsStatus := perConnectorMCPEntriesForOSWithHomeGuardStatus(windowsConfig, registry, "windows", func(string) error { return nil })
	if windowsStatus.partial || len(windowsRows) != 1 {
		t.Fatalf("windows adapter rows=%+v status=%+v", windowsRows, windowsStatus)
	}
	mac, windows := macRows[0], windowsRows[0]
	if mac.componentType != windows.componentType || mac.itemName != windows.itemName ||
		mac.mcpRuntimeServerName != windows.mcpRuntimeServerName || mac.agentConnector != windows.agentConnector ||
		mac.mcpTransport != windows.mcpTransport || mac.mcpCommandBasename != windows.mcpCommandBasename ||
		mac.mcpSourceScope != windows.mcpSourceScope {
		t.Fatalf("platform contracts differ:\nmac=%+v\nwindows=%+v", mac, windows)
	}
}
