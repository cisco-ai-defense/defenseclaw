// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestConnectorsEndpointPublishesCodexAndClaudeCapabilities(t *testing.T) {
	home := t.TempDir()
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex-state"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude-state"))

	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewCodexConnector())
	registry.RegisterBuiltin(connector.NewClaudeCodeConnector())
	api := &APIServer{
		addr:              "127.0.0.1:18970",
		connectorRegistry: registry,
	}

	recorder := httptest.NewRecorder()
	api.handleConnectors(recorder, httptest.NewRequest(http.MethodGet, "/v1/connectors", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /v1/connectors status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Connectors []struct {
			Name           string                           `json:"name"`
			Capabilities   *connector.ConnectorCapabilities `json:"capabilities"`
			HookCapability *connector.HookCapability        `json:"hook_capabilities"`
			Locations      *connector.ConnectorLocations    `json:"locations"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode /v1/connectors response: %v", err)
	}
	if len(response.Connectors) != 2 {
		t.Fatalf("connector entries=%d want 2: %s", len(response.Connectors), recorder.Body.String())
	}
	for _, entry := range response.Connectors {
		if entry.Capabilities == nil || entry.HookCapability == nil || entry.Locations == nil {
			t.Errorf("%s missing public capability metadata: %+v", entry.Name, entry)
			continue
		}
		if entry.Capabilities.LLMTrafficMode != connector.LLMTrafficModeHooksOnly || !entry.Capabilities.Telemetry.NativeOTLP {
			t.Errorf("%s capabilities=%+v", entry.Name, entry.Capabilities)
		}
		if len(entry.Locations.TelemetryConfigPaths) == 0 || len(entry.Locations.Surfaces) != 5 {
			t.Errorf("%s locations=%+v", entry.Name, entry.Locations)
		}
		for _, surface := range []string{"mcp", "skills", "rules", "plugins", "agents"} {
			if !entry.Locations.Surfaces[surface].Supported {
				t.Errorf("%s API location surface %s=%+v", entry.Name, surface, entry.Locations.Surfaces[surface])
			}
		}
	}
}

func TestConnectorsEndpointPublishesOpenCodeReviewedAssets(t *testing.T) {
	home := t.TempDir()
	restoreHome, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)
	t.Setenv("OPENCODE_CONFIG", "")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")

	registry := connector.NewRegistry()
	registry.RegisterBuiltin(connector.NewOpenCodeConnector())
	api := &APIServer{
		addr:              "127.0.0.1:18970",
		connectorRegistry: registry,
	}
	recorder := httptest.NewRecorder()
	api.handleConnectors(recorder, httptest.NewRequest(http.MethodGet, "/v1/connectors", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /v1/connectors status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Connectors []struct {
			Name         string                           `json:"name"`
			Capabilities *connector.ConnectorCapabilities `json:"capabilities"`
			Locations    *connector.ConnectorLocations    `json:"locations"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Connectors) != 1 || response.Connectors[0].Name != "opencode" {
		t.Fatalf("OpenCode API response=%s", recorder.Body.String())
	}
	entry := response.Connectors[0]
	if entry.Capabilities == nil || !entry.Capabilities.MCP.Supported || entry.Locations == nil || !entry.Locations.Surfaces["mcp"].Supported {
		t.Fatalf("OpenCode API omitted MCP capability/locations: %+v", entry)
	}
	for name, surface := range map[string]connector.SurfaceCapability{
		"skills":  entry.Capabilities.Skills,
		"rules":   entry.Capabilities.Rules,
		"plugins": entry.Capabilities.Plugins,
		"agents":  entry.Capabilities.Agents,
	} {
		if !surface.Supported {
			t.Errorf("OpenCode API omitted reviewed %s surface: %+v", name, surface)
		}
	}
	if entry.Capabilities.Skills.DiscoveryOnly || !entry.Capabilities.Skills.RequiresOptIn || len(entry.Capabilities.Skills.WritePaths) == 0 {
		t.Fatalf("OpenCode API skill capability=%+v", entry.Capabilities.Skills)
	}
	if !entry.Capabilities.Rules.DiscoveryOnly || !entry.Capabilities.Plugins.DiscoveryOnly || !entry.Capabilities.Agents.DiscoveryOnly {
		t.Fatalf("OpenCode API discovery-only mismatch: rules=%+v plugins=%+v agents=%+v", entry.Capabilities.Rules, entry.Capabilities.Plugins, entry.Capabilities.Agents)
	}
}
