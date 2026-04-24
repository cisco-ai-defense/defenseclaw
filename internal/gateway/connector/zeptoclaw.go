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

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ZeptoClawConnector handles LLM traffic routing and tool inspection for ZeptoClaw.
// LLM traffic: patches api_base in ~/.zeptoclaw/config.json to route through proxy.
// Tool inspection: adds before_tool hook to ZeptoClaw's config.json that gates
// every tool execution via /api/v1/inspect/tool.
type ZeptoClawConnector struct {
	gatewayToken string
	masterKey    string
}

// NewZeptoClawConnector creates a new ZeptoClaw connector.
func NewZeptoClawConnector() *ZeptoClawConnector {
	return &ZeptoClawConnector{}
}

func (c *ZeptoClawConnector) Name() string                           { return "zeptoclaw" }
func (c *ZeptoClawConnector) Description() string                    { return "api_base redirect + config hooks" }
func (c *ZeptoClawConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *ZeptoClawConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *ZeptoClawConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Surface 1: Patch ZeptoClaw config to route api_base through proxy.
	if err := c.patchZeptoClawConfig(opts); err != nil {
		return fmt.Errorf("zeptoclaw config patch: %w", err)
	}

	// Surface 2: Tool inspection hook script
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScript(hookDir, opts.APIAddr); err != nil {
		return fmt.Errorf("zeptoclaw hook script: %w", err)
	}

	// Surface 3: Plugin subprocess enforcement
	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("zeptoclaw subprocess enforcement: %w", err)
	}

	return nil
}

func (c *ZeptoClawConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	c.restoreZeptoClawConfig(opts)
	TeardownSubprocessEnforcement(opts)
	return nil
}

func (c *ZeptoClawConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && token == c.gatewayToken {
			return true
		}
	}

	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == c.masterKey {
			return true
		}
	}

	if isLoopback && c.gatewayToken == "" {
		return true
	}

	if c.gatewayToken == "" && c.masterKey == "" {
		return true
	}

	return false
}

// SetCredentials injects the gateway token and master key at sidecar boot.
func (c *ZeptoClawConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *ZeptoClawConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "zeptoclaw",
		RawAPIKey:     ExtractAPIKey(r),
		RawBody:       body,
		RawModel:      ParseModelFromBody(body),
		Stream:        ParseStreamFromBody(body),
		ExtraHeaders:  map[string]string{},
	}

	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}

// zeptoClawBackup stores the original config for teardown.
type zeptoClawBackup struct {
	OriginalProviders json.RawMessage `json:"original_providers"`
	OriginalHooks     json.RawMessage `json:"original_hooks"`
	OriginalSafety    json.RawMessage `json:"original_safety,omitempty"`
}

func (c *ZeptoClawConnector) saveBackup(dataDir string, backup zeptoClawBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, "zeptoclaw_backup.json"), data, 0o644)
}

func (c *ZeptoClawConnector) loadBackup(dataDir string) (zeptoClawBackup, error) {
	var backup zeptoClawBackup
	data, err := os.ReadFile(filepath.Join(dataDir, "zeptoclaw_backup.json"))
	if err != nil {
		return backup, err
	}
	return backup, json.Unmarshal(data, &backup)
}

// ZeptoClawConfigPathOverride allows tests to redirect the config path.
var ZeptoClawConfigPathOverride string

func zeptoClawConfigPath() string {
	if ZeptoClawConfigPathOverride != "" {
		return ZeptoClawConfigPathOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".zeptoclaw", "config.json")
}

// patchZeptoClawConfig reads ZeptoClaw's config.json, backs up the original
// provider, hook, and safety settings, then patches each provider's api_base to
// route through the proxy and sets safety.allow_private_endpoints so the
// localhost proxy URL passes SSRF validation.
func (c *ZeptoClawConnector) patchZeptoClawConfig(opts SetupOpts) error {
	configPath := zeptoClawConfigPath()

	config := map[string]interface{}{}
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read zeptoclaw config: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse zeptoclaw config: %w", err)
		}
	}

	backup := zeptoClawBackup{}
	if providers, ok := config["providers"]; ok {
		raw, _ := json.Marshal(providers)
		backup.OriginalProviders = raw
	}
	if hooks, ok := config["hooks"]; ok {
		raw, _ := json.Marshal(hooks)
		backup.OriginalHooks = raw
	}
	if safety, ok := config["safety"]; ok {
		raw, _ := json.Marshal(safety)
		backup.OriginalSafety = raw
	}

	if err := c.saveBackup(opts.DataDir, backup); err != nil {
		return fmt.Errorf("save zeptoclaw backup: %w", err)
	}

	proxyURL := "http://" + opts.ProxyAddr + "/c/zeptoclaw"

	// Patch each configured provider's api_base to route through proxy.
	providers, _ := config["providers"].(map[string]interface{})
	if providers == nil {
		providers = map[string]interface{}{}
	}
	for name, val := range providers {
		prov, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		// Skip non-provider keys (retry, fallback, rotation, plugins).
		switch name {
		case "retry", "fallback", "rotation", "plugins":
			continue
		}
		prov["api_base"] = proxyURL
	}
	config["providers"] = providers

	// Allow the localhost proxy URL to pass SSRF validation.
	safety, _ := config["safety"].(map[string]interface{})
	if safety == nil {
		safety = map[string]interface{}{}
	}
	safety["allow_private_endpoints"] = true
	config["safety"] = safety

	hookDir := filepath.Join(opts.DataDir, "hooks")
	config["hooks"] = map[string]interface{}{
		"before_tool":    filepath.Join(hookDir, "inspect-tool.sh"),
		"before_request": filepath.Join(hookDir, "inspect-request.sh"),
		"after_response": filepath.Join(hookDir, "inspect-response.sh"),
		"after_tool":     filepath.Join(hookDir, "inspect-tool-response.sh"),
	}

	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal zeptoclaw config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create zeptoclaw config dir: %w", err)
	}

	return os.WriteFile(configPath, out, 0o644)
}

func (c *ZeptoClawConnector) restoreZeptoClawConfig(opts SetupOpts) {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		return
	}

	configPath := zeptoClawConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	config := map[string]interface{}{}
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	if len(backup.OriginalProviders) > 0 && string(backup.OriginalProviders) != "null" {
		var orig interface{}
		json.Unmarshal(backup.OriginalProviders, &orig)
		config["providers"] = orig
	} else {
		delete(config, "providers")
	}

	if len(backup.OriginalHooks) > 0 && string(backup.OriginalHooks) != "null" {
		var orig interface{}
		json.Unmarshal(backup.OriginalHooks, &orig)
		config["hooks"] = orig
	} else {
		delete(config, "hooks")
	}

	if len(backup.OriginalSafety) > 0 && string(backup.OriginalSafety) != "null" {
		var orig interface{}
		json.Unmarshal(backup.OriginalSafety, &orig)
		config["safety"] = orig
	} else {
		delete(config, "safety")
	}

	out, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, out, 0o644)
	os.Remove(filepath.Join(opts.DataDir, "zeptoclaw_backup.json"))
}
