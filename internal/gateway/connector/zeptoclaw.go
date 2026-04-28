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
	"sync"
)

// ZeptoClawConnector handles LLM traffic routing and tool inspection for ZeptoClaw.
// LLM traffic: patches api_base in ~/.zeptoclaw/config.json to route through proxy.
// Tool inspection: proxy-side response-scan — the proxy inspects tool_calls in the
// LLM response stream. ZeptoClaw's hooks schema (before_tool/after_tool) expects
// structured HookRule objects, not script paths, so config-based hook wiring is not
// used. Hook scripts are still written to disk for subprocess enforcement.
type ZeptoClawConnector struct {
	gatewayToken string
	masterKey    string

	loopbackWarn sync.Once

	// snapshotMu protects providers.
	snapshotMu sync.RWMutex
	providers  map[string]ZeptoClawProviderEntry
}

// ZeptoClawProviderEntry is a resolved provider record captured at Setup time
// from ~/.zeptoclaw/config.json. ZeptoClaw is a native binary with no fetch
// interceptor, so the connector must synthesize the X-DC-Target-URL /
// X-AI-Auth that the proxy's provider-resolution chain expects. The snapshot
// holds the real upstream and key for every provider the user configured.
type ZeptoClawProviderEntry struct {
	APIBase string
	APIKey  string
}

// zeptoClawDefaultAPIBase maps provider names to well-known upstream URLs so a
// snapshot entry whose api_base was null in the source config can still be
// routed. Kept intentionally small — only providers ZeptoClaw lists as
// top-level keys in its config schema.
var zeptoClawDefaultAPIBase = map[string]string{
	"anthropic":  "https://api.anthropic.com",
	"openai":     "https://api.openai.com/v1",
	"openrouter": "https://openrouter.ai/api/v1",
	"groq":       "https://api.groq.com/openai/v1",
	"deepseek":   "https://api.deepseek.com",
	"gemini":     "https://generativelanguage.googleapis.com/v1beta",
	"xai":        "https://api.x.ai/v1",
	"novita":     "https://api.novita.ai/v3/openai",
}

// NewZeptoClawConnector creates a new ZeptoClaw connector.
func NewZeptoClawConnector() *ZeptoClawConnector {
	return &ZeptoClawConnector{}
}

func (c *ZeptoClawConnector) Name() string                           { return "zeptoclaw" }
func (c *ZeptoClawConnector) Description() string                    { return "api_base redirect + proxy response-scan" }
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
	if err := WriteHookScriptsForConnector(hookDir, opts.APIAddr, opts.APIToken, c.Name()); err != nil {
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
	var errs []string

	if err := c.restoreZeptoClawConfig(opts); err != nil {
		errs = append(errs, fmt.Sprintf("restore config: %v", err))
	}

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		errs = append(errs, fmt.Sprintf("subprocess enforcement: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("zeptoclaw teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (c *ZeptoClawConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check if config.json still has proxy api_base
	proxyURL := "http://" + opts.ProxyAddr + "/c/zeptoclaw"
	configPath := zeptoClawConfigPath()
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]interface{}
		if json.Unmarshal(data, &config) == nil {
			if providers, ok := config["providers"].(map[string]interface{}); ok {
				for name, val := range providers {
					prov, ok := val.(map[string]interface{})
					if !ok {
						continue
					}
					if base, ok := prov["api_base"].(string); ok && base == proxyURL {
						residual = append(residual, fmt.Sprintf("providers.%s.api_base still points to proxy", name))
					}
				}
			}
		}
	}

	// Check backup file (should be removed after clean teardown)
	backupPath := filepath.Join(opts.DataDir, "zeptoclaw_backup.json")
	if _, err := os.Stat(backupPath); err == nil {
		residual = append(residual, "zeptoclaw_backup.json still exists")
	}

	// Check shims directory
	shimDir := filepath.Join(opts.DataDir, "shims")
	if entries, err := os.ReadDir(shimDir); err == nil && len(entries) > 0 {
		residual = append(residual, fmt.Sprintf("shims/ still has %d entries", len(entries)))
	}

	if len(residual) > 0 {
		return fmt.Errorf("zeptoclaw teardown incomplete: %s", strings.Join(residual, "; "))
	}
	return nil
}

// Authenticate trusts loopback callers unconditionally. ZeptoClaw is
// a native Rust binary with no fetch interceptor: its Authorization
// header carries the upstream provider API key, never DefenseClaw's
// gateway token, and it has no way to inject X-DC-Auth. Denying
// loopback when a gateway token is configured would make zeptoclaw
// fundamentally unroutable — every request would 401 before guardrail
// inspection ran.
//
// Non-loopback callers (bridge / remote deployments) are still gated
// on X-DC-Auth or the master key. The gateway token exists to protect
// those paths, not to break the local-only native binary path.
func (c *ZeptoClawConnector) Authenticate(r *http.Request) bool {
	if IsLoopback(r) {
		if c.gatewayToken != "" {
			c.loopbackWarn.Do(func() {
				fmt.Fprintf(os.Stderr, "[SECURITY] zeptoclaw: loopback request accepted without token — DEFENSECLAW_GATEWAY_TOKEN is set but zeptoclaw connector cannot enforce it on native binary traffic\n")
			})
		}
		return true
	}

	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && SecureTokenMatch(token, c.gatewayToken) {
			return true
		}
	}

	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && SecureTokenMatch(strings.TrimPrefix(auth, "Bearer "), c.masterKey) {
			return true
		}
	}

	return false
}

// SetCredentials injects the gateway token and master key at sidecar boot.
func (c *ZeptoClawConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

// SetProviderSnapshot stores the user's resolved provider table. Called by
// Setup() after reading ~/.zeptoclaw/config.json, and exposed so tests can
// seed it directly.
func (c *ZeptoClawConnector) SetProviderSnapshot(snap map[string]ZeptoClawProviderEntry) {
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.providers = snap
}

// ProviderSnapshot returns a copy of the provider table.
func (c *ZeptoClawConnector) ProviderSnapshot() map[string]ZeptoClawProviderEntry {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	out := make(map[string]ZeptoClawProviderEntry, len(c.providers))
	for k, v := range c.providers {
		out[k] = v
	}
	return out
}

// resolveUpstream picks the upstream api_base and key for a given model.
//
//   - Model strings look like "anthropic/claude-sonnet-4.5" or plain
//     "gpt-4o". If the prefix matches a configured provider with a usable
//     key, use it directly.
//   - Otherwise (no prefix, unknown prefix, or the matching entry has no
//     key because the user never configured that slot), fall back to the
//     single configured provider. ZeptoClaw's built-in model router takes
//     a "provider/model" string that crosses its configured providers, so
//     an OpenRouter-only config can still legitimately send
//     "anthropic/claude-*" — that request must go to OpenRouter upstream.
//
// Returns ("", "") when no usable provider is configured; the caller then
// leaves RawUpstream empty and the proxy's default resolver kicks in.
func (c *ZeptoClawConnector) resolveUpstream(model string) (string, string) {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()

	if prefix, _, ok := splitZeptoClawModel(model); ok {
		if e, found := c.providers[prefix]; found && e.APIKey != "" {
			return zeptoClawBaseOrDefault(prefix, e.APIBase), e.APIKey
		}
	}

	// No direct hit; fall back to the sole configured provider. If the
	// user has configured several, we have no preference — return the
	// first one with a key. A richer policy (e.g. rotation order from the
	// config) would go here.
	for name, e := range c.providers {
		if e.APIKey == "" {
			continue
		}
		return zeptoClawBaseOrDefault(name, e.APIBase), e.APIKey
	}

	return "", ""
}

// splitZeptoClawModel splits "prefix/tail" into ("prefix", "tail", true) if
// the prefix is a ZeptoClaw-known provider name. Returns ("", model, false)
// otherwise so plain model strings like "gpt-4o" are treated as unprefixed.
func splitZeptoClawModel(model string) (prefix, tail string, ok bool) {
	i := strings.IndexByte(model, '/')
	if i < 0 {
		return "", model, false
	}
	p := model[:i]
	if _, known := zeptoClawDefaultAPIBase[p]; !known {
		return "", model, false
	}
	return p, model[i+1:], true
}

func zeptoClawBaseOrDefault(provider, configured string) string {
	if configured != "" {
		return configured
	}
	return zeptoClawDefaultAPIBase[provider]
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

	// ZeptoClaw is a native binary with no fetch interceptor to set
	// X-DC-Target-URL / X-AI-Auth. Resolve the real upstream from the
	// provider snapshot captured at Setup; the request that actually
	// hits the proxy then carries the inbound client key, so prefer the
	// snapshot key when present and fall back to the inbound header.
	if upstream, key := c.resolveUpstream(cs.RawModel); upstream != "" {
		cs.RawUpstream = upstream
		if key != "" {
			cs.RawAPIKey = key
		}
	}

	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}

// --- ComponentScanner interface ---

func (c *ZeptoClawConnector) SupportsComponentScanning() bool { return true }

func (c *ZeptoClawConnector) ComponentTargets(cwd string) map[string][]string {
	home := os.Getenv("HOME")
	zeptoDir := filepath.Join(home, ".zeptoclaw")

	targets := map[string][]string{
		"skill":  {filepath.Join(zeptoDir, "skills"), filepath.Join(cwd, ".zeptoclaw", "skills")},
		"plugin": {filepath.Join(zeptoDir, "plugins"), filepath.Join(zeptoDir, "plugins", "cache")},
		"mcp":    {filepath.Join(zeptoDir, "config.json"), filepath.Join(cwd, ".mcp.json")},
		"config": {filepath.Join(zeptoDir, "config.json")},
	}
	return targets
}

// zeptoClawBackup stores the original config for teardown.
type zeptoClawBackup struct {
	OriginalProviders json.RawMessage `json:"original_providers"`
	OriginalSafety    json.RawMessage `json:"original_safety,omitempty"`
}

func (c *ZeptoClawConnector) saveBackup(dataDir string, backup zeptoClawBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, "zeptoclaw_backup.json"), data, 0o600)
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
//
// Idempotency: on re-entry (second sidecar boot), the on-disk config already
// contains the patched api_base. Writing a fresh backup from that state would
// lose the user's pristine upstream forever. We therefore keep the first
// backup we wrote and source the snapshot from it when it exists.
func (c *ZeptoClawConnector) patchZeptoClawConfig(opts SetupOpts) error {
	configPath := zeptoClawConfigPath()

	return withFileLock(configPath, func() error {
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

		backupPath := filepath.Join(opts.DataDir, "zeptoclaw_backup.json")
		_, backupStatErr := os.Stat(backupPath)
		backupExists := backupStatErr == nil

		pristineProviders := map[string]interface{}{}
		if backupExists {
			if bk, err := c.loadBackup(opts.DataDir); err == nil && len(bk.OriginalProviders) > 0 {
				_ = json.Unmarshal(bk.OriginalProviders, &pristineProviders)
			}
		} else {
			if p, ok := config["providers"].(map[string]interface{}); ok {
				pristineProviders = p
			}
		}

		if !backupExists {
			backup := zeptoClawBackup{}
			if providers, ok := config["providers"]; ok {
				raw, _ := json.Marshal(providers)
				backup.OriginalProviders = raw
			}
			if safety, ok := config["safety"]; ok {
				raw, _ := json.Marshal(safety)
				backup.OriginalSafety = raw
			}
			if err := c.saveBackup(opts.DataDir, backup); err != nil {
				return fmt.Errorf("save zeptoclaw backup: %w", err)
			}
		}

		proxyURL := "http://" + opts.ProxyAddr + "/c/zeptoclaw"

		snapshot := map[string]ZeptoClawProviderEntry{}
		for name, val := range pristineProviders {
			prov, ok := val.(map[string]interface{})
			if !ok {
				continue
			}
			switch name {
			case "retry", "fallback", "rotation", "plugins":
				continue
			}
			entry := ZeptoClawProviderEntry{
				APIBase: zeptoClawDefaultAPIBase[name],
			}
			if base, ok := prov["api_base"].(string); ok && base != "" {
				entry.APIBase = base
			}
			if key, ok := prov["api_key"].(string); ok {
				entry.APIKey = key
			}
			snapshot[name] = entry
		}
		c.SetProviderSnapshot(snapshot)

		if len(snapshot) == 0 {
			if backupExists {
				fmt.Fprintf(os.Stderr, "[zeptoclaw] WARNING: backup at %s exists but yielded no usable providers — config may be corrupted\n", backupPath)
			}
			return fmt.Errorf("zeptoclaw: no usable providers found in %s (backup exists: %v) — cannot route LLM traffic",
				configPath, backupExists)
		}

		providers, _ := config["providers"].(map[string]interface{})
		if providers == nil {
			providers = map[string]interface{}{}
		}
		for name, val := range providers {
			prov, ok := val.(map[string]interface{})
			if !ok {
				continue
			}
			switch name {
			case "retry", "fallback", "rotation", "plugins":
				continue
			}
			prov["api_base"] = proxyURL
		}
		config["providers"] = providers

		safety, _ := config["safety"].(map[string]interface{})
		if safety == nil {
			safety = map[string]interface{}{}
		}
		safety["allow_private_endpoints"] = true
		config["safety"] = safety

		out, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal zeptoclaw config: %w", err)
		}

		return atomicWriteFile(configPath, out, 0o644)
	})
}

func (c *ZeptoClawConnector) restoreZeptoClawConfig(opts SetupOpts) error {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		return fmt.Errorf("load zeptoclaw backup: %w", err)
	}

	configPath := zeptoClawConfigPath()

	return withFileLock(configPath, func() error {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read zeptoclaw config for restore: %w", err)
		}

		config := map[string]interface{}{}
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse zeptoclaw config for restore: %w", err)
		}

		if len(backup.OriginalProviders) > 0 && string(backup.OriginalProviders) != "null" {
			var orig interface{}
			if err := json.Unmarshal(backup.OriginalProviders, &orig); err != nil {
				return fmt.Errorf("unmarshal original providers: %w", err)
			}
			config["providers"] = orig
		} else {
			delete(config, "providers")
		}

		if len(backup.OriginalSafety) > 0 && string(backup.OriginalSafety) != "null" {
			var orig interface{}
			if err := json.Unmarshal(backup.OriginalSafety, &orig); err != nil {
				return fmt.Errorf("unmarshal original safety: %w", err)
			}
			config["safety"] = orig
		} else {
			delete(config, "safety")
		}

		out, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal restored config: %w", err)
		}

		if err := atomicWriteFile(configPath, out, 0o644); err != nil {
			return fmt.Errorf("write restored config: %w", err)
		}

		os.Remove(filepath.Join(opts.DataDir, "zeptoclaw_backup.json"))
		return nil
	})
}
