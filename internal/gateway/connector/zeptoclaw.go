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
// LLM response stream.
//
// === BY-DESIGN: ZeptoClaw before_tool hook wiring is WONTFIX (architectural) ===
// Plan C3 / matrix §"Out of scope". ZeptoClaw's HooksConfig.before_tool is a
// notification list — an in-process callback signal — NOT an external-script
// trigger. The shape is `[]HookRule{Match, Action}`, structured objects, not
// shell paths. There is no schema slot for "run /path/to/inspect-tool.sh
// before this tool fires" and adding one is out of our control: we do not own
// the ZeptoClaw binary.
//
// What this means for the security guarantee:
//  1. Pre-tool gating cannot run from the agent process directly.
//  2. We achieve the same result via proxy-side response-scan: the gateway
//     inspects the model's `tool_calls` array on the LLM response stream
//     before it reaches the agent, and rejects/rewrites disallowed calls.
//  3. The ToolModeBoth setting on this connector is what wires that flow —
//     the proxy is the policy enforcement point, not the agent.
//
// The hook scripts are still written under DataDir/hooks for two reasons:
//   - Subprocess enforcement (shim PATH) reuses inspect-tool.sh.
//   - Forward-compat: if ZeptoClaw ever grows external-script hook
//     support, the artifacts are already on disk and only the agent-side
//     wiring needs to land.
//
// Do NOT add a "patch before_tool to point at our script" branch in Setup —
// it will silently no-op or, worse, write a malformed HookRule and break
// the user's config. See plan C3 + docs/CONNECTOR-MATRIX.md "By-design
// connector limitations" for the canonical statement.
type ZeptoClawConnector struct {
	gatewayToken string
	masterKey    string

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

// AllowedHosts returns ZeptoClaw's upstream LLM hosts that the
// firewall layer must allow when the user has BYOK'd against
// non-OpenAI/Anthropic providers. The default ZeptoClaw config ships
// with OpenRouter and Together AI as commonly-used cheap upstream
// brokers. Without these in the firewall allow-list, a default-deny
// firewall blocks every chat at L4 and the user sees "DNS lookup
// blocked" instead of a clean "no API key" error. See S3.3 / F26.
func (c *ZeptoClawConnector) AllowedHosts() []string {
	return []string{
		"openrouter.ai",
		"api.together.xyz",
	}
}

func (c *ZeptoClawConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Surface 1: Patch ZeptoClaw config to route api_base through proxy.
	if err := c.patchZeptoClawConfig(opts); err != nil {
		return fmt.Errorf("zeptoclaw config patch: %w", err)
	}

	// Surface 2: Tool inspection hook script
	// Plan C2: ZeptoClaw does not own a vendor hook template
	// (only generic inspect-* scripts apply). It deliberately does
	// NOT implement HookScriptOwner — the empty-extras path below
	// flows through writeHookScriptsCommon's generic-only branch.
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObject(hookDir, opts.APIAddr, opts.APIToken, c); err != nil {
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

// providerBearerMatchesSnapshot accepts loopback callers that present the
// same provider api_key ZeptoClaw has in config (the snapshot is taken before
// api_base is rewritten to the proxy). Remote callers cannot use this path.
func (c *ZeptoClawConnector) providerBearerMatchesSnapshot(r *http.Request) bool {
	if !IsLoopback(r) {
		return false
	}
	auth := r.Header.Get("Authorization")
	key := ExtractBearerKey(auth)
	if key == "" || strings.HasPrefix(key, "sk-dc-") {
		return false
	}
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	for _, e := range c.providers {
		if e.APIKey == "" {
			continue
		}
		if SecureTokenMatch(key, e.APIKey) {
			return true
		}
	}
	return false
}

// Authenticate enforces credentials on every ZeptoClaw request — no more
// unconditional loopback bypass (plan B1 / S0.3). The previous behavior
// allowed any local process to hit /c/zeptoclaw/* and have its
// upstream key recorded in the provider-snapshot path. With first-boot
// token synthesis (plan B2), the gateway always has a token to enforce,
// so the only legitimate "no token configured" path is the brief window
// before ensureGatewayToken() runs. We retain a narrow loopback-allow
// for that case so a fully-fresh install can complete its first request
// without 401, but reject loopback the moment a token is configured.
//
// ZeptoClaw is a native Rust binary with no fetch interceptor, so the
// hooks/inspect-*.sh scripts (which run on the same host) inject the
// X-DC-Auth header bearing the synthesized gateway token. That token
// flow is what keeps loopback callers authenticated post-boot.
//
// The ZeptoClaw process itself sends only the upstream provider credential
// in Authorization (e.g. Bedrock bearer). After B1 we still require either
// X-DC-Auth, the master key, or—on loopback only—a bearer that matches an
// api_key captured in the Setup-time provider snapshot (same secret Zepto
// has in ~/.zeptoclaw/config.json).
func (c *ZeptoClawConnector) Authenticate(r *http.Request) bool {
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

	if c.gatewayToken != "" && c.providerBearerMatchesSnapshot(r) {
		return true
	}

	// Narrow loopback-allow ONLY for the unconfigured-gateway window.
	// Once first-boot token synthesis lands (plan B2), this branch is
	// effectively unreachable in production — but defensive belt-and-
	// suspenders for the brief boot interval before ensureGatewayToken
	// finishes writing ~/.defenseclaw/.env.
	if c.gatewayToken == "" && c.masterKey == "" && IsLoopback(r) {
		return true
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

// Route classifies inbound /c/zeptoclaw/* traffic. Plan B1: the
// provider-snapshot lookup and inbound-key extraction are now gated
// behind isChatPath. Non-chat paths get an empty RawAPIKey and a
// PassthroughMode=true signal — they were never going to reach a
// chat completion API anyway, and recording the inbound key on a
// non-chat path was a needless secret-residency risk.
func (c *ZeptoClawConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "zeptoclaw",
		RawBody:       body,
		RawModel:      ParseModelFromBody(body),
		Stream:        ParseStreamFromBody(body),
		ExtraHeaders:  map[string]string{},
	}

	if !isChatPath(r.URL.Path) {
		// Non-chat path: leave RawAPIKey empty and skip the upstream
		// resolver. The proxy's passthrough path forwards the inbound
		// Authorization header verbatim — no DefenseClaw machinery
		// touches the request body or the secret.
		cs.PassthroughMode = true
		return cs, nil
	}

	cs.RawAPIKey = ExtractAPIKey(r)

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

	return cs, nil
}

// --- AgentPathProvider / EnvRequirementsProvider / HookScriptProvider ---

// AgentPaths reports the on-disk footprint ZeptoClaw's connector
// touches. ZeptoClaw is a native Rust binary configured entirely
// through ~/.zeptoclaw/config.json, so only that file is patched.
// The connector also writes the inspect-* hook scripts into
// <DataDir>/hooks/ for proxy-side tool inspection.
func (c *ZeptoClawConnector) AgentPaths(opts SetupOpts) AgentPaths {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	hooks := make([]string, 0, len(HookScripts()))
	for _, name := range HookScripts() {
		hooks = append(hooks, filepath.Join(hookDir, name))
	}
	return AgentPaths{
		PatchedFiles: []string{zeptoClawConfigPath()},
		BackupFiles:  []string{filepath.Join(opts.DataDir, "zeptoclaw_backup.json")},
		HookScripts:  hooks,
		CreatedDirs:  []string{filepath.Join(opts.DataDir, "shims")},
	}
}

// HookScripts is a convenience wrapper over AgentPaths.HookScripts
// so callers that only need the hook list don't have to construct a
// full AgentPaths.
func (c *ZeptoClawConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

// RequiredEnv reports the env vars ZeptoClaw needs for proxy
// routing. ZeptoClaw is a native binary that reads its api_base
// from config.json, so no env vars are required — Setup patches
// the JSON file directly. We still return a single EnvScopeNone
// entry as documentation so `defenseclaw doctor` can show a
// "no env vars required" line instead of staying silent.
func (c *ZeptoClawConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{
		{
			Name:        "",
			Scope:       EnvScopeNone,
			Required:    false,
			Description: "ZeptoClaw is configured via ~/.zeptoclaw/config.json (api_base patched at setup); no env vars are needed for routing.",
		},
	}
}

// HasUsableProviders implements ProviderProbe. Counts the entries in
// the provider snapshot that have a non-empty API key — these are the
// upstreams that resolveUpstream() can route a chat request to. Setup
// already errors when the snapshot is empty, but plan A4 tightens the
// guarantee at boot: even if Setup somehow returned a snapshot full of
// blank-key entries (e.g. a config edit between setup and run), the
// gateway refuses to start traffic.
func (c *ZeptoClawConnector) HasUsableProviders() (int, error) {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	count := 0
	for _, e := range c.providers {
		if strings.TrimSpace(e.APIKey) != "" {
			count++
		}
	}
	return count, nil
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
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), "config.json", configPath); err != nil {
			return fmt.Errorf("capture zeptoclaw config backup: %w", err)
		}

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

		if err := atomicWriteFile(configPath, out, 0o644); err != nil {
			return err
		}
		return updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "config.json", configPath)
	})
}

func (c *ZeptoClawConnector) restoreZeptoClawConfig(opts SetupOpts) error {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		return fmt.Errorf("load zeptoclaw backup: %w", err)
	}

	configPath := zeptoClawConfigPath()

	return withFileLock(configPath, func() error {
		if restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "config.json", configPath); err != nil {
			return fmt.Errorf("managed config restore: %w", err)
		} else if restored {
			os.Remove(filepath.Join(opts.DataDir, "zeptoclaw_backup.json"))
			return nil
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read zeptoclaw config for restore: %w", err)
		}

		config := map[string]interface{}{}
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("parse zeptoclaw config for restore: %w", err)
		}

		proxyURL := "http://" + opts.ProxyAddr + "/c/zeptoclaw"
		originalProviders := map[string]interface{}{}
		if len(backup.OriginalProviders) > 0 && string(backup.OriginalProviders) != "null" {
			if err := json.Unmarshal(backup.OriginalProviders, &originalProviders); err != nil {
				return fmt.Errorf("unmarshal original providers: %w", err)
			}
		}
		if providers, ok := config["providers"].(map[string]interface{}); ok {
			for name, val := range providers {
				prov, ok := val.(map[string]interface{})
				if !ok {
					continue
				}
				if cur, _ := prov["api_base"].(string); cur != proxyURL {
					continue
				}
				if origVal, ok := originalProviders[name]; ok {
					if origProv, ok := origVal.(map[string]interface{}); ok {
						if origBase, ok := origProv["api_base"]; ok {
							prov["api_base"] = origBase
						} else {
							delete(prov, "api_base")
						}
					}
				} else {
					delete(prov, "api_base")
				}
				providers[name] = prov
			}
			config["providers"] = providers
		}

		originalSafety := map[string]interface{}{}
		if len(backup.OriginalSafety) > 0 && string(backup.OriginalSafety) != "null" {
			if err := json.Unmarshal(backup.OriginalSafety, &originalSafety); err != nil {
				return fmt.Errorf("unmarshal original safety: %w", err)
			}
		}
		if safety, ok := config["safety"].(map[string]interface{}); ok {
			if cur, _ := safety["allow_private_endpoints"].(bool); cur {
				if orig, ok := originalSafety["allow_private_endpoints"]; ok {
					safety["allow_private_endpoints"] = orig
				} else {
					delete(safety, "allow_private_endpoints")
				}
			}
			if len(safety) == 0 {
				delete(config, "safety")
			} else {
				config["safety"] = safety
			}
		}

		out, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal restored config: %w", err)
		}

		if err := atomicWriteFile(configPath, out, 0o644); err != nil {
			return fmt.Errorf("write restored config: %w", err)
		}

		os.Remove(filepath.Join(opts.DataDir, "zeptoclaw_backup.json"))
		discardManagedFileBackup(opts.DataDir, c.Name(), "config.json")
		return nil
	})
}
