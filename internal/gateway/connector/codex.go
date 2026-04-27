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

	"github.com/pelletier/go-toml/v2"
)

// CodexConnector handles all security surfaces for OpenAI Codex.
// LLM traffic: rewrites [model_providers.*].base_url in
// ~/.codex/config.toml to route through the DefenseClaw proxy, and
// snapshots the original upstreams so Route() can synthesize
// X-DC-Target-URL / X-AI-Auth for the native Rust binary (no fetch
// interceptor available).
// Tool inspection: hook script called from the inline [hooks] TOML
// table Setup() writes into config.toml.
// Implements ComponentScanner, StopScanner.
type CodexConnector struct {
	gatewayToken string
	masterKey    string

	// snapshotMu protects providers.
	snapshotMu sync.RWMutex
	providers  map[string]CodexProviderEntry
}

// CodexProviderEntry is a resolved provider record captured at Setup
// time from ~/.codex/config.toml, before base_url is rewritten to the
// proxy. Codex is a native binary with no fetch interceptor, so
// Route() reads this snapshot to supply the real upstream and API key
// the proxy needs to forward the request.
type CodexProviderEntry struct {
	BaseURL string
	APIKey  string
}

// NewCodexConnector creates a new Codex connector.
func NewCodexConnector() *CodexConnector {
	return &CodexConnector{}
}

func (c *CodexConnector) Name() string { return "codex" }
func (c *CodexConnector) Description() string {
	return "env var + hook script (6 events, component scanning)"
}
func (c *CodexConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *CodexConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *CodexConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := c.writeEnvOverride(opts); err != nil {
		return fmt.Errorf("codex env override: %w", err)
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsWithToken(hookDir, opts.APIAddr, opts.APIToken); err != nil {
		return fmt.Errorf("codex hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "codex-hook.sh")
	if err := c.patchCodexConfig(opts, hookScript); err != nil {
		return fmt.Errorf("codex config.toml patch: %w", err)
	}

	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("codex subprocess enforcement: %w", err)
	}

	return nil
}

func (c *CodexConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	c.restoreCodexConfig(opts)
	c.removeEnvOverride(opts)

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		return fmt.Errorf("codex teardown: subprocess enforcement: %w", err)
	}
	return nil
}

func (c *CodexConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check env override files
	for _, name := range []string{codexEnvFileName, "codex.env"} {
		if _, err := os.Stat(filepath.Join(opts.DataDir, name)); err == nil {
			residual = append(residual, name)
		}
	}

	// Check shims directory
	shimDir := filepath.Join(opts.DataDir, "shims")
	if entries, err := os.ReadDir(shimDir); err == nil && len(entries) > 0 {
		residual = append(residual, fmt.Sprintf("shims/ still has %d entries", len(entries)))
	}

	if len(residual) > 0 {
		return fmt.Errorf("codex teardown incomplete: %s", strings.Join(residual, "; "))
	}
	return nil
}

// Authenticate trusts loopback callers unconditionally because
// codex-cli is a native Rust binary with no fetch interceptor: it
// sends the upstream provider API key in the Authorization header and
// cannot inject X-DC-Auth. Denying loopback when a gateway token is
// configured would make codex fundamentally unroutable — every request
// would 401 and no guardrail would ever execute.
//
// Non-loopback callers (bridge / remote deployments) are still gated
// on X-DC-Auth or the master key. The gateway token exists to protect
// those paths, not to break the local-only native binary path.
func (c *CodexConnector) Authenticate(r *http.Request) bool {
	if IsLoopback(r) {
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

func (c *CodexConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

// SetProviderSnapshot stores the user's resolved provider table. Called
// by Setup() after reading ~/.codex/config.toml, exposed so tests can
// seed it directly.
func (c *CodexConnector) SetProviderSnapshot(snap map[string]CodexProviderEntry) {
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.providers = snap
}

// ProviderSnapshot returns a copy of the provider table.
func (c *CodexConnector) ProviderSnapshot() map[string]CodexProviderEntry {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	out := make(map[string]CodexProviderEntry, len(c.providers))
	for k, v := range c.providers {
		out[k] = v
	}
	return out
}

// resolveUpstream picks the upstream base_url + api_key for the given
// request. Codex config.toml's top-level `model_provider` names the
// active provider, but that context is lost by the time the request
// hits the proxy. We pick the first entry that has a usable key —
// typical codex installs configure one provider at a time.
func (c *CodexConnector) resolveUpstream() (string, string) {
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()

	for _, e := range c.providers {
		if e.APIKey != "" && e.BaseURL != "" {
			return e.BaseURL, e.APIKey
		}
	}
	// Relaxed fallback: accept an entry with just a base_url so the
	// upstream still gets reached; the client-supplied Authorization
	// header will carry its own credential in that case.
	for _, e := range c.providers {
		if e.BaseURL != "" {
			return e.BaseURL, ""
		}
	}
	return "", ""
}

func (c *CodexConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	cs := &ConnectorSignals{
		ConnectorName: "codex",
		RawAPIKey:     ExtractAPIKey(r),
		RawBody:       body,
		RawModel:      ParseModelFromBody(body),
		Stream:        ParseStreamFromBody(body),
		ExtraHeaders:  map[string]string{},
	}

	// Codex is a native binary with no fetch interceptor to set
	// X-DC-Target-URL / X-AI-Auth. Resolve the real upstream from the
	// provider snapshot captured at Setup. Prefer the snapshot key
	// over the inbound Authorization header so upstream auth stays
	// consistent with what the user configured in config.toml.
	if upstream, key := c.resolveUpstream(); upstream != "" {
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

func (c *CodexConnector) SupportsComponentScanning() bool { return true }

func (c *CodexConnector) ComponentTargets(cwd string) map[string][]string {
	home := os.Getenv("HOME")
	codexDir := filepath.Join(home, ".codex")

	targets := map[string][]string{
		"skill":  {filepath.Join(codexDir, "skills"), filepath.Join(cwd, ".codex", "skills")},
		"plugin": {filepath.Join(codexDir, "plugins"), filepath.Join(codexDir, "plugins", "cache")},
		"mcp":    {filepath.Join(codexDir, "config.toml"), filepath.Join(cwd, ".mcp.json")},
	}
	return targets
}

// --- StopScanner interface ---

func (c *CodexConnector) SupportsStopScan() bool { return true }

// --- Env override ---

type codexBackup struct {
	HadBaseURL bool   `json:"had_base_url"`
	OldBaseURL string `json:"old_base_url"`
}

func (c *CodexConnector) saveBackup(dataDir string, backup codexBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, "codex_backup.json"), data, 0o600)
}

const codexEnvFileName = "codex_env.sh"

func (c *CodexConnector) writeEnvOverride(opts SetupOpts) error {
	backup := codexBackup{}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		backup.HadBaseURL = true
		backup.OldBaseURL = v
	}
	if err := c.saveBackup(opts.DataDir, backup); err != nil {
		return fmt.Errorf("save codex backup: %w", err)
	}

	proxyURL := "http://" + opts.ProxyAddr + "/c/codex"
	content := fmt.Sprintf(
		"# Generated by defenseclaw setup — source this file before running codex.\n"+
			"export OPENAI_BASE_URL=%q\n",
		proxyURL,
	)

	envPath := filepath.Join(opts.DataDir, codexEnvFileName)
	if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write codex env file: %w", err)
	}

	dotenvPath := filepath.Join(opts.DataDir, "codex.env")
	dotenvContent := fmt.Sprintf("OPENAI_BASE_URL=%s\n", proxyURL)
	if err := os.WriteFile(dotenvPath, []byte(dotenvContent), 0o644); err != nil {
		return fmt.Errorf("write codex .env: %w", err)
	}

	return nil
}

func (c *CodexConnector) removeEnvOverride(opts SetupOpts) {
	os.Remove(filepath.Join(opts.DataDir, codexEnvFileName))
	os.Remove(filepath.Join(opts.DataDir, "codex.env"))
	os.Remove(filepath.Join(opts.DataDir, "codex_backup.json"))
}

// --- config.toml patching (LLM routing + hook registration) ---
//
// Codex reads provider base_url from ~/.codex/config.toml and *ignores*
// OPENAI_BASE_URL for non-default providers (openrouter, ollama,
// lmstudio, etc.). To guarantee every model provider flows through
// DefenseClaw, rewrite each [model_providers.*].base_url to the proxy.
//
// Hooks are loaded from a sibling hooks.json referenced by
// config.toml's top-level `hooks` key. The feature flag
// features.codex_hooks must be true for hooks to actually run — that
// flag defaults to off.

// CodexConfigPathOverride allows tests to redirect the config path.
var CodexConfigPathOverride string

func codexConfigPath() string {
	if CodexConfigPathOverride != "" {
		return CodexConfigPathOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".codex", "config.toml")
}

type codexConfigBackup struct {
	// Per-provider base_url values keyed by provider name. Only
	// providers that had an explicit base_url are recorded; providers
	// without one are restored by deleting the proxy override we added.
	OriginalBaseURLs map[string]string `json:"original_base_urls"`
	// HadHooksKey tracks whether config.toml already had a top-level
	// [hooks] table so Teardown can decide between restoring the
	// original value vs. deleting the key we added. OriginalHooks
	// holds the inline HookEventsToml struct when present.
	HadHooksKey   bool            `json:"had_hooks_key"`
	OriginalHooks json.RawMessage `json:"original_hooks,omitempty"`
	// AddedCodexHooksFlag is true if we flipped features.codex_hooks on
	// during Setup. Teardown only clears the flag if we were the ones
	// who set it.
	AddedCodexHooksFlag bool `json:"added_codex_hooks_flag"`
}

func (c *CodexConnector) saveConfigBackup(dataDir string, backup codexConfigBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, "codex_config_backup.json"), data, 0o600)
}

func (c *CodexConnector) loadConfigBackup(dataDir string) (codexConfigBackup, error) {
	var backup codexConfigBackup
	data, err := os.ReadFile(filepath.Join(dataDir, "codex_config_backup.json"))
	if err != nil {
		return backup, err
	}
	return backup, json.Unmarshal(data, &backup)
}

// codexHookGroups mirrors claudecode.go's grouping, but timeout is in
// seconds (not ms) per codex's TOML schema. Stop-time scans get a
// larger budget.
var codexHookGroups = []struct {
	eventType string
	matcher   string
	timeout   int
}{
	{"SessionStart", "startup|resume|clear", 30},
	{"UserPromptSubmit", "", 30},
	{"PreToolUse", "*", 30},
	{"PostToolUse", "*", 30},
	{"Stop", "", 90},
}

func (c *CodexConnector) patchCodexConfig(opts SetupOpts, hookScript string) error {
	configPath := codexConfigPath()

	raw, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read codex config: %w", err)
	}
	cfg := map[string]interface{}{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("parse codex config: %w", err)
		}
	}

	backupPath := filepath.Join(opts.DataDir, "codex_config_backup.json")
	backupExists := false
	if _, statErr := os.Stat(backupPath); statErr == nil {
		backupExists = true
	}

	backup := codexConfigBackup{OriginalBaseURLs: map[string]string{}}
	if !backupExists {
		if existing, ok := cfg["hooks"]; ok {
			backup.HadHooksKey = true
			if raw, err := json.Marshal(existing); err == nil {
				backup.OriginalHooks = raw
			}
		}
		if providers, ok := cfg["model_providers"].(map[string]interface{}); ok {
			for name, p := range providers {
				if pm, ok := p.(map[string]interface{}); ok {
					if bu, ok := pm["base_url"].(string); ok {
						backup.OriginalBaseURLs[name] = bu
					}
				}
			}
		}
	}

	// Capture the provider snapshot from the *pristine* config (before
	// the rewrite) so Route() can synthesize X-DC-Target-URL later. If
	// we already have a backup from a prior Setup, prefer that — the
	// current cfg's base_urls will all be the proxy URL already.
	pristineProviders := map[string]interface{}{}
	if backupExists {
		// Rebuild pristine providers from backup: every provider that
		// had an original URL gets it back for snapshot purposes.
		if b, err := c.loadConfigBackup(opts.DataDir); err == nil {
			cur, _ := cfg["model_providers"].(map[string]interface{})
			for name, provVal := range cur {
				pm, ok := provVal.(map[string]interface{})
				if !ok {
					pm = map[string]interface{}{}
				}
				clone := map[string]interface{}{}
				for k, v := range pm {
					clone[k] = v
				}
				if orig, had := b.OriginalBaseURLs[name]; had {
					clone["base_url"] = orig
				} else {
					delete(clone, "base_url")
				}
				pristineProviders[name] = clone
			}
		}
	} else if cur, ok := cfg["model_providers"].(map[string]interface{}); ok {
		for name, v := range cur {
			pristineProviders[name] = v
		}
	}
	c.SetProviderSnapshot(buildCodexProviderSnapshot(pristineProviders))

	proxyURL := "http://" + opts.ProxyAddr + "/c/codex"
	providers, _ := cfg["model_providers"].(map[string]interface{})
	if providers == nil {
		providers = map[string]interface{}{}
	}
	if len(providers) == 0 {
		// No providers declared — create a default openai entry so the
		// operator's Codex install routes even without a hand-written
		// provider block.
		providers["openai"] = map[string]interface{}{
			"name":     "openai",
			"base_url": proxyURL,
			"env_key":  "OPENAI_API_KEY",
		}
	} else {
		for name, p := range providers {
			pm, ok := p.(map[string]interface{})
			if !ok {
				pm = map[string]interface{}{}
			}
			pm["base_url"] = proxyURL
			providers[name] = pm
		}
	}
	cfg["model_providers"] = providers

	// Codex's [hooks] table is an inline struct (HookEventsToml) with
	// per-event fields. It is NOT a path to a hooks.json file — passing
	// a string triggers a TOML parse error at codex startup.
	cfg["hooks"] = buildCodexHooksTable(hookScript)

	features, _ := cfg["features"].(map[string]interface{})
	if features == nil {
		features = map[string]interface{}{}
	}
	if v, ok := features["codex_hooks"].(bool); !ok || !v {
		if !backupExists {
			backup.AddedCodexHooksFlag = true
		}
	}
	features["codex_hooks"] = true
	cfg["features"] = features

	if !backupExists {
		if err := c.saveConfigBackup(opts.DataDir, backup); err != nil {
			return fmt.Errorf("save codex config backup: %w", err)
		}
	}

	out, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal codex config: %w", err)
	}
	// Atomic + 0o600: a partial write of config.toml can brick Codex
	// (it's the only file Codex reads at startup), and the file may
	// carry env-var bindings that resolve to provider API keys at
	// runtime. atomicWriteFile uses CreateTemp + Rename + Chmod so a
	// crash mid-write leaves the previous config in place. See S0.11.
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create codex config dir: %w", err)
	}
	if err := atomicWriteFile(configPath, out, 0o600); err != nil {
		return fmt.Errorf("write codex config: %w", err)
	}

	return nil
}

// buildCodexProviderSnapshot extracts the pristine {base_url, api_key}
// pairs for every provider. api_key is resolved by looking up
// `env_key` in the process env — codex config.toml stores the env var
// *name*, not the key itself. Providers whose env_key is unset are
// still captured (with APIKey=="") so Route() can at least return the
// upstream URL; the proxy will then forward the client's
// Authorization header verbatim.
func buildCodexProviderSnapshot(providers map[string]interface{}) map[string]CodexProviderEntry {
	snapshot := map[string]CodexProviderEntry{}
	for name, val := range providers {
		pm, ok := val.(map[string]interface{})
		if !ok {
			continue
		}
		entry := CodexProviderEntry{}
		if bu, ok := pm["base_url"].(string); ok && bu != "" {
			entry.BaseURL = bu
		}
		if ev, ok := pm["env_key"].(string); ok && ev != "" {
			if v := os.Getenv(ev); v != "" {
				entry.APIKey = v
			}
		}
		if direct, ok := pm["api_key"].(string); ok && direct != "" && entry.APIKey == "" {
			entry.APIKey = direct
		}
		snapshot[name] = entry
	}
	return snapshot
}

// buildCodexHooksTable produces the [hooks] HookEventsToml structure
// that codex expects. Each event maps to a sequence of MatcherGroup
// records; each MatcherGroup wraps a sequence of HookHandlerConfig
// records (type-tagged; we use the `command` variant).
//
// Timeouts are in seconds (not milliseconds) per codex's TOML schema.
func buildCodexHooksTable(hookScript string) map[string]interface{} {
	out := map[string]interface{}{}
	for _, group := range codexHookGroups {
		matcherGroup := map[string]interface{}{
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": hookScript,
					"timeout": group.timeout,
				},
			},
		}
		if group.matcher != "" {
			matcherGroup["matcher"] = group.matcher
		}
		out[group.eventType] = []interface{}{matcherGroup}
	}
	return out
}

func (c *CodexConnector) restoreCodexConfig(opts SetupOpts) {
	backup, err := c.loadConfigBackup(opts.DataDir)
	if err != nil {
		return
	}

	configPath := codexConfigPath()
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return
	}

	if providers, ok := cfg["model_providers"].(map[string]interface{}); ok {
		for name, p := range providers {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if orig, had := backup.OriginalBaseURLs[name]; had {
				pm["base_url"] = orig
			} else {
				delete(pm, "base_url")
			}
			providers[name] = pm
		}
	}

	if backup.HadHooksKey && len(backup.OriginalHooks) > 0 {
		var orig interface{}
		if err := json.Unmarshal(backup.OriginalHooks, &orig); err == nil {
			cfg["hooks"] = orig
		} else {
			delete(cfg, "hooks")
		}
	} else {
		delete(cfg, "hooks")
	}

	if backup.AddedCodexHooksFlag {
		if features, ok := cfg["features"].(map[string]interface{}); ok {
			delete(features, "codex_hooks")
			if len(features) == 0 {
				delete(cfg, "features")
			} else {
				cfg["features"] = features
			}
		}
	}

	if out, err := toml.Marshal(cfg); err == nil {
		// Best-effort restore path: if rewrite fails we leave the
		// existing (already-patched) config in place rather than the
		// half-written attempt. atomicWriteFile guarantees that
		// invariant. See S0.11.
		_ = atomicWriteFile(configPath, out, 0o600)
	}

	// Remove any stale hooks.json from an earlier version that
	// mistakenly used the file-path approach.
	hooksPath := filepath.Join(filepath.Dir(configPath), "hooks.json")
	_ = os.Remove(hooksPath)
	_ = os.Remove(filepath.Join(opts.DataDir, "codex_config_backup.json"))
}
