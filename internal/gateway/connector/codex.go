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
	"errors"
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

	// PR #141 audit H1: emit a single `[SECURITY]` warning per
	// process when loopback bypass is exercised while a gateway
	// token is configured. The native-binary loopback carve-out
	// is intentional (see Authenticate), but operators must see
	// it surfaced at least once.
	loopbackWarn sync.Once

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

func (c *CodexConnector) Name() string        { return "codex" }
func (c *CodexConnector) HookAPIPath() string { return "/api/v1/codex/hook" }

// HookScriptNames implements HookScriptOwner (plan C2 / S2.5). Codex
// owns codex-hook.sh; the generic inspect-* scripts come from the
// shared list maintained by WriteHookScriptsForConnector. Including
// a non-existent template name here produces an explicit write
// error rather than a silent skip — the embed FS is authoritative.
func (c *CodexConnector) HookScriptNames(SetupOpts) []string {
	return []string{"codex-hook.sh"}
}
func (c *CodexConnector) Description() string {
	return "config.toml model_providers patch + hook script (6 events, component scanning)"
}
func (c *CodexConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *CodexConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

// AllowedHosts returns the Codex update / docs / GitHub release
// channels. api.openai.com is already in the firewall's static
// defaults so we don't repeat it. See S3.3 / F26.
func (c *CodexConnector) AllowedHosts() []string {
	return []string{
		// Update / release channel — Codex pulls binaries from GitHub.
		"github.com",
		"api.github.com",
		"objects.githubusercontent.com",
		// Docs CDN.
		"openai.com",
		"platform.openai.com",
	}
}

func (c *CodexConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// We intentionally do NOT export a global OPENAI_BASE_URL.
	//
	// codex-cli reads provider routing from
	// ~/.codex/config.toml's [model_providers.*].base_url, and
	// patchCodexConfig (called below) rewrites those entries to
	// point at the DefenseClaw proxy. Setting OPENAI_BASE_URL in
	// the user's environment additionally would silently route
	// every other OpenAI-SDK consumer on the host (Python LiteLLM,
	// the openai CLI, IDE plugins, ad-hoc scripts, even other
	// agents) through this proxy — a config-blast-radius bug we
	// explicitly close out as part of S8.1 / F31.
	//
	// We still capture whether the operator already had
	// OPENAI_BASE_URL set so audit / Teardown have provenance, and
	// we still wire cleanupLegacyEnvFiles into Teardown so any
	// codex_env.sh / codex.env files left behind by an older
	// DefenseClaw release get removed; see
	// TestCodex_Teardown_RemovesLegacyEnvFiles.
	if err := c.saveEnvBackup(opts); err != nil {
		return fmt.Errorf("codex env backup: %w", err)
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	// Plan C2: HookScriptOwner-driven. codex_hook.sh ships from the
	// connector method; generic inspect-* scripts come from the
	// shared list inside writeHookScriptsCommon.
	if err := WriteHookScriptsForConnectorObject(hookDir, opts.APIAddr, opts.APIToken, c); err != nil {
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
	c.cleanupLegacyEnvFiles(opts)

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		return fmt.Errorf("codex teardown: subprocess enforcement: %w", err)
	}
	return nil
}

func (c *CodexConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check legacy env override files. New installs no longer write
	// these (S8.1 / F31), but VerifyClean must still flag them if
	// an old install left them on disk and Teardown failed to clean
	// up.
	for _, name := range []string{codexEnvFileName, codexDotenvFileName} {
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
		// PR #141 audit H1: ZeptoClaw closed its loopback-trust gap in
		// plan B1 because its inspect-*.sh hooks can inject X-DC-Auth.
		// codex-cli is a native Rust binary that opens connections to
		// /c/codex/responses directly with `Authorization: Bearer
		// <provider-key>` and has no shell-script seam to inject the
		// gateway token. Strict-rejecting loopback when a gateway
		// token is configured would 401 every codex request and no
		// guardrail would ever execute — see
		// TestCodex_Authenticate_NativeBinaryLoopback for the
		// production rationale. Until codex grows a token-injection
		// path, the most we can do is surface the architectural gap
		// once at boot so operators in shared-host deployments are
		// aware that other local processes can impersonate codex.
		if c.gatewayToken != "" {
			c.loopbackWarn.Do(func() {
				fmt.Fprintf(os.Stderr,
					"[SECURITY] codex: loopback request accepted without X-DC-Auth — "+
						"DEFENSECLAW_GATEWAY_TOKEN is set but the codex native binary "+
						"has no seam to inject it. Any process on this host can route "+
						"through /c/codex/* with no further authentication.\n")
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

// HasUsableProviders implements ProviderProbe (plan A4). Mirrors
// resolveUpstream's "first usable entry" rule: any provider with at
// least one populated field (key or base URL) counts. We additionally
// accept a non-empty OPENAI_API_KEY env var as a fallback so installs
// that haven't yet finished a Setup-time snapshot capture still boot.
func (c *CodexConnector) HasUsableProviders() (int, error) {
	c.snapshotMu.RLock()
	count := 0
	for _, e := range c.providers {
		if strings.TrimSpace(e.APIKey) != "" || strings.TrimSpace(e.BaseURL) != "" {
			count++
		}
	}
	c.snapshotMu.RUnlock()
	if count > 0 {
		return count, nil
	}
	if strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) != "" {
		return 1, nil
	}
	return 0, errors.New("codex: no upstream provider configured (~/.codex/config.toml has no [providers] entry with key or base_url, and OPENAI_API_KEY is unset)")
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

// --- AgentPathProvider / EnvRequirementsProvider / HookScriptProvider ---

// AgentPaths reports the on-disk footprint Codex's connector
// touches. The canonical scoped routing primitive is the patch
// applied to ~/.codex/config.toml's [model_providers.*].base_url,
// backed up via codex_config_backup.json. Older releases also
// wrote codex_env.sh / codex.env into <DataDir>; those are still
// surfaced here so tools that audit DefenseClaw's footprint find
// them and Teardown can remove them.
func (c *CodexConnector) AgentPaths(opts SetupOpts) AgentPaths {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	hooks := make([]string, 0, len(HookScripts()))
	for _, name := range HookScripts() {
		hooks = append(hooks, filepath.Join(hookDir, name))
	}
	return AgentPaths{
		PatchedFiles: []string{codexConfigPath()},
		BackupFiles: []string{
			filepath.Join(opts.DataDir, "codex_config_backup.json"),
			filepath.Join(opts.DataDir, "codex_backup.json"),
		},
		HookScripts: hooks,
		CreatedDirs: []string{filepath.Join(opts.DataDir, "shims")},
	}
}

func (c *CodexConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

// RequiredEnv reports Codex's env requirements. Codex picks its
// model provider via [model_providers.*].base_url in config.toml,
// which Setup patches directly — so the connector does not require
// the operator to set OPENAI_BASE_URL in their shell. Older
// releases wrote a codex_env.sh that exported it globally; that
// path is being retired (see PR-H / S8.1) because it bleeds into
// non-Codex OpenAI SDK clients. Documenting both the canonical
// scoped path and the legacy var here gives `defenseclaw doctor`
// enough context to flag mis-configurations.
func (c *CodexConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{
		{
			Name:        "OPENAI_BASE_URL",
			Scope:       EnvScopeProcess,
			Required:    false,
			Description: "Optional. Codex's primary routing surface is the [model_providers.openai].base_url patch in ~/.codex/config.toml. Setting OPENAI_BASE_URL globally is discouraged because it also redirects unrelated OpenAI SDK clients.",
		},
	}
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

// codexEnvFileName / codexDotenvName are the legacy global env
// override files that earlier versions of DefenseClaw shipped. We no
// longer write them (S8.1 / F31), but Teardown still cleans them up
// so an upgrade-then-uninstall flow leaves the operator's host
// pristine. Tests reference these names via
// TestCodex_Teardown_RemovesLegacyEnvFiles.
const (
	codexEnvFileName    = "codex_env.sh"
	codexDotenvFileName = "codex.env"
)

// saveEnvBackup records whether the operator already had a global
// OPENAI_BASE_URL set when DefenseClaw was installed. Setup() does
// NOT overwrite that env var (see comment in Setup()), but the
// backup is preserved both for forensics and to support a future
// strict-restoration flow if we ever start writing the env again.
func (c *CodexConnector) saveEnvBackup(opts SetupOpts) error {
	backup := codexBackup{}
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		backup.HadBaseURL = true
		backup.OldBaseURL = v
	}
	return c.saveBackup(opts.DataDir, backup)
}

// cleanupLegacyEnvFiles removes any codex_env.sh / codex.env files
// left behind by an older DefenseClaw release. It also removes the
// codex_backup.json forensic file so VerifyClean can pass.
//
// New installs never write these files (S8.1 / F31), but we keep
// the cleanup path so an "upgrade-then-uninstall" sequence ends
// with the operator's host pristine.
func (c *CodexConnector) cleanupLegacyEnvFiles(opts SetupOpts) {
	os.Remove(filepath.Join(opts.DataDir, codexEnvFileName))
	os.Remove(filepath.Join(opts.DataDir, codexDotenvFileName))
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
//
// === BY-DESIGN: Codex hook invocation is WONTFIX (architectural) ===
// Plan C3 / matrix §"Out of scope". Today's `codex` binary does NOT
// honor a settings-based hook invocation pipeline — there is no
// codex code path that reads a `[hooks]` table out of config.toml
// and shells out to `command` on the matching event. We write the
// table anyway as a forward-compatibility placeholder: the moment
// codex grows external-script hook support (the schema is already
// in their TOML grammar), this Setup is wired and only the
// agent-side dispatch needs to land upstream.
//
// Pre-execution gating for Codex flows from a different surface:
//  1. Path-based interception — proxy admits Codex via the
//     `/c/codex/...` route prefix (codex.HookAPIPath()), which forces
//     every tool call through GuardrailProxy.Route + response-scan.
//  2. ToolModeBoth on the connector — pre-call telemetry is captured
//     from the LLM response side, where the proxy still has the
//     unstreamed `tool_calls` array to inspect.
//
// In short: the on-disk `[hooks]` block is a future-proofing artifact;
// the security guarantee comes from the proxy, not the agent. Do not
// "fix" this by emitting fake handlers or shelling out from here —
// codex won't read it. See plan C3 + docs/CONNECTOR-MATRIX.md
// "By-design connector limitations" for the canonical statement.
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
