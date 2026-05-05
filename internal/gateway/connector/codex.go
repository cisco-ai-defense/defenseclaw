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

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/pelletier/go-toml/v2"
)

// codexReservedProviderIDs are the built-in Codex provider IDs that
// cannot appear under [model_providers.*]. Codex 5.x (PR
// openai/codex#12024, March 2026) hard-fails at startup with
// "model_providers contains reserved built-in provider IDs" if any
// of these are present. To redirect the built-in `openai` provider
// at a proxy, set the top-level `openai_base_url` field instead.
// (`ollama` and `lmstudio` have no public top-level override; we
// strip them on Setup so a stale entry from an older config doesn't
// keep the user's Codex stuck in the rejection path.)
var codexReservedProviderIDs = []string{"openai", "ollama", "lmstudio"}

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
	// activeProvider mirrors config.toml's top-level model_provider.
	// Codex does not forward that context to the proxy, so Route()
	// must remember it from Setup to avoid selecting an arbitrary
	// provider out of the snapshot map when multiple providers exist.
	activeProvider string
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
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("codex hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "codex-hook.sh")
	if err := c.patchCodexConfig(opts, hookScript); err != nil {
		return fmt.Errorf("codex config.toml patch: %w", err)
	}

	if opts.InstallCodeGuard {
		if err := ensureCodexCodeGuardSkill(ctx, opts); err != nil {
			return fmt.Errorf("codex CodeGuard skill install: %w", err)
		}
	}

	// Subprocess sandbox is part of the enforcement path: the policy
	// is consulted by codex-hook.sh's PreToolUse handler to decide
	// whether to BLOCK a tool call. In observability-only mode
	// (opts.CodexEnforcement == false, the default) the hook still
	// runs, still posts to /api/v1/codex/hook, and still records the
	// tool call in gateway.jsonl — but it never returns a "block"
	// decision because the policy is absent, so the agent runs
	// unimpeded. The hook handler in api.go falls back to "allow"
	// when the per-data-dir subprocess.json is missing, so this is
	// safe-by-construction and doesn't require additional plumbing.
	if opts.CodexEnforcement {
		policy := ResolveSubprocessPolicy(SubprocessSandbox)
		if err := SetupSubprocessEnforcement(policy, opts); err != nil {
			return fmt.Errorf("codex subprocess enforcement: %w", err)
		}
	}

	return nil
}

func (c *CodexConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	c.restoreCodexConfig(opts)
	c.cleanupLegacyEnvFiles(opts)

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		return fmt.Errorf("codex teardown: subprocess enforcement: %w", err)
	}
	if err := writeDisabledCodexHook(opts); err != nil {
		return fmt.Errorf("codex teardown: disabled hook: %w", err)
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

	configPath := codexConfigPath()
	if data, err := os.ReadFile(configPath); err == nil {
		cfg := map[string]interface{}{}
		if err := toml.Unmarshal(data, &cfg); err == nil {
			hooksDir := filepath.Join(opts.DataDir, "hooks")
			if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
				for eventType, val := range hooks {
					list, _ := val.([]interface{})
					for _, entry := range list {
						if isOwnedHook(entry, hooksDir) {
							residual = append(residual, fmt.Sprintf("config.toml hooks[%s] still contains defenseclaw hook", eventType))
							break
						}
					}
				}
			}
			if codexOtelBlockLooksManaged(cfg["otel"], opts) {
				residual = append(residual, "config.toml [otel] still points at defenseclaw")
			}
			managedNotify := []interface{}{"bash", filepath.Join(opts.DataDir, "notify-bridge.sh")}
			if codexValueMatches(cfg["notify"], managedNotify) {
				residual = append(residual, "config.toml notify still points at defenseclaw bridge")
			}
			proxyURL := "http://" + opts.ProxyAddr + "/c/codex"
			if cur, _ := cfg["openai_base_url"].(string); cur == proxyURL {
				residual = append(residual, "config.toml openai_base_url still points at defenseclaw")
			}
			if providers, ok := cfg["model_providers"].(map[string]interface{}); ok {
				for name, val := range providers {
					pm, _ := val.(map[string]interface{})
					if cur, _ := pm["base_url"].(string); cur == proxyURL {
						residual = append(residual, fmt.Sprintf("config.toml model_providers.%s.base_url still points at defenseclaw", name))
					}
				}
			}
		}
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

func (c *CodexConnector) setActiveProvider(name string) {
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.activeProvider = strings.TrimSpace(name)
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

	if c.activeProvider != "" {
		if e, ok := c.providers[c.activeProvider]; ok {
			if e.APIKey != "" && e.BaseURL != "" {
				return e.BaseURL, e.APIKey
			}
			if e.BaseURL != "" {
				return e.BaseURL, ""
			}
		}
	}

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
// backed up via managed + legacy backup files. Older releases also
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
			managedFileBackupPath(opts.DataDir, c.Name(), "config.toml"),
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

// CodexAuthPathOverride allows tests to redirect ~/.codex/auth.json.
// Used by detectCodexChatGPTMode() so we can exercise both auth-mode
// branches without touching the operator's real auth file.
var CodexAuthPathOverride string

func codexConfigPath() string {
	if CodexConfigPathOverride != "" {
		return CodexConfigPathOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".codex", "config.toml")
}

func codexAuthPath() string {
	if CodexAuthPathOverride != "" {
		return CodexAuthPathOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
}

// codexChatGPTBackendURL is the upstream Codex CLI talks to when the
// user is logged in via ChatGPT/Plus (auth_mode="chatgpt"). The real
// codex CLI source builds requests as `<base>/responses` against this
// URL, so it doubles as the `base_url` we synthesize into the provider
// snapshot — Route() concatenates the incoming `/responses` suffix to
// produce `https://chatgpt.com/backend-api/codex/responses`, which is
// the only endpoint the ChatGPT access token is valid against.
//
// IMPORTANT: openai's `api.openai.com/v1/responses` endpoint will NOT
// accept this token, so synthesizing api.openai.com when the operator
// is in chatgpt mode produces a permanent 401 loop ("Reconnecting…")
// in the codex TUI. See also: gateway-rooted regression where every
// codex request returned a `passthrough → https://api.openai.com/v1/
// responses` line in gateway.log followed by no usable response.
const codexChatGPTBackendURL = "https://chatgpt.com/backend-api/codex"

// detectCodexChatGPTMode returns true when ~/.codex/auth.json exists
// and reports `"auth_mode": "chatgpt"`. Returns false (with no error
// surfaced) when the file is missing, malformed, or names a different
// auth_mode — both are valid states (operator may not have logged in
// yet, or may be using OPENAI_API_KEY).
//
// Why we don't propagate read errors: this function is consulted from
// patchCodexConfig() to *choose a default*, and missing/corrupt
// auth.json is a legitimate state that should not block Setup. The
// caller falls back to the api.openai.com default in that case, which
// is correct for the OPENAI_API_KEY auth path.
func detectCodexChatGPTMode() bool {
	raw, err := os.ReadFile(codexAuthPath())
	if err != nil {
		return false
	}
	// We only need a single field; ignore everything else (auth.json
	// also stores tokens that are not safe to surface here).
	var probe struct {
		AuthMode string `json:"auth_mode"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(probe.AuthMode), "chatgpt")
}

type codexConfigBackup struct {
	// Per-provider base_url values keyed by provider name. Only
	// providers that had an explicit base_url are recorded; providers
	// without one are restored by deleting the proxy override we added.
	// Reserved IDs (openai/ollama/lmstudio) are NOT tracked here —
	// see ReservedProviderBlocks for the full-block backup of those.
	OriginalBaseURLs map[string]string `json:"original_base_urls"`
	// ReservedProviderBlocks holds the entire [model_providers.<id>]
	// table for any reserved built-in IDs (openai, ollama, lmstudio)
	// that were present in the operator's pristine config. We strip
	// those tables on Setup because Codex 5.x rejects them at startup
	// (PR openai/codex#12024); Teardown restores them verbatim so an
	// operator who downgrades Codex still gets their original config
	// back. JSON-encoded so the in-memory shape (nested
	// map[string]interface{}) survives the on-disk round trip.
	ReservedProviderBlocks map[string]json.RawMessage `json:"reserved_provider_blocks,omitempty"`
	// HadOpenAIBaseURL records whether the operator's pristine config
	// already had a top-level openai_base_url field, and what it was.
	// On Teardown we restore the original value or delete our override.
	HadOpenAIBaseURL      bool   `json:"had_openai_base_url"`
	OriginalOpenAIBaseURL string `json:"original_openai_base_url,omitempty"`
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

	// HadOtelBlock / OriginalOtel back up the operator's pristine
	// [otel] block. Setup overwrites this with our own
	// {log_user_prompt = redaction-dependent, exporter = otlp-http to gateway},
	// regardless of enforcement mode (OTel telemetry runs end-to-end
	// in observability mode too — that's the whole point of the
	// observability default). Teardown restores the original or
	// deletes the key if there was none.
	HadOtelBlock bool            `json:"had_otel_block"`
	OriginalOtel json.RawMessage `json:"original_otel,omitempty"`

	// HadNotify / OriginalNotify back up the operator's pristine
	// notify = [...] entry. Setup overwrites with
	// notify = ["bash", "<DataDir>/notify-bridge.sh"] so codex
	// agent-turn-complete events flow to /api/v1/codex/notify.
	// Teardown restores or deletes.
	HadNotify      bool            `json:"had_notify"`
	OriginalNotify json.RawMessage `json:"original_notify,omitempty"`
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
	if err := captureManagedFileBackup(opts.DataDir, c.Name(), "config.toml", configPath); err != nil {
		return fmt.Errorf("capture codex config backup: %w", err)
	}

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
	c.setActiveProvider(codexActiveProviderFromConfig(cfg))

	backupPath := filepath.Join(opts.DataDir, "codex_config_backup.json")
	backupExists := false
	if _, statErr := os.Stat(backupPath); statErr == nil {
		backupExists = true
	}

	backup := codexConfigBackup{
		OriginalBaseURLs:       map[string]string{},
		ReservedProviderBlocks: map[string]json.RawMessage{},
	}
	if !backupExists {
		if existing, ok := cfg["hooks"]; ok {
			backup.HadHooksKey = true
			if raw, err := json.Marshal(existing); err == nil {
				backup.OriginalHooks = raw
			}
		}
		// Capture the operator's pre-DefenseClaw openai_base_url so
		// Teardown can put it back. Empty string is a valid value
		// (the field exists but was unset to "" by the operator), so
		// we use a separate bool flag rather than treating "" as "absent".
		if existing, ok := cfg["openai_base_url"].(string); ok {
			backup.HadOpenAIBaseURL = true
			backup.OriginalOpenAIBaseURL = existing
		}
		// Capture pristine [otel] and notify so Teardown can restore
		// either verbatim or delete-if-we-added. Both run on every
		// install (observability + enforcement) — see the comments on
		// HadOtelBlock / HadNotify in codexConfigBackup.
		if existing, ok := cfg["otel"]; ok {
			backup.HadOtelBlock = true
			if raw, err := json.Marshal(existing); err == nil {
				backup.OriginalOtel = raw
			}
		}
		if existing, ok := cfg["notify"]; ok {
			backup.HadNotify = true
			if raw, err := json.Marshal(existing); err == nil {
				backup.OriginalNotify = raw
			}
		}
		if providers, ok := cfg["model_providers"].(map[string]interface{}); ok {
			for name, p := range providers {
				if isCodexReservedProviderID(name) {
					// Save the entire reserved-id block so Teardown
					// can restore it verbatim. Don't record its
					// base_url under OriginalBaseURLs — that map
					// drives the per-provider restore loop, and the
					// reserved block round-trips through a separate
					// path (see restoreCodexConfig).
					if raw, err := json.Marshal(p); err == nil {
						backup.ReservedProviderBlocks[name] = raw
					}
					continue
				}
				if pm, ok := p.(map[string]interface{}); ok {
					if bu, ok := pm["base_url"].(string); ok {
						backup.OriginalBaseURLs[name] = bu
					}
				}
			}
		}
	}

	// Enforcement-mode block: rebuild the pristine provider snapshot
	// (used by Route() during proxy passthrough), synthesize a
	// canonical `openai` entry for the snapshot (Codex 5.x can't carry
	// a [model_providers.openai] block), rewrite openai_base_url to
	// the proxy, strip reserved IDs, and rewrite custom-provider
	// base_urls to the proxy.
	//
	// In observability mode (opts.CodexEnforcement == false, the
	// default) this entire block is skipped: codex talks DIRECTLY to
	// its native upstream (api.openai.com/v1/responses for
	// OPENAI_API_KEY mode, chatgpt.com/backend-api/codex/responses
	// for chatgpt mode), no openai_base_url override is written, and
	// no reserved-ID strip happens. Hooks (the next block) still run
	// — that's the entry point for tool-call telemetry into
	// /api/v1/codex/hook. Operator can flip this back on by setting
	// guardrail.codex_enforcement_enabled: true in config.yaml.
	if opts.CodexEnforcement {
		// Capture the provider snapshot from the *pristine* config
		// (before the rewrite) so Route() can synthesize
		// X-DC-Target-URL later. If we already have a backup from a
		// prior Setup, prefer that — the current cfg's base_urls
		// will all be the proxy URL already.
		pristineProviders := map[string]interface{}{}
		if backupExists {
			// Rebuild pristine providers from backup: every provider
			// that had an original URL gets it back for snapshot
			// purposes.
			if b, err := c.loadConfigBackup(opts.DataDir); err == nil {
				cur, _ := cfg["model_providers"].(map[string]interface{})
				for name, provVal := range cur {
					if isCodexReservedProviderID(name) {
						// Reserved entries shouldn't be in cur after
						// a post-fix Setup, but a pre-fix backup may
						// have left one behind. Skip — we'll
						// synthesize the canonical openai entry
						// below.
						continue
					}
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
				// Re-attach reserved blocks from the prior backup so
				// the snapshot still has the original `openai`
				// upstream for Route() to point at when codex sends
				// `/c/codex/responses`.
				for name, rawBlock := range b.ReservedProviderBlocks {
					var block interface{}
					if err := json.Unmarshal(rawBlock, &block); err == nil {
						pristineProviders[name] = block
					}
				}
			}
		} else if cur, ok := cfg["model_providers"].(map[string]interface{}); ok {
			for name, v := range cur {
				pristineProviders[name] = v
			}
		}

		// Always synthesize a canonical `openai` snapshot entry.
		// Codex 5.x can't carry a [model_providers.openai] block in
		// config.toml, so the operator's pristine config typically
		// has no `openai` entry at all. Without this synthetic
		// record, Route() would have no upstream URL to attach when
		// codex sends `/c/codex/responses`, and the proxy would 502.
		// Operator overrides (custom base_url via openai_base_url, or
		// a backed-up reserved block) win.
		//
		// Auth-mode-aware default: when ~/.codex/auth.json reports
		// `auth_mode: "chatgpt"` (the user logged in via ChatGPT/Plus
		// rather than supplying an OPENAI_API_KEY), the *only*
		// endpoint the issued access token is valid against is
		// `chatgpt.com/backend-api/codex/responses`. Defaulting to
		// `api.openai.com/v1` in that mode produces a permanent 401
		// loop in the codex TUI ("Reconnecting… 5/5"), because Codex
		// retries indefinitely on opaque upstream errors. The
		// operator's explicit `openai_base_url` (captured in
		// backup.OriginalOpenAIBaseURL) always wins over both
		// defaults so an enterprise gateway override is preserved.
		// Env var OPENAI_API_KEY remains the env key in both modes —
		// Route() forwards the incoming Authorization header
		// verbatim, which carries the ChatGPT access token in chatgpt
		// mode and the OPENAI_API_KEY-derived bearer in api-key mode.
		if _, ok := pristineProviders["openai"]; !ok {
			openaiBaseURL := "https://api.openai.com/v1"
			if detectCodexChatGPTMode() {
				openaiBaseURL = codexChatGPTBackendURL
			}
			if backup.HadOpenAIBaseURL && backup.OriginalOpenAIBaseURL != "" {
				openaiBaseURL = backup.OriginalOpenAIBaseURL
			} else if backupExists {
				if b, err := c.loadConfigBackup(opts.DataDir); err == nil &&
					b.HadOpenAIBaseURL && b.OriginalOpenAIBaseURL != "" {
					openaiBaseURL = b.OriginalOpenAIBaseURL
				}
			}
			pristineProviders["openai"] = map[string]interface{}{
				"name":     "openai",
				"base_url": openaiBaseURL,
				"env_key":  "OPENAI_API_KEY",
			}
		}
		c.SetProviderSnapshot(buildCodexProviderSnapshot(pristineProviders))

		proxyURL := "http://" + opts.ProxyAddr + "/c/codex"

		// Built-in `openai` redirect: must use the top-level
		// openai_base_url field, NOT a [model_providers.openai]
		// block. Codex 5.x (PR openai/codex#12024) treats `openai`,
		// `ollama`, and `lmstudio` as reserved built-in provider IDs
		// and refuses to start with the error:
		// "model_providers contains reserved built-in provider IDs:
		// `openai`. Built-in providers cannot be overridden."
		cfg["openai_base_url"] = proxyURL

		// Strip any reserved-ID entries already present in the config
		// — either from a pristine pre-DefenseClaw config (rare,
		// since older Codex accepted them) or from a previous
		// DefenseClaw setup that pre-dated this fix. Their original
		// blocks are preserved in backup.ReservedProviderBlocks for
		// Teardown.
		providers, _ := cfg["model_providers"].(map[string]interface{})
		if providers != nil {
			for _, id := range codexReservedProviderIDs {
				delete(providers, id)
			}
			// Rewrite remaining (custom-named) providers to route
			// through the proxy. Codex still honors per-provider
			// base_url for non-built-in IDs (e.g. `openrouter`,
			// `azure`, `groq`, etc.), so this is the correct path
			// for those.
			for name, p := range providers {
				pm, ok := p.(map[string]interface{})
				if !ok {
					pm = map[string]interface{}{}
				}
				pm["base_url"] = proxyURL
				providers[name] = pm
			}
			if len(providers) > 0 {
				cfg["model_providers"] = providers
			} else {
				// Avoid leaving an empty [model_providers] table
				// behind — it's harmless but adds visual noise to
				// the operator's config.toml. Codex tolerates the
				// key being absent.
				delete(cfg, "model_providers")
			}
		}
	}

	// Codex's [hooks] table is an inline struct (HookEventsToml) with
	// per-event fields. It is NOT a path to a hooks.json file —
	// passing a string triggers a TOML parse error at codex startup.
	// Always installed, regardless of enforcement mode: hooks are the
	// entry point for tool-call telemetry into /api/v1/codex/hook
	// (UserPromptSubmit, PreToolUse, PostToolUse, PermissionRequest,
	// Stop). In observability mode the hook handler logs but never
	// blocks; in enforcement mode it can also block based on the
	// subprocess sandbox policy.
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

	// Native OTel exporter — runs on every install regardless of
	// enforcement mode. Codex's [otel] block produces structured
	// logs (raw API request/response, model + token counts) and
	// metrics that complement the hook-based event stream. The
	// /v1/logs and /v1/metrics endpoints on the gateway's API port
	// receive the OTLP-HTTP payload and normalize into
	// gateway.jsonl with source="codex_otel".
	cfg["otel"] = buildCodexOtelBlock(opts)

	// agent-turn-complete bridge: codex shells out to ``notify`` with
	// a JSON payload describing each completed turn. We point it at a
	// per-instance bash bridge that POSTs to /api/v1/codex/notify.
	// Runs on every install — the bridge is harmless when the
	// endpoint isn't yet wired (curl --fail-with-body silently drops
	// the event rather than crashing codex).
	if err := writeCodexNotifyBridge(opts); err != nil {
		return fmt.Errorf("write codex notify bridge: %w", err)
	}
	cfg["notify"] = []string{"bash", filepath.Join(opts.DataDir, "notify-bridge.sh")}

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
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "config.toml", configPath); err != nil {
		return fmt.Errorf("update codex config backup hash: %w", err)
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

func codexActiveProviderFromConfig(cfg map[string]interface{}) string {
	if cfg == nil {
		return ""
	}
	name, _ := cfg["model_provider"].(string)
	return strings.TrimSpace(name)
}

// buildCodexHooksTable produces the [hooks] HookEventsToml structure
// current Codex releases execute for lifecycle events. Each event maps
// to a sequence of MatcherGroup records; each MatcherGroup wraps a
// sequence of HookHandlerConfig records (type-tagged; we use the
// `command` variant).
//
// Timeouts are in seconds (not milliseconds) per Codex's TOML schema.
// The generated hook script decides fail-open vs fail-closed from
// SetupOpts: observability-only installs allow the tool when the
// gateway is unavailable, while enforcement installs can block.
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

// buildCodexOtelBlock returns the [otel] table that points codex's
// native OTel exporter at the gateway's OTLP-HTTP receiver. The shape
// matches codex's documented config (see
// https://developers.openai.com/codex/config-advanced) and the
// authoritative Rust schema in
// codex-rs/config/src/types.rs::OtelExporterKind::OtlpHttp:
//
//	[otel]
//	log_user_prompt = false
//	[otel.exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/logs"
//	protocol = "json"
//	headers = { x-defenseclaw-token = "<token>" }
//	[otel.trace_exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/traces"
//	protocol = "json"
//	headers = { x-defenseclaw-token = "<token>" }
//	[otel.metrics_exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/metrics"
//	protocol = "json"
//	headers = { x-defenseclaw-token = "<token>" }
//
// The `protocol` field is REQUIRED by codex's serde-deserialized
// schema - omitting it produces `invalid configuration: missing
// field `protocol` in `otel.exporter``` at codex startup, which
// blocks the entire CLI from launching (not just OTel export). We
// hard-code `"json"` because the gateway's OTLP-HTTP receiver
// (internal/gateway/otel_ingest.go) accepts `application/json` only
// and 415s any `application/x-protobuf` body - a mismatched
// protocol would silently drop every batch instead of erroring out.
//
// log_user_prompt = false is the privacy-preserving default: codex's
// native OTel emits prompt text only when this is true. When redaction
// is explicitly disabled, DefenseClaw flips it to true so native Codex
// OTel joins the same raw-content mode as the hook/proxy telemetry.
// Teardown restores the operator's pristine [otel] block or deletes
// ours if there was none.
//
// Headers carry the gateway token so the OTLP-HTTP receiver can
// authenticate the codex CLI process the same way the hook script
// does. The header name is intentionally NOT "Authorization" so the
// receiver can distinguish OTel traffic from hook/REST traffic in
// audit logs.
func buildCodexOtelBlock(opts SetupOpts) map[string]interface{} {
	headers := map[string]interface{}{}
	if opts.APIToken != "" {
		headers["x-defenseclaw-token"] = opts.APIToken
	}
	headers["x-defenseclaw-source"] = "codex"
	// X-DefenseClaw-Client satisfies the gateway's CSRF gate
	// (apiCSRFProtect) which rejects POSTs without it. The
	// header is the same one the CLI and inspect hooks set —
	// codex's OTel exporter merges it into every outbound POST.
	headers["x-defenseclaw-client"] = "codex-otel/1.0"
	exporterFor := func(path string) map[string]interface{} {
		return map[string]interface{}{
			"otlp-http": map[string]interface{}{
				"endpoint": "http://" + opts.APIAddr + path,
				// "json" matches the kebab-case serde tag for
				// OtelHttpProtocol::Json. Codex's deserializer is
				// case-sensitive (rename_all = "kebab-case") — "JSON"
				// or "Json" would fail with the same missing-field
				// flavour error.
				"protocol": "json",
				"headers":  headers,
			},
		}
	}
	return map[string]interface{}{
		"log_user_prompt":  redaction.DisableAll(),
		"exporter":         exporterFor("/v1/logs"),
		"trace_exporter":   exporterFor("/v1/traces"),
		"metrics_exporter": exporterFor("/v1/metrics"),
	}
}

// writeCodexNotifyBridge writes ~/.defenseclaw/notify-bridge.sh, the
// shell shim codex invokes on agent-turn-complete. The script POSTs
// codex's JSON arg to /api/v1/codex/notify with the gateway token
// baked in. We use `--max-time 5` and `--silent --show-error`
// so a transient gateway outage doesn't make codex's notify chain
// hang or print noise to the operator's terminal — telemetry is
// best-effort, the agent's UX is not.
//
// Per-instance script (lives under DataDir, owned 0o700) so a
// multi-tenant install can have one notify-bridge per gateway
// process. The token is baked in rather than read from the
// environment because codex spawns the bridge as a subshell and
// the host's environment may scrub DEFENSECLAW_GATEWAY_TOKEN.
func writeCodexNotifyBridge(opts SetupOpts) error {
	scriptPath := filepath.Join(opts.DataDir, "notify-bridge.sh")
	endpoint := "http://" + opts.APIAddr + "/api/v1/codex/notify"
	body := "#!/usr/bin/env bash\n" +
		"# Auto-generated by defenseclaw setup guardrail. DO NOT EDIT.\n" +
		"# Codex invokes this bridge on agent-turn-complete with a single\n" +
		"# JSON arg. We forward to the gateway notify endpoint with the\n" +
		"# baked-in token; outages are silent (telemetry is best-effort).\n" +
		"set -u\n" +
		"JSON=\"${1:-}\"\n" +
		"if [ -z \"${JSON}\" ]; then\n" +
		"  exit 0\n" +
		"fi\n" +
		"curl --silent --show-error --max-time 5 \\\n" +
		"  --header 'Content-Type: application/json' \\\n" +
		// Authorization: Bearer is the canonical credential the
		// gateway's tokenAuth middleware checks first (with
		// X-DefenseClaw-Token as a fallback). Using the standard
		// header keeps the bridge interoperable with curl/proxy
		// debugging and matches the python CLI / inspect-hook
		// auth contract.
		"  --header 'Authorization: Bearer " + opts.APIToken + "' \\\n" +
		// X-DefenseClaw-Client is required by the gateway's CSRF gate;
		// without it apiCSRFProtect 403s the POST. inspect-tool-response
		// and the python CLI set the same header; the value is purely
		// observational (logged in audit).
		"  --header 'X-DefenseClaw-Client: codex-notify/1.0' \\\n" +
		"  --header 'x-defenseclaw-source: codex-notify' \\\n" +
		"  --data \"${JSON}\" \\\n" +
		"  '" + endpoint + "' >/dev/null 2>&1 || true\n"
	if err := os.MkdirAll(opts.DataDir, 0o755); err != nil {
		return fmt.Errorf("ensure data dir: %w", err)
	}
	if err := atomicWriteFile(scriptPath, []byte(body), 0o700); err != nil {
		return fmt.Errorf("write notify bridge: %w", err)
	}
	return nil
}

// writeDisabledCodexHook leaves a no-op tombstone at the path older
// Codex processes may have cached before teardown. The config restore
// removes the hook registration for new Codex sessions; this keeps
// already-running sessions from surfacing repeated "hook failed" noise.
func writeDisabledCodexHook(opts SetupOpts) error {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		return fmt.Errorf("ensure hook dir: %w", err)
	}
	body := "#!/bin/bash\n" +
		"# defenseclaw-managed-hook disabled\n" +
		"# Codex connector was torn down. Existing Codex processes may\n" +
		"# keep this hook path cached until restart, so exit successfully\n" +
		"# without forwarding stale payloads.\n" +
		"exit 0\n"
	return atomicWriteFile(filepath.Join(hookDir, "codex-hook.sh"), []byte(body), 0o700)
}

// isCodexReservedProviderID reports whether name is one of the
// built-in provider IDs Codex 5.x rejects under [model_providers.*].
// See codexReservedProviderIDs for the full list and rationale.
func isCodexReservedProviderID(name string) bool {
	for _, id := range codexReservedProviderIDs {
		if id == name {
			return true
		}
	}
	return false
}

func (c *CodexConnector) restoreCodexConfig(opts SetupOpts) {
	backup, err := c.loadConfigBackup(opts.DataDir)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[codex] config backup unavailable; falling back to surgical cleanup: %v\n", err)
		}
		backup = codexConfigBackup{}
	}

	configPath := codexConfigPath()
	if restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "config.toml", configPath); err != nil {
		fmt.Fprintf(os.Stderr, "[codex] managed config restore skipped: %v\n", err)
	} else if restored {
		c.cleanupCodexRestoreArtifacts(opts, configPath)
		return
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return
	}

	proxyURL := "http://" + opts.ProxyAddr + "/c/codex"

	// Restore the top-level openai_base_url only when it still points
	// at DefenseClaw. If the operator changed it after Setup, leave
	// their newer value alone; the exact managed-backup restore path
	// above handles the no-drift case byte-for-byte.
	if cur, _ := cfg["openai_base_url"].(string); cur == proxyURL {
		if backup.HadOpenAIBaseURL {
			cfg["openai_base_url"] = backup.OriginalOpenAIBaseURL
		} else {
			delete(cfg, "openai_base_url")
		}
	}

	// Restore non-reserved provider base_urls only for entries that
	// still point at the DefenseClaw proxy. User-edited provider URLs
	// win on drifted configs.
	if providers, ok := cfg["model_providers"].(map[string]interface{}); ok {
		for name, p := range providers {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if cur, _ := pm["base_url"].(string); cur == proxyURL {
				if orig, had := backup.OriginalBaseURLs[name]; had {
					pm["base_url"] = orig
				} else {
					delete(pm, "base_url")
				}
			}
			providers[name] = pm
		}
	}

	// Re-attach the original reserved-ID blocks (openai/ollama/lmstudio)
	// if the operator had any in their pristine config. We restore
	// verbatim — even though current Codex rejects them, the operator
	// had them for a reason (e.g. they downgraded back to a Codex
	// release that accepted overrides) and Teardown's contract is
	// "pre-DefenseClaw shape", not "current-Codex-validated shape".
	if len(backup.ReservedProviderBlocks) > 0 {
		providers, _ := cfg["model_providers"].(map[string]interface{})
		if providers == nil {
			providers = map[string]interface{}{}
		}
		for name, raw := range backup.ReservedProviderBlocks {
			var block interface{}
			if err := json.Unmarshal(raw, &block); err == nil {
				providers[name] = block
			}
		}
		if len(providers) > 0 {
			cfg["model_providers"] = providers
		}
	}

	removedOwnedHooks := false
	hooksRemain := false
	if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
		hooksDir := filepath.Join(opts.DataDir, "hooks")
		for eventType, val := range hooks {
			before := codexHookEntryCount(val)
			remaining := removeOwnedHooks(val, hooksDir)
			if before != len(remaining) {
				removedOwnedHooks = true
			}
			if len(remaining) == 0 {
				delete(hooks, eventType)
			} else {
				hooks[eventType] = remaining
			}
		}
		if len(hooks) == 0 {
			delete(cfg, "hooks")
		} else {
			hooksRemain = true
			cfg["hooks"] = hooks
		}
	} else if !backup.HadHooksKey {
		delete(cfg, "hooks")
	}

	if backup.AddedCodexHooksFlag || (removedOwnedHooks && !hooksRemain) {
		if features, ok := cfg["features"].(map[string]interface{}); ok {
			delete(features, "codex_hooks")
			if len(features) == 0 {
				delete(cfg, "features")
			} else {
				cfg["features"] = features
			}
		}
	}

	// Restore OTel/notify only if the current values are still the
	// DefenseClaw-managed values. If the operator edited either field
	// after Setup, preserve their newer config.
	managedOtel := codexValueMatches(cfg["otel"], buildCodexOtelBlock(opts)) || codexOtelBlockLooksManaged(cfg["otel"], opts)
	if managedOtel && backup.HadOtelBlock && len(backup.OriginalOtel) > 0 {
		var orig interface{}
		if err := json.Unmarshal(backup.OriginalOtel, &orig); err == nil {
			cfg["otel"] = orig
		} else {
			delete(cfg, "otel")
		}
	} else if managedOtel {
		delete(cfg, "otel")
	}

	managedNotify := []interface{}{"bash", filepath.Join(opts.DataDir, "notify-bridge.sh")}
	if codexValueMatches(cfg["notify"], managedNotify) && backup.HadNotify && len(backup.OriginalNotify) > 0 {
		var orig interface{}
		if err := json.Unmarshal(backup.OriginalNotify, &orig); err == nil {
			cfg["notify"] = orig
		} else {
			delete(cfg, "notify")
		}
	} else if codexValueMatches(cfg["notify"], managedNotify) {
		delete(cfg, "notify")
	}

	if out, err := toml.Marshal(cfg); err == nil {
		// Best-effort restore path: if rewrite fails we leave the
		// existing (already-patched) config in place rather than the
		// half-written attempt. atomicWriteFile guarantees that
		// invariant. See S0.11.
		if err := atomicWriteFile(configPath, out, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "[codex] restore write failed: %v\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "[codex] restore marshal failed: %v\n", err)
		return
	}

	discardManagedFileBackup(opts.DataDir, c.Name(), "config.toml")
	c.cleanupCodexRestoreArtifacts(opts, configPath)
}

func (c *CodexConnector) cleanupCodexRestoreArtifacts(opts SetupOpts, configPath string) {
	// Remove any stale hooks.json from an earlier version that
	// mistakenly used the file-path approach, plus the notify bridge
	// shim we wrote in Setup.
	hooksPath := filepath.Join(filepath.Dir(configPath), "hooks.json")
	_ = os.Remove(hooksPath)
	_ = os.Remove(filepath.Join(opts.DataDir, "notify-bridge.sh"))
	_ = os.Remove(filepath.Join(opts.DataDir, "codex_config_backup.json"))
}

func codexHookEntryCount(v interface{}) int {
	list, ok := v.([]interface{})
	if !ok {
		return 0
	}
	return len(list)
}

func codexValueMatches(a, b interface{}) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aj) == string(bj)
}

func codexOtelBlockLooksManaged(v interface{}, opts SetupOpts) bool {
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	return codexExporterLooksManaged(m["exporter"], "http://"+opts.APIAddr+"/v1/logs")
}

func codexExporterLooksManaged(v interface{}, endpoint string) bool {
	exporter, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	otlpHTTP, ok := exporter["otlp-http"].(map[string]interface{})
	if !ok {
		return false
	}
	if got, _ := otlpHTTP["endpoint"].(string); got != endpoint {
		return false
	}
	headers, _ := otlpHTTP["headers"].(map[string]interface{})
	if headers == nil {
		return false
	}
	return headers["x-defenseclaw-source"] == "codex" || headers["x-defenseclaw-client"] == "codex-otel/1.0"
}
