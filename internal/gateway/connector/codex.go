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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/pelletier/go-toml/v2"
)

// CodexConnector is the hook-only security surface for OpenAI Codex.
// It does not interpose on chat traffic; codex-cli talks directly to
// its native upstream (api.openai.com or the ChatGPT backend). The
// connector wires three telemetry/inspection channels into
// ~/.codex/config.toml:
//   - codex-hook.sh under [hooks] for tool-call inspection
//   - [otel.exporter.otlp-http] for native OTLP telemetry
//   - notify-bridge.sh wired to `notify` for agent-turn events
//
// Implements ComponentScanner, StopScanner.
type CodexConnector struct {
	gatewayToken string
	masterKey    string

	// Emit a single `[SECURITY]` warning per process the first time
	// the loopback bypass is exercised while a gateway token is
	// configured. The native-binary loopback carve-out is intentional
	// (see Authenticate), but operators must see it surfaced at least
	// once so they know a non-token-authed path is live.
	loopbackWarn sync.Once

	// Provider snapshot recorded at setup time (avarice F-1365). Used
	// by Authenticate to accept loopback callers that present a
	// Bearer token matching one of the operator-configured codex
	// provider keys — this is how the native codex CLI continues to
	// authenticate without an X-DC-Auth header.
	snapshotMu sync.RWMutex
	providers  map[string]CodexProviderEntry
}

// CodexProviderEntry mirrors the fields the codex Authenticate path
// reads off ~/.codex/config.toml's [model_providers.*] table. Only
// APIKey is consulted today; the struct is exported so test code can
// inject a snapshot via SetProviderSnapshot.
type CodexProviderEntry struct {
	APIKey string
}

// SetProviderSnapshot replaces the operator-recorded codex provider
// list. Called by the sidecar after parsing config.toml; tests inject
// directly. Safe to call concurrently with Authenticate.
func (c *CodexConnector) SetProviderSnapshot(providers map[string]CodexProviderEntry) {
	if c == nil {
		return
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.providers = providers
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

func (c *CodexConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// Hook-only connector: patchCodexConfig wires hooks, OTel, and the
	// notify bridge without rewriting provider URLs or exporting a
	// global OPENAI_BASE_URL. The legacy LLM-proxy surface has been
	// removed — Codex talks directly to its native upstream and
	// DefenseClaw only observes via hooks + OTel.

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

	return nil
}

func (c *CodexConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	c.restoreCodexConfig(opts)

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		return fmt.Errorf("codex teardown: subprocess enforcement: %w", err)
	}
	// Cached-PID safety: long-lived Codex sessions cache the absolute
	// hook path at startup. We replace codex-hook.sh in place with the
	// shared v0 tombstone (atomic rename, no ENOENT window) instead of
	// deleting it — see writeDisabledHookTombstone for the full
	// contract.
	if err := writeDisabledHookTombstone(opts, "codex-hook.sh", "Codex"); err != nil {
		return fmt.Errorf("codex teardown: disabled hook: %w", err)
	}
	return nil
}

func (c *CodexConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

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
//
// SECURITY: the loopback carve-out is routed through
// AcceptLoopbackWithWarning so the [SECURITY] log line stays
// consistent across the (currently single) set of connectors that need
// the exception, and so any future caller has to opt in explicitly
// rather than slip the same pattern in via copy-paste. Audit any new
// loopback consumer against the threat model documented on
// AcceptLoopbackWithWarning itself.
func (c *CodexConnector) Authenticate(r *http.Request) bool {
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

	if IsLoopback(r) {
		// No gateway token configured → preserve legacy local-only
		// behavior (any loopback caller is trusted).
		if c.gatewayToken == "" {
			return true
		}
		// Avarice F-1365: with a token configured, require proof
		// that the loopback caller possesses either the gateway
		// token (X-DC-Auth, handled above), the master key
		// (Authorization Bearer master, handled above), or a known
		// codex provider key. The native codex CLI authenticates
		// via the last path because it already sends
		// Authorization: Bearer <provider-key>.
		if c.matchesKnownProviderKey(r) {
			return true
		}
		// Operator escape hatch: DEFENSECLAW_CODEX_LOOPBACK_TRUST=1
		// restores the legacy "trust any loopback" behavior for
		// single-user dev hosts that haven't recorded a provider
		// snapshot yet.
		if strings.TrimSpace(os.Getenv("DEFENSECLAW_CODEX_LOOPBACK_TRUST")) == "1" {
			AcceptLoopbackWithWarning(r, c.gatewayToken, "codex",
				"DEFENSECLAW_CODEX_LOOPBACK_TRUST=1 — trusting loopback /c/codex/* requests without proof of credential possession",
				&c.loopbackWarn)
			return true
		}
		c.loopbackWarn.Do(func() {
			fmt.Fprintln(os.Stderr,
				"[SECURITY] codex: rejecting loopback /c/codex/* request — "+
					"no X-DC-Auth, no matching master key, and no recognized "+
					"provider Authorization header. Set "+
					"DEFENSECLAW_CODEX_LOOPBACK_TRUST=1 to opt back into "+
					"the legacy loose behavior on a single-user host (F-1365).")
		})
		return false
	}

	return false
}

// matchesKnownProviderKey returns true if r's Authorization Bearer
// matches any operator-recorded codex provider api_key. This is how
// the native codex Rust binary authenticates loopback calls under
// the F-1365 hardening: it already sends the provider key, so
// possession of that key is accepted as authentication.
func (c *CodexConnector) matchesKnownProviderKey(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == "" {
		return false
	}
	c.snapshotMu.RLock()
	defer c.snapshotMu.RUnlock()
	for _, p := range c.providers {
		if p.APIKey == "" {
			continue
		}
		if SecureTokenMatch(token, p.APIKey) {
			return true
		}
	}
	return false
}

func (c *CodexConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *CodexConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{
		ConnectorName:   "codex",
		RawBody:         body,
		RawModel:        ParseModelFromBody(body),
		Stream:          ParseStreamFromBody(body),
		PassthroughMode: !isChatPath(r.URL.Path),
	}, nil
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
	return AgentPaths{
		PatchedFiles: []string{codexConfigPath()},
		BackupFiles: []string{
			managedFileBackupPath(opts.DataDir, c.Name(), "config.toml"),
			filepath.Join(opts.DataDir, "codex_config_backup.json"),
			filepath.Join(opts.DataDir, "codex_backup.json"),
		},
		HookScripts: hookScriptPathsForConnector(opts, c),
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

// HookCapabilities declares the Codex hook surface for the unified
// hook collector and the agent_hook verdict mapper. The shape is
// derived from the events `evaluateCodexHook` and `codexOutput`
// handle today (SessionStart, UserPromptSubmit, PreToolUse,
// PermissionRequest, PostToolUse, Stop) and the deny-shaped JSON
// envelope codex's hook protocol accepts.
//
// CanBlock=true: codex's PreToolUse / PermissionRequest hookSpecific
// outputs honour permissionDecision=deny; UserPromptSubmit/PostToolUse/
// Stop honour decision=block.
//
// CanAskNative=false: Codex does not surface a native HITL ask channel
// from a hook decision today. confirm verdicts fall back to alert in
// action mode (see evaluateCodexHook). When a future Codex release
// exposes a native ask surface this should flip to true and AskEvents
// populated.
//
// ConfigPath surfaces the on-disk config the operator inspects to
// audit hook wiring.
func (c *CodexConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return HookCapability{
		CanBlock:     true,
		CanAskNative: false,
		BlockEvents: []string{
			"UserPromptSubmit",
			"PreToolUse",
			"PermissionRequest",
			"PostToolUse",
			"Stop",
		},
		SupportsFailClosed: true,
		Scope:              "user",
		ConfigPath:         codexConfigPath(),
	}
}

// HookProfile implements HookProfileProvider. The profile is the
// single declarative description of the connector consumed by:
//   - the unified hook collector (Decode/MapVerdict/Respond callbacks
//     below) for /api/v1/codex/hook;
//   - buildCodexOtelBlock for the codex ~/.codex/config.toml [otel]
//     table; and
//   - operator-visible doctor reports.
//
// Endpoint is the gateway's loopback OTLP-HTTP receiver. Headers
// carry the gateway token + CSRF client identifier; the spec
// renderer canonicalizes header keys to lower-case so the resulting
// TOML matches the wire format codex's deserializer expects.
//
// ServiceName / ResourceAttributes are intentionally omitted —
// codex's documented [otel] schema doesn't accept those keys, and
// codex emits its own richer identity tags (originator, model,
// auth_mode, etc.) on every span/metric. See the inline comment in
// the returned spec for the full rationale and links.
//
// LogUserPrompts is driven by the global redaction toggle: when the
// operator has explicitly disabled redaction we flip codex's native
// log_user_prompt = true so prompts flow through native telemetry
// alongside the hook channel.
func (c *CodexConnector) HookProfile(opts SetupOpts) HookProfile {
	headers := map[string]string{
		"x-defenseclaw-source": "codex",
		"x-defenseclaw-client": "codex-otel/1.0",
	}
	if opts.APIToken != "" {
		headers["x-defenseclaw-token"] = opts.APIToken
	}
	// Intentionally NOT setting ServiceName / ResourceAttributes
	// on codex's NativeOTLPSpec — see F1 rationale below.
	//
	// Codex's documented [otel] TOML schema accepts exactly:
	// environment, log_user_prompt, exporter, trace_exporter,
	// metrics_exporter (and the per-exporter sub-tables). No
	// service_name / resource_attributes key exists, and the
	// schema is published as strict (see
	// https://github.com/openai/codex/issues/17012). Writing those
	// keys risks codex rejecting the config at startup.
	//
	// Codex's OTel SDK also emits its own intrinsic identity tags
	// on every metric — auth_mode, originator, session_source,
	// model, app.version — and uses different service.name values
	// for its sub-processes (codex-app-server, codex_exec). Forcing
	// service.name=codex from outside would COLLAPSE that natural
	// distinction, making dashboards LESS useful than they are
	// today. Operators who need to identify codex traffic should
	// filter on the connector header (x-defenseclaw-source=codex)
	// or on codex's intrinsic originator tag.
	//
	// The M3 work (consistent resource attributes across all
	// connectors) applies to env-block-style connectors like
	// claudecode where the agent's natural service.name would
	// otherwise be useless to operators. For TOML/path-token
	// connectors that already self-identify (codex, geminicli),
	// the upstream tags are richer than anything we could
	// synthesize from the outside.
	profile := HookProfile{
		Name:                "codex",
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		NativeOTLP: &NativeOTLPSpec{
			Kind:           NativeOTLPTOMLBlock,
			Endpoint:       "http://" + opts.APIAddr,
			Protocol:       "json",
			Headers:        headers,
			LogUserPrompts: redaction.DisableAll(),
		},
		// Profile-driven callbacks are the canonical shape for
		// codex hook decode / verdict mapping / response. The
		// gateway profile-runtime registry uses these pure callbacks
		// for response/mode behavior and keeps APIServer-owned
		// scanner / asset-policy / notifier work in the unified
		// collector. Golden tests keep those layers in lockstep.
		Decode:     codexProfileDecode,
		MapVerdict: codexProfileMapVerdict,
		Respond:    codexProfileRespond,
	}
	return ApplyHookContract(profile, opts)
}

// --- ComponentScanner interface ---

func (c *CodexConnector) SupportsComponentScanning() bool { return true }

func (c *CodexConnector) ComponentTargets(cwd string) map[string][]string {
	home := userHomeDir()
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

// --- config.toml patching (hook registration + OTel + notify) ---

// CodexConfigPathOverride allows tests to redirect the config path.
var CodexConfigPathOverride string

func codexConfigPath() string {
	if CodexConfigPathOverride != "" {
		return CodexConfigPathOverride
	}
	return filepath.Join(userHomeDir(), ".codex", "config.toml")
}

// codexConfigBackup captures the pre-DefenseClaw shape of the three
// config.toml subtrees Setup() modifies — [hooks], [otel], and the
// top-level `notify` array — so Teardown can restore them verbatim or
// remove the keys we added. The byte-for-byte managed-file backup
// stored under <DataDir>/backups/managed/codex/config.toml.json is
// the primary restore path; this JSON-encoded shape covers the
// drifted-config fallback (when the operator hand-edited config.toml
// after Setup, the managed-backup hash no longer matches and we fall
// through to the field-level restore).
type codexConfigBackup struct {
	// HadHooksKey + OriginalHooks back up the inline [hooks] table.
	HadHooksKey   bool            `json:"had_hooks_key"`
	OriginalHooks json.RawMessage `json:"original_hooks,omitempty"`
	// AddedCodexHooksFlag tracks whether Setup flipped [features].hooks
	// on; Teardown only clears the flag if we were the ones who set it.
	//
	// IMPORTANT: the JSON tag must remain "added_codex_hooks_flag"
	// for on-disk backwards compatibility with previously written
	// codex.json backups. Renaming the tag would silently lose the
	// flag for every existing install at upgrade time, and Teardown
	// would then refuse to strip the [features].hooks/codex_hooks
	// block we added — leaving hook fan-out enabled even after the
	// operator removed DefenseClaw.
	AddedCodexHooksFlag bool `json:"added_codex_hooks_flag"`
	// HadOtelBlock / OriginalOtel back up the operator's pristine
	// [otel] block.
	HadOtelBlock bool            `json:"had_otel_block"`
	OriginalOtel json.RawMessage `json:"original_otel,omitempty"`
	// HadNotify / OriginalNotify back up the operator's pristine
	// notify = [...] entry.
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
	{"PermissionRequest", "*", 30},
	{"PostToolUse", "*", 30},
	{"SubagentStart", "*", 30},
	{"SubagentStop", "*", 90},
	{"PreCompact", "", 30},
	{"PostCompact", "", 30},
	{"Stop", "", 90},
}

// isDefenseClawCodexProxyRedirect reports whether v is the loopback
// LLM-proxy URL DefenseClaw itself wrote into ~/.codex/config.toml
// during the LLM-proxy era (before codex became hook-only). Matching
// is strict on three axes so an operator's enterprise gateway URL is
// never mistaken for ours:
//
//   - scheme must be http or https (rejects file://, ws://, etc.)
//   - host must be loopback (127.0.0.1, ::1, or the literal "localhost")
//   - path must begin with /c/codex (the legacy proxy mount point)
//
// Any port is accepted because the historical default of :4000 was
// configurable via `setup` and operators may have overridden it.
func isDefenseClawCodexProxyRedirect(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "127.0.0.1", "::1", "localhost":
	default:
		return false
	}
	path := strings.TrimSuffix(u.Path, "/")
	return path == "/c/codex" || strings.HasPrefix(path, "/c/codex/")
}

func (c *CodexConnector) patchCodexConfig(opts SetupOpts, hookScript string) error {
	// filepath.ToSlash is a no-op on Unix (already uses '/'). On Windows it
	// converts backslashes so bash (Git Bash / MSYS2) can resolve the path.
	hookScript = filepath.ToSlash(hookScript)
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

	// Heal legacy installs that injected a DefenseClaw LLM-proxy
	// redirect at the top-level `openai_base_url`. The proxy listener
	// no longer binds (the value points at a closed loopback port), so
	// leaving the key in place causes every Codex turn to fail with
	// "stream disconnected before completion" against the dead
	// 127.0.0.1:<port>/c/codex endpoint.
	//
	// The strip is intentionally narrow: it only deletes values whose
	// URL shape matches the loopback /c/codex pattern DefenseClaw
	// itself wrote. An operator's enterprise gateway URL (e.g.
	// https://gateway.corp.example/openai) is preserved and continues
	// to be covered by TestCodex_Setup_DefaultObservability_NoProxyRewrite.
	if v, ok := cfg["openai_base_url"].(string); ok && isDefenseClawCodexProxyRedirect(v) {
		delete(cfg, "openai_base_url")
	}

	backupPath := filepath.Join(opts.DataDir, "codex_config_backup.json")
	backupExists := false
	if _, statErr := os.Stat(backupPath); statErr == nil {
		backupExists = true
	}

	backup := codexConfigBackup{}
	if !backupExists {
		if existing, ok := cfg["hooks"]; ok {
			backup.HadHooksKey = true
			if raw, err := json.Marshal(existing); err == nil {
				backup.OriginalHooks = raw
			}
		}
		// Capture pristine [otel] and notify so Teardown can restore
		// either verbatim or delete-if-we-added.
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
	}

	// Codex's [hooks] table is an inline struct (HookEventsToml) with
	// per-event fields. It is NOT a path to a hooks.json file —
	// passing a string triggers a TOML parse error at codex startup.
	// Always installed, regardless of enforcement mode: hooks are the
	// entry point for tool-call telemetry into /api/v1/codex/hook
	// (SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest,
	// PostToolUse, Stop).
	// In observability mode the hook handler logs but never
	// blocks; in enforcement mode it can also block based on the
	// subprocess sandbox policy.
	cfg["hooks"] = buildCodexHooksTable(configPath, hookInvocationCommand("codex", hookScript))

	features, _ := cfg["features"].(map[string]interface{})
	if features == nil {
		features = map[string]interface{}{}
	}
	if v, ok := features["hooks"].(bool); !ok || !v {
		if !backupExists {
			backup.AddedCodexHooksFlag = true
		}
	}
	features["hooks"] = true
	delete(features, "codex_hooks")
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
func buildCodexHooksTable(configPath, hookCommand string) map[string]interface{} {
	out := map[string]interface{}{}
	state := map[string]interface{}{}
	keySource := codexHookStateKeySource(configPath)
	for _, group := range codexHookGroups {
		matcherGroup := map[string]interface{}{
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": hookCommand,
					"timeout": group.timeout,
				},
			},
		}
		if group.matcher != "" {
			matcherGroup["matcher"] = group.matcher
		}
		out[group.eventType] = []interface{}{matcherGroup}
		eventKey := codexHookEventKeyLabel(group.eventType)
		// The trust hash is computed over the SAME command Codex executes, so
		// Codex recognizes the entry and teardown can reproduce the fingerprint.
		state[codexHookStateKey(keySource, eventKey, 0, 0)] = map[string]interface{}{
			"trusted_hash": codexCommandHookHash(eventKey, group.matcher, hookCommand, group.timeout),
		}
	}
	out["state"] = state
	return out
}

func codexHookEventKeyLabel(eventType string) string {
	switch eventType {
	case "PreToolUse":
		return "pre_tool_use"
	case "PermissionRequest":
		return "permission_request"
	case "PostToolUse":
		return "post_tool_use"
	case "SubagentStart":
		return "subagent_start"
	case "SubagentStop":
		return "subagent_stop"
	case "PreCompact":
		return "pre_compact"
	case "PostCompact":
		return "post_compact"
	case "SessionStart":
		return "session_start"
	case "UserPromptSubmit":
		return "user_prompt_submit"
	case "Stop":
		return "stop"
	default:
		return eventType
	}
}

func codexHookStateKeySource(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return configPath
	}
	return abs
}

func codexHookStateKey(keySource, eventKey string, groupIndex, handlerIndex int) string {
	return fmt.Sprintf("%s:%s:%d:%d", keySource, eventKey, groupIndex, handlerIndex)
}

// codexCommandHookHash produces the value Codex stores under
// hooks.state[<key>].trusted_hash to suppress the "DefenseClaw inserted
// a hook, do you trust it?" prompt on Codex startup.
//
// SECURITY MODEL — this is NOT tamper detection.
//
// Anyone with write access to ~/.codex/config.toml can recompute a
// matching hash for arbitrary hook content using the same algorithm,
// because the inputs are written next to the output. The "sha256:"
// prefix is a Codex format requirement, not an integrity claim. The
// hash exists solely so DefenseClaw's teardown logic
// (removeOwnedCodexHookState) can recognize the entries it inserted
// and leave operator-edited entries alone — that is, it is a
// self-fingerprint for ownership, not a security boundary.
//
// Determinism note: codexCanonicalJSON relies on encoding/json's
// alphabetical key ordering for map[string]interface{} (stable since
// Go 1.12). Tests pin a known hash to catch any future drift in the
// canonical form, which would otherwise re-prompt every existing
// installation on the next Codex launch.
func codexCommandHookHash(eventKey, matcher, command string, timeout int) string {
	hook := map[string]interface{}{
		"async":   false,
		"command": command,
		"timeout": timeout,
		"type":    "command",
	}
	identity := map[string]interface{}{
		"event_name": eventKey,
		"hooks":      []interface{}{hook},
	}
	if matcher != "" {
		identity["matcher"] = matcher
	}
	return codexVersionForTOML(identity)
}

// codexVersionForTOML returns the "sha256:<hex>" fingerprint Codex
// expects in hooks.state.<key>.trusted_hash. See codexCommandHookHash
// for why this is a self-recognition fingerprint and not an integrity
// check.
func codexVersionForTOML(v interface{}) string {
	serialized := codexCanonicalJSON(v)
	hash := sha256.Sum256(serialized)
	return fmt.Sprintf("sha256:%x", hash[:])
}

// codexCanonicalJSON serializes v with stable map-key ordering. This
// determinism is required so that codexCommandHookHash produces the
// same value across runs and across goroutines for the same logical
// hook identity.
func codexCanonicalJSON(v interface{}) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("null")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
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
// hard-code `"json"` because it is the stable protocol DefenseClaw has
// used for Codex native telemetry since the first OTLP integration. The
// gateway also accepts OTLP protobuf, but pinning JSON avoids changing
// Codex's wire format during setup/teardown upgrades.
//
// log_user_prompt = false is the privacy-preserving default: codex's
// native OTel emits prompt text only when this is true. When redaction
// is explicitly disabled, DefenseClaw flips it to true so native Codex
// OTel joins the same raw-content mode as the hook telemetry.
// Teardown restores the operator's pristine [otel] block or deletes
// ours if there was none.
//
// Headers carry the gateway token so the OTLP-HTTP receiver can
// authenticate the codex CLI process the same way the hook script
// does. The header name is intentionally NOT "Authorization" so the
// receiver can distinguish OTel traffic from hook/REST traffic in
// audit logs.
func buildCodexOtelBlock(opts SetupOpts) map[string]interface{} {
	// Spec-driven OTLP wiring. The connector's HookProfile carries
	// the declarative NativeOTLPSpec; this helper just asks it for
	// the TOML rendering. spec.TOMLBlock() validates Endpoint /
	// Protocol / Headers and produces the same shape the codex
	// kebab-case serde accepts.
	//
	// If validation ever fails (spec misconfigured in code),
	// returning an empty map is preferable to silently writing a
	// half-built [otel] block: codex's deserializer will reject the
	// empty block at startup with a clear missing-field error, and
	// the operator gets a deterministic failure instead of an
	// OTLP exporter that succeeds-but-points-nowhere.
	spec := (&CodexConnector{}).HookProfile(opts).NativeOTLP
	if spec == nil {
		return map[string]interface{}{}
	}
	block, err := spec.TOMLBlock()
	if err != nil {
		return map[string]interface{}{}
	}
	return block
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
	authHeader := shellSingleQuote("Authorization: Bearer " + opts.APIToken)
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
		"TRACE_HEADERS=()\n" +
		"TP=\"${DEFENSECLAW_TRACEPARENT:-${TRACEPARENT:-}}\"\n" +
		"TS=\"${DEFENSECLAW_TRACESTATE:-${TRACESTATE:-}}\"\n" +
		"case \"${TP}\" in *$'\\n'*|*$'\\r'*) TP=\"\" ;; esac\n" +
		"case \"${TS}\" in *$'\\n'*|*$'\\r'*) TS=\"\" ;; esac\n" +
		"if [ -n \"${TP}\" ]; then TRACE_HEADERS+=(--header \"traceparent: ${TP}\"); fi\n" +
		"if [ -n \"${TS}\" ]; then TRACE_HEADERS+=(--header \"tracestate: ${TS}\"); fi\n" +
		"curl --silent --show-error --max-time 5 \\\n" +
		"  --header 'Content-Type: application/json' \\\n" +
		// Authorization: Bearer is the canonical credential the
		// gateway's tokenAuth middleware checks first (with
		// X-DefenseClaw-Token as a fallback). Using the standard
		// header keeps the bridge interoperable with curl/proxy
		// debugging and matches the python CLI / inspect-hook
		// auth contract.
		"  --header " + authHeader + " \\\n" +
		// X-DefenseClaw-Client is required by the gateway's CSRF gate;
		// without it apiCSRFProtect 403s the POST. inspect-tool-response
		// and the python CLI set the same header; the value is purely
		// observational (logged in audit).
		"  --header 'X-DefenseClaw-Client: codex-notify/1.0' \\\n" +
		"  --header 'x-defenseclaw-source: codex-notify' \\\n" +
		"  \"${TRACE_HEADERS[@]}\" \\\n" +
		"  --data \"${JSON}\" \\\n" +
		"  " + shellSingleQuote(endpoint) + " >/dev/null 2>&1 || true\n"
	if err := os.MkdirAll(opts.DataDir, 0o755); err != nil {
		return fmt.Errorf("ensure data dir: %w", err)
	}
	if err := atomicWriteFile(scriptPath, []byte(body), 0o700); err != nil {
		return fmt.Errorf("write notify bridge: %w", err)
	}
	return nil
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
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

	removedOwnedHooks := false
	hookEventsRemain := false
	if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
		hooksDir := filepath.Join(opts.DataDir, "hooks")
		for eventType, val := range hooks {
			if eventType == "state" {
				continue
			}
			before := codexHookEntryCount(val)
			remaining := removeOwnedHooks(val, hooksDir)
			if before != len(remaining) {
				removedOwnedHooks = true
			}
			if len(remaining) == 0 {
				delete(hooks, eventType)
			} else {
				hooks[eventType] = remaining
				hookEventsRemain = true
			}
		}
		// Reproduce the exact command used at setup (Unix: ToSlash'd .sh path;
		// Windows: native Go invocation) so the trust-hash fingerprint matches.
		hookCommand := hookInvocationCommand("codex", filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "codex-hook.sh")))
		if removeOwnedCodexHookState(hooks, configPath, hookCommand) {
			removedOwnedHooks = true
		}
		if len(hooks) == 0 {
			delete(cfg, "hooks")
		} else {
			cfg["hooks"] = hooks
		}
	} else if !backup.HadHooksKey {
		delete(cfg, "hooks")
	}

	if backup.AddedCodexHooksFlag || (removedOwnedHooks && !hookEventsRemain) {
		if features, ok := cfg["features"].(map[string]interface{}); ok {
			delete(features, "hooks")
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

func removeOwnedCodexHookState(hooks map[string]interface{}, configPath, hookCommand string) bool {
	state, ok := hooks["state"].(map[string]interface{})
	if !ok {
		return false
	}
	removed := false
	keySource := codexHookStateKeySource(configPath)
	for _, group := range codexHookGroups {
		eventKey := codexHookEventKeyLabel(group.eventType)
		key := codexHookStateKey(keySource, eventKey, 0, 0)
		entry, ok := state[key].(map[string]interface{})
		if !ok {
			continue
		}
		expectedHash := codexCommandHookHash(eventKey, group.matcher, hookCommand, group.timeout)
		if trustedHash, _ := entry["trusted_hash"].(string); trustedHash == expectedHash {
			delete(state, key)
			removed = true
		}
	}
	if len(state) == 0 {
		delete(hooks, "state")
	} else {
		hooks["state"] = state
	}
	return removed
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
