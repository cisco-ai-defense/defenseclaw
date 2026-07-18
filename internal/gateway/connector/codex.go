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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
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

// codexLifecycleMu complements the cross-process lifecycle lock. File-lock
// semantics for separately opened descriptors differ across supported Unix
// variants, so the process-local mutex is required as well.
var codexLifecycleMu sync.Mutex

func withCodexLifecycleTransaction(opts SetupOpts, fn func() error) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("codex lifecycle transaction: empty data dir")
	}
	// Keep the lifecycle lock at the already-selected data root. Creating the
	// hooks directory before native executable/policy validation would leave a
	// false installation artifact after a fail-closed discovery refusal.
	lockDir := opts.DataDir
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return fmt.Errorf("codex lifecycle transaction: create lock dir: %w", err)
	}

	codexLifecycleMu.Lock()
	defer codexLifecycleMu.Unlock()
	return withOwnedFileLock(filepath.Join(lockDir, ".codex-lifecycle.lock"), fn)
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
	return "config.toml model_providers patch + hook script (10 events, component scanning)"
}
func (c *CodexConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *CodexConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *CodexConnector) Setup(ctx context.Context, opts SetupOpts) error {
	return withCodexLifecycleTransaction(opts, func() error {
		return c.setupLocked(ctx, opts)
	})
}

func (c *CodexConnector) setupLocked(ctx context.Context, opts SetupOpts) error {
	// Inspect Codex's effective requirements before creating tokens, hook
	// scripts, backups, or touching config.toml. A managed-only deployment
	// ignores user hooks, so proceeding would report a protected install while
	// Codex silently bypasses every DefenseClaw handler.
	if err := enforceCodexUserHookPolicy(ctx, opts); err != nil {
		return err
	}

	// Hook-only connector: patchCodexConfig wires hooks, OTel, and the
	// notify bridge without rewriting provider URLs or exporting a
	// global OPENAI_BASE_URL. The legacy LLM-proxy surface has been
	// removed — Codex talks directly to its native upstream and
	// DefenseClaw only observes via hooks + OTel.

	otlpToken, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeCodex, opts.OTLPPathToken)
	if err != nil {
		return fmt.Errorf("codex scoped OTLP token: %w", err)
	}
	opts.OTLPPathToken = otlpToken

	hookDir := filepath.Join(opts.DataDir, "hooks")
	// Plan C2: HookScriptOwner-driven. codex_hook.sh ships from the
	// connector method; generic inspect-* scripts come from the
	// shared list inside writeHookScriptsCommon.
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("codex hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "codex-hook.sh")
	if runtime.GOOS == "windows" {
		// Native Windows installs use Codex's documented legacy managed
		// configuration layer. Codex treats hooks discovered from this source as
		// administrator-managed, so setup never needs to synthesize private
		// hooks.state trust records or ask the operator to approve /hooks.
		if err := c.patchCodexManagedHooks(opts, hookScript); err != nil {
			return fmt.Errorf("codex managed_config.toml hook patch: %w", err)
		}
	}
	if err := c.patchCodexConfig(opts, hookScript); err != nil {
		if runtime.GOOS == "windows" {
			if rollbackErr := c.restoreCodexManagedHooks(opts); rollbackErr != nil {
				return fmt.Errorf("codex config.toml patch: %w (managed hook rollback failed: %v)", err, rollbackErr)
			}
		}
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
	return withCodexLifecycleTransaction(opts, func() error {
		return c.teardownLocked(ctx, opts)
	})
}

func (c *CodexConnector) teardownLocked(ctx context.Context, opts SetupOpts) error {
	if err := c.restoreCodexConfig(opts); err != nil {
		// Keep the scoped OTLP credential valid while config.toml may still
		// reference it. Revoking first would strand a partially restored Codex
		// config on a permanently unauthorized endpoint.
		return fmt.Errorf("codex teardown: config restore: %w", err)
	}
	if runtime.GOOS == "windows" {
		if err := c.restoreCodexManagedHooks(opts); err != nil {
			return fmt.Errorf("codex teardown: managed hook restore: %w", err)
		}
	}

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
	if err := c.VerifyClean(opts); err != nil {
		return fmt.Errorf("codex teardown: verify clean before token revocation: %w", err)
	}
	if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeCodex); err != nil {
		return fmt.Errorf("codex teardown: revoke scoped OTLP token: %w", err)
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
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse codex config while verifying cleanup: %w", err)
		} else {
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
			} else if _, exists := cfg["hooks"]; exists {
				return fmt.Errorf("verify Codex hooks: unsupported config.toml hooks type %T", cfg["hooks"])
			}
			residual = append(residual, codexOtelResidueFields(cfg["otel"], opts)...)
			if codexNotifyLooksManaged(cfg["notify"], opts) {
				residual = append(residual, "config.toml notify still points at defenseclaw bridge")
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read codex config while verifying cleanup: %w", err)
	}
	if runtime.GOOS == "windows" {
		managedPath := codexManagedConfigPath()
		if data, err := os.ReadFile(managedPath); err == nil {
			cfg := map[string]interface{}{}
			if err := toml.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("parse Codex managed config while verifying cleanup: %w", err)
			}
			if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
				for eventType, val := range hooks {
					if eventType == "state" {
						continue
					}
					list, _ := val.([]interface{})
					for _, entry := range list {
						if isOwnedHook(entry, filepath.Join(opts.DataDir, "hooks")) {
							residual = append(residual, fmt.Sprintf("managed_config.toml hooks[%s] still contains defenseclaw hook", eventType))
							break
						}
					}
				}
			} else if _, exists := cfg["hooks"]; exists {
				return fmt.Errorf("verify Codex managed hooks: unsupported managed_config.toml hooks type %T", cfg["hooks"])
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read Codex managed config while verifying cleanup: %w", err)
		}
	}
	if err := inspectCodexHooksJSON(opts, func(eventType string) {
		residual = append(residual, fmt.Sprintf("hooks.json hooks[%s] still contains defenseclaw hook", eventType))
	}); err != nil {
		return err
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
	patchedFiles := []string{codexConfigPath()}
	backupFiles := []string{
		managedFileBackupPath(opts.DataDir, c.Name(), "config.toml"),
		filepath.Join(opts.DataDir, "codex_config_backup.json"),
		filepath.Join(opts.DataDir, "codex_backup.json"),
	}
	if runtime.GOOS == "windows" {
		patchedFiles = append(patchedFiles, codexManagedConfigPath())
		backupFiles = append(backupFiles, managedFileBackupPath(opts.DataDir, c.Name(), codexManagedConfigLogicalName))
	}
	return AgentPaths{
		PatchedFiles:         patchedFiles,
		BackupFiles:          backupFiles,
		HookScripts:          hookScriptPathsForConnector(opts, c),
		GeneratedFiles:       []string{filepath.Join(opts.DataDir, "hooks", otlpPathTokenFileName(OTLPScopeCodex))},
		GeneratedExecutables: []string{filepath.Join(opts.DataDir, "notify-bridge.sh")},
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
		ConfigPath:         codexHookConfigPath(),
	}
}

// HookProfile implements HookProfileProvider. The profile is the
// single declarative description of the connector consumed by:
//   - the unified hook collector (Decode/MapVerdict/Respond callbacks
//     below) for /api/v1/codex/hook;
//   - the setup-only Codex OTLP renderer for ~/.codex/config.toml; and
//   - operator-visible doctor reports.
//
// Endpoint is the gateway's standard loopback OTLP receiver. Codex supports
// arbitrary exporter headers, so its connector-scoped credential is carried
// as an Authorization bearer instead of appearing in the URL. The gateway
// binds that bearer to x-defenseclaw-source=codex; it cannot authenticate the
// management API or Claude traffic.
//
// ServiceName / ResourceAttributes are intentionally omitted —
// codex's documented [otel] schema doesn't accept those keys, and
// codex emits its own richer identity tags (originator, model,
// auth_mode, etc.) on every span/metric. See the inline comment in
// the returned spec for the full rationale and links.
//
// LogUserPrompts is always enabled at the source. Observability v8 keeps the
// canonical record immutable and applies redaction independently for every
// destination, so suppressing prompt content here would make an unredacted
// route impossible and would make two destinations disagree about one source
// occurrence.
func (c *CodexConnector) HookProfile(opts SetupOpts) HookProfile {
	otlpToken := strings.TrimSpace(opts.OTLPPathToken)
	if otlpToken == "" && opts.DataDir != "" {
		otlpToken, _ = LoadOTLPPathToken(opts.DataDir, OTLPScopeCodex)
	}
	headers := map[string]string{
		"x-defenseclaw-source": "codex",
		"x-defenseclaw-client": "codex-otel/1.0",
	}
	if otlpToken != "" {
		headers["authorization"] = "Bearer " + otlpToken
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
			LogUserPrompts: true,
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
	codexDir := codexHomeDir()

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
	return filepath.Join(codexHomeDir(), "config.toml")
}

const codexManagedConfigLogicalName = "managed_config.toml"

// codexManagedConfigPath is intentionally derived from config.toml's parent so
// tests and configured CODEX_HOME installs always address the same Codex home.
func codexManagedConfigPath() string {
	return filepath.Join(filepath.Dir(codexConfigPath()), codexManagedConfigLogicalName)
}

func codexHookConfigPath() string {
	if runtime.GOOS == "windows" {
		return codexManagedConfigPath()
	}
	return codexConfigPath()
}

// ownedHookContractPresent performs the Codex-specific runtime guardian check.
// A command substring is insufficient: Codex only executes a handler when its
// complete event shape is valid and its source is trusted. On Windows that
// source is managed_config.toml; legacy user-scoped registrations additionally
// require position-aware trust state. Reuse Setup's authoritative verifier so
// guardian repair cannot mistake a partial, moved, disabled, asynchronous, or
// untrusted matrix for active protection.
func (c *CodexConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	userConfigPath := codexConfigPath()
	data, err := os.ReadFile(userConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
	} else {
		cfg := map[string]interface{}{}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return false, fmt.Errorf("parse Codex config for hook guardian: %w", err)
		}
		if rawFeatures, exists := cfg["features"]; exists {
			features, ok := rawFeatures.(map[string]interface{})
			if !ok {
				return false, nil
			}
			for _, key := range []string{"hooks", "codex_hooks"} {
				if rawEnabled, exists := features[key]; exists {
					enabled, ok := rawEnabled.(bool)
					if !ok || !enabled {
						return false, nil
					}
				}
			}
		}
	}

	configPath := codexHookConfigPath()
	data, err = os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse Codex hook config for guardian: %w", err)
	}
	if rawFeatures, exists := cfg["features"]; exists {
		features, ok := rawFeatures.(map[string]interface{})
		if !ok {
			return false, nil
		}
		for _, key := range []string{"hooks", "codex_hooks"} {
			if rawEnabled, exists := features[key]; exists {
				enabled, ok := rawEnabled.(bool)
				if !ok || !enabled {
					return false, nil
				}
			}
		}
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	var verifyErr error
	if runtime.GOOS == "windows" {
		verifyErr = verifyManagedCodexHookMatrix(hooks, configPath, filepath.Join(opts.DataDir, "hooks"))
	} else {
		verifyErr = verifyTrustedCodexHookMatrix(hooks, configPath, filepath.Join(opts.DataDir, "hooks"))
	}
	if verifyErr != nil {
		return false, nil
	}
	return true, nil
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
	backupPath := filepath.Join(opts.DataDir, "codex_config_backup.json")
	backupExists := false
	hooksDir := filepath.Join(opts.DataDir, "hooks")

	var transformed []byte
	var backupToSave codexConfigBackup
	render := func(raw []byte) error {
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

		backup := codexConfigBackup{}
		if !backupExists {
			if existing, ok := cfg["hooks"]; ok {
				backup.HadHooksKey = true
				raw, err := json.Marshal(existing)
				if err != nil {
					return fmt.Errorf("capture original Codex hooks: %w", err)
				}
				backup.OriginalHooks = raw
			}
			// Capture pristine [otel] and notify so Teardown can restore
			// either verbatim or delete-if-we-added.
			if existing, ok := cfg["otel"]; ok {
				backup.HadOtelBlock = true
				raw, err := json.Marshal(existing)
				if err != nil {
					return fmt.Errorf("capture original Codex OTel config: %w", err)
				}
				backup.OriginalOtel = raw
			}
			if existing, ok := cfg["notify"]; ok {
				backup.HadNotify = true
				raw, err := json.Marshal(existing)
				if err != nil {
					return fmt.Errorf("capture original Codex notify config: %w", err)
				}
				backup.OriginalNotify = raw
			}
			backupToSave = backup
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
		hooks, hooksExist := cfg["hooks"].(map[string]interface{})
		if _, exists := cfg["hooks"]; exists && !hooksExist {
			return fmt.Errorf("Codex hooks configuration has unsupported type %T; refusing to replace it", cfg["hooks"])
		}
		if runtime.GOOS == "windows" {
			// Upgrade away from the old user-scoped registration. Remove only
			// provably owned handlers and trust records; the effective hook matrix
			// now lives in managed_config.toml and is trusted by source.
			if hooksExist {
				if _, err := removeOwnedCodexHooksAndState(hooks, configPath, hooksDir); err != nil {
					return fmt.Errorf("remove legacy DefenseClaw Codex hooks: %w", err)
				}
				if len(hooks) == 0 {
					delete(cfg, "hooks")
				} else {
					cfg["hooks"] = hooks
				}
			}
		} else {
			if !hooksExist {
				hooks = map[string]interface{}{}
			}
			if err := mergeOwnedCodexHooks(hooks, configPath, hookScript, hooksDir, true); err != nil {
				return err
			}
			cfg["hooks"] = hooks
		}

		features, _ := cfg["features"].(map[string]interface{})
		if features == nil {
			features = map[string]interface{}{}
		}
		if enabled, explicitlySet := features["hooks"].(bool); explicitlySet && !enabled {
			return fmt.Errorf("Codex hooks are disabled in config.toml; enable [features].hooks before installing the Codex connector")
		}
		if enabled, explicitlySet := features["codex_hooks"].(bool); explicitlySet && !enabled {
			return fmt.Errorf("Codex hooks are disabled by deprecated [features].codex_hooks; enable hooks before installing the Codex connector")
		}
		// Remove the retired alias when it is enabled. Current Codex accepts the
		// [features].hooks key (and enables hooks by default) and warns on the old
		// name.
		delete(features, "codex_hooks")

		// Native OTel exporter — runs on every install regardless of
		// enforcement mode. Codex's [otel] block produces structured
		// logs (raw API request/response, model + token counts) and
		// metrics that complement the hook-based event stream. The
		// /v1/logs and /v1/metrics endpoints on the gateway's API port
		// receive the OTLP-HTTP payload and normalize into
		// gateway.jsonl with source="codex_otel".
		otelBlock, err := buildCodexOtelBlockWithPathToken(opts, opts.OTLPPathToken)
		if err != nil {
			return fmt.Errorf("render scoped Codex OTLP config: %w", err)
		}
		cfg["otel"] = otelBlock

		// agent-turn-complete bridge: Codex appends one JSON payload argument to
		// this argv array. Windows invokes the installed no-console hook launcher;
		// Unix keeps the existing Bash bridge. The native form is an
		// argv array rather than a command string, so paths containing spaces need
		// no shell quoting and no Bash/jq/curl dependency is introduced.
		if runtime.GOOS == "windows" {
			cfg["notify"] = codexNativeNotifyCommand()
			// Heal a bridge left by an older Windows setup. It is no longer
			// referenced and contains a baked gateway token.
			_ = os.Remove(filepath.Join(opts.DataDir, "notify-bridge.sh"))
		} else {
			if err := writeCodexNotifyBridge(opts); err != nil {
				return fmt.Errorf("write codex notify bridge: %w", err)
			}
			cfg["notify"] = codexShellNotifyCommand(opts)
		}

		out, err := toml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshal codex config: %w", err)
		}
		// Verify the exact representation that Codex will parse, not just the
		// pre-marshalling Go maps. This catches schema/key normalization drift that
		// would otherwise leave Setup successful while Codex reports the hooks as
		// untrusted or silently omits part of the required event matrix.
		rendered := map[string]interface{}{}
		if err := toml.Unmarshal(out, &rendered); err != nil {
			return fmt.Errorf("verify rendered codex config: %w", err)
		}
		if runtime.GOOS != "windows" {
			renderedHooks, ok := rendered["hooks"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("verify rendered codex config: hooks has unsupported type %T", rendered["hooks"])
			}
			if err := verifyTrustedCodexHookMatrix(renderedHooks, configPath, hooksDir); err != nil {
				return fmt.Errorf("verify trusted DefenseClaw Codex hooks: %w", err)
			}
		} else if err := verifyNoOwnedCodexHooks(rendered, hooksDir); err != nil {
			return fmt.Errorf("verify legacy Codex user hook cleanup: %w", err)
		}
		transformed = out
		return nil
	}
	// Atomic + 0o600: a partial write of config.toml can brick Codex
	// (it's the only file Codex reads at startup), and the file may
	// carry env-var bindings that resolve to provider API keys at
	// runtime. atomicWriteFile uses CreateTemp + Rename + Chmod so a
	// crash mid-write leaves the previous config in place. See S0.11.
	if err := ensureCodexConfigDir(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("create Codex config directory: %w", err)
	}
	if err := withFileLock(configPath, func() error {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), "config.toml", configPath); err != nil {
			return fmt.Errorf("capture codex config backup: %w", err)
		}
		managedBackup, err := loadManagedFileBackupForTransform(
			opts.DataDir,
			c.Name(),
			"config.toml",
			configPath,
		)
		if err != nil {
			return fmt.Errorf("load managed codex config backup: %w", err)
		}
		if _, statErr := os.Stat(backupPath); statErr == nil {
			backupExists = true
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("inspect codex config backup: %w", statErr)
		}

		exactBackupSafe := true
		if err := atomicTransformFileWithStateDir(configPath, opts.DataDir, 0o600, func(raw []byte, exists bool) (atomicTransformResult, error) {
			if !managedFileBackupMatchesSnapshot(managedBackup, raw, exists) {
				exactBackupSafe = false
			}
			if err := render(raw); err != nil {
				return atomicTransformResult{}, err
			}
			if exactBackupSafe {
				// Publish the intended post-image hash before replacing config.toml.
				// A stop after replacement can then restore the pristine bytes
				// exactly; a stop before replacement leaves a hash mismatch and
				// teardown safely falls back to surgical cleanup.
				if err := updateManagedFileBackupPostHashValue(
					opts.DataDir,
					c.Name(),
					"config.toml",
					configPath,
					managedFileSnapshotHash(transformed, true),
				); err != nil {
					return atomicTransformResult{}, fmt.Errorf("publish intended codex config backup hash: %w", err)
				}
			}
			return atomicTransformResult{Data: append([]byte(nil), transformed...)}, nil
		}); err != nil {
			if !exactBackupSafe {
				discardManagedFileBackup(opts.DataDir, c.Name(), "config.toml")
			}
			return err
		}

		persisted, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read persisted codex config for trust verification: %w", err)
		}
		persistedConfig := map[string]interface{}{}
		if err := toml.Unmarshal(persisted, &persistedConfig); err != nil {
			return fmt.Errorf("parse persisted codex config for trust verification: %w", err)
		}
		if runtime.GOOS != "windows" {
			persistedHooks, ok := persistedConfig["hooks"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("verify persisted codex config: hooks has unsupported type %T", persistedConfig["hooks"])
			}
			if err := verifyTrustedCodexHookMatrix(persistedHooks, configPath, hooksDir); err != nil {
				return fmt.Errorf("verify persisted trusted DefenseClaw Codex hooks: %w", err)
			}
		} else if err := verifyNoOwnedCodexHooks(persistedConfig, hooksDir); err != nil {
			return fmt.Errorf("verify persisted legacy Codex user hook cleanup: %w", err)
		}
		if !backupExists {
			if err := c.saveConfigBackup(opts.DataDir, backupToSave); err != nil {
				return fmt.Errorf("save codex config backup: %w", err)
			}
		}
		if !bytes.Equal(persisted, transformed) {
			// An external edit landed after our replacement. The hook matrix may
			// still be healthy, but exact restoration would erase that edit.
			exactBackupSafe = false
		}
		if !exactBackupSafe {
			discardManagedFileBackup(opts.DataDir, c.Name(), "config.toml")
			return nil
		}
		if err := updateManagedFileBackupPostHashValue(
			opts.DataDir,
			c.Name(),
			"config.toml",
			configPath,
			managedFileSnapshotHash(transformed, true),
		); err != nil {
			return fmt.Errorf("update codex config backup hash: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("write codex config: %w", err)
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
	_ = configPath // retained for source-compatible migration tests
	if runtime.GOOS == "windows" {
		// Codex prefers command_windows on native Windows, but command remains
		// part of the persisted registration and is inspected by lifecycle and
		// compatibility tooling. Keep both fields native so a fallback can never
		// select the Unix hook script on a Windows installation.
		hookCommand = hookInvocationCommandFor("windows", "codex", hookCommand)
	}
	for _, group := range codexHookGroups {
		handler := map[string]interface{}{
			"type":    "command",
			"command": hookCommand,
			"timeout": group.timeout,
		}
		if runtime.GOOS == "windows" {
			handler["command_windows"] = windowsCodexHookCommand()
		}
		matcherGroup := map[string]interface{}{
			"hooks": []interface{}{handler},
		}
		if group.matcher != "" {
			matcherGroup["matcher"] = group.matcher
		}
		out[group.eventType] = []interface{}{matcherGroup}
	}
	return out
}

func windowsCodexHookCommand() string {
	return windowsNativeHookCommand("codex")
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
		abs = configPath
	}
	return codexNormalizeHookKeySourceForPlatform(runtime.GOOS, abs)
}

// codexNormalizeHookKeySourceForPlatform mirrors AbsolutePathBuf's Windows
// device-path normalization. Codex strips supported verbatim prefixes before
// using source_path.display() in the positional state key; retaining one here
// would make otherwise valid long-path installations permanently untrusted.
func codexNormalizeHookKeySourceForPlatform(goos, path string) string {
	if goos != "windows" {
		return path
	}
	for _, prefix := range []string{`\\?\UNC\`, `\\.\UNC\`} {
		if strings.HasPrefix(path, prefix) {
			return `\\` + strings.TrimPrefix(path, prefix)
		}
	}
	for _, prefix := range []string{`\\?\`, `\\.\`} {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(path, prefix)
		if len(candidate) >= 3 && ((candidate[0] >= 'A' && candidate[0] <= 'Z') || (candidate[0] >= 'a' && candidate[0] <= 'z')) && candidate[1] == ':' && (candidate[2] == '\\' || candidate[2] == '/') {
			return candidate
		}
	}
	return path
}

func codexHookStateKey(keySource, eventKey string, groupIndex, handlerIndex int) string {
	return fmt.Sprintf("%s:%s:%d:%d", keySource, eventKey, groupIndex, handlerIndex)
}

// codexCommandHookHash produces the value Codex stores under
// hooks.state[<key>].trusted_hash. It is the non-Windows convenience wrapper
// used by compatibility tests and legacy-state cleanup; production setup hashes
// the actual rendered handler with codexCommandHookHashForPlatform.
//
// SECURITY MODEL — this is NOT tamper detection.
//
// Anyone with write access to ~/.codex/config.toml can recompute a
// matching hash for arbitrary hook content using the same algorithm,
// because the inputs are written next to the output. The "sha256:"
// prefix is a Codex format requirement, not an integrity claim. Setup selection
// is explicit user consent to trust these handlers. The hash also lets
// removeOwnedCodexHookState recognize the entries DefenseClaw inserted
// and leave operator-edited entries alone — that is, it is a
// self-fingerprint for ownership, not a security boundary.
//
// Determinism note: codexCanonicalJSON relies on encoding/json's
// alphabetical key ordering for map[string]interface{} (stable since
// Go 1.12). Tests pin a known hash to catch any future drift in the
// canonical form, which would otherwise re-prompt every existing
// installation on the next Codex launch.
func codexCommandHookHash(eventKey, matcher, command string, timeout int) string {
	var normalizedMatcher interface{}
	if matcher != "" {
		normalizedMatcher = matcher
	}
	hash, _ := codexCommandHookHashForPlatform("linux", eventKey, normalizedMatcher, map[string]interface{}{
		"type":    "command",
		"command": command,
		"timeout": timeout,
		"async":   false,
	})
	return hash
}

// codexCommandHookHashForPlatform mirrors openai/codex hook discovery. Codex
// first selects commandWindows on Windows (falling back to command), clamps the
// timeout to at least one second, and then hashes a normalized handler with no
// commandWindows override. Codex converts the identity through toml::Value
// before canonical JSON, so absent Option fields (matcher, commandWindows, and
// statusMessage) are omitted rather than serialized as JSON null.
func codexCommandHookHashForPlatform(
	goos string,
	eventKey string,
	matcher interface{},
	handler map[string]interface{},
) (string, error) {
	if kind, _ := handler["type"].(string); kind != "command" {
		return "", fmt.Errorf("handler type is %q, want command", kind)
	}
	command, ok := handler["command"].(string)
	if !ok || strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("command handler has an empty command")
	}
	commandWindows, err := codexOptionalString(handler, "commandWindows", "command_windows")
	if err != nil {
		return "", err
	}
	selectedCommand := command
	if goos == "windows" && commandWindows != nil {
		selectedCommand = *commandWindows
	}
	if strings.TrimSpace(selectedCommand) == "" {
		return "", fmt.Errorf("selected command is empty")
	}

	timeout := 600
	if rawTimeout, exists := handler["timeout"]; exists {
		parsed, ok := codexInteger(rawTimeout)
		if !ok {
			return "", fmt.Errorf("command timeout has unsupported type %T", rawTimeout)
		}
		if parsed < 0 {
			return "", fmt.Errorf("command timeout must be non-negative")
		}
		timeout = parsed
	}
	if timeout < 1 {
		timeout = 1
	}

	async := false
	if rawAsync, exists := handler["async"]; exists {
		var ok bool
		async, ok = rawAsync.(bool)
		if !ok {
			return "", fmt.Errorf("command async has unsupported type %T", rawAsync)
		}
	}
	statusMessage, err := codexOptionalString(handler, "statusMessage")
	if err != nil {
		return "", err
	}

	// UserPromptSubmit and Stop ignore configured matchers during discovery.
	// Every other supported event retains Some("") versus None, so validate and
	// preserve that distinction in the normalized identity.
	if eventKey == "user_prompt_submit" || eventKey == "stop" {
		matcher = nil
	} else if matcher != nil {
		if _, ok := matcher.(string); !ok {
			return "", fmt.Errorf("matcher has unsupported type %T", matcher)
		}
	}

	normalizedHandler := map[string]interface{}{
		"type":    "command",
		"command": selectedCommand,
		"timeout": timeout,
		"async":   async,
	}
	if statusMessage != nil {
		normalizedHandler["statusMessage"] = *statusMessage
	}
	identity := map[string]interface{}{
		"event_name": eventKey,
		"hooks":      []interface{}{normalizedHandler},
	}
	if matcher != nil {
		identity["matcher"] = matcher
	}
	return codexVersionForTOML(identity), nil
}

func codexOptionalString(values map[string]interface{}, keys ...string) (*string, error) {
	for _, key := range keys {
		raw, exists := values[key]
		if !exists || raw == nil {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%s has unsupported type %T", key, raw)
		}
		return &value, nil
	}
	return nil, nil
}

func codexInteger(value interface{}) (int, bool) {
	maxInt := uint64(^uint(0) >> 1)
	switch typed := value.(type) {
	case int:
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case uint:
		if uint64(typed) > maxInt {
			return 0, false
		}
		return int(typed), true
	case uint8:
		return int(typed), true
	case uint16:
		return int(typed), true
	case uint32:
		if uint64(typed) > maxInt {
			return 0, false
		}
		return int(typed), true
	case uint64:
		if typed > maxInt {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

// legacyCodexCommandHookHash reproduces the incomplete pre-parity
// DefenseClaw fingerprint. It is used only to remove a state entry at the exact
// position of an owned handler during upgrade; new trust state always uses the
// current Codex normalization above.
func legacyCodexCommandHookHash(eventKey string, matcher interface{}, command string, timeout int) string {
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
	if matcherValue, ok := matcher.(string); ok && matcherValue != "" {
		identity["matcher"] = matcherValue
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
//	log_user_prompt = true
//	[otel.exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/logs"
//	protocol = "json"
//	headers = { authorization = "Bearer <connector-scoped-token>", x-defenseclaw-source = "codex", x-defenseclaw-client = "codex-otel/1.0" }
//	[otel.trace_exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/traces"
//	protocol = "json"
//	headers = { authorization = "Bearer <connector-scoped-token>", x-defenseclaw-source = "codex", x-defenseclaw-client = "codex-otel/1.0" }
//	[otel.metrics_exporter.otlp-http]
//	endpoint = "http://127.0.0.1:18970/v1/metrics"
//	protocol = "json"
//	headers = { authorization = "Bearer <connector-scoped-token>", x-defenseclaw-source = "codex", x-defenseclaw-client = "codex-otel/1.0" }
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
// log_user_prompt = true preserves source facts. Destination-specific v8
// redaction is applied centrally after ingest rather than destructively at
// the Codex source.
// Teardown restores the operator's pristine [otel] block or deletes
// ours if there was none.
//
// Authentication uses a dedicated, 32-byte connector-scoped bearer. It is not
// the hook token and cannot authorize management or another connector's OTLP
// traffic. Keeping it in Authorization prevents credential leakage through
// endpoint URLs, diagnostics, and proxy logs.
func buildCodexOtelBlockWithPathToken(opts SetupOpts, pathToken string) (map[string]interface{}, error) {
	// Spec-driven OTLP wiring. The connector's HookProfile carries
	// the declarative NativeOTLPSpec; this helper just asks it for
	// the TOML rendering. spec.TOMLBlock() validates Endpoint /
	// Protocol / Headers and produces the same shape the codex
	// kebab-case serde accepts.
	//
	// Validation failures are returned to setup so config.toml is never
	// replaced with a half-built [otel] block.
	opts.OTLPPathToken = strings.TrimSpace(pathToken)
	spec := (&CodexConnector{}).HookProfile(opts).NativeOTLP
	if spec == nil {
		return nil, fmt.Errorf("codex: nil NativeOTLPSpec")
	}
	block, err := spec.TOMLBlock()
	if err != nil {
		return nil, err
	}
	return block, nil
}

func buildCodexOtelBlock(opts SetupOpts) map[string]interface{} {
	block, err := buildCodexOtelBlockWithPathToken(opts, opts.OTLPPathToken)
	if err != nil {
		return map[string]interface{}{}
	}
	return block
}

func codexNativeNotifyCommand() []string {
	return []string{defenseclawHookBinary(), "notify"}
}

func codexShellNotifyCommand(opts SetupOpts) []string {
	return []string{"bash", filepath.Join(opts.DataDir, "notify-bridge.sh")}
}

// codexNotifyLooksManaged recognizes both the current platform command and the
// legacy Bash bridge. Native matching is strict on argv shape and DefenseClaw
// executable basename so teardown never removes an unrelated user notifier
// that happens to contain the word "notify".
func codexNotifyLooksManaged(v interface{}, opts SetupOpts) bool {
	if codexValueMatches(v, codexShellNotifyCommand(opts)) {
		return true
	}
	var argv []string
	switch list := v.(type) {
	case []string:
		argv = append(argv, list...)
	case []interface{}:
		for _, raw := range list {
			s, ok := raw.(string)
			if !ok {
				return false
			}
			argv = append(argv, s)
		}
	default:
		return false
	}
	if len(argv) == 2 && argv[0] == "bash" &&
		pathidentity.Same(argv[1], filepath.Join(opts.DataDir, "notify-bridge.sh")) {
		// Older Windows releases serialized this path with either slash style.
		// Treat lexical spellings of the same bound data-root bridge alike, but
		// never claim another absolute script merely because its basename matches.
		return true
	}
	return len(argv) == 2 && argv[1] == "notify" && isDefenseClawHookExecutable(argv[0])
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

func (c *CodexConnector) restoreCodexConfig(opts SetupOpts) error {
	backup, err := c.loadConfigBackup(opts.DataDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("load config backup: %w", err)
		}
		backup = codexConfigBackup{}
	}

	configPath := codexConfigPath()
	// Teardown is also used while switching connectors and after a user has
	// removed ~/.codex. The lock file lives beside config.toml, so recreate and
	// validate that parent before attempting to open the lock. On Windows this
	// fails closed for ACL or reparse-point substitution instead of following an
	// attacker-controlled directory.
	if err := ensureCodexConfigDir(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("prepare Codex config directory for restore: %w", err)
	}
	managedBackup, err := loadManagedFileBackupForTransform(
		opts.DataDir,
		c.Name(),
		"config.toml",
		configPath,
	)
	if err != nil {
		return fmt.Errorf("load managed config backup: %w", err)
	}

	var transformed atomicTransformResult
	render := func(raw []byte, exists bool) error {
		if exact, ok := managedFileBackupTransform(managedBackup, raw, exists); ok {
			if !exact.Remove {
				cleaned, err := restoreOwnedCodexConfigFromTOML(
					exact.Data,
					true,
					backup,
					opts,
					configPath,
				)
				if err != nil {
					return fmt.Errorf("clean exact-restored Codex config: %w", err)
				}
				exact.Data = cleaned.Data
				exact.Remove = cleaned.Remove
			}
			transformed = exact
			return nil
		}
		cleaned, err := restoreOwnedCodexConfigFromTOML(raw, exists, backup, opts, configPath)
		if err != nil {
			return err
		}
		transformed = cleaned
		return nil
	}
	if err := withFileLock(configPath, func() error {
		return atomicTransformFileWithStateDir(configPath, opts.DataDir, 0o600, func(raw []byte, exists bool) (atomicTransformResult, error) {
			if err := render(raw, exists); err != nil {
				return atomicTransformResult{}, err
			}
			return transformed, nil
		})
	}); err != nil {
		return fmt.Errorf("write restored codex config: %w", err)
	}

	discardManagedFileBackup(opts.DataDir, c.Name(), "config.toml")
	return c.cleanupCodexRestoreArtifacts(opts)
}

// restoreOwnedCodexConfigFromTOML removes or restores every config.toml field
// DefenseClaw can own. Exact managed-file backups also pass through this filter:
// an older release may have captured an already-managed file as its pristine
// snapshot during upgrade. Returning raw unchanged when no owned field changes
// preserves byte-exact restoration for operator-only configurations.
func restoreOwnedCodexConfigFromTOML(
	raw []byte,
	exists bool,
	backup codexConfigBackup,
	opts SetupOpts,
	configPath string,
) (atomicTransformResult, error) {
	if !exists {
		return atomicTransformResult{Remove: true}, nil
	}
	cfg := map[string]interface{}{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			return atomicTransformResult{}, fmt.Errorf("parse codex config: %w", err)
		}
	}
	originalShape, err := json.Marshal(cfg)
	if err != nil {
		return atomicTransformResult{}, fmt.Errorf("snapshot codex config shape: %w", err)
	}

	removedOwnedHooks := false
	hookEventsRemain := false
	if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
		hooksDir := filepath.Join(opts.DataDir, "hooks")
		// Trust keys are position-aware, so inspect and remove exactly owned
		// records before filtering their corresponding handlers out of the table.
		stateRemoved, err := removeOwnedCodexHookState(hooks, configPath, hooksDir)
		if err != nil {
			return atomicTransformResult{}, fmt.Errorf("restore Codex hook trust: %w", err)
		}
		if stateRemoved {
			removedOwnedHooks = true
		}
		for eventType, val := range hooks {
			if eventType == "state" {
				continue
			}
			if _, ok := val.([]interface{}); !ok {
				return atomicTransformResult{}, fmt.Errorf("restore Codex hooks.%s: unsupported type %T", eventType, val)
			}
			before := codexHookEntryCount(val)
			remaining := removeOwnedHooks(val, hooksDir)
			if before != len(remaining) || !codexValueMatches(val, remaining) {
				removedOwnedHooks = true
			}
			if len(remaining) == 0 {
				delete(hooks, eventType)
			} else {
				hooks[eventType] = remaining
				hookEventsRemain = true
			}
		}
		if len(hooks) == 0 {
			delete(cfg, "hooks")
		} else {
			cfg["hooks"] = hooks
		}
	} else if _, present := cfg["hooks"]; present {
		return atomicTransformResult{}, fmt.Errorf("restore Codex hooks: unsupported config.toml hooks type %T", cfg["hooks"])
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

	// Restore OTel exporter entries independently. One managed sibling does not
	// make the entire [otel] table ours: an operator may have replaced another
	// exporter or added unrelated settings after Setup. Managed entries return to
	// their saved value (or are deleted if Setup added them), while current
	// operator-owned exporters/subtables survive verbatim. Ownership detection is
	// structural and never loads or mints the scoped credential.
	restoreCodexOtelEntries(cfg, backup, opts)

	managedNotify := codexNotifyLooksManaged(cfg["notify"], opts)
	if managedNotify && backup.HadNotify && len(backup.OriginalNotify) > 0 {
		var orig interface{}
		if err := json.Unmarshal(backup.OriginalNotify, &orig); err != nil {
			return atomicTransformResult{}, fmt.Errorf("restore original Codex notify config: %w", err)
		}
		// A predecessor may have captured an already-managed command as the
		// operator's original value during an upgrade. Reapplying that stale
		// registration would defeat the current snapshot filter above.
		if codexNotifyLooksManaged(orig, opts) {
			delete(cfg, "notify")
		} else {
			cfg["notify"] = orig
		}
	} else if managedNotify {
		delete(cfg, "notify")
	}

	restoredShape, err := json.Marshal(cfg)
	if err != nil {
		return atomicTransformResult{}, fmt.Errorf("snapshot restored codex config shape: %w", err)
	}
	if bytes.Equal(originalShape, restoredShape) {
		return atomicTransformResult{Data: append([]byte(nil), raw...)}, nil
	}
	if len(cfg) == 0 {
		return atomicTransformResult{Remove: true}, nil
	}
	out, err := toml.Marshal(cfg)
	if err != nil {
		return atomicTransformResult{}, fmt.Errorf("marshal restored codex config: %w", err)
	}
	return atomicTransformResult{Data: out}, nil
}

func (c *CodexConnector) cleanupCodexRestoreArtifacts(opts SetupOpts) error {
	// hooks.json is a first-class Codex hook source and may contain unrelated
	// user hooks. DefenseClaw only owns its data-dir bridge and backup files.
	if err := removeOwnedCodexHooksJSON(opts); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(opts.DataDir, "notify-bridge.sh"),
		filepath.Join(opts.DataDir, "codex_config_backup.json"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func codexHooksJSONPath() string {
	return filepath.Join(filepath.Dir(codexConfigPath()), "hooks.json")
}

func inspectCodexHooksJSON(opts SetupOpts, found func(eventType string)) error {
	raw, err := os.ReadFile(codexHooksJSONPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read Codex hooks.json: %w", err)
	}
	root := map[string]interface{}{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse Codex hooks.json: %w", err)
	}
	hooks, ok := root["hooks"].(map[string]interface{})
	if _, exists := root["hooks"]; exists && !ok {
		return fmt.Errorf("parse Codex hooks.json: hooks has unsupported type %T", root["hooks"])
	}
	hooksDir := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks"))
	for eventType, value := range hooks {
		entries, _ := value.([]interface{})
		for _, entry := range entries {
			if isOwnedHook(entry, hooksDir) {
				found(eventType)
				break
			}
		}
	}
	return nil
}

func removeOwnedCodexHooksJSON(opts SetupOpts) error {
	path := codexHooksJSONPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read Codex hooks.json: %w", err)
	}
	root := map[string]interface{}{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse Codex hooks.json: %w", err)
	}
	hooks, ok := root["hooks"].(map[string]interface{})
	if _, exists := root["hooks"]; exists && !ok {
		return fmt.Errorf("parse Codex hooks.json: hooks has unsupported type %T", root["hooks"])
	}
	hooksDir := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks"))
	changed := false
	for eventType, value := range hooks {
		before := codexHookEntryCount(value)
		remaining := removeOwnedHooks(value, hooksDir)
		if before == len(remaining) {
			continue
		}
		changed = true
		if len(remaining) == 0 {
			delete(hooks, eventType)
		} else {
			hooks[eventType] = remaining
		}
	}
	if !changed {
		return nil
	}
	if len(hooks) == 0 {
		delete(root, "hooks")
	}
	if len(root) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove empty Codex hooks.json: %w", err)
		}
		return nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal restored Codex hooks.json: %w", err)
	}
	out = append(out, '\n')
	if err := atomicWriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write restored Codex hooks.json: %w", err)
	}
	return nil
}

func codexHookEntryCount(v interface{}) int {
	list, ok := v.([]interface{})
	if !ok {
		return 0
	}
	return len(list)
}

type codexOwnedHookLocation struct {
	groupIndex   int
	handlerIndex int
	matcher      interface{}
	handler      map[string]interface{}
	currentHash  string
}

// removeOwnedCodexHooksAndState surgically removes the legacy user-scoped
// DefenseClaw matrix. State is inspected first because Codex keys trust by the
// handler's current position. Unrelated handlers, groups, state entries, and
// metadata are left byte-for-byte equivalent after TOML round-tripping.
func removeOwnedCodexHooksAndState(hooks map[string]interface{}, configPath, hooksDir string) (bool, error) {
	changed, err := removeOwnedCodexHookState(hooks, configPath, hooksDir)
	if err != nil {
		return false, err
	}
	for eventType, value := range hooks {
		if eventType == "state" {
			continue
		}
		if _, ok := value.([]interface{}); !ok {
			return false, fmt.Errorf("hooks.%s has unsupported type %T", eventType, value)
		}
		before := codexHookEntryCount(value)
		remaining := removeMatchingHookHandlers(value, func(rawHook interface{}) bool {
			return isOwnedCodexHookHandler(rawHook, hooksDir)
		})
		if before != len(remaining) || !codexValueMatches(value, remaining) {
			changed = true
		}
		if len(remaining) == 0 {
			delete(hooks, eventType)
		} else {
			hooks[eventType] = remaining
		}
	}
	return changed, nil
}

// removeOwnedCodexHooksFromTOML removes only DefenseClaw-owned handlers and
// their matching positional trust records from one Codex TOML document. The
// original bytes are returned unchanged when there is nothing to remove so an
// exact backup restore remains byte-for-byte exact for operator-only files.
//
// Setup intentionally strips legacy user-scoped registrations while moving the
// active matrix to managed_config.toml on Windows. A pristine backup captured
// before that migration may therefore contain an older DefenseClaw matrix. Any
// exact restore must apply this ownership filter before publishing the restored
// bytes or uninstall would resurrect a dangling hook.
func removeOwnedCodexHooksFromTOML(raw []byte, configPath, hooksDir string) ([]byte, bool, error) {
	cfg := map[string]interface{}{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &cfg); err != nil {
			return nil, false, fmt.Errorf("parse Codex config: %w", err)
		}
	}
	rawHooks, present := cfg["hooks"]
	if !present {
		return raw, false, nil
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("hooks has unsupported type %T", rawHooks)
	}
	changed, err := removeOwnedCodexHooksAndState(hooks, configPath, hooksDir)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return raw, false, nil
	}
	if len(hooks) == 0 {
		delete(cfg, "hooks")
	} else {
		cfg["hooks"] = hooks
	}
	if len(cfg) == 0 {
		return nil, true, nil
	}
	out, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("marshal restored Codex config: %w", err)
	}
	return out, true, nil
}

func mergeOwnedCodexHooks(
	hooks map[string]interface{},
	configPath, hookScript, hooksDir string,
	writeTrustState bool,
) error {
	if _, err := removeOwnedCodexHookState(hooks, configPath, hooksDir); err != nil {
		return fmt.Errorf("inspect existing DefenseClaw Codex hook trust: %w", err)
	}
	generatedHooks := buildCodexHooksTable(configPath, hookScript)
	for eventType, value := range hooks {
		if eventType == "state" {
			continue
		}
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("Codex hooks.%s has unsupported type %T; refusing to replace it", eventType, value)
		}
		if _, generated := generatedHooks[eventType]; generated {
			continue
		}
		remaining := removeOwnedHooks(value, hooksDir)
		if len(remaining) == 0 {
			delete(hooks, eventType)
		} else {
			hooks[eventType] = remaining
		}
	}
	for eventType, value := range generatedHooks {
		newEntries, _ := value.([]interface{})
		existing, _ := hooks[eventType].([]interface{})
		merged, err := replaceOwnedCodexHookInPlace(existing, newEntries, hooksDir)
		if err != nil {
			return fmt.Errorf("repair Codex hooks.%s: %w", eventType, err)
		}
		hooks[eventType] = merged
	}
	if writeTrustState {
		if err := trustOwnedCodexHooks(hooks, configPath, hooksDir); err != nil {
			return fmt.Errorf("trust DefenseClaw Codex hooks: %w", err)
		}
		return nil
	}
	if err := verifyManagedCodexHookMatrix(hooks, configPath, hooksDir); err != nil {
		return fmt.Errorf("verify managed DefenseClaw Codex hooks: %w", err)
	}
	return nil
}

func verifyNoOwnedCodexHooks(document map[string]interface{}, hooksDir string) error {
	rawHooks, exists := document["hooks"]
	if !exists {
		return nil
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return fmt.Errorf("hooks has unsupported type %T", rawHooks)
	}
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		locations, err := ownedCodexHookLocations(runtime.GOOS, codexHookEventKeyLabel(eventType), rawGroups, hooksDir)
		if err != nil {
			return fmt.Errorf("hooks.%s: %w", eventType, err)
		}
		if len(locations) > 0 {
			return fmt.Errorf("hooks.%s still contains %d DefenseClaw handlers", eventType, len(locations))
		}
	}
	return nil
}

// removeOwnedCodexHookState removes only a trust record whose positional key
// points at a currently present DefenseClaw handler and whose hash matches that
// handler. A state entry at the same key with an operator-edited hash is left
// untouched. This must run before the owned handlers are filtered from hooks.
// Discovery and hashing errors are returned even when hooks.state is absent:
// otherwise Setup/Teardown could silently mutate a malformed owned handler
// after failing to compute the exact positional trust identity Codex uses.
func removeOwnedCodexHookState(hooks map[string]interface{}, configPath, hooksDir string) (bool, error) {
	state, stateExists := hooks["state"].(map[string]interface{})
	if rawState, present := hooks["state"]; present && !stateExists {
		return false, fmt.Errorf("hooks.state has unsupported type %T", rawState)
	}
	removed := false
	keySource := codexHookStateKeySource(configPath)
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		eventKey := codexHookEventKeyLabel(eventType)
		locations, err := ownedCodexHookLocations(runtime.GOOS, eventKey, rawGroups, hooksDir)
		if err != nil {
			return false, fmt.Errorf("hooks.%s: %w", eventType, err)
		}
		if !stateExists {
			continue
		}
		for _, location := range locations {
			key := codexHookStateKey(keySource, eventKey, location.groupIndex, location.handlerIndex)
			entry, ok := state[key].(map[string]interface{})
			if !ok {
				continue
			}
			trustedHash, _ := entry["trusted_hash"].(string)
			legacyHash := legacyHashForOwnedCodexLocation(eventKey, location)
			if trustedHash != location.currentHash && (legacyHash == "" || trustedHash != legacyHash) {
				continue
			}
			delete(state, key)
			removed = true
		}
	}
	if stateExists && len(state) == 0 {
		delete(hooks, "state")
	} else if stateExists {
		hooks["state"] = state
	}
	return removed, nil
}

// replaceOwnedCodexHookInPlace refreshes the generated handler without moving
// its positional Codex trust identity. This matters when an operator adds a
// trusted hook after DefenseClaw: remove+append would compact the user hook into
// DefenseClaw's old slot and then collide with the user's still-valid state key.
//
// If an operator deliberately placed another handler in the same matcher group,
// preserve that handler and all group metadata. The generated matcher and owned
// handler shape are refreshed in their original slots; no unrelated group or
// handler is re-indexed.
func replaceOwnedCodexHookInPlace(existing, generated []interface{}, hooksDir string) ([]interface{}, error) {
	if len(generated) != 1 {
		return nil, fmt.Errorf("generated group count = %d, want 1", len(generated))
	}
	generatedGroup, ok := generated[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("generated group has unsupported type %T", generated[0])
	}
	generatedHandlers, ok := generatedGroup["hooks"].([]interface{})
	if !ok || len(generatedHandlers) != 1 {
		return nil, fmt.Errorf("generated handler count = %d, want 1", len(generatedHandlers))
	}

	result := make([]interface{}, 0, len(existing)+1)
	replaced := false
	for _, rawGroup := range existing {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			result = append(result, rawGroup)
			continue
		}
		handlers, ok := group["hooks"].([]interface{})
		if !ok {
			result = append(result, rawGroup)
			continue
		}
		updatedHandlers := make([]interface{}, 0, len(handlers))
		groupReplaced := false
		for _, handler := range handlers {
			if !isOwnedCodexHookHandler(handler, hooksDir) {
				updatedHandlers = append(updatedHandlers, handler)
				continue
			}
			if replaced {
				// Removing a duplicate would re-index any later user hook and
				// invalidate its positional trust state. Stop before publishing
				// any transformed bytes instead.
				return nil, fmt.Errorf("multiple DefenseClaw handlers require manual repair")
			}
			updatedHandlers = append(updatedHandlers, generatedHandlers[0])
			replaced = true
			groupReplaced = true
		}
		if groupReplaced {
			matcher, generatedMatcherPresent := generatedGroup["matcher"]
			currentMatcher, currentMatcherPresent := group["matcher"]
			if len(updatedHandlers) > 1 &&
				(currentMatcherPresent != generatedMatcherPresent || !codexValueMatches(currentMatcher, matcher)) {
				return nil, fmt.Errorf("shared DefenseClaw matcher group was edited; refusing to change unrelated handler semantics")
			}
			if generatedMatcherPresent {
				group["matcher"] = matcher
			} else {
				delete(group, "matcher")
			}
		}
		group["hooks"] = updatedHandlers
		result = append(result, group)
	}
	if !replaced {
		result = append(result, generated[0])
	}
	return result, nil
}

func legacyHashForOwnedCodexLocation(eventKey string, location codexOwnedHookLocation) string {
	async, _ := location.handler["async"].(bool)
	if async {
		return ""
	}
	command, _ := location.handler["command"].(string)
	if command == "" {
		return ""
	}
	timeout := 600
	if rawTimeout, exists := location.handler["timeout"]; exists {
		var ok bool
		timeout, ok = codexInteger(rawTimeout)
		if !ok || timeout < 0 {
			return ""
		}
	}
	return legacyCodexCommandHookHash(eventKey, location.matcher, command, timeout)
}

// isOwnedCodexHookHandler also recognizes a valid DefenseClaw command_windows
// when the generic command field is malformed. Codex requires both fields to be
// valid, but the native override still proves which product wrote the handler;
// treating it as foreign would let repair append a second handler and publish a
// configuration Codex cannot parse instead of returning the discovery error.
func isOwnedCodexHookHandler(rawHook interface{}, hooksDir string) bool {
	if isOwnedHookHandler(rawHook, hooksDir) {
		return true
	}
	handler, ok := rawHook.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"commandWindows", "command_windows"} {
		candidate, ok := handler[key].(string)
		if !ok || strings.TrimSpace(candidate) == "" {
			continue
		}
		if isOwnedHookHandler(map[string]interface{}{"command": candidate}, hooksDir) {
			return true
		}
	}
	return false
}

func ownedCodexHookLocations(
	goos string,
	eventKey string,
	rawGroups interface{},
	hooksDir string,
) ([]codexOwnedHookLocation, error) {
	groups, ok := rawGroups.([]interface{})
	if !ok {
		return nil, fmt.Errorf("event groups have unsupported type %T", rawGroups)
	}
	locations := make([]codexOwnedHookLocation, 0, 1)
	for groupIndex, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			continue
		}
		matcher := group["matcher"]
		handlers, ok := group["hooks"].([]interface{})
		if !ok {
			continue
		}
		for handlerIndex, rawHandler := range handlers {
			if !isOwnedCodexHookHandler(rawHandler, hooksDir) {
				continue
			}
			handler, ok := rawHandler.(map[string]interface{})
			if !ok {
				continue
			}
			currentHash, err := codexCommandHookHashForPlatform(goos, eventKey, matcher, handler)
			if err != nil {
				return nil, fmt.Errorf("hash owned handler %d:%d: %w", groupIndex, handlerIndex, err)
			}
			locations = append(locations, codexOwnedHookLocation{
				groupIndex:   groupIndex,
				handlerIndex: handlerIndex,
				matcher:      matcher,
				handler:      handler,
				currentHash:  currentHash,
			})
		}
	}
	return locations, nil
}

// trustOwnedCodexHooks records setup's explicit consent for every required
// DefenseClaw handler after it has been merged with unrelated hooks. Positional
// keys are derived from the final table. A colliding state record is overwritten
// only when its hash already proves that it belongs to the exact handler at that
// position; otherwise setup fails without touching the file.
func trustOwnedCodexHooks(hooks map[string]interface{}, configPath, hooksDir string) error {
	state, exists := hooks["state"].(map[string]interface{})
	if rawState, present := hooks["state"]; present && !exists {
		return fmt.Errorf("hooks.state has unsupported type %T", rawState)
	}
	if !exists {
		state = map[string]interface{}{}
	}
	keySource := codexHookStateKeySource(configPath)
	for _, expected := range codexHookGroups {
		eventKey := codexHookEventKeyLabel(expected.eventType)
		locations, err := ownedCodexHookLocations(runtime.GOOS, eventKey, hooks[expected.eventType], hooksDir)
		if err != nil {
			return fmt.Errorf("%s: %w", expected.eventType, err)
		}
		if len(locations) != 1 {
			return fmt.Errorf("%s has %d DefenseClaw handlers, want 1", expected.eventType, len(locations))
		}
		location := locations[0]
		key := codexHookStateKey(keySource, eventKey, location.groupIndex, location.handlerIndex)
		if rawEntry, collision := state[key]; collision {
			entry, ok := rawEntry.(map[string]interface{})
			trustedHash, _ := entry["trusted_hash"].(string)
			if !ok || trustedHash != location.currentHash {
				return fmt.Errorf("state key %q belongs to another hook; refusing to overwrite it", key)
			}
		}
		state[key] = map[string]interface{}{"trusted_hash": location.currentHash}
	}
	hooks["state"] = state
	return verifyTrustedCodexHookMatrix(hooks, configPath, hooksDir)
}

// verifyTrustedCodexHookMatrix applies Codex's discovery/hash contract to the
// complete required event matrix. It verifies exact commands (including the
// native Windows override and generic fallback), synchronous execution,
// matcher, timeout, positional key, enabled state, and trusted hash.
func verifyTrustedCodexHookMatrix(hooks map[string]interface{}, configPath, hooksDir string) error {
	return verifyCodexHookMatrix(hooks, configPath, hooksDir, true)
}

// verifyManagedCodexHookMatrix verifies the same complete synchronous matrix
// without private hooks.state data. Codex trusts handlers from
// managed_config.toml by source, including when allow_managed_hooks_only is
// enabled, so no per-user approval record is either needed or supported.
func verifyManagedCodexHookMatrix(hooks map[string]interface{}, configPath, hooksDir string) error {
	return verifyCodexHookMatrix(hooks, configPath, hooksDir, false)
}

func verifyCodexHookMatrix(hooks map[string]interface{}, configPath, hooksDir string, requireTrustState bool) error {
	var state map[string]interface{}
	if requireTrustState {
		var ok bool
		state, ok = hooks["state"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("hooks.state has unsupported type %T", hooks["state"])
		}
	}
	keySource := codexHookStateKeySource(configPath)
	expectedTable := buildCodexHooksTable(configPath, filepath.ToSlash(filepath.Join(hooksDir, "codex-hook.sh")))
	expectedEvents := make(map[string]struct{}, len(codexHookGroups))
	for _, expected := range codexHookGroups {
		expectedEvents[expected.eventType] = struct{}{}
		eventKey := codexHookEventKeyLabel(expected.eventType)
		locations, err := ownedCodexHookLocations(runtime.GOOS, eventKey, hooks[expected.eventType], hooksDir)
		if err != nil {
			return fmt.Errorf("%s: %w", expected.eventType, err)
		}
		if len(locations) != 1 {
			return fmt.Errorf("%s has %d DefenseClaw handlers, want 1", expected.eventType, len(locations))
		}
		location := locations[0]
		expectedGroups := expectedTable[expected.eventType].([]interface{})
		expectedGroup := expectedGroups[0].(map[string]interface{})
		expectedHandlers := expectedGroup["hooks"].([]interface{})
		expectedHandler := expectedHandlers[0].(map[string]interface{})
		if err := verifyCodexOwnedHandlerShape(location, expectedGroup, expectedHandler); err != nil {
			return fmt.Errorf("%s: %w", expected.eventType, err)
		}
		if requireTrustState {
			key := codexHookStateKey(keySource, eventKey, location.groupIndex, location.handlerIndex)
			entry, ok := state[key].(map[string]interface{})
			if !ok {
				return fmt.Errorf("%s trust state %q is missing or malformed", expected.eventType, key)
			}
			if enabled, _ := entry["enabled"].(bool); entry["enabled"] != nil && !enabled {
				return fmt.Errorf("%s trust state %q is disabled", expected.eventType, key)
			}
			if trustedHash, _ := entry["trusted_hash"].(string); trustedHash != location.currentHash {
				return fmt.Errorf("%s trust state %q is not trusted", expected.eventType, key)
			}
		}
	}
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		if _, expected := expectedEvents[eventType]; expected {
			continue
		}
		locations, err := ownedCodexHookLocations(runtime.GOOS, codexHookEventKeyLabel(eventType), rawGroups, hooksDir)
		if err != nil {
			return fmt.Errorf("%s: %w", eventType, err)
		}
		if len(locations) > 0 {
			return fmt.Errorf("unexpected event %s has %d DefenseClaw handlers", eventType, len(locations))
		}
	}
	return nil
}

func verifyCodexOwnedHandlerShape(
	location codexOwnedHookLocation,
	expectedGroup map[string]interface{},
	expectedHandler map[string]interface{},
) error {
	if !codexValueMatches(location.matcher, expectedGroup["matcher"]) {
		return fmt.Errorf("matcher = %#v, want %#v", location.matcher, expectedGroup["matcher"])
	}
	for _, key := range []string{"type", "command", "command_windows"} {
		if !codexValueMatches(location.handler[key], expectedHandler[key]) {
			return fmt.Errorf("%s = %#v, want %#v", key, location.handler[key], expectedHandler[key])
		}
	}
	timeout, ok := codexInteger(location.handler["timeout"])
	if !ok {
		return fmt.Errorf("timeout has unsupported type %T", location.handler["timeout"])
	}
	expectedTimeout, _ := codexInteger(expectedHandler["timeout"])
	if timeout != expectedTimeout {
		return fmt.Errorf("timeout = %d, want %d", timeout, expectedTimeout)
	}
	if async, _ := location.handler["async"].(bool); async {
		return fmt.Errorf("async handler cannot enforce DefenseClaw policy")
	}
	if status, exists := location.handler["statusMessage"]; exists && status != nil {
		return fmt.Errorf("unexpected statusMessage %#v", status)
	}
	return nil
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

var codexOtelExporterKeys = [...]string{"exporter", "trace_exporter", "metrics_exporter"}

func restoreCodexOtelEntries(cfg map[string]interface{}, backup codexConfigBackup, opts SetupOpts) {
	current, ok := cfg["otel"].(map[string]interface{})
	if !ok {
		// A missing or non-table value is a current operator edit. It cannot
		// contain one of our exporter endpoints, so preserve it.
		return
	}

	var originalValue interface{}
	originalDecoded := false
	original := map[string]interface{}(nil)
	if backup.HadOtelBlock && len(backup.OriginalOtel) > 0 {
		if err := json.Unmarshal(backup.OriginalOtel, &originalValue); err == nil {
			originalDecoded = true
			original, _ = originalValue.(map[string]interface{})
		}
	}

	// TOML normally decodes [otel] as a map. Preserve a legacy scalar original
	// when the current table is still entirely Setup-owned; if the operator added
	// anything, their current table wins and only managed entries are removed.
	if originalDecoded && original == nil && codexOtelTableIsEntirelyManaged(current, opts) {
		cfg["otel"] = originalValue
		return
	}

	for _, key := range codexOtelExporterKeys {
		value, exists := current[key]
		if !exists {
			continue
		}
		var saved interface{}
		hadSaved := false
		if original != nil {
			saved, hadSaved = original[key]
		}
		if !codexExporterLooksManaged(value, opts) {
			// Endpoint drift can make an exporter operator-owned while leaving the
			// exact pair of DefenseClaw header markers Setup wrote. In that case,
			// preserve the endpoint, protocol, and unrelated headers, and restore or
			// remove only the three header entries proven by the paired markers.
			// A single marker is deliberately not mutation authority; VerifyClean
			// reports it as residue so uninstall remains fail-closed.
			if codexExporterHasManagedHeaderPair(value) {
				restoreCodexOwnedExporterHeaders(value, saved, hadSaved)
			}
			continue
		}
		if original != nil {
			if hadSaved {
				// Field-level backups from older releases may themselves be
				// contaminated by a prior managed setup. Product-namespaced header
				// keys remain residue even when a predecessor wrote an obsolete
				// endpoint or marker value that no longer satisfies the full
				// current ownership predicate.
				if !codexExporterLooksManaged(saved, opts) &&
					!codexExporterHasManagedHeaderResidue(saved) {
					current[key] = saved
					continue
				}
			}
		}
		delete(current, key)
	}

	// Setup owns log_user_prompt only while it retains the value Setup wrote.
	// A current false/non-boolean value is an operator edit and must survive.
	if value, exists := current["log_user_prompt"]; exists && value == true {
		if original != nil {
			if saved, hadSaved := original["log_user_prompt"]; hadSaved {
				current["log_user_prompt"] = saved
			} else {
				delete(current, "log_user_prompt")
			}
		} else {
			delete(current, "log_user_prompt")
		}
	}

	// Setup replaced the original [otel] table wholesale. Re-add displaced
	// unrelated original keys, but never overwrite a current operator edit.
	for key, saved := range original {
		if key == "log_user_prompt" || codexOtelExporterKey(key) {
			continue
		}
		if _, exists := current[key]; !exists {
			current[key] = saved
		}
	}

	if len(current) == 0 {
		delete(cfg, "otel")
	} else {
		cfg["otel"] = current
	}
}

func codexOtelExporterKey(key string) bool {
	switch key {
	case "exporter", "trace_exporter", "metrics_exporter":
		return true
	default:
		return false
	}
}

func codexOtelTableIsEntirelyManaged(current map[string]interface{}, opts SetupOpts) bool {
	if len(current) == 0 {
		return false
	}
	sawManagedExporter := false
	for key, value := range current {
		switch key {
		case "log_user_prompt":
			if value != true {
				return false
			}
		case "exporter", "trace_exporter", "metrics_exporter":
			if !codexExporterLooksManaged(value, opts) {
				return false
			}
			sawManagedExporter = true
		default:
			return false
		}
	}
	return sawManagedExporter
}

func codexOtelBlockLooksManaged(v interface{}, opts SetupOpts) bool {
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range codexOtelExporterKeys {
		if codexExporterLooksManaged(m[key], opts) {
			return true
		}
	}
	return false
}

func codexOtelResidueFields(v interface{}, opts SetupOpts) []string {
	otel, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	var residual []string
	for _, key := range codexOtelExporterKeys {
		exporter := otel[key]
		if codexExporterLooksManaged(exporter, opts) {
			residual = append(residual, fmt.Sprintf("config.toml otel.%s.otlp-http.endpoint retains DefenseClaw exporter", key))
		}
		if !codexExporterHasManagedHeaderResidue(exporter) {
			continue
		}
		headers := codexExporterHeaders(exporter)
		if _, exists := headers["x-defenseclaw-source"]; exists {
			residual = append(residual, fmt.Sprintf("config.toml otel.%s.otlp-http.headers.x-defenseclaw-source retains DefenseClaw marker", key))
		}
		if _, exists := headers["x-defenseclaw-client"]; exists {
			residual = append(residual, fmt.Sprintf("config.toml otel.%s.otlp-http.headers.x-defenseclaw-client retains DefenseClaw marker", key))
		}
	}
	if len(residual) > 0 {
		residual = append([]string{"config.toml [otel] still contains DefenseClaw-owned fields"}, residual...)
	}
	return residual
}

func codexExporterHeaders(v interface{}) map[string]interface{} {
	exporter, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	otlpHTTP, ok := exporter["otlp-http"].(map[string]interface{})
	if !ok {
		return nil
	}
	headers, _ := otlpHTTP["headers"].(map[string]interface{})
	return headers
}

func codexExporterHasManagedHeaderResidue(v interface{}) bool {
	headers := codexExporterHeaders(v)
	if headers == nil {
		return false
	}
	_, hasSource := headers["x-defenseclaw-source"]
	_, hasClient := headers["x-defenseclaw-client"]
	return hasSource || hasClient
}

func codexExporterHasManagedHeaderPair(v interface{}) bool {
	headers := codexExporterHeaders(v)
	if headers == nil {
		return false
	}
	_, hasSource := headers["x-defenseclaw-source"]
	_, hasClient := headers["x-defenseclaw-client"]
	return hasSource && hasClient
}

func restoreCodexOwnedExporterHeaders(current, saved interface{}, hadSaved bool) {
	headers := codexExporterHeaders(current)
	if headers == nil || !codexExporterHasManagedHeaderPair(current) {
		return
	}
	delete(headers, "x-defenseclaw-source")
	delete(headers, "x-defenseclaw-client")

	// The product-namespaced pair above is ownership authority and must never
	// survive cleanup. Authorization is generic, so restore it only from a
	// saved exporter that was not itself a stale managed snapshot.
	savedHeaders := map[string]interface{}(nil)
	if hadSaved && !codexExporterHasManagedHeaderResidue(saved) {
		savedHeaders = codexExporterHeaders(saved)
	}
	if value, exists := savedHeaders["authorization"]; exists {
		headers["authorization"] = value
	} else {
		delete(headers, "authorization")
	}
	exporter := current.(map[string]interface{})
	otlpHTTP := exporter["otlp-http"].(map[string]interface{})
	if len(headers) == 0 {
		delete(otlpHTTP, "headers")
	} else {
		otlpHTTP["headers"] = headers
	}
}

func codexExporterLooksManaged(v interface{}, opts SetupOpts) bool {
	exporter, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	otlpHTTP, ok := exporter["otlp-http"].(map[string]interface{})
	if !ok {
		return false
	}
	endpoint, _ := otlpHTTP["endpoint"].(string)
	if codexScopedOTLPEndpointLooksManaged(endpoint) {
		return true
	}
	headers, _ := otlpHTTP["headers"].(map[string]interface{})
	if headers == nil {
		return false
	}
	sourceMarker := headers["x-defenseclaw-source"] == "codex"
	clientMarker := headers["x-defenseclaw-client"] == "codex-otel/1.0"
	directBase := "http://" + strings.TrimSpace(opts.APIAddr) + "/v1/"
	if endpoint == directBase+"logs" || endpoint == directBase+"traces" || endpoint == directBase+"metrics" {
		return sourceMarker || clientMarker
	}
	// Older releases used the unscoped /v1/<signal> receiver. A later
	// operator change to gateway.api_port must not strand that registration,
	// but port-independent ownership is deliberately stronger: require the
	// exact pair of product markers and a strict loopback OTLP URL.
	return sourceMarker && clientMarker && codexLegacyDirectOTLPEndpointLooksManaged(endpoint)
}

func codexScopedOTLPEndpointLooksManaged(endpoint string) bool {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	// The random connector-scoped path and the loopback-only authority are the
	// durable ownership boundary. The API port is mutable configuration, so it
	// cannot be part of teardown identity. Requiring an explicit port avoids
	// claiming a generic local HTTP path that the product never emits.
	if !codexLoopbackOTLPAuthorityLooksManaged(parsed) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "otlp" || parts[1] != "codex" || parts[3] != "v1" || !otlpTokenHexRE.MatchString(parts[2]) {
		return false
	}
	switch parts[4] {
	case "logs", "metrics", "traces":
		return true
	default:
		return false
	}
}

func codexLegacyDirectOTLPEndpointLooksManaged(endpoint string) bool {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	if !codexLoopbackOTLPAuthorityLooksManaged(parsed) {
		return false
	}
	switch parsed.Path {
	case "/v1/logs", "/v1/metrics", "/v1/traces":
		return true
	default:
		return false
	}
}

func codexLoopbackOTLPAuthorityLooksManaged(parsed *url.URL) bool {
	if parsed == nil || !codexLoopbackHost(parsed.Hostname()) {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port > 0 && port <= 65535
}

func codexLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func codexConfigHasManagedOTLPEndpoint(configPath string, opts SetupOpts) (bool, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return false, err
	}
	return codexOtelBlockLooksManaged(cfg["otel"], opts), nil
}
