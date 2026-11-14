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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// In-image Claude Code system policy (Linux managed tier).
const (
	claudeCodeSandboxManagedRoot    = "/etc/claude-code"
	claudeCodeSandboxDropInName     = "50-defenseclaw.json"
	claudeCodeSandboxOtelHelperPath = SandboxLibDir + "/otel-headers.sh"
)

// ClaudeCodeSandboxDropInPath is where the managed hook drop-in lands.
const ClaudeCodeSandboxDropInPath = claudeCodeSandboxManagedRoot + "/managed-settings.d/" + claudeCodeSandboxDropInName

// claudeCodeSandboxStartupEnv must be real process environment: Claude
// applies managed-settings env too late for startup traffic (autoupdater,
// marketplace clone, feature-flag fetches), and OpenShell does not propagate
// image ENV, so these travel through sandbox create --env as well.
//
// The image pins Claude Code, so it neither updates itself nor tells the
// user how to: DISABLE_UPDATES makes `claude update` say updates are managed,
// and DISABLE_INSTALLATION_CHECKS drops the native-installer checks (a
// ~/.local/bin/claude link, the installMethod in ~/.claude.json) that the
// pinned binary never satisfies. The in-image launcher puts ~/.local/bin
// on PATH for the one check that ignores it.
//
// CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG=1 (2.1.311) treats the user's own
// Claude Code files (~/.claude, which the workload can write) as untrusted.
// Claude reads it from the environment it started with, before any settings
// apply, so no settings file can turn it off. It is what keeps a user
// settings processWrapper from taking effect: that key names a launcher
// Claude starts its background service, sessions and workers through,
// outside any tool call and so unseen by PreToolUse, and a managed
// processWrapper or CLAUDE_CODE_PROCESS_WRAPPER of "" does not outrank it
// (Claude skips an empty managed value; measured on 2.1.311, rel-1-0-10
// TST-1230). With the flag Claude also ignores CLAUDE_CODE_PLUGIN_DIRS,
// CLAUDE_CODE_PLUGIN_DIR_WATCH and CLAUDE_CODE_PROCESS_WRAPPER in the user
// settings env block, stops a plugin folder placed directly in the personal
// skills directory (~/.claude/skills/NAME) from loading as a plugin (its
// skills still load; marketplace plugins at user, project and local scope
// still load: measured on 2.1.311, rel-1-0-10 GAP-0279), ignores allowed-tools in
// the user's own skills and commands, lets the user's own agents neither
// widen their permission mode nor add MCP servers, refuses cloud subagents,
// and refuses every prompt while ~/.claude/settings.json has errors (it
// names the file). Managed settings, the hooks, the OTLP export and the
// endpoint pins are unchanged (the hook-fire probe and the run-config probe
// pass with it).
var claudeCodeSandboxStartupEnv = map[string]string{
	"DISABLE_AUTOUPDATER":                                  "1",
	"DISABLE_UPDATES":                                      "1",
	"DISABLE_INSTALLATION_CHECKS":                          "1",
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":             "1",
	"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
	"CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG":                 "1",
}

// claudeCodeSandboxPinnedEnv are managed-env values that project or user
// settings cannot override. Claude Code (2.1.x) reads an empty value as
// unset for every variable pinned to "".
//
//   - CLAUDE_CODE_SIMPLE=0 keeps hooks active when the agent requests
//     Claude's simple/bare mode.
//   - CLAUDE_CODE_SHELL_PREFIX names a program Claude runs every shell-form
//     hook command, Bash tool command and stdio MCP server launch through,
//     in place of the command itself. Set from a settings file (the
//     workload-writable ~/.claude/settings.json, or a repository's committed
//     .claude/settings.json under the pre-trusted /work) it would replace
//     every DefenseClaw hook even with allowManagedHooksOnly on.
//   - CLAUDE_CODE_SHELL, then SHELL when it names an executable bash or zsh,
//     choose the shell that runs each Bash tool command after PreToolUse
//     approved its text. Hooks are started through /bin/sh and never read
//     them, but unpinned they would let a settings file hand every approved
//     command to a program of its choosing.
//   - CLAUDE_CODE_STOP_HOOK_BLOCK_CAP and
//     CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS keep Claude's defaults (eight
//     consecutive Stop blocks honoured; a SessionEnd budget taken from the
//     managed hook timeouts), so settings cannot cut DefenseClaw's Stop
//     verdicts or its SessionEnd audit short. DISABLE_BRIEF_MODE_STOP_HOOK
//     only switches Claude's built-in brief-mode reminder and stays unpinned.
//   - The loader and shell-startup variables act before the first line of a
//     hook runs (when the dynamic loader starts bash, or when Claude's
//     spawning shell starts).
//
// Every other inherited variable, PATH and PYTHONPATH included, is dropped
// by the hook itself (_sandbox.sh) before it starts a child process. PATH
// and PYTHONPATH stay unpinned because the same env block shapes the agent's
// own tool processes, where projects set them legitimately. The image
// build's hook-fire probe plants the mode, shell and shell-startup variables
// above, and PATH, in user and project settings, and fails the image when a
// hook no longer fires or a planted program runs.
//
// Model provider selection (claudeCodeSandboxProviderEnv: the provider
// switches, base URLs, bearer and custom headers) is deliberately not pinned
// in this static image. Managed env outranks the process environment, so a
// pin here would override the provider each run passes with sandbox create
// --env and break every non-default endpoint: Bedrock Mantle through
// ANTHROPIC_BASE_URL, mock servers and custom gateways. It is pinned per run
// instead, by the sandbox manager's read-only 60-defenseclaw-run.json drop-in
// (SandboxRunFiles), which carries the provider env that run chose, so a
// repository's committed settings cannot point the conversation elsewhere.
var claudeCodeSandboxPinnedEnv = map[string]string{
	"CLAUDE_CODE_SIMPLE":                      "0",
	"CLAUDE_CODE_SHELL_PREFIX":                "",
	"CLAUDE_CODE_SHELL":                       "",
	"SHELL":                                   "/bin/bash",
	"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP":         "",
	"CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS": "",
	"LD_PRELOAD":                              "",
	"LD_LIBRARY_PATH":                         "",
	"LD_AUDIT":                                "",
	"BASH_ENV":                                "",
	"ENV":                                     "",
	// New in 2.1.311 and personal-config sensitive (with
	// CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG Claude ignores them in the user
	// settings env block). Each is pinned too, for a claude started without
	// the startup environment:
	//
	//   - CLAUDE_CODE_PLUGIN_DIRS names folders that are each a plugin root,
	//     loaded as --plugin-dir loads one: its skills, agents, commands,
	//     hooks and MCP servers. Set in the user settings env block, Claude
	//     loads the plugin and starts its MCP server (measured; Claude does
	//     not read it from a project's settings).
	//   - CLAUDE_CODE_PROCESS_WRAPPER names the launcher Claude starts its
	//     background service, sessions and workers through. This pin stops
	//     it in a settings env block; the processWrapper settings key is
	//     stopped by CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG alone (see
	//     claudeCodeSandboxStartupEnv).
	//   - CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER switches on proxyAuthHelper,
	//     a command Claude runs at startup, with no tool call, to print a
	//     Proxy-Authorization header for the HTTPS_PROXY that OpenShell
	//     sends sandbox egress through. A user settings file can name the
	//     helper and switch it on in its env block. The helper key itself
	//     stays unpinned: "" there is a value Claude keeps, and the sandbox
	//     proxy takes no credentials from Claude.
	"CLAUDE_CODE_PLUGIN_DIRS":              "",
	"CLAUDE_CODE_PROCESS_WRAPPER":          "",
	"CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER": "",
}

// claudeCodeSandboxServiceEndpointEnv are the settings-env variables that
// move one of Claude Code's own non-model services to another host: the
// artifacts and memory APIs (and their tokens), the Remote Control bridge,
// the remote tools bridge and session ingress, the feature-flag server
// (CLAUDE_CODE_GB_BASE_URL), voice streaming, the remote runner API, the
// per-signal OpenTelemetry endpoints (which outrank the
// OTEL_EXPORTER_OTLP_ENDPOINT the drop-in points at the ingress) and the
// internal metrics, tracing and OTLP endpoints. A sandbox run sets none of
// them, so the drop-in pins each one to "" (unset); a per-signal OTLP
// endpoint the native OTLP spec already points at the ingress keeps that
// value, which pins it just as well. Either way a repository's
// committed settings cannot send conversation content, credentials or
// telemetry to a host of its choosing, or flip Claude's feature flags,
// without a tool call. Measured on 2.1.311: its kns list (the service base
// URLs), its Ga and tr lists (artifacts, memory), the model catalog URL
// (model metadata, also a file: URL) and the OTLP per-signal names, which
// 2.1.156 did not read.
var claudeCodeSandboxServiceEndpointEnv = []string{
	"ANT_CLAUDE_CODE_METRICS_ENDPOINT",
	"ANT_OTEL_EXPORTER_OTLP_ENDPOINT",
	"ANT_OTEL_EXPORTER_OTLP_HEADERS",
	"BETA_TRACING_ENDPOINT",
	"CLAUDE_BRIDGE_BASE_URL",
	"CLAUDE_BRIDGE_SESSION_INGRESS_URL",
	"CLAUDE_CODE_ARTIFACTS_API_BASE_URL",
	"CLAUDE_CODE_ARTIFACTS_API_TOKEN",
	"CLAUDE_CODE_ARTIFACT_ASSET_BASE_URL",
	"CLAUDE_CODE_ARTIFACT_LIVE_BASE_URL",
	"CLAUDE_CODE_ARTIFACT_SYNC_BASE_URL",
	"CLAUDE_CODE_ARTIFACT_VIEWER_BASE_URL",
	"CLAUDE_CODE_GB_BASE_URL",
	"CLAUDE_CODE_MEMORY_API_BASE_URL",
	"CLAUDE_CODE_MEMORY_API_TOKEN",
	"CLAUDE_CODE_MODEL_CATALOG_URL",
	"CLAUDE_REMOTE_TOOLS_BRIDGE_URL",
	"CLAUDE_RUNNER_API_BASE_URL",
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_PROFILES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"SESSION_INGRESS_URL",
	"VOICE_STREAM_BASE_URL",
}

// claudeCodeSandboxPinnedHelpers name programs Claude runs by itself, outside
// any tool call and so unseen by PreToolUse, when a settings file sets them;
// the drop-in pins each to "" (p2-render-4). In the 2.1.311 settings schema
// each is an optional string, read from the merged settings, where the
// managed tier outranks user and project values, and run only when non-empty:
// apiKeyHelper prints the API key, awsCredentialExport and awsAuthRefresh run
// for Bedrock and gcpAuthRefresh for Vertex, providers a settings file can
// select through its env block. DefenseClaw passes credentials as OpenShell
// placeholders and never uses them (apiKeyHelper would also add a second auth
// header, which Bedrock Mantle rejects).
//
// inferenceCredentialHelper is not pinned: in 2.1.311 it is a field of Claude
// Desktop's third-party managed configuration (scope 3p, which Desktop hands
// to the Claude Code it starts), not a Claude Code settings key, and a
// ~/.claude/settings.json that names one is not run (measured with the pin
// removed; an apiKeyHelper planted the same way runs).
var claudeCodeSandboxPinnedHelpers = []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh"}

// SandboxArtifacts renders the Claude Code overlay: sandbox hook scripts,
// the managed-settings.d drop-in (hooks, allowManagedHooksOnly, OTLP to the
// ingress through otelHeadersHelper, pinned env and auth helpers), the
// helper itself and the pre-seeded ~/.claude.json that skips first-run
// prompts.
func (c *ClaudeCodeConnector) SandboxArtifacts(target SandboxRenderTarget) (SandboxArtifacts, error) {
	rt, err := resolveSandboxTarget(c.Name(), target)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	hookFiles, err := renderSandboxHookFiles(c.Name(), rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	dropIn, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyClaudeCodeSandboxDropIn(dropIn, rt); err != nil {
		return SandboxArtifacts{}, err
	}
	preseed, err := renderClaudeCodeSandboxPreseed()
	if err != nil {
		return SandboxArtifacts{}, err
	}

	files := append(hookFiles,
		SandboxFile{Path: ClaudeCodeSandboxDropInPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: dropIn},
		SandboxFile{Path: claudeCodeSandboxOtelHelperPath, Mode: 0o755, Owner: SandboxOwnerRoot, Data: []byte(claudeCodeOtelHelperFor(rt))},
		SandboxFile{Path: path.Join(SandboxHomeDir, ".claude.json"), Mode: 0o600, Owner: SandboxOwnerUser, Data: preseed},
	)
	env := make(map[string]string, len(claudeCodeSandboxStartupEnv))
	for key, value := range claudeCodeSandboxStartupEnv {
		env[key] = value
	}
	binaries := append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "claude", Role: SandboxBinaryHarness})
	return finalizeSandboxArtifactsFor(rt, SandboxArtifacts{
		Connector:    c.Name(),
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files:        files,
		Env:          env,
		Binaries:     binaries,
	})
}

// renderClaudeCodeSandboxDropIn renders the managed-settings.d drop-in.
// Claude silently drops a whole drop-in that carries one schema-invalid
// field, so the document holds only keys verified against Claude Code 2.1.x
// and the image build's hook-fire probe proves the hooks actually run.
//
// Claude's own bubblewrap sandbox is pinned off (sandbox.enabled, a boolean
// in the 2.1.311 settings schema): it cannot nest inside OpenShell, and a
// project or user setting that enabled it, with sandbox.failIfUnavailable,
// would stop the harness at startup. The hook-fire probe plants exactly
// that in its hostile user and project settings.
//
// The auth helpers in claudeCodeSandboxPinnedHelpers are pinned to "". Two
// other command-running settings are left out on purpose:
//
//   - statusLine (like fileSuggestion and subagentStatusLine) is an object,
//     {"type": "command", "command": ...}, so a string there would drop this
//     whole drop-in. It needs no pin: with allowManagedHooksOnly on, Claude
//     reads all three from managed settings only.
//   - enableAllProjectMcpServers false would not stop a trusted project's
//     .mcp.json stdio servers: Claude approves every one of them when it runs
//     non-interactively or when skipDangerousModePermissionPrompt is set in
//     any tier (as here), and a project's own enabledMcpjsonServers list
//     merges past any managed value. Those servers start without a
//     PreToolUse. The per-run managed configuration closes them (pack key
//     mcp.project_servers: block): managed-mcp.json, Claude's exclusive MCP
//     mode, plus allowManagedMcpServersOnly and allowedMcpServers.
func renderClaudeCodeSandboxDropIn(rt resolvedSandboxTarget) ([]byte, error) {
	return renderClaudeCodeSandboxDropInWithHook(rt, path.Join(SandboxHookDir, "claude-code-hook.sh"), nil)
}

// renderClaudeCodeSandboxRunHookDropIn replaces the image's managed hook
// file for each run, including runs based on an already verified overlay.
func renderClaudeCodeSandboxRunHookDropIn(rt resolvedSandboxTarget) ([]byte, error) {
	hookCommand, hookArgs := claudeCodeSandboxHookInvocation()
	return renderClaudeCodeSandboxDropInWithHook(rt, hookCommand, hookArgs)
}

func renderClaudeCodeSandboxDropInWithHook(rt resolvedSandboxTarget, hookCommand string, hookArgs []string) ([]byte, error) {
	hooks, err := renderClaudeCodeManagedHookMatrix(hookCommand, hookArgs, rt.opts)
	if err != nil {
		return nil, err
	}
	env, err := claudeCodeSandboxManagedEnv(rt)
	if err != nil {
		return nil, err
	}
	policy := map[string]interface{}{
		"allowManagedHooksOnly":             true,
		"skipDangerousModePermissionPrompt": true,
		"otelHeadersHelper":                 claudeCodeSandboxOtelHelperPath,
		"hooks":                             hooks,
		"env":                               env,
		"sandbox":                           map[string]interface{}{"enabled": false},
	}
	for _, key := range claudeCodeSandboxPinnedHelpers {
		policy[key] = ""
	}
	body, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Claude Code sandbox managed settings: %w", err)
	}
	return append(body, '\n'), nil
}

// claudeCodeSandboxHookInvocation starts the managed hook through Bash's
// privileged mode. Claude Code runs handlers with args directly, so the
// inherited shell settings cannot change whether the hook command starts.
// The fixed command also turns a missing image hook into a blocking result.
func claudeCodeSandboxHookInvocation() (string, []string) {
	hookPath := path.Join(SandboxHookDir, "claude-code-hook.sh")
	const missingHook = "DefenseClaw blocked this: its sandbox hook could not start. Rebuild the sandbox image and retry."
	return "/bin/bash", []string{"-p", "-c", claudeCodeMissingHookGuardWith(hookPath, missingHook)}
}

// claudeCodeSandboxManagedEnv reuses the connector's native OTLP spec with the
// ingress as endpoint. Its Authorization header cannot be static (the token
// placeholder is revision-scoped), so the spec carries no headers and the
// otelHeadersHelper supplies them per export. Content-capture gates stay
// pinned off exactly as on the host.
func claudeCodeSandboxManagedEnv(rt resolvedSandboxTarget) (map[string]string, error) {
	spec := (&ClaudeCodeConnector{}).HookProfile(SetupOpts{APIAddr: rt.ingressAddr, sandboxNativeOTLP: true}).NativeOTLP
	if spec == nil {
		return nil, fmt.Errorf("claudecode: nil NativeOTLPSpec")
	}
	sandboxSpec := *spec
	sandboxSpec.Headers = nil
	extra := make(map[string]string, len(spec.ExtraEnv))
	for key, value := range spec.ExtraEnv {
		// The sandbox hooks bake their fail mode and never read this.
		if key == "DEFENSECLAW_FAIL_MODE" {
			continue
		}
		extra[key] = value
	}
	sandboxSpec.ExtraEnv = extra
	env, err := sandboxSpec.EnvBlock()
	if err != nil {
		return nil, fmt.Errorf("render Claude Code sandbox OTLP env: %w", err)
	}
	for key, value := range env {
		env[key] = rt.substrateOTLPEndpoint(value)
	}
	for key, value := range claudeCodeSandboxStartupEnv {
		env[key] = value
	}
	for key, value := range claudeCodeSandboxPinnedEnv {
		env[key] = value
	}
	for _, key := range claudeCodeSandboxServiceEndpointEnv {
		if _, set := env[key]; set {
			if claudeCodeOTLPEndpointKey(key) {
				continue
			}
			return nil, fmt.Errorf("claudecode: the sandbox OTLP env already sets %s, which the drop-in pins unset", key)
		}
		env[key] = ""
	}
	return env, nil
}

// verifyClaudeCodeSandboxDropIn lays the drop-in out under a scratch managed
// root and runs Claude's file-tier reader and DefenseClaw's managed-hook
// verifiers against it, so the image never ships a policy the guardian would
// reject.
func verifyClaudeCodeSandboxDropIn(dropIn []byte, rt resolvedSandboxTarget) error {
	source, err := stageClaudeCodeManagedSettings(map[string][]byte{claudeCodeSandboxDropInName: dropIn})
	if err != nil {
		return err
	}
	return verifyClaudeCodeSandboxManagedSource(source, rt)
}

// stageClaudeCodeManagedSettings writes dropIns (file name → content) into a
// scratch managed-settings.d and returns what Claude's file-tier reader
// merges from them, in Claude's sorted drop-in order.
func stageClaudeCodeManagedSettings(dropIns map[string][]byte) (*claudeCodeSettingsSource, error) {
	root, err := os.MkdirTemp("", "defenseclaw-claude-managed-")
	if err != nil {
		return nil, fmt.Errorf("stage Claude Code managed settings: %w", err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "managed-settings.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("stage Claude Code managed settings: %w", err)
	}
	for name, data := range dropIns {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return nil, fmt.Errorf("stage Claude Code managed settings: %w", err)
		}
	}
	source, err := readClaudeCodeManagedFileSettingsAt(root)
	if err != nil {
		return nil, fmt.Errorf("verify Claude Code sandbox managed settings: %w", err)
	}
	if source == nil {
		return nil, fmt.Errorf("verify Claude Code sandbox managed settings: drop-in was not loaded")
	}
	return source, nil
}

// verifyClaudeCodeSandboxManagedSource checks the merged managed tier of a
// sandbox image: the hook contract, allowManagedHooksOnly, Claude's own
// sandbox off, the pinned helpers and the pinned env.
func verifyClaudeCodeSandboxManagedSource(source *claudeCodeSettingsSource, rt resolvedSandboxTarget) error {
	if err := validateClaudeCodeManagedHookControls(source, true); err != nil {
		return fmt.Errorf("verify Claude Code sandbox managed settings: %w", err)
	}
	if only, _ := source.settings["allowManagedHooksOnly"].(bool); !only {
		return fmt.Errorf("verify Claude Code sandbox managed settings: allowManagedHooksOnly is not true")
	}
	sandbox, _ := source.settings["sandbox"].(map[string]interface{})
	if enabled, ok := sandbox["enabled"].(bool); !ok || enabled {
		return fmt.Errorf("verify Claude Code sandbox managed settings: Claude's own sandbox is not pinned off")
	}
	for _, key := range claudeCodeSandboxPinnedHelpers {
		if got, ok := source.settings[key].(string); !ok || got != "" {
			return fmt.Errorf("verify Claude Code sandbox managed settings: %s is not pinned to \"\"", key)
		}
	}
	env, _ := source.settings["env"].(map[string]interface{})
	pinned := make([]string, 0, len(claudeCodeSandboxPinnedEnv))
	for key := range claudeCodeSandboxPinnedEnv {
		pinned = append(pinned, key)
	}
	sort.Strings(pinned)
	for _, key := range pinned {
		want := claudeCodeSandboxPinnedEnv[key]
		if got, ok := env[key].(string); !ok || got != want {
			return fmt.Errorf("verify Claude Code sandbox managed settings: env %s is not pinned to %q", key, want)
		}
	}
	ok, err := claudeCodeSourceHasHookContract(source, rt.opts, true)
	if err != nil {
		return fmt.Errorf("verify Claude Code sandbox managed settings: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify Claude Code sandbox managed settings: hook contract %s is incomplete", rt.contract.ContractID)
	}
	return nil
}

// renderClaudeCodeSandboxPreseed pre-accepts onboarding and the workspace
// trust dialog. Trust on /work is inherited by every project mounted below
// it, which keeps the image independent of the repository name.
func renderClaudeCodeSandboxPreseed() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	err := enc.Encode(map[string]interface{}{
		"hasCompletedOnboarding": true,
		"theme":                  "dark",
		"projects": map[string]interface{}{
			"/work":        map[string]interface{}{"hasTrustDialogAccepted": true},
			SandboxHomeDir: map[string]interface{}{"hasTrustDialogAccepted": true},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal Claude Code preseed: %w", err)
	}
	return buf.Bytes(), nil
}

// claudeCodeOtelHelperFor is the otelHeadersHelper of rt's runtime.
func claudeCodeOtelHelperFor(rt resolvedSandboxTarget) string {
	if rt.ingress.Substrate() {
		return claudeCodeSubstrateOtelHelper
	}
	return claudeCodeSandboxOtelHelper
}

// claudeCodeSandboxOtelHelper is Claude's otelHeadersHelper: it prints the
// OTLP exporter headers as JSON on every export. The bearer is the OpenShell
// placeholder read at runtime; a value outside the placeholder alphabet is
// never interpolated into JSON.
const claudeCodeSandboxOtelHelper = `#!/bin/sh
# defenseclaw-managed-hook v1
# DefenseClaw Claude Code otelHeadersHelper (OpenShell sandbox images).
# Prints the OTLP exporter headers for the DefenseClaw hook ingress. The
# bearer is the per-sandbox binding token placeholder; the OpenShell
# supervisor substitutes the real value only on the ingress endpoint.
token="${DEFENSECLAW_SANDBOX_TOKEN:-}"
case "$token" in
  ''|*[!A-Za-z0-9:._-]*)
    printf '{"x-defenseclaw-source":"claudecode","x-defenseclaw-client":"claudecode-otel/1.0"}\n'
    exit 0
    ;;
esac
printf '{"Authorization":"Bearer %s","x-defenseclaw-source":"claudecode","x-defenseclaw-client":"claudecode-otel/1.0"}\n' "$token"
`
