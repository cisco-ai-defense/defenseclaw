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
// relocated binary never satisfies. The in-image launcher puts ~/.local/bin
// on PATH for the one check that ignores it.
var claudeCodeSandboxStartupEnv = map[string]string{
	"DISABLE_AUTOUPDATER":                                  "1",
	"DISABLE_UPDATES":                                      "1",
	"DISABLE_INSTALLATION_CHECKS":                          "1",
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":             "1",
	"CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
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
}

// claudeCodeSandboxPinnedHelpers name programs Claude runs by itself, outside
// any tool call and so unseen by PreToolUse, when a settings file sets them;
// the drop-in pins each to "" (p2-render-4). In the 2.1.156 settings schema
// each is an optional string, read from the merged settings, where the
// managed tier outranks user and project values, and run only when non-empty:
// apiKeyHelper prints the API key, awsCredentialExport and awsAuthRefresh run
// for Bedrock and gcpAuthRefresh for Vertex, providers a settings file can
// select through its env block. DefenseClaw passes credentials as OpenShell
// placeholders and never uses them (apiKeyHelper would also add a second auth
// header, which Bedrock Mantle rejects).
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
		SandboxFile{Path: claudeCodeSandboxOtelHelperPath, Mode: 0o755, Owner: SandboxOwnerRoot, Data: []byte(claudeCodeSandboxOtelHelper)},
		SandboxFile{Path: path.Join(SandboxHomeDir, ".claude.json"), Mode: 0o600, Owner: SandboxOwnerUser, Data: preseed},
	)
	env := make(map[string]string, len(claudeCodeSandboxStartupEnv))
	for key, value := range claudeCodeSandboxStartupEnv {
		env[key] = value
	}
	binaries := append(sandboxHookRuntimeBinaries(), SandboxBinary{Name: "claude", Role: SandboxBinaryHarness})
	return finalizeSandboxArtifacts(SandboxArtifacts{
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
// in the 2.1.156 settings schema): it cannot nest inside OpenShell, and a
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
	hookCommand := path.Join(SandboxHookDir, "claude-code-hook.sh")
	hooks, err := renderClaudeCodeManagedHookMatrix(hookCommand, nil, rt.opts)
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

// claudeCodeSandboxManagedEnv reuses the connector's native OTLP spec with the
// ingress as endpoint. Its Authorization header cannot be static (the token
// placeholder is revision-scoped), so the spec carries no headers and the
// otelHeadersHelper supplies them per export. Content-capture gates stay
// pinned off exactly as on the host.
func claudeCodeSandboxManagedEnv(rt resolvedSandboxTarget) (map[string]string, error) {
	spec := (&ClaudeCodeConnector{}).HookProfile(SetupOpts{APIAddr: rt.ingressAddr}).NativeOTLP
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
	for key, value := range claudeCodeSandboxStartupEnv {
		env[key] = value
	}
	for key, value := range claudeCodeSandboxPinnedEnv {
		env[key] = value
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
