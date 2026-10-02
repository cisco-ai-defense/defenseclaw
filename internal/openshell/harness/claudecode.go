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

package harness

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// claudeCodeBaseVersion is the Claude Code release the digest-pinned
// community base image ships (measured: /usr/local/bin/claude 2.1.156). That
// pin is relocated from the base, and it is the only pinned release.
const claudeCodeBaseVersion = "2.1.156"

// ClaudeCode is the Claude Code harness.
var ClaudeCode = register(&Spec{
	Name:           "claudecode",
	DisplayName:    "Claude Code",
	Command:        "claude",
	DefaultVersion: claudeCodeBaseVersion,
	Provider:       connector.NewClaudeCodeConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification:   Verification{Status: VerifiedLive, Note: "test/e2e/openshell TestSandboxDaemon: hooks at the ingress, a DefenseClaw-blocked command denied, egress blocklist and OpenShell deny"},
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/claude", "--version"},
		VersionRE:   regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+) \(Claude Code\)`),
		// The native Claude Code build is one ELF; an npm build is a node
		// script, whose interpreter is then the network binary.
		NetworkBinaries: `p="$(readlink -f "$(command -v claude)")"
case "$(head -c 2 "$p")" in
  '#!')
    set -- $(head -n 1 "$p" | sed 's/^#![[:space:]]*//')
    if [ "$(basename "$1")" = env ]; then shift; fi
    readlink -f "$(command -v "$1")"
    ;;
  *) printf '%s\n' "$p" ;;
esac`,
	},
	// Only the base image's release is pinned: the digest-pinned base
	// carries its bytes. Another release would come from the npm registry
	// with no reviewed digest, so it is refused.
	install: func(version string) ([]InstallStep, error) {
		if version != claudeCodeBaseVersion {
			return nil, fmt.Errorf("harness claudecode: %s has no pinned digests (DefenseClaw pins the base image's %s)", version, claudeCodeBaseVersion)
		}
		root := InstallRootBase + "/claudecode"
		return []InstallStep{{
			Comment: "Relocate the base image's Claude Code " + version + " to a root-owned prefix and pin it",
			Run: `set -eu; root=` + shellQuote(root) + `; ` +
				`install -d -o root -g root -m 0755 "$root" "$root/bin"; ` +
				`src="$(readlink -f /usr/local/bin/claude)"; ` +
				`case "$src" in "$root"/*) ;; *) install -o root -g root -m 0755 "$src" "$root/bin/claude"; ln -sfn "$root/bin/claude" /usr/local/bin/claude ;; esac; ` +
				`got="$(DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 /usr/local/bin/claude --version 2>/dev/null | awk 'NR==1{print $1}')"; ` +
				`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Claude Code '$got' is not the pinned ` + version + `" >&2; exit 1; }`,
		}}, nil
	},
	launcher: claudeCodeLauncher,
	bypassFlags: []bypassFlag{
		{name: "--dangerously-skip-permissions"},
		{name: "--allow-dangerously-skip-permissions"},
		{name: "--permission-mode", value: func(v string) bool { return strings.TrimSpace(v) == "bypassPermissions" }},
	},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		if cp.ProfileID == profiles.ClaudeBedrockMantleID {
			if model, _ := claudeCodeModelArg(opts.Args); model != "" {
				if mantle, ok := MantleClaudeModel(model); ok {
					return nil, fmt.Errorf("--model %s is an Amazon Bedrock Runtime model id, but this sandbox reaches Bedrock through the Mantle "+
						"Anthropic route, which names that model %s: run with -- --model %s, or without --model for %s",
						model, mantle, mantle, ClaudeCodeMantleDefaultModel)
				}
			}
		}
		argv := []string{ClaudeCodeLauncherPath}
		if opts.Yolo {
			argv = append(argv, "--dangerously-skip-permissions")
		}
		if opts.Mode == Headless {
			argv = append(argv, "-p", opts.Prompt)
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{ProfileID: profiles.AnthropicID, Hosts: []string{"api.anthropic.com"}, Note: "ANTHROPIC_API_KEY sent as x-api-key"},
		{ProfileID: profiles.ClaudeOAuthID, Hosts: []string{"api.anthropic.com"}, Note: "CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token` sent as a bearer"},
		{
			ProfileID: profiles.ClaudeBedrockMantleID,
			Hosts:     []string{bedrockHostToken},
			// Mantle serves Claude models under anthropic.* ids only, so
			// Claude Code's own default and every /model alias fail there
			// ("There's an issue with the selected model"). The run's
			// managed drop-in pins these variables (ClaudeCodeSandboxModelEnv),
			// so every Claude Code the sandbox starts gets them;
			// --model or /model picks another.
			DefaultModel: ClaudeCodeMantleDefaultModel,
			Env: map[string]string{
				"ANTHROPIC_BASE_URL": "https://" + bedrockHostToken + "/anthropic",
				// Mantle's Anthropic route rejects experimental beta headers.
				"CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
				"ANTHROPIC_MODEL":                        ClaudeCodeMantleDefaultModel,
				"ANTHROPIC_DEFAULT_OPUS_MODEL":           "anthropic.claude-opus-4-8",
				"ANTHROPIC_DEFAULT_SONNET_MODEL":         "anthropic.claude-sonnet-5",
				"ANTHROPIC_DEFAULT_HAIKU_MODEL":          "anthropic.claude-haiku-4-5",
				"ANTHROPIC_SMALL_FAST_MODEL":             "anthropic.claude-haiku-4-5",
			},
			Note: "Bedrock API key sent as x-api-key to the Mantle Anthropic route (default model " + ClaudeCodeMantleDefaultModel + "; the Opus, Sonnet and Haiku aliases map to Mantle's anthropic.* ids)",
		},
	},
	modelArg:  claudeCodeModelArg,
	modelFlag: "--model",
	customization: []CustomizationPath{
		{Host: ".claude/CLAUDE.md", Sandbox: "/sandbox/.claude/CLAUDE.md", Note: "user memory"},
		{Host: ".claude/agents", Sandbox: "/sandbox/.claude/agents", Dir: true, Note: "user subagents"},
		{Host: ".claude/commands", Sandbox: "/sandbox/.claude/commands", Dir: true, Note: "user slash commands"},
		{Host: ".claude/skills", Sandbox: "/sandbox/.claude/skills", Dir: true, Note: "user skills"},
		{Host: ".claude/output-styles", Sandbox: "/sandbox/.claude/output-styles", Dir: true, Note: "user output styles"},
	},
	preseedRefresh: []string{
		"record the last 20 characters of the ANTHROPIC_API_KEY placeholder in ~/.claude.json customApiKeyResponses.approved (Claude keys its custom-key approval on them and the placeholder changes every start)",
	},
})

// ClaudeCodeMantleDefaultModel is the model Claude Code runs on Amazon
// Bedrock Mantle unless the caller picks another with --model.
const ClaudeCodeMantleDefaultModel = "anthropic.claude-sonnet-5"

// bedrockRuntimeClaudeModel matches an Amazon Bedrock Runtime Claude model
// id: an optional inference-profile prefix (us., eu., global., ...) and an
// optional -YYYYMMDD-vN:M version, around the Mantle id.
var bedrockRuntimeClaudeModel = regexp.MustCompile(`^(?:[a-z]{2,6}(?:-[a-z]+)?\.)?(anthropic\.claude-[a-z0-9-]+?)(?:-[0-9]{8}-v[0-9]+(?::[0-9]+)?)?$`)

// MantleClaudeModel returns the Mantle id of a Bedrock Runtime Claude model
// id (us.anthropic.claude-haiku-4-5-20251001-v1:0 is
// anthropic.claude-haiku-4-5), and false for a Mantle id or any other name.
func MantleClaudeModel(model string) (string, bool) {
	m := bedrockRuntimeClaudeModel.FindStringSubmatch(model)
	if m == nil || m[1] == model {
		return "", false
	}
	return m[1], true
}

// LaunchEnvProblem refuses --env settings that move a harness off the
// provider route its credential profile runs it on: on the Mantle profile a
// Bedrock API key reaches Claude Code as an Anthropic key, and
// CLAUDE_CODE_USE_BEDROCK would send it to bedrock-runtime with AWS
// credentials the sandbox does not have (GAP-1286).
func LaunchEnvProblem(profileID string, env map[string]string) error {
	if profileID != profiles.ClaudeBedrockMantleID {
		return nil
	}
	if _, set := env["CLAUDE_CODE_USE_BEDROCK"]; set {
		return fmt.Errorf("--env CLAUDE_CODE_USE_BEDROCK: this sandbox runs Claude Code on Amazon Bedrock through the Mantle Anthropic route " +
			"with your Bedrock API key (AWS_BEARER_TOKEN_BEDROCK); CLAUDE_CODE_USE_BEDROCK switches Claude Code to bedrock-runtime " +
			"with AWS credentials, which the sandbox does not have. Leave it out")
	}
	return nil
}

// ClaudeCodeLauncherPath is the in-image Claude Code launcher.
const ClaudeCodeLauncherPath = LauncherDir + "/claudecode-launch"

// claudeCodeModelArg returns the model Claude Code's --model names (the last
// one, as --model MODEL or --model=MODEL), which Claude applies above
// ANTHROPIC_MODEL and every settings file. Arguments after "--" are never
// flags; Claude Code has no configuration override that picks a model.
func claudeCodeModelArg(args []string) (flag, override string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if value, ok := strings.CutPrefix(arg, "--model="); ok {
			flag = strings.TrimSpace(value)
			continue
		}
		if arg == "--model" && i+1 < len(args) {
			i++
			flag = strings.TrimSpace(args[i])
		}
	}
	return flag, ""
}

var claudeCodeLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v2
# DefenseClaw Claude Code launcher (OpenShell sandbox images, root-owned).
# Refreshes the first-run state that cannot be baked into the image, then
# execs the pinned Claude Code binary with the caller's arguments.
#
# Claude keys its custom API key approval on the last 20 characters of the
# key. For an OpenShell placeholder those include revision digits that change
# on every sandbox start, so the approval is recorded again on each launch.
set -u
` + launcherPreamble + `# Claude Code's native build asks the user to add ~/.local/bin, where its own
# installer links it, to PATH until it is there (DISABLE_INSTALLATION_CHECKS
# does not cover that check). The pinned binary never lives there; the entry
# only follows the system directories, as Ubuntu's ~/.profile adds it.
case "${HOME:-}" in
  /*)
    case ":$PATH:" in
      *":$HOME/.local/bin:"*) ;;
      *) PATH="$PATH:$HOME/.local/bin" ;;
    esac
    ;;
esac
cfg="${HOME:-/sandbox}/.claude.json"
key="${ANTHROPIC_API_KEY:-}"
if [ -n "$key" ] && [ -f "$cfg" ] && [ ! -L "$cfg" ] && [ -w "$cfg" ] && [ -x /usr/bin/jq ]; then
  if [ "${#key}" -gt 20 ]; then
    suffix="${key:${#key}-20}"
  else
    suffix="$key"
  fi
  tmp="$(/usr/bin/mktemp "$cfg.XXXXXX" 2>/dev/null)" || tmp=""
  if [ -n "$tmp" ]; then
    if /usr/bin/jq --arg s "$suffix" \
      '.customApiKeyResponses.approved = (((.customApiKeyResponses.approved // []) + [$s]) | unique)
       | .customApiKeyResponses.rejected = (.customApiKeyResponses.rejected // [])' \
      "$cfg" >"$tmp" 2>/dev/null; then
      /bin/mv -f "$tmp" "$cfg"
    else
      /bin/rm -f "$tmp"
    fi
  fi
fi

# Imported MCP servers when the run lets the project's own servers start too
# (pack mcp.project_servers: allow): the sandbox manager mounts them
# read-only and they join the user-scope registry on every start. With
# project servers blocked it mounts /etc/claude-code/managed-mcp.json
# instead, which Claude reads exclusively.
servers=` + "\"" + connector.ClaudeCodeSandboxRunMCPServersPath + "\"" + `
if [ -f "$servers" ] && [ -f "$cfg" ] && [ ! -L "$cfg" ] && [ -w "$cfg" ] && [ -x /usr/bin/jq ]; then
  tmp="$(/usr/bin/mktemp "$cfg.XXXXXX" 2>/dev/null)" || tmp=""
  if [ -n "$tmp" ]; then
    if /usr/bin/jq --slurpfile run "$servers" \
      '.mcpServers = ((.mcpServers // {}) + ($run[0].mcpServers // {}))' \
      "$cfg" >"$tmp" 2>/dev/null; then
      /bin/mv -f "$tmp" "$cfg"
    else
      /bin/rm -f "$tmp"
    fi
  fi
fi
` + launcherExec(`/usr/local/bin/claude "$@"`)
