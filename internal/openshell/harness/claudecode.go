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
	"regexp"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// claudeCodeBaseVersion is the Claude Code release the digest-pinned
// community base image ships (measured: /usr/local/bin/claude 2.1.156). That
// pin is relocated from the base; any other pin is installed from npm.
const claudeCodeBaseVersion = "2.1.156"

// ClaudeCode is the Claude Code harness.
var ClaudeCode = register(&Spec{
	Name:           "claudecode",
	DisplayName:    "Claude Code",
	Command:        "claude",
	DefaultVersion: claudeCodeBaseVersion,
	Provider:       connector.NewClaudeCodeConnector(),
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
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/claudecode"
		check := `got="$(DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 /usr/local/bin/claude --version 2>/dev/null | awk 'NR==1{print $1}')"; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Claude Code '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		if version == claudeCodeBaseVersion {
			return []InstallStep{{
				Comment: "Relocate the base image's Claude Code " + version + " to a root-owned prefix and pin it",
				Run: `set -eu; root=` + shellQuote(root) + `; ` +
					`install -d -o root -g root -m 0755 "$root" "$root/bin"; ` +
					`src="$(readlink -f /usr/local/bin/claude)"; ` +
					`case "$src" in "$root"/*) ;; *) install -o root -g root -m 0755 "$src" "$root/bin/claude"; ln -sfn "$root/bin/claude" /usr/local/bin/claude ;; esac; ` +
					check,
			}}, nil
		}
		return []InstallStep{{
			Comment: "Install Claude Code " + version + " from npm into a root-owned prefix",
			Run: `set -eu; root=` + shellQuote(root) + `; ` +
				`install -d -o root -g root -m 0755 "$root"; ` +
				`npm install -g --no-fund --no-audit --prefix "$root" ` + shellQuote("@anthropic-ai/claude-code@"+version) + `; ` +
				`ln -sfn "$root/bin/claude" /usr/local/bin/claude; ` +
				check,
		}}, nil
	},
	launcher: claudeCodeLauncher,
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
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
			Env: map[string]string{
				"ANTHROPIC_BASE_URL": "https://" + bedrockHostToken + "/anthropic",
				// Mantle's Anthropic route rejects experimental beta headers.
				"CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
			},
			Note: "Bedrock API key sent as x-api-key to the Mantle Anthropic route",
		},
	},
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

// ClaudeCodeLauncherPath is the in-image Claude Code launcher.
const ClaudeCodeLauncherPath = LauncherDir + "/claudecode-launch"

const claudeCodeLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Claude Code launcher (OpenShell sandbox images, root-owned).
# Refreshes the first-run state that cannot be baked into the image, then
# execs the pinned Claude Code binary with the caller's arguments.
#
# Claude keys its custom API key approval on the last 20 characters of the
# key. For an OpenShell placeholder those include revision digits that change
# on every sandbox start, so the approval is recorded again on each launch.
set -u
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
exec /usr/local/bin/claude "$@"
`
