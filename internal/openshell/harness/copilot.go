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

// copilotPin is the reviewed GitHub Copilot CLI release (copilot-hooks-v2,
// >=1.0.76). The community base image's Copilot CLI 1.0.16 is outside every
// contract and is removed.
var copilotPin = npmPin{
	Package:   "@github/copilot",
	Version:   "1.0.88",
	Integrity: "sha512-JVpBoJS8vXWdnQxb8FgeFYH6dDBVoYL0/LVJVXHNEHlyOfUd7jMqOxFLmVXweZ6pkAEaNvmoPt9jZJeSx2IPhw==",
	// npm-loader.js spawns this single-executable build of the CLI.
	Native: map[string]npmNative{
		"aarch64": {Path: "lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-arm64/copilot", SHA256: "487b36f3ea6bf5024bcdc797b2c0825a35313cbe92ada331d3a7f28f3f944550"},
		"x86_64":  {Path: "lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot", SHA256: "0059754cf78c3f3bf2c9d4564dfa7e9e25f3a3f8f411f2f0cdad9363f5662748"},
	},
}

// CopilotPackageCache is the root-owned package cache the image pre-extracts
// the pinned CLI into. The executable otherwise extracts its JavaScript into
// ~/.cache/copilot on first run and prefers the newest package it finds in
// any user-writable cache, so the workload could replace the running CLI.
const CopilotPackageCache = InstallRootBase + "/copilot/cache"

// copilotBYOKEnv is the non-secret env of a Copilot custom-provider profile.
// Offline mode skips every non-provider request (GitHub auth, telemetry, web
// tools, the GitHub MCP server, updates).
func copilotBYOKEnv(baseURL, modelID, wireModel string) map[string]string {
	env := map[string]string{
		"COPILOT_PROVIDER_BASE_URL": baseURL,
		"COPILOT_PROVIDER_TYPE":     "anthropic",
		"COPILOT_OFFLINE":           "true",
	}
	if modelID != "" {
		env["COPILOT_PROVIDER_MODEL_ID"] = modelID
		env["COPILOT_PROVIDER_WIRE_MODEL"] = wireModel
	}
	return env
}

// Copilot is the GitHub Copilot CLI harness. Its hooks are a root-owned
// /etc/github-copilot/policy.d document, and the managed settings admit only
// managed hooks (tamper tier managed).
var Copilot = register(&Spec{
	Name:           "copilot",
	DisplayName:    "GitHub Copilot CLI",
	Command:        "copilot",
	DefaultVersion: copilotPin.Version,
	Provider:       connector.NewCopilotConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification: Verification{
		Status: VerifiedLive,
		Note:   "hook-fire probe (built-in mock LLM through Copilot's BYOK Anthropic provider): policy.d hooks sessionStart, userPromptSubmitted, preToolUse, postToolUse, agentStop and sessionEnd reach the ingress with the sandbox token and an idempotency key, a BLOCKME tool call is denied (exit 2 and the JSON verdict both deny), and user disableAllHooks, user or repository hooks, planted newer packages, and a launch environment with BASH_ENV and ENV files that exit 0 and a PATH of planted bash, sh, curl and jq change nothing; live OpenShell 0.1.1 run (TestLiveSandboxHookOnlyHarness) with the DefenseClaw ingress and egress proxy: all eight fired hooks reach the ingress authenticated and keyed, an allowed tool call runs, with the shell tool on DefenseClaw's block list the DCBLOCK tool call gets the real gateway's block verdict, has no side effect and Copilot shows the reason and passes it to the model, a tool call's plain curl reaches example.org through the proxy the launcher exports, the proxy blocks webhook.site, a connection around the proxy is refused; GitHub-token model access is unverified (no entitled account)",
	},
	probe: ProbeSpec{
		// Through the launcher, so the probe uses the pre-extracted package
		// the sandbox runs (the bare binary would extract a fresh copy).
		VersionArgv: []string{CopilotLauncherPath, "--version"},
		VersionRE:   regexp.MustCompile(`^GitHub Copilot CLI ([0-9]+\.[0-9]+\.[0-9]+)`),
		// npm-loader.js (node) only spawns the native executable, which makes
		// every model request; its runtime helper ships in the package cache.
		NetworkBinaries: `find ` + InstallRootBase + `/copilot/lib -type f -path '*/@github/copilot-linux-*/copilot' -exec readlink -f {} \;
find ` + CopilotPackageCache + ` -type f -path '*/prebuilds/*/copilot-runtime' -exec readlink -f {} \;`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/copilot"
		run, err := copilotPin.installRun(root, version, "copilot", "@github/copilot")
		if err != nil {
			return nil, err
		}
		extract := `cache=` + shellQuote(CopilotPackageCache) + `; h="$(mktemp -d)"; ` +
			`got="$(HOME="$h" COPILOT_AUTO_UPDATE=false COPILOT_PKG_CACHE_HOME="$cache" /usr/local/bin/copilot --version 2>/dev/null | head -n 1)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote("GitHub Copilot CLI "+version+".") + ` ] || { echo "Copilot '$got' is not the pinned ` + version + `" >&2; exit 1; }; ` +
			`[ -n "$(find "$cache/pkg" -mindepth 3 -maxdepth 3 -name .extraction-complete -path '*/` + version + `/*')" ] || { echo "Copilot package was not extracted into $cache" >&2; exit 1; }; ` +
			`chown -R root:root "$cache"; chmod -R go-w "$cache"`
		return []InstallStep{{
			Comment: "Replace the base image's Copilot CLI with the pinned " + version + " in a root-owned prefix, pre-extract its package into a root-owned cache and build its pidfd_open fallback",
			Run:     run + "; " + extract + "; " + copilotPidfdInstall(),
		}}, nil
	},
	launcher: copilotLauncher,
	// --yolo is --allow-all; --allow-all-tools approves every tool call
	// (safe headless runs add it themselves).
	bypassFlags: []bypassFlag{{name: "--yolo"}, {name: "--allow-all"}, {name: "--allow-all-tools"}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{CopilotLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "-p", opts.Prompt)
		}
		switch {
		case opts.Yolo:
			argv = append(argv, "--yolo")
		case opts.Mode == Headless:
			// Non-interactive mode refuses to run without tool approval;
			// paths and URLs keep Copilot's own prompts off, and the
			// DefenseClaw hooks still gate every tool call.
			argv = append(argv, "--allow-all-tools")
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.CopilotGitHubID,
			Hosts:      []string{"api.github.com", "api.githubcopilot.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com"},
			Note:       "COPILOT_GITHUB_TOKEN (a Copilot-entitled GitHub token) sent to GitHub and the Copilot API",
			Unverified: "no Copilot-entitled GitHub account was available: the host set is taken from the CLI (api.github.com, api.githubcopilot.com) and GitHub's per-plan Copilot API hosts, not from a live run",
		},
		{
			ProfileID: profiles.CopilotAnthropicID,
			Hosts:     []string{"api.anthropic.com"},
			Env:       copilotBYOKEnv("https://api.anthropic.com", "", ""),
			Note:      "BYOK: COPILOT_PROVIDER_API_KEY sent as x-api-key to the Anthropic Messages API (pick a model with --model)",
		},
		{
			ProfileID: profiles.CopilotBedrockMantleID,
			Hosts:     []string{bedrockHostToken},
			Env:       copilotBYOKEnv("https://"+bedrockHostToken+"/anthropic", "claude-haiku-4.5", "anthropic.claude-haiku-4-5"),
			Note:      "BYOK: Bedrock API key sent as x-api-key to the Mantle Anthropic route (default model anthropic.claude-haiku-4-5)",
		},
	},
	customization: []CustomizationPath{
		{Host: ".copilot/copilot-instructions.md", Sandbox: "/sandbox/.copilot/copilot-instructions.md", Note: "user instructions"},
		{Host: ".copilot/agents", Sandbox: "/sandbox/.copilot/agents", Dir: true, Note: "user custom agents"},
		{Host: ".copilot/skills", Sandbox: "/sandbox/.copilot/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"pin COPILOT_PKG_CACHE_HOME to the root-owned pre-extracted package and COPILOT_AUTO_UPDATE=false, and drop COPILOT_CLI_DIST_DIR and COPILOT_CLI_VERSION, so only the pinned CLI runs",
		"set NODE_OPTIONS to --disable-warning=UNDICI-EHPA alone, so Node's experimental-EnvHttpProxyAgent warning does not print above the TUI at every start",
		"trust the exact working directory under /work or /sandbox in ~/.copilot/config.json (folder trust skips the interactive prompt)",
	},
	env: map[string]string{
		"COPILOT_AUTO_UPDATE":    "false",
		"COPILOT_PKG_CACHE_HOME": CopilotPackageCache,
	},
})

// CopilotLauncherPath is the in-image Copilot launcher.
const CopilotLauncherPath = LauncherDir + "/copilot-launch"

var copilotLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v2
# DefenseClaw GitHub Copilot CLI launcher (OpenShell sandbox images,
# root-owned). Pins the CLI to the package pre-extracted at image build,
# trusts the working directory, then execs the pinned CLI with the caller's
# arguments.
set -u
` + launcherPreamble + `# The executable prefers the newest package in any cache it searches unless
# auto-update is off, and a dist override replaces it outright.
unset COPILOT_CLI_DIST_DIR COPILOT_CLI_VERSION COPILOT_CACHE_HOME
COPILOT_AUTO_UPDATE=false
COPILOT_PKG_CACHE_HOME=` + CopilotPackageCache + `
export COPILOT_AUTO_UPDATE COPILOT_PKG_CACHE_HOME

# Folder trust is recorded per directory in ~/.copilot/config.json.
dir="$(pwd -P 2>/dev/null || true)"
cfg="${COPILOT_HOME:-${HOME:-/sandbox}/.copilot}/config.json"
case "$dir" in
  /work/*|/sandbox|/sandbox/*)
    if [ -f "$cfg" ] && [ ! -L "$cfg" ] && [ -w "$cfg" ] && [ -x /usr/bin/jq ]; then
      tmp="$(/usr/bin/mktemp "$cfg.XXXXXX" 2>/dev/null)" || tmp=""
      if [ -n "$tmp" ]; then
        if /usr/bin/jq --arg d "$dir" '.trustedFolders = (((.trustedFolders // []) + [$d]) | unique)' "$cfg" >"$tmp" 2>/dev/null; then
          /bin/mv -f "$tmp" "$cfg"
        else
          /bin/rm -f "$tmp"
        fi
      fi
    fi
    ;;
esac

# Copilot's npm launcher runs on the image's Node, which warns at every start
# that the EnvHttpProxyAgent behind NODE_USE_ENV_PROXY is experimental, above
# the TUI (the native CLI it starts does not). This fixed NODE_OPTIONS
# silences only that warning (Copilot's tool commands inherit it); the
# caller's NODE_OPTIONS is dropped with the other start-up variables.
# The sandbox refuses pidfd_open, so without the root-owned fallback the
# image builds (preloaded after the loader scrub above) every hook would wait
# out Copilot's 30-second hook timeout in the TUI. The native CLI drops
# LD_PRELOAD at load, so its hooks and tools do not inherit it.
dc_pidfd=()
if [ -f ` + CopilotPidfdShim + ` ]; then
  dc_pidfd=(LD_PRELOAD=` + CopilotPidfdShim + `)
fi
` + launcherExec(`"${dc_pidfd[@]}" NODE_OPTIONS=--disable-warning=UNDICI-EHPA /usr/local/bin/copilot "$@"`)
