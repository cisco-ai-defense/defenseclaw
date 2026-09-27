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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// kiroPin is the Kiro CLI release DefenseClaw's sandbox-only
// kiro-cli-hooks-v1 contract was measured on. The digests are the ones Kiro's
// release manifest (prod.download.cli.kiro.dev/stable/latest/manifest.json)
// publishes for the headless Linux archives; the official installer fetches
// the same files.
var kiroPin = tarballPin{
	Version: "2.24.1",
	Archives: map[string]tarballArchive{
		"aarch64": {URL: "https://prod.download.cli.kiro.dev/stable/2.24.1/kirocli-aarch64-linux.tar.gz", SHA256: "3cdffc3bd2fffab374793ff5d14f5332064aef986572ba8b81096188c9febab3"},
		"x86_64":  {URL: "https://prod.download.cli.kiro.dev/stable/2.24.1/kirocli-x86_64-linux.tar.gz", SHA256: "9ddc94fe5d1c7530e14bf93b98e78b0bc74e3a36e14cfcf756373ba65ce41a2a"},
	},
	Strip:        1,
	DigestSource: "Kiro release manifest (stable channel)",
}

// Kiro is the Kiro CLI harness. Its hooks live in the DefenseClaw agent,
// alone in a root-owned agents directory the launcher forces
// KIRO_AGENT_CONFIG_DIR to, so no agent file in HOME or the project can take
// its place; Kiro has no system settings tier and still reads user and
// project settings and MCP servers (tamper tier user).
var Kiro = register(&Spec{
	Name:        "kiro",
	DisplayName: "Kiro CLI",
	// kiro-cli is a front end that starts kiro-cli-chat from PATH; the
	// launcher runs the pinned kiro-cli-chat directly.
	Command:        "kiro-cli-chat",
	DefaultVersion: kiroPin.Version,
	Provider:       connector.NewKiroConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	verification: Verification{
		Status: VerifiedLive,
		Note:   "hook-fire probe (host and relay network modes) with Kiro's own scripted-response mode (KIRO_MOCK_CHAT_RESPONSE and a placeholder KIRO_API_KEY, no network): the agent hooks userPromptSubmit, preToolUse, postToolUse and stop reach the ingress with the sandbox token and an idempotency key, a BLOCKME shell call is denied (exit 2 from preToolUse; Kiro reports the tool as failed) and an allowed one runs, also with hookless agents named defenseclaw in ~/.kiro/agents (defenseclaw.json and a.json, which sorts first) and in the project (defenseclaw.json and project.json), the user settings' default agent switched to Kiro's built-in one, hookless agents behind KIRO_HOME, KIRO_AGENT_CONFIG_DIR and KIRO_TEST_AGENTS_DIR, a planted KIRO_CHAT_SHELL and AMAZON_Q_CHAT_SHELL, BASH_ENV and ENV files and a PATH of planted tools; live OpenShell 0.1.1 run (TestLiveSandboxHookOnlyHarness, scripted mode) with the DefenseClaw ingress and egress proxy: every hook reaches the ingress authenticated and keyed, an allowed tool call runs, with the shell tool on DefenseClaw's block list the DCBLOCK call gets the real gateway's block verdict and never runs, a tool call's plain curl reaches example.org through the proxy the launcher exports, the proxy blocks webhook.site, a connection around the proxy is refused; a model through KIRO_API_KEY (Kiro Pro) or an in-sandbox login is unverified (no Kiro account)",
	},
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/kiro-cli-chat", "--version"},
		VersionRE:   regexp.MustCompile(`^kiro-cli-chat ([0-9]+\.[0-9]+\.[0-9]+)`),
		// kiro-cli-chat is the agent (it makes every model request); the
		// kiro-cli front end runs the login flow.
		NetworkBinaries: `readlink -f /usr/local/bin/kiro-cli-chat
readlink -f /usr/local/bin/kiro-cli`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/kiro"
		run, err := kiroPin.installRun(root, version)
		if err != nil {
			return nil, err
		}
		link := `for b in kiro-cli kiro-cli-chat kiro-cli-term; do [ -x "$root/bin/$b" ] || { echo "Kiro CLI archive lacks bin/$b" >&2; exit 1; }; ln -sfn "$root/bin/$b" "/usr/local/bin/$b"; done; ` +
			`h="$(mktemp -d)"; got="$(HOME="$h" /usr/local/bin/kiro-cli-chat --version 2>/dev/null | head -n 1)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote("kiro-cli-chat "+version) + ` ] || { echo "Kiro CLI '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		return []InstallStep{{
			Comment: "Install Kiro CLI " + version + " from its release archive into a root-owned prefix (vendor sha256 checked)",
			Run:     run + "; " + link,
		}}, nil
	},
	launcher:    kiroLauncher,
	bypassFlags: []bypassFlag{{name: "--trust-all-tools"}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{KiroLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "--no-interactive")
		}
		if opts.Yolo {
			argv = append(argv, "--trust-all-tools")
		}
		argv = append(argv, cp.LaunchArgs...)
		argv = append(argv, opts.Args...)
		if opts.Mode == Headless {
			argv = append(argv, opts.Prompt)
		}
		return argv, nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.KiroID,
			Hosts:      []string{"q.us-east-1.amazonaws.com", "runtime.us-east-1.kiro.dev", "management.us-east-1.kiro.dev", "prod.us-east-1.auth.desktop.kiro.dev"},
			Note:       "KIRO_API_KEY (a Kiro Pro API key for headless use) sent to the Kiro and Amazon Q service endpoints in us-east-1",
			Unverified: "no Kiro Pro account was available: the host set is the us-east-1 service endpoints the pinned kiro-cli-chat names (Amazon Q streaming, Kiro runtime, management and auth); the scripted live run, with a placeholder key, called management.<region>.kiro.dev in four regions and q.us-east-1.amazonaws.com, but never a model",
		},
	},
	login: &LoginOption{
		Argv:       []string{KiroLauncherPath, KiroLoginCommand, "--use-device-flow"},
		Note:       "AWS Builder ID or IAM Identity Center device-code login inside the sandbox (kiro-cli login through the launcher); the token stays in the sandbox's ~/.local/share/kiro-cli, where the workload can read it and send it out, so prefer the KIRO_API_KEY provider profile",
		Unverified: "no Kiro account was available to complete a device-code login",
	},
	customization: []CustomizationPath{
		{Host: ".kiro/steering", Sandbox: "/sandbox/.kiro/steering", Dir: true, Note: "user steering documents"},
		{Host: ".kiro/skills", Sandbox: "/sandbox/.kiro/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"force " + connector.KiroSandboxAgentDirEnv + " to the root-owned " + connector.KiroSandboxAgentDir + ", which holds only the DefenseClaw agent (Kiro picks an agent by the name inside any file of ~/.kiro/agents or the project's .kiro/agents, and reads neither with the variable set), and refuse to start when the agent is missing",
		"pin HOME and drop every KIRO_*, Q_*, AMAZON_Q_*, ASBX_KIRO_* and KAS_* variable but KIRO_API_KEY and KIRO_MOCK_CHAT_RESPONSE (they relocate the agents, settings and data and replace the shell tool's shell), and select the DefenseClaw agent with --agent (a caller --agent is refused)",
		"select the local V2 agent engine with --v2, whose agent hooks the image verifies, and refuse --v3, --agent-engine, --cloud and --repo (the V3 engine replays no scripted response and was not measured; a cloud session runs outside the sandbox)",
	},
})

// KiroLauncherPath is the in-image Kiro CLI launcher.
const KiroLauncherPath = LauncherDir + "/kiro-launch"

// kiroLauncherKeptEnv are the only Kiro variables the launcher passes on: the
// API key, and the scripted-response file the image's hook-fire probe drives
// Kiro with (every scripted tool call still goes through the hooks).
var kiroLauncherKeptEnv = []string{"KIRO_API_KEY", "KIRO_MOCK_CHAT_RESPONSE"}

// kiroLauncherDroppedEnv are the patterns of the variables Kiro CLI 2.24.1
// reads to relocate or replace what it runs with. Measured: KIRO_HOME,
// KIRO_TEST_AGENTS_DIR and KIRO_AGENT_CONFIG_DIR move the agents it reads
// (and with them the hooks), and KIRO_CHAT_SHELL and AMAZON_Q_CHAT_SHELL run
// every approved shell command through a program of the caller's choosing.
// The binary also reads settings, data, recording, engine and agent-server
// paths from KIRO_*, Q_*, AMAZON_Q_*, ASBX_KIRO_* and KAS_* variables.
var kiroLauncherDroppedEnv = []string{"KIRO_*", "Q_*", "AMAZON_Q_*", "ASBX_KIRO_*", "KAS_*"}

// KiroLoginCommand, as the launcher's first argument, runs the Kiro login
// (the kiro-cli front end) with the caller's other arguments instead of a
// chat.
const KiroLoginCommand = "login"

var kiroLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Kiro CLI launcher (OpenShell sandbox images, root-owned). Kiro
# reads the DefenseClaw hooks from the agent it runs with, and picks an agent
# by the name inside any file of its agents directories, so the launcher
# points Kiro at the root-owned directory that holds only the DefenseClaw
# agent, drops the other variables Kiro relocates itself with, and starts the
# pinned kiro-cli-chat with that agent selected and the caller's chat
# arguments. "kiro-launch ` + KiroLoginCommand + ` ..." runs the Kiro login instead.
set -u
` + launcherPreamble + `refuse() {
  echo "defenseclaw: refusing to start Kiro: $1. $2" >&2
  exit 2
}
# Kiro relocates its agents, settings, data and shell through these.
for name in $(compgen -e); do
  case "$name" in
    ` + strings.Join(kiroLauncherKeptEnv, "|") + `) ;;
    ` + strings.Join(kiroLauncherDroppedEnv, "|") + `) unset -v "$name" ;;
  esac
done
HOME=` + connector.SandboxHomeDir + `
export HOME
if [ "${1:-}" = ` + KiroLoginCommand + ` ]; then
  shift
  ` + launcherExec(`/usr/local/bin/kiro-cli `+KiroLoginCommand+` "$@"`) + `fi
for arg in "$@"; do
  case "$arg" in
    --agent|--agent=*)
      refuse "$arg is not supported in a DefenseClaw sandbox" "The DefenseClaw agent carries the hooks every Kiro session runs with."
      ;;
    # The launcher selects the agent engine the hooks were measured on;
    # a cloud session runs its tools outside the sandbox.
    --v2|--v3|--agent-engine|--agent-engine=*|--cloud|--repo|--repo=*)
      refuse "$arg is not supported in a DefenseClaw sandbox" "DefenseClaw runs Kiro's local V2 agent engine, whose agent hooks it verifies."
      ;;
  esac
done
# With ` + connector.KiroSandboxAgentDirEnv + ` set, Kiro reads agents from that directory alone
# (neither ~/.kiro/agents nor the project's .kiro/agents), so no agent file
# the workload or a repository adds can take the DefenseClaw agent's name.
` + connector.KiroSandboxAgentDirEnv + `="` + connector.KiroSandboxAgentDir + `"
export ` + connector.KiroSandboxAgentDirEnv + `
agent="$` + connector.KiroSandboxAgentDirEnv + `/` + connector.KiroSandboxAgentName + `.json"
[ -f "$agent" ] && [ -r "$agent" ] ||
  refuse "the DefenseClaw agent $agent is missing" "Kiro runs without hooks when its agent is missing."
` + launcherExec(`/usr/local/bin/kiro-cli-chat chat --v2 --agent `+connector.KiroSandboxAgentName+` "$@"`)
