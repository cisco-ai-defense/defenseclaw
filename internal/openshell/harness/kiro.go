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

// Kiro is the Kiro CLI harness. Its hooks live in the DefenseClaw agent in
// ~/.kiro/agents (tamper tier user); the launcher restores that agent from a
// root-owned template on every start, selects it, and refuses a project
// agent that would shadow it.
var Kiro = register(&Spec{
	Name:        "kiro",
	DisplayName: "Kiro CLI",
	// kiro-cli is a front end that starts kiro-cli-chat from PATH; the
	// launcher runs the pinned kiro-cli-chat directly.
	Command:        "kiro-cli-chat",
	DefaultVersion: kiroPin.Version,
	Provider:       connector.NewKiroConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	Verification: Verification{
		Status: Verified,
		Reason: "hook-fire probe (host and relay network modes) with Kiro's own scripted-response mode (KIRO_MOCK_CHAT_RESPONSE and a placeholder KIRO_API_KEY, no network): the agent hooks userPromptSubmit, preToolUse, postToolUse and stop reach the ingress with the sandbox token and an idempotency key, a BLOCKME shell call is denied (exit 2 from preToolUse; Kiro reports the tool as failed) and an allowed one runs, also with a hookless user agent, a relocated KIRO_HOME, BASH_ENV and ENV files and a PATH of planted tools, and the launcher refuses a shadowing project agent; live OpenShell 0.1.1 run (TestLiveSandboxHookOnlyHarness, scripted mode) with the DefenseClaw ingress and egress proxy: every hook reaches the ingress authenticated and keyed, an allowed tool call runs, with the shell tool on DefenseClaw's block list the DCBLOCK call gets the real gateway's block verdict and never runs, a tool call's plain curl reaches example.org through the proxy the launcher exports, the proxy blocks webhook.site, a connection around the proxy is refused; a model through KIRO_API_KEY (Kiro Pro) or an in-sandbox login is unverified (no Kiro account)",
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
	launcher: kiroLauncher,
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
		Argv:       []string{"/usr/local/bin/kiro-cli", "login", "--use-device-flow"},
		Note:       "AWS Builder ID or IAM Identity Center device-code login inside the sandbox; the token stays in the sandbox's ~/.local/share/kiro-cli",
		Unverified: "no Kiro account was available to complete a device-code login",
	},
	customization: []CustomizationPath{
		{Host: ".kiro/steering", Sandbox: "/sandbox/.kiro/steering", Dir: true, Note: "user steering documents"},
		{Host: ".kiro/skills", Sandbox: "/sandbox/.kiro/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"restore ~/.kiro/agents/" + connector.KiroSandboxAgentName + ".json from the root-owned template (the agent can edit or remove it, and Kiro runs without hooks when the selected agent fails to load)",
		"refuse to start beside a project .kiro/agents/" + connector.KiroSandboxAgentName + ".json in the working directory (Kiro prefers it over the global agent)",
		"pin HOME and drop KIRO_HOME, which relocate the agents directory, and select the DefenseClaw agent with --agent (a caller --agent is refused)",
		"select the local V2 agent engine with --v2, whose agent hooks the image verifies, and refuse --v3, --agent-engine, --cloud and --repo (the V3 engine replays no scripted response and was not measured; a cloud session runs outside the sandbox)",
	},
})

// KiroLauncherPath is the in-image Kiro CLI launcher.
const KiroLauncherPath = LauncherDir + "/kiro-launch"

var kiroLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Kiro CLI launcher (OpenShell sandbox images, root-owned). Kiro
# reads the DefenseClaw hooks from the agent it runs with, so the launcher
# restores that agent from its root-owned template, refuses a project agent
# that would shadow it, and starts the pinned kiro-cli-chat with it selected
# and the caller's chat arguments.
set -u
` + launcherPreamble + `refuse() {
  echo "defenseclaw: refusing to start Kiro: $1. $2" >&2
  exit 2
}
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
# KIRO_HOME moves the directory Kiro reads its agents from.
unset KIRO_HOME
HOME=` + connector.SandboxHomeDir + `
export HOME
agents="$HOME/.kiro/agents"
agent="$agents/` + connector.KiroSandboxAgentName + `.json"
/bin/mkdir -p "$agents" 2>/dev/null || refuse "$agents cannot be created" "The DefenseClaw agent lives there."
[ -d "$agents" ] && [ ! -L "$agents" ] || refuse "$agents is not a directory" "The DefenseClaw agent lives there."
/bin/rm -f "$agent" 2>/dev/null
/bin/cp "` + connector.KiroSandboxAgentTemplatePath + `" "$agent" 2>/dev/null && /bin/chmod 0644 "$agent" 2>/dev/null ||
  refuse "the DefenseClaw agent could not be restored to $agent" "Kiro runs without hooks when its agent is missing."
# A project agent of the same name in the working directory wins over the
# global one (Kiro 2.24.1 reads .kiro/agents in the working directory only).
dir="$(pwd -P 2>/dev/null)" || refuse "the working directory cannot be resolved" "A project agent there could replace the DefenseClaw agent."
home_real="$(cd "$HOME" 2>/dev/null && pwd -P)" || home_real="$HOME"
if [ "$dir" != "$home_real" ]; then
  shadow="${dir%/}/.kiro/agents/` + connector.KiroSandboxAgentName + `.json"
  if [ -e "$shadow" ] || [ -L "$shadow" ]; then
    refuse "$shadow replaces the DefenseClaw agent" "Remove it and start Kiro again."
  fi
fi
` + launcherExec(`/usr/local/bin/kiro-cli-chat chat --v2 --agent `+connector.KiroSandboxAgentName+` "$@"`)
