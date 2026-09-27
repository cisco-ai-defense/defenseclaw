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

// hermesTool is Nous Research's Hermes Agent from PyPI. 0.19.0 is the newest
// release on PyPI and resolves to hermes-hooks-v1 (>=0.19.0,<0.21.0); it is
// also the first release with the /etc/hermes managed scope the image's
// hooks live in.
var hermesTool = uvTool{
	harness:      "hermes",
	dist:         "hermes-agent",
	commands:     []string{"hermes"},
	versionCheck: `/usr/local/bin/hermes --version | awk 'NR==1{sub(/^v/,"",$3); print $3}'`,
}

// Hermes is the Hermes Agent harness.
var Hermes = register(&Spec{
	Name:           "hermes",
	DisplayName:    "Hermes Agent",
	Command:        "hermes",
	DefaultVersion: "0.19.0",
	Provider:       connector.NewHermesConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification: Verification{Status: VerifiedLive,
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=hermes): hooks at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy with the blocklist and a sandbox unblock"},
	probe: ProbeSpec{
		VersionArgv:     []string{"/usr/local/bin/hermes", "--version"},
		VersionRE:       regexp.MustCompile(`^Hermes Agent v([0-9]+\.[0-9]+\.[0-9]+)`),
		NetworkBinaries: hermesTool.networkBinaries(),
	},
	install: func(version string) ([]InstallStep, error) {
		return hermesTool.installSteps("Hermes Agent", version), nil
	},
	launcher: hermesLauncher,
	// A passthrough --yolo would skip Hermes' dangerous-command approvals.
	bypassFlags: []bypassFlag{{name: "--yolo"}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{HermesLauncherPath}
		if opts.Mode == Headless {
			// Quiet mode prints only the final answer and the session line.
			argv = append(argv, "chat", "-q", opts.Prompt, "-Q")
		}
		if opts.Yolo {
			argv = append(argv, "--yolo")
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.OpenAIID,
			Hosts:      []string{"api.openai.com"},
			Env:        map[string]string{connector.HermesSandboxProviderBaseURLEnv: "https://api.openai.com/v1"},
			LaunchArgs: []string{"--provider", connector.HermesSandboxProviderName},
			Note:       "OPENAI_API_KEY sent as a bearer through the image's managed defenseclaw provider (Chat Completions)",
		},
		{
			ProfileID:  profiles.AnthropicID,
			Hosts:      []string{"api.anthropic.com"},
			LaunchArgs: []string{"--provider", "anthropic"},
			Note:       "ANTHROPIC_API_KEY sent as x-api-key by Hermes' built-in anthropic provider",
		},
		{
			ProfileID:  profiles.BedrockMantleOpenAIID,
			Hosts:      []string{bedrockHostToken},
			Env:        map[string]string{connector.HermesSandboxProviderBaseURLEnv: "https://" + bedrockHostToken + "/v1"},
			LaunchArgs: []string{"--provider", connector.HermesSandboxProviderName},
			Note:       "Bedrock API key sent as a bearer to the Mantle Chat Completions route through the managed defenseclaw provider",
		},
	},
	customization: []CustomizationPath{
		{Host: ".hermes/SOUL.md", Sandbox: "/sandbox/.hermes/SOUL.md", Note: "persona"},
		{Host: ".hermes/skills", Sandbox: "/sandbox/.hermes/skills", Dir: true, Note: "user skills"},
		{Host: ".hermes/memories", Sandbox: "/sandbox/.hermes/memories", Dir: true, Note: "built-in memory"},
	},
	preseedRefresh: []string{
		"refuse --safe-mode (Hermes skips every shell hook in safe mode) and drop HERMES_SAFE_MODE, HERMES_MANAGED_DIR and HERMES_ENABLE_PROJECT_PLUGINS from the environment",
		"export HERMES_ACCEPT_HOOKS=1 so the managed hooks register without the first-use consent prompt (the managed layer pins hooks_auto_accept as well)",
		"copy the provider profile's credential placeholder (BEDROCK_MANTLE_API_KEY or OPENAI_API_KEY) into HERMES_DEFENSECLAW_API_KEY for the managed defenseclaw provider",
	},
})

// HermesLauncherPath is the in-image Hermes launcher.
const HermesLauncherPath = LauncherDir + "/hermes-launch"

var hermesLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v2
# DefenseClaw Hermes launcher (OpenShell sandbox images, root-owned). Keeps
# the managed hooks in force and hands the managed defenseclaw provider its
# credential, then execs the pinned Hermes with the caller's arguments.
set -u
` + launcherPreamble + `# Safe mode skips every shell hook, and DefenseClaw's hooks are the only gate
# on a sandboxed tool call.
for arg in "$@"; do
  case "$arg" in
    --safe-mode)
      echo "defenseclaw: hermes --safe-mode turns DefenseClaw's hooks off and is not available in a sandbox" >&2
      exit 2
      ;;
  esac
done
unset HERMES_SAFE_MODE HERMES_MANAGED_DIR HERMES_ENABLE_PROJECT_PLUGINS
HERMES_ACCEPT_HOOKS=1
export HERMES_ACCEPT_HOOKS

# The managed provider reads its key from HERMES_DEFENSECLAW_API_KEY; the
# sandbox's provider profile delivers the placeholder under its own name.
if [ -z "${HERMES_DEFENSECLAW_API_KEY:-}" ]; then
  for name in BEDROCK_MANTLE_API_KEY OPENAI_API_KEY; do
    value="${!name:-}"
    if [ -n "$value" ]; then
      HERMES_DEFENSECLAW_API_KEY="$value"
      export HERMES_DEFENSECLAW_API_KEY
      break
    fi
  done
  unset name value
fi
` + launcherExec(`/usr/local/bin/hermes "$@"`)
