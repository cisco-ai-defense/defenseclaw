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

// openCodePin is the reviewed OpenCode release (opencode-hooks-v1 covers
// >=1.18.10,<1.19.0). The community base image's OpenCode 1.2.18 is outside
// every contract and is removed.
var openCodePin = npmPin{
	Package:   "opencode-ai",
	Version:   "1.18.31",
	Integrity: "sha512-J95feefeWwtIaw3irx76WjzWcgQXxmuHmDVphvs5ep9X30fBJ6T6bFhw50i9Kx50MG/xPn5w2pafXIfNtdry9w==",
	// The package's postinstall copies the platform package's binary here.
	Native: map[string]npmNative{
		"aarch64": {Path: "lib/node_modules/opencode-ai/bin/opencode.exe", SHA256: "82ab43b7e8b7d931c26ba170c90de6082a2e2af8fc84a9ce9a506357b91160d7"},
		"x86_64":  {Path: "lib/node_modules/opencode-ai/bin/opencode.exe", SHA256: "f9dab32248695e9ebd56b16a1921798fd85112cf5a69c7dfd0cabc1e17be4a11"},
	},
}

// openCodeMantleConfig is the OPENCODE_CONFIG_CONTENT of the Bedrock Mantle
// profile: a custom provider on OpenCode's bundled Anthropic SDK, keyed from
// the placeholder in BEDROCK_MANTLE_API_KEY ({env:...} is resolved per
// start, so the revision-scoped placeholder is never baked).
const openCodeMantleConfig = `{"provider":{"mantle":{"npm":"@ai-sdk/anthropic","name":"Amazon Bedrock Mantle",` +
	`"options":{"baseURL":"https://` + bedrockHostToken + `/anthropic/v1","apiKey":"{env:BEDROCK_MANTLE_API_KEY}"},` +
	`"models":{"anthropic.claude-haiku-4-5":{"name":"Claude Haiku 4.5 (Bedrock Mantle)","tool_call":true}}}},` +
	`"model":"mantle/anthropic.claude-haiku-4-5"}`

// OpenCode is the OpenCode harness. Its hooks are a root-owned bridge plugin
// registered from the managed /etc/opencode/opencode.json (tamper tier
// managed); `--pure` and OPENCODE_PURE, which load no external plugin at all,
// are refused by the launcher, as is the managed-config test override.
var OpenCode = register(&Spec{
	Name:           "opencode",
	DisplayName:    "OpenCode",
	Command:        "opencode",
	DefaultVersion: openCodePin.Version,
	Provider:       connector.NewOpenCodeConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	Verification: Verification{
		Status: Verified,
		Reason: "hook-fire probe (built-in mock LLM through OpenCode's bundled Anthropic SDK): the managed plugin loads, tool.execute.before/after reach the ingress with the sandbox token and an idempotency key, a BLOCKME tool call is denied and has no side effect; user config plugin:[] cannot remove it",
	},
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/opencode", "--version"},
		VersionRE:   regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)$`),
		// The npm package installs one Bun-compiled executable that makes
		// every model request itself.
		NetworkBinaries: `readlink -f "$(command -v opencode)"`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/opencode"
		run, err := openCodePin.installRun(root, version, "opencode", "opencode-ai")
		if err != nil {
			return nil, err
		}
		check := `h="$(mktemp -d)"; got="$(HOME="$h" OPENCODE_DISABLE_AUTOUPDATE=1 /usr/local/bin/opencode --version 2>/dev/null | head -n 1)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "OpenCode '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		return []InstallStep{{
			Comment: "Replace the base image's OpenCode with the pinned " + version + " in a root-owned prefix (registry integrity and native sha256 checked)",
			Run:     run + "; " + check,
		}}, nil
	},
	launcher: openCodeLauncher,
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{OpenCodeLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "run")
		}
		if opts.Yolo {
			// Auto-approve every permission not explicitly denied; the
			// DefenseClaw plugin still gates every tool call.
			argv = append(argv, "--auto")
		}
		argv = append(argv, cp.LaunchArgs...)
		argv = append(argv, opts.Args...)
		if opts.Mode == Headless {
			argv = append(argv, opts.Prompt)
		}
		return argv, nil
	},
	credentialProfiles: []CredentialProfile{
		{ProfileID: profiles.OpenCodeAnthropicID, Hosts: []string{"api.anthropic.com"}, Note: "ANTHROPIC_API_KEY sent as x-api-key by OpenCode's built-in anthropic provider (select a model with -m anthropic/<model>)"},
		{ProfileID: profiles.OpenCodeOpenAIID, Hosts: []string{"api.openai.com"}, Note: "OPENAI_API_KEY sent as a bearer by OpenCode's built-in openai provider (select a model with -m openai/<model>)"},
		{
			ProfileID: profiles.OpenCodeBedrockMantleID,
			Hosts:     []string{bedrockHostToken},
			Env:       map[string]string{"OPENCODE_CONFIG_CONTENT": openCodeMantleConfig},
			Note:      "Bedrock API key sent as x-api-key to the Mantle Anthropic route through a custom provider (default model anthropic.claude-haiku-4-5)",
		},
	},
	customization: []CustomizationPath{
		{Host: ".config/opencode/AGENTS.md", Sandbox: "/sandbox/.config/opencode/AGENTS.md", Note: "user rules"},
		// OpenCode also reads the singular agent/, command/ and skill/.
		{Host: ".config/opencode/agents", Sandbox: "/sandbox/.config/opencode/agents", Dir: true, Note: "user agents"},
		{Host: ".config/opencode/commands", Sandbox: "/sandbox/.config/opencode/commands", Dir: true, Note: "user commands"},
		{Host: ".config/opencode/skills", Sandbox: "/sandbox/.config/opencode/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"refuse --pure and drop OPENCODE_PURE and OPENCODE_TEST_MANAGED_CONFIG_DIR, which would load no external plugin or replace the managed /etc/opencode config",
	},
	env: map[string]string{
		// OpenCode fetches the models.dev catalog on start; keep it (models
		// need it) but never let it pull an auto-update.
		"OPENCODE_DISABLE_AUTOUPDATE": "1",
	},
})

// OpenCodeLauncherPath is the in-image OpenCode launcher.
const OpenCodeLauncherPath = LauncherDir + "/opencode-launch"

const openCodeLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw OpenCode launcher (OpenShell sandbox images, root-owned).
# The DefenseClaw policy plugin is registered from the managed
# /etc/opencode/opencode.json. Refuse the switches that would run OpenCode
# without it, then exec the pinned OpenCode binary with the caller's
# arguments.
set -u
for arg in "$@"; do
  case "$arg" in
    --pure|--pure=*)
      echo "defenseclaw: opencode --pure runs without the DefenseClaw policy plugin; refusing" >&2
      exit 2
      ;;
  esac
done
unset OPENCODE_PURE OPENCODE_TEST_MANAGED_CONFIG_DIR
OPENCODE_DISABLE_AUTOUPDATE=1
export OPENCODE_DISABLE_AUTOUPDATE
exec /usr/local/bin/opencode "$@"
`
