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

// ampPin is the @ampcode/cli build DefenseClaw's amp-plugin-v1 contract was
// certified against (its floor 0.0.1785334225).
var ampPin = npmPin{
	Package:   "@ampcode/cli",
	Version:   "0.0.1785334225-g9abe75",
	Integrity: "sha512-KldjFXlN1tqxG4ATW2p/0RsMtjzOz3BcXCvxxReFG+E3OQWrvXy1lbms+7bBbJKFoA2PYliobVekh9CDs0McrA==",
	// The package's install script copies the platform package's Bun
	// executable here.
	Native: map[string]npmNative{
		"aarch64": {Path: "lib/node_modules/@ampcode/cli/bin/amp.exe", SHA256: "5d08d6ec9e84dffac2dc0e320e7144467daf01e8326dac067dd6198f825b2f29"},
		"x86_64":  {Path: "lib/node_modules/@ampcode/cli/bin/amp.exe", SHA256: "c92fa468409e4d38e85c7049797163e7c517f08fe65f0f0555d913e1bdb08d1a"},
	},
}

// ampVersionRE matches Amp's build-suffixed releases.
var ampVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{6,40}$`)

// Amp is the Amp CLI harness. Amp loads plugins only from the user's
// ~/.config/amp/plugins (tamper tier user).
//
// Amp routes every model request, and the account check that precedes the
// first turn, through its own service (AMP_URL, https://ampcode.com by
// default: JSON-RPC calls to /api/internal?<method> with the AMP_API_KEY
// bearer). There is no local or bring-your-own model endpoint, so neither the
// hook-fire probe's mock nor a Bedrock model can drive it, and its images
// stay unverified until a probe runs with a real key.
var Amp = register(&Spec{
	Name:           "amp",
	DisplayName:    "Amp",
	Command:        "amp",
	DefaultVersion: ampPin.Version,
	Provider:       connector.NewAMPConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	verification: Verification{
		Status: Unverified,
		Note:   "Amp needs an Amp account API key (AMP_API_KEY) for every run: without one `amp -x` stops at getUserInfo before any agent turn, and Amp has no local or bring-your-own model endpoint a mock or Bedrock could serve. Measured on the pin: the sandbox plugin loads from ~/.config/amp/plugins before any server call and its executable contract (env token, idempotency key, one retry, fail closed) passes; hook firing at the ingress, blocking and the ampcode.com endpoint set need a key",
	},
	versionPattern: ampVersionRE,
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/amp", "--version"},
		VersionRE:   regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]+) `),
		// One Bun-compiled executable makes every request.
		NetworkBinaries: `readlink -f "$(command -v amp)"`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/amp"
		run, err := ampPin.installRun(root, version, "amp", "")
		if err != nil {
			return nil, err
		}
		check := `h="$(mktemp -d)"; got="$(HOME="$h" AMP_SKIP_UPDATE_CHECK=1 /usr/local/bin/amp --version 2>/dev/null | head -n 1 | cut -d' ' -f1)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Amp '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		return []InstallStep{{
			Comment: "Install Amp " + version + " in a root-owned prefix (registry integrity and native sha256 checked)",
			Run:     run + "; " + check,
		}}, nil
	},
	launcher:    ampLauncher,
	bypassFlags: []bypassFlag{{name: "--dangerously-allow-all"}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{AmpLauncherPath}
		if opts.Yolo {
			argv = append(argv, "--dangerously-allow-all")
		}
		argv = append(argv, cp.LaunchArgs...)
		argv = append(argv, opts.Args...)
		if opts.Mode == Headless {
			// Execute mode starts the turn before plugins are ready unless
			// told to wait; the DefenseClaw plugin must see every event.
			argv = append(argv, "--plugin-ready-timeout", "30", "-x", opts.Prompt)
		}
		return argv, nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.AmpID,
			Hosts:      []string{"ampcode.com"},
			Note:       "AMP_API_KEY sent as a bearer to the Amp service, which serves the account check, threads and every model request",
			Unverified: "no Amp account key was available: the single host is where the pinned CLI sends its authenticated requests (measured against a stand-in AMP_URL), not a live run against ampcode.com",
		},
	},
	customization: []CustomizationPath{
		{Host: ".config/amp/AGENTS.md", Sandbox: "/sandbox/.config/amp/AGENTS.md", Note: "user guidance"},
		{Host: ".config/amp/checks", Sandbox: "/sandbox/.config/amp/checks", Dir: true, Note: "user checks"},
		{Host: ".config/agents/skills", Sandbox: "/sandbox/.config/agents/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"pin HOME and XDG_CONFIG_HOME so Amp reads the image's ~/.config/amp/plugins, and drop the plugin and settings overrides (AMP_DISABLE_PLUGINS, AMP_PLUGIN_URI, AMP_PLUGIN_SOURCE_BASE64, AMP_SETTINGS_FILE)",
	},
	env: map[string]string{
		"AMP_SKIP_UPDATE_CHECK": "1",
	},
})

// AmpLauncherPath is the in-image Amp launcher.
const AmpLauncherPath = LauncherDir + "/amp-launch"

var ampLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Amp launcher (OpenShell sandbox images, root-owned). Amp loads
# the DefenseClaw policy plugin from ~/.config/amp/plugins; point it at the
# image HOME and drop the overrides that would load other plugins or
# settings, then exec the pinned Amp binary with the caller's arguments.
set -u
` + launcherPreamble + `for arg in "$@"; do
  case "$arg" in
    --settings-file|--settings-file=*)
      echo "defenseclaw: amp --settings-file is not supported in a DefenseClaw sandbox" >&2
      exit 2
      ;;
  esac
done
unset AMP_DISABLE_PLUGINS AMP_PLUGIN_URI AMP_PLUGIN_SOURCE_BASE64 AMP_SETTINGS_FILE XDG_CONFIG_HOME
HOME=` + connector.SandboxHomeDir + `
AMP_SKIP_UPDATE_CHECK=1
export HOME AMP_SKIP_UPDATE_CHECK
` + launcherExec(`/usr/local/bin/amp "$@"`)
