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

// omnigentTool is Databricks' OmniGent from PyPI. 0.13.0 is the newest
// release inside omnigent-custom-policy-v1 (>=0.7.0,<0.14.0). The install
// adds the root-owned DefenseClaw policy directory to the tool environment's
// import path with a .pth file, so the server imports the bridge by name.
var omnigentTool = uvTool{
	harness:      "omnigent",
	dist:         "omnigent",
	commands:     []string{"omnigent"},
	versionCheck: `OMNIGENT_NO_UPDATE_CHECK=1 /usr/local/bin/omnigent --version | awk 'NR==1{print $2}'`,
	extra: `site="$(` + shellQuote(InstallRootBase+"/omnigent/tools/omnigent/bin/python") + ` -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; ` +
		`case "$site" in ` + InstallRootBase + `/omnigent/*) ;; *) echo "OmniGent site-packages $site is outside the install root" >&2; exit 1 ;; esac; ` +
		`printf '%s\n' ` + shellQuote(connector.OmnigentSandboxPolicyDir) + ` >"$site/defenseclaw_omnigent.pth"; ` +
		`chown root:root "$site/defenseclaw_omnigent.pth"; chmod 0644 "$site/defenseclaw_omnigent.pth"`,
}

// OmniGent is the OmniGent meta-harness. Its policies run in the OmniGent
// server that `omnigent run` starts (or reuses) inside the sandbox; the
// launcher points that server at the image's root-owned configuration.
// OmniGent has no skip-permissions switch: approval pauses come from its
// policies, DefenseClaw's among them, so Yolo adds nothing.
var OmniGent = register(&Spec{
	Name:           "omnigent",
	DisplayName:    "OmniGent",
	Command:        "omnigent",
	DefaultVersion: "0.13.0",
	Provider:       connector.NewOmnigentConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification: Verification{Status: VerifiedLive,
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=omnigent, the sandbox agent on a Responses mock): policy events at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy from a tool command with the blocklist and a sandbox unblock"},
	probe: ProbeSpec{
		VersionArgv:     []string{"/usr/bin/env", "OMNIGENT_NO_UPDATE_CHECK=1", "/usr/local/bin/omnigent", "--version"},
		VersionRE:       regexp.MustCompile(`^omnigent ([0-9]+\.[0-9]+\.[0-9]+)`),
		NetworkBinaries: omnigentTool.networkBinaries(),
	},
	install: func(version string) ([]InstallStep, error) {
		return omnigentTool.installSteps("OmniGent", version), nil
	},
	launcher: omnigentLauncher,
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{OmniGentLauncherPath, "run"}
		if opts.Mode == Headless {
			argv = append(argv, "-p", opts.Prompt)
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{ProfileID: profiles.AnthropicID, Hosts: []string{"api.anthropic.com"}, Note: "ANTHROPIC_API_KEY, which OmniGent picks up from the environment"},
		{ProfileID: profiles.OpenAIID, Hosts: []string{"api.openai.com"}, Note: "OPENAI_API_KEY, which OmniGent picks up from the environment"},
	},
	customization: []CustomizationPath{
		{Host: "omnigent", Sandbox: "/sandbox/omnigent", Dir: true, Note: "agent workspace (agent YAML files and their assets)"},
	},
	preseedRefresh: []string{
		"point OMNIGENT_CONFIG_HOME at the root-owned " + connector.OmnigentSandboxConfigHome + " (policy_modules and the server-wide DefenseClaw policy) and drop OMNIGENT_CONFIG",
		"set OMNIGENT_NO_UPDATE_CHECK=1 (the pinned install cannot upgrade itself)",
	},
})

// OmniGentLauncherPath is the in-image OmniGent launcher.
const OmniGentLauncherPath = LauncherDir + "/omnigent-launch"

var omnigentLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v2
# DefenseClaw OmniGent launcher (OpenShell sandbox images, root-owned).
# OmniGent evaluates policies in the server that ` + "`omnigent run`" + ` starts,
# which reads $OMNIGENT_CONFIG_HOME/config.yaml; this pins that to the
# image's root-owned configuration, then execs the pinned OmniGent.
set -u
` + launcherPreamble + `unset OMNIGENT_CONFIG OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN
OMNIGENT_CONFIG_HOME=` + shellQuote(connector.OmnigentSandboxConfigHome) + `
OMNIGENT_NO_UPDATE_CHECK=1
export OMNIGENT_CONFIG_HOME OMNIGENT_NO_UPDATE_CHECK
# OmniGent's local host daemon starts the server the policy runs in with only
# provider and OMNIGENT_* variables, so the binding token placeholder travels
# under an OMNIGENT_ name as well.
case "${DEFENSECLAW_SANDBOX_TOKEN:-}" in
  ''|*[!A-Za-z0-9:._-]*) ;;
  *)
    OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN="$DEFENSECLAW_SANDBOX_TOKEN"
    export OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN
    ;;
esac
# The host daemon keeps the proxy variables, but the runner that executes the
# agent's tools inherits only its own allowlist and the names listed in
# OMNIGENT_RUNNER_ENV_PASSTHROUGH. List the proxy settings there, so tool
# commands also go through the DefenseClaw egress proxy. The CLI, daemon,
# server and runner talk to each other over loopback, which stays off the
# proxy: through it, 127.0.0.1 would be the proxy's own host.
if [ -n "${HTTPS_PROXY:-}" ]; then
  NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,localhost,::1"; no_proxy="$NO_PROXY"
  export NO_PROXY no_proxy
  OMNIGENT_RUNNER_ENV_PASSTHROUGH="${OMNIGENT_RUNNER_ENV_PASSTHROUGH:+$OMNIGENT_RUNNER_ENV_PASSTHROUGH,}` + omnigentRunnerProxyPassthrough + `"
  export OMNIGENT_RUNNER_ENV_PASSTHROUGH
fi
` + launcherExec(`/usr/local/bin/omnigent "$@"`)

// omnigentRunnerProxyPassthrough lists the proxy variables OmniGent's host
// daemon keeps (_HOST_DAEMON_PROXY_ENV_ALLOWLIST in omnigent/cli.py) that
// the launcher preamble exports.
const omnigentRunnerProxyPassthrough = "HTTPS_PROXY,HTTP_PROXY,NO_PROXY,https_proxy,http_proxy,no_proxy"
