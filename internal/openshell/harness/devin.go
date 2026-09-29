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
)

// devinPin is the Devin CLI release the devin-hooks-v1 contract pins. The
// digests are the ones Devin's versioned release manifest
// (static.devin.ai/cli/3000.4.25/manifest.json) publishes; the official
// installer (cli.devin.ai/install.sh) fetches the same archives.
var devinPin = tarballPin{
	Version: "3000.4.25",
	Archives: map[string]tarballArchive{
		"aarch64": {URL: "https://static.devin.ai/cli/3000.4.25/devin-3000.4.25-aarch64-unknown-linux.tar.gz", SHA256: "31e4020f8a4dc04e80e485770cb467270ff7c8b15595c03bcf41f78817bc2e93"},
		"x86_64":  {URL: "https://static.devin.ai/cli/3000.4.25/devin-3000.4.25-x86_64-unknown-linux.tar.gz", SHA256: "02ae86c4c502d5f1676175663dbed36ef2c0750a4e094c51294845228eeac5da"},
	},
	DigestSource: "Devin versioned release manifest",
}

// Devin is the Devin CLI harness. Its hooks live in the user config.json
// (tamper tier user); the launcher restores them from a root-owned template
// on every start and skips Devin's workspace trust check, whose declined
// prompt (Restricted Mode) runs without hooks and which stops a headless run
// outright.
//
// Devin requires a Devin account login before any agent turn, including with
// its OpenAI-compatible backend (ACP_BACKEND=openai), and its login is an
// interactive browser or pasted-token flow, so neither the hook-fire probe's
// mock nor a Bedrock model can drive it and its images stay unverified until
// a probe runs in a logged-in sandbox.
var Devin = register(&Spec{
	Name:           "devin",
	DisplayName:    "Devin CLI",
	Command:        "devin",
	DefaultVersion: devinPin.Version,
	Provider:       connector.NewDevinConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	TamperNote:     "the hook scripts are root-owned; ~/.config/devin/config.json, which registers them, is the agent's to edit and gets them back at every start, and a project's .devin hooks run beside them",
	verification: Verification{
		Status: Unverified,
		Note:   "the Devin CLI needs a Devin account login (`devin auth login`, a browser or pasted-token flow) before any agent turn: without one `devin -p` stops at \"Login canceled\" and fires no hook, also with ACP_BACKEND=openai pointed at a mock, and there is no API-key or bring-your-own-model path that skips the login. Measured on the pin: the archive matches the vendor manifest, the binary runs in the community base, and --permission-mode dangerous is the skip-permissions mode. The launcher passes --respect-workspace-trust false (accepted before a prompt and before a subcommand): Devin's bundled docs say --print fails in an untrusted directory, and a declined trust prompt runs Restricted Mode without hooks; the trade-off is that a project's own hooks (.devin/hooks.v1.json) load beside DefenseClaw's without a prompt, which the user tier leaves open. Hook firing at the ingress, blocking, the trust bypass in a real turn and the Devin endpoint set need a logged-in sandbox",
	},
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/devin", "--version"},
		VersionRE:   regexp.MustCompile(`^devin ([0-9]+\.[0-9]+\.[0-9]+)`),
		// One native executable makes every request.
		NetworkBinaries: `readlink -f /usr/local/bin/devin`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/devin"
		run, err := devinPin.installRun(root, version)
		if err != nil {
			return nil, err
		}
		link := `[ -x "$root/bin/devin" ] || { echo "Devin CLI archive lacks bin/devin" >&2; exit 1; }; ln -sfn "$root/bin/devin" /usr/local/bin/devin; ` +
			`h="$(mktemp -d)"; got="$(HOME="$h" /usr/local/bin/devin --version 2>/dev/null | head -n 1 | cut -d' ' -f2)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Devin CLI '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		return []InstallStep{{
			Comment: "Install Devin CLI " + version + " from its release archive into a root-owned prefix (vendor sha256 checked)",
			Run:     run + "; " + link,
		}}, nil
	},
	launcher: devinLauncher,
	bypassFlags: []bypassFlag{{name: "--permission-mode", value: func(v string) bool {
		v = strings.TrimSpace(v)
		return v == "dangerous" || v == "autonomous"
	}}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{DevinLauncherPath}
		if opts.Yolo {
			// "autonomous" needs Devin's own bubblewrap sandbox, which
			// cannot nest inside OpenShell.
			argv = append(argv, "--permission-mode", "dangerous")
		}
		argv = append(argv, cp.LaunchArgs...)
		argv = append(argv, opts.Args...)
		if opts.Mode == Headless {
			argv = append(argv, "-p", opts.Prompt)
		}
		return argv, nil
	},
	login: &LoginOption{
		Argv:       []string{DevinLauncherPath, "auth", "login", "--force-manual-token-flow"},
		Note:       "Devin account login inside the sandbox (paste the token from the browser flow; devin auth login through the launcher); the credential stays in the sandbox's ~/.local/share/devin, where the workload can read it and send it out, and Devin has no API-key provider profile to use instead",
		Unverified: "no Devin account was available to complete a login",
	},
	customization: []CustomizationPath{
		{Host: ".config/devin/AGENTS.md", Sandbox: "/sandbox/.config/devin/AGENTS.md", Note: "user rules"},
		{Host: ".config/devin/skills", Sandbox: "/sandbox/.config/devin/skills", Dir: true, Note: "user skills"},
		{Host: ".config/devin/agents", Sandbox: "/sandbox/.config/devin/agents", Dir: true, Note: "user agents"},
	},
	preseedRefresh: []string{
		"put the DefenseClaw hooks back into ~/.config/devin/config.json from the root-owned template, keeping the other settings (the agent can edit or remove them), and refuse to start when config.json is not a regular file or the restored file lacks the hooks",
		"pin HOME and drop XDG_CONFIG_HOME, which move the config Devin reads, and refuse a caller --config",
		"skip the workspace trust check with --respect-workspace-trust false (a headless --print run fails in an untrusted directory, and a declined trust prompt runs Restricted Mode without hooks), refuse a caller --respect-workspace-trust and drop the respect_workspace_trust and skip_workspace_trust config keys; the project's own .devin hooks then load beside DefenseClaw's without a prompt",
	},
})

// DevinLauncherPath is the in-image Devin CLI launcher.
const DevinLauncherPath = LauncherDir + "/devin-launch"

var devinLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Devin CLI launcher (OpenShell sandbox images, root-owned). Devin
# reads the DefenseClaw hooks from the user config.json, so the launcher puts
# them back from the root-owned template, pins the config location, and
# execs the pinned Devin CLI with the workspace trust check off (a declined
# trust prompt runs Devin without hooks) and the caller's arguments.
set -u
` + launcherPreamble + `refuse() {
  echo "defenseclaw: refusing to start Devin: $1. $2" >&2
  exit 2
}
for arg in "$@"; do
  case "$arg" in
    --config|--config=*)
      refuse "$arg is not supported in a DefenseClaw sandbox" "The DefenseClaw hooks live in the default config."
      ;;
    --respect-workspace-trust|--respect-workspace-trust=*)
      refuse "$arg is not supported in a DefenseClaw sandbox" "Devin runs without hooks in an untrusted workspace, so the launcher skips the trust check."
      ;;
  esac
done
# XDG_CONFIG_HOME moves the config Devin reads.
unset XDG_CONFIG_HOME
HOME=` + connector.SandboxHomeDir + `
export HOME
cfg="$HOME/.config/devin/config.json"
template="` + connector.DevinSandboxConfigTemplatePath + `"
[ -x /usr/bin/jq ] || refuse "jq is missing" "The DefenseClaw hooks cannot be restored without it."
# mv -f onto a directory (or a link to one) moves the restored config inside
# it and exits 0, and Devin would start with no config.json and no hooks.
if [ -e "$cfg" ] && [ ! -f "$cfg" ]; then
  refuse "$cfg is not a regular file" "Devin reads the DefenseClaw hooks from it; remove it and start Devin again."
fi
/bin/mkdir -p "${cfg%/*}" 2>/dev/null || refuse "${cfg%/*} cannot be created" "The DefenseClaw hooks live there."
tmp="$(/usr/bin/mktemp "$cfg.XXXXXX" 2>/dev/null)" || refuse "$cfg cannot be updated" "The DefenseClaw hooks live there."
# Keep the user's other settings, less the workspace trust keys, which could
# otherwise turn the trust check the launcher skips back on; a config that is
# missing, unreadable or not exactly one JSON object (comments included) is
# replaced by the template.
if [ -f "$cfg" ] && [ ! -L "$cfg" ] &&
  /usr/bin/jq -s --slurpfile t "$template" 'if length == 1 and (.[0] | type) == "object" then .[0] | .hooks = $t[0].hooks | del(.respect_workspace_trust, .skip_workspace_trust) else error("not one object") end' "$cfg" >"$tmp" 2>/dev/null; then
  :
elif ! /bin/cp "$template" "$tmp" 2>/dev/null; then
  /bin/rm -f "$tmp"
  refuse "the DefenseClaw hooks could not be restored to $cfg" "Devin runs without hooks when they are missing."
fi
/bin/chmod 0600 "$tmp" 2>/dev/null
/bin/mv -f "$tmp" "$cfg" 2>/dev/null || { /bin/rm -f "$tmp"; refuse "the DefenseClaw hooks could not be restored to $cfg" "Devin runs without hooks when they are missing."; }
# The restore must have landed: a regular file carrying the template's
# hooks, also when something replaced the config in between.
if [ -L "$cfg" ] || [ ! -f "$cfg" ] ||
  ! /usr/bin/jq -e --slurpfile t "$template" '.hooks == $t[0].hooks' "$cfg" >/dev/null 2>&1; then
  /bin/rm -f "$tmp" 2>/dev/null
  refuse "the DefenseClaw hooks could not be restored to $cfg" "Devin runs without hooks when they are missing."
fi
unset tmp
` + launcherExec(`/usr/local/bin/devin --respect-workspace-trust false "$@"`)
