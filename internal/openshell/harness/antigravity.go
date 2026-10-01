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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// antigravityRelease is one pinned Antigravity CLI build. Google's installer
// (https://antigravity.google/cli/install.sh) reads a per-platform manifest
// that names the tarball and its SHA-512; the pins below are copied from the
// manifests the installer served on 2026-09-27, so an image build downloads
// exactly those bytes and verifies them without trusting the manifest again.
type antigravityRelease struct {
	url    string
	sha512 string
}

// antigravityReleases maps a pinned version to its tarball per `uname -m`.
var antigravityReleases = map[string]map[string]antigravityRelease{
	"1.2.12": {
		"aarch64": {
			url:    "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.2.12-5784551402897408/linux-arm/cli_linux_arm64.tar.gz",
			sha512: "e2f10960197efbf2455edb1284ae686821e244908367f507bcb6a0d0f616e945d3eec5cdf29b41bbcd7f630826d0e9e233f457184d1696fa91e81d6a7ed440c9",
		},
		"x86_64": {
			url:    "https://storage.googleapis.com/antigravity-public/antigravity-cli/1.2.12-5784551402897408/linux-x64/cli_linux_x64.tar.gz",
			sha512: "d5f0fe7433cb7c43ea878c07627a4fdb82d218f3bef5e6436266f5d9fdd2df145523453b9be0c4250391a64a007f5f42f7faff797bc2b2d502e7efb4874e383a",
		},
	},
}

var sha512RE = regexp.MustCompile(`^[0-9a-f]{128}$`)

// Antigravity is Google's Antigravity CLI (agy). It is a single native
// binary; the network binary is the binary itself.
var Antigravity = register(&Spec{
	Name:           "antigravity",
	DisplayName:    "Antigravity",
	Command:        "agy",
	DefaultVersion: "1.2.12",
	Provider:       connector.NewAntigravityConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	TamperNote:     "the hook scripts are root-owned; ~/.gemini/config/hooks.json, which registers them, is the agent's to edit and is restored at every start",
	verification: Verification{Status: VerifiedLive,
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=antigravity, Gemini-API mock through GEMINI_API_KEY): hooks at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy with the blocklist and a sandbox unblock; hook-fire probe with a replaced user hooks.json and a hooks path replaced by a directory (refused). Verified with the Gemini-API mock only: the defenseclaw-gemini profile has not carried a real Gemini key (no account), and Google sign-in inside a sandbox is untested"},
	probe: ProbeSpec{
		VersionArgv:     []string{"/usr/local/bin/agy", "--version"},
		VersionRE:       regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)$`),
		NetworkBinaries: `readlink -f /usr/local/bin/agy`,
	},
	install:  antigravityInstallSteps,
	launcher: antigravityLauncher,
	// A passthrough --dangerously-skip-permissions would skip agy's prompts.
	// agy parses Go flags: one or two dashes, and =true (strconv.ParseBool).
	bypassFlags: []bypassFlag{
		{name: "--dangerously-skip-permissions", inline: goBoolTrue},
		{name: "-dangerously-skip-permissions", inline: goBoolTrue},
	},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{AntigravityLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "-p", opts.Prompt)
		}
		if opts.Yolo {
			argv = append(argv, "--dangerously-skip-permissions")
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.GeminiID,
			Hosts:      []string{"generativelanguage.googleapis.com"},
			Note:       "GEMINI_API_KEY sent as x-goog-api-key; the launcher selects agy's gemini model provider when the key is present",
			Unverified: "no Gemini API account on the verification host; only the Gemini-API mock was run",
		},
	},
	customization: []CustomizationPath{
		{Host: ".gemini/config/skills", Sandbox: "/sandbox/.gemini/config/skills", Dir: true, Note: "user skills"},
		{Host: ".gemini/config/agents", Sandbox: "/sandbox/.gemini/config/agents", Dir: true, Note: "user agents"},
		{Host: ".gemini/GEMINI.md", Sandbox: "/sandbox/.gemini/GEMINI.md", Note: "user rules"},
	},
	preseedRefresh: []string{
		"restore ~/.gemini/config/hooks.json from the root-owned canonical copy (an edit made during a session is undone at the next start)",
		"refuse to start when a hooks.json agy adds to the global one (the workspace's and every --add-dir directory's .agents/hooks.json, their and the user's plugins', ~/.gemini/antigravity-cli/hooks.json) reuses a DefenseClaw hook key, as JSON decodes it",
		"select the gemini model provider in ~/.gemini/antigravity-cli/settings.json when GEMINI_API_KEY is set (an API key skips the Google sign-in)",
		"trust the exact working directory under /work or /sandbox in ~/.gemini/antigravity-cli/settings.json (trustedWorkspaces), so agy does not ask whether to trust the folder",
	},
})

// antigravityInstallSteps downloads the pinned tarball for the build
// architecture, verifies its SHA-512 and installs the binary root-owned.
func antigravityInstallSteps(version string) ([]InstallStep, error) {
	builds, ok := antigravityReleases[version]
	if !ok {
		known := make([]string, 0, len(antigravityReleases))
		for v := range antigravityReleases {
			known = append(known, v)
		}
		sort.Strings(known)
		return nil, fmt.Errorf("harness antigravity: no pinned download for %s (pinned: %s)", version, strings.Join(known, ", "))
	}
	arches := make([]string, 0, len(builds))
	for arch := range builds {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	var cases strings.Builder
	for _, arch := range arches {
		b := builds[arch]
		if !strings.HasPrefix(b.url, "https://") || !sha512RE.MatchString(b.sha512) {
			return nil, fmt.Errorf("harness antigravity: malformed pin for %s %s", version, arch)
		}
		fmt.Fprintf(&cases, "%s) url=%s; sum=%s ;; ", arch, shellQuote(b.url), shellQuote(b.sha512))
	}
	root := InstallRootBase + "/antigravity"
	return []InstallStep{{
		Comment: "Install Antigravity CLI " + version + " from Google's pinned tarball (SHA-512 verified) into a root-owned prefix",
		Run: `set -eu; root=` + shellQuote(root) + `; ` +
			`case "$(uname -m)" in ` + cases.String() + `*) echo "Antigravity CLI ` + version + ` has no pinned build for $(uname -m)" >&2; exit 1 ;; esac; ` +
			`tmp="$(mktemp -d)"; ` +
			`curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/agy.tar.gz" "$url"; ` +
			`printf '%s  %s\n' "$sum" "$tmp/agy.tar.gz" | sha512sum -c - >/dev/null; ` +
			`tar -xzf "$tmp/agy.tar.gz" -C "$tmp" antigravity; ` +
			`install -d -o root -g root -m 0755 "$root" "$root/bin"; ` +
			`install -o root -g root -m 0755 "$tmp/antigravity" "$root/bin/agy"; ` +
			`rm -rf "$tmp"; ln -sfn "$root/bin/agy" /usr/local/bin/agy; ` +
			`got="$(cd /tmp && HOME=/tmp/defenseclaw-version-home /usr/local/bin/agy --version 2>/dev/null | head -n 1)"; rm -rf /tmp/defenseclaw-version-home; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Antigravity CLI '$got' is not the pinned ` + version + `" >&2; exit 1; }`,
	}}, nil
}

// AntigravityLauncherPath is the in-image Antigravity launcher.
const AntigravityLauncherPath = LauncherDir + "/antigravity-launch"

// antigravityHookKeyGuard refuses to start agy while a hooks file it reads
// besides the restored global one carries a DefenseClaw hook key, which
// could take the place of DefenseClaw's hook group: the .agents/hooks.json
// of the working directory and of every --add-dir directory (agy parses Go
// flags: one or two dashes, the value next or after "="), the hooks.json
// files of the plugins in their .agents/plugins and in
// ~/.gemini/config/plugins (up to three directories deep), and
// ~/.gemini/antigravity-cli/hooks.json, the other hooks path the pinned
// binary names.
//
// Keys are compared as agy decodes them: jq reads each file as JSON, so a
// key that spells the prefix with \u escapes is caught like a literal one
// (in any letter case). A file jq cannot parse, such as JSON with comments
// or trailing commas, which agy's reader accepts, is searched byte by byte:
// a JSON key can spell the prefix only literally or with \u escapes, so the
// file is refused when it names the prefix or holds an escape.
var antigravityHookKeyGuard = `ag_prefix=` + shellQuote(connector.AntigravitySandboxHookKeyPrefix) + `
ag_files=("$workspace/.agents/hooks.json" "$home/.gemini/antigravity-cli/hooks.json")
ag_plugins=("$workspace/.agents/plugins" "$home/.gemini/config/plugins")
ag_prev=""
for ag_arg in "$@"; do
  ag_dir=""
  case "$ag_prev" in -add-dir|--add-dir) ag_dir="$ag_arg" ;; esac
  case "$ag_arg" in -add-dir=*|--add-dir=*) ag_dir="${ag_arg#*=}" ;; esac
  if [ -n "$ag_dir" ]; then
    ag_files+=("$ag_dir/.agents/hooks.json")
    ag_plugins+=("$ag_dir/.agents/plugins")
  fi
  ag_prev="$ag_arg"
done
shopt -s dotglob
for ag_dir in "${ag_plugins[@]}"; do
  [ -d "$ag_dir" ] || continue
  for ag_file in "$ag_dir"/*/hooks.json "$ag_dir"/*/*/hooks.json "$ag_dir"/*/*/*/hooks.json; do
    [ -f "$ag_file" ] && ag_files+=("$ag_file")
  done
done
shopt -u dotglob
for ag_file in "${ag_files[@]}"; do
  [ -f "$ag_file" ] || continue
  /usr/bin/jq -e -s --arg p "$ag_prefix" 'any(.[] | objects | keys[]; ascii_downcase | startswith($p))' "$ag_file" >/dev/null 2>&1
  case $? in
    0) ag_reason="reuses a DefenseClaw hook key" ;;
    1) continue ;;
    *)
      LC_ALL=C /usr/bin/grep -aqiF "$ag_prefix" "$ag_file" 2>/dev/null || LC_ALL=C /usr/bin/grep -aqF '\u' "$ag_file" 2>/dev/null || continue
      ag_reason="is not plain JSON and names a DefenseClaw hook key or holds a \\u escape that could spell one"
      ;;
  esac
  echo "defenseclaw: $ag_file $ag_reason and could replace DefenseClaw's hooks; refusing to start agy" >&2
  exit 2
done
unset ag_prefix ag_files ag_plugins ag_prev ag_arg ag_dir ag_file ag_reason
`

var antigravityLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v3
# DefenseClaw Antigravity launcher (OpenShell sandbox images, root-owned).
# agy has no managed hook tier: its global hooks live in
# ~/.gemini/config/hooks.json, which this restores from the root-owned
# canonical copy before every start. A workspace, --add-dir or plugin
# hooks.json that reuses a DefenseClaw hook key is refused. It trusts the
# working directory and, with GEMINI_API_KEY set, selects agy's gemini model
# provider, then execs the pinned agy.
set -u
` + launcherPreamble + `home="${HOME:-/sandbox}"
workspace="$(pwd -P 2>/dev/null || pwd)"
` + antigravityHookKeyGuard + restoreUserHooksScript("agy", connector.AntigravitySandboxCanonicalHooksPath, "$home/.gemini/config", "$home/.gemini/config/hooks.json",
	"$home/.gemini", "$home/.gemini/config", "$home/.gemini/config/hooks.json") + `
# agy asks whether to trust a workspace, by its exact path, at its first
# start there; every project is under /work or /sandbox. An API key skips
# the Google sign-in only with the gemini model provider.
settings="$home/.gemini/antigravity-cli/settings.json"
ag_trust=""
case "$workspace" in
  /work/*|/sandbox|/sandbox/*) ag_trust="$workspace" ;;
esac
ag_gemini=""
[ -n "${GEMINI_API_KEY:-}" ] && ag_gemini=1
if { [ -n "$ag_trust" ] || [ -n "$ag_gemini" ]; } && [ -x /usr/bin/jq ] && [ ! -L "$settings" ] && { [ ! -e "$settings" ] || [ -f "$settings" ]; } && /bin/mkdir -p "$home/.gemini/antigravity-cli" 2>/dev/null; then
  current='{}'
  if [ -s "$settings" ]; then
    current="$(/bin/cat "$settings" 2>/dev/null)" || current='{}'
  fi
  tmp="$(/usr/bin/mktemp "$settings.XXXXXX" 2>/dev/null)" || tmp=""
  if [ -n "$tmp" ]; then
    if printf '%s' "$current" | /usr/bin/jq --arg d "$ag_trust" --arg g "$ag_gemini" '(if type == "object" then . else {} end)
        | if $g == "" then . else .modelProvider = "gemini" end
        | if $d == "" then . else .trustedWorkspaces = (((.trustedWorkspaces | if type == "array" then . else [] end) + [$d]) | unique) end' >"$tmp" 2>/dev/null; then
      /bin/mv -f "$tmp" "$settings"
    else
      /bin/rm -f "$tmp"
    fi
  fi
fi
unset ag_trust ag_gemini
` + launcherExec(`/usr/local/bin/agy "$@"`)
