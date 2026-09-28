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
	"encoding/base64"
	"regexp"
	"strings"

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
	// The Ctrl-Z shim (hermesSuspendModule, base64 so the Dockerfile RUN
	// stays one line) goes into the tool environment's site-packages with a
	// .pth file that imports it at every interpreter start.
	extra: `site="$(` + shellQuote(InstallRootBase+"/hermes/tools/hermes-agent/bin/python") + ` -I -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; ` +
		`case "$site" in ` + InstallRootBase + `/hermes/*) ;; *) echo "Hermes site-packages $site is outside the install root" >&2; exit 1 ;; esac; ` +
		`printf '%s' ` + shellQuote(base64.StdEncoding.EncodeToString([]byte(hermesSuspendModule))) + ` | base64 -d >"$site/` + hermesSuspendModuleName + `.py"; ` +
		`printf 'import ` + hermesSuspendModuleName + `\n' >"$site/` + hermesSuspendModuleName + `.pth"; ` +
		`chown root:root "$site/` + hermesSuspendModuleName + `.py" "$site/` + hermesSuspendModuleName + `.pth"; ` +
		`chmod 0644 "$site/` + hermesSuspendModuleName + `.py" "$site/` + hermesSuspendModuleName + `.pth"`,
}

// hermesSuspendModuleName is the root-owned module the Hermes tool
// environment imports at start.
const hermesSuspendModuleName = "defenseclaw_hermes_suspend"

// hermesSuspendModule turns Hermes' Ctrl-Z into a notice. Hermes 0.19.0
// binds Ctrl-Z to os.kill(0, SIGTSTP) (cli.py handle_ctrl_z), which the
// OpenShell sandbox refuses (EPERM for a kill() aimed at a process group):
// the exception reached prompt_toolkit's event loop, which printed a
// traceback and waited for Enter. The shim answers that one call, and no
// other, with the notice the launcher's supervisor shows for every harness,
// so Hermes keeps running.
const hermesSuspendModule = `"""DefenseClaw: Ctrl-Z cannot suspend Hermes in an OpenShell sandbox.

The sandbox refuses a kill() aimed at a process group, which is how Hermes
suspends itself; say so instead of failing inside Hermes' event loop.
"""
import os as _os
import signal as _signal

_kill = _os.kill


def _defenseclaw_kill(pid, sig):
    if pid == 0 and sig == _signal.SIGTSTP:
        try:
            _os.write(2, b"\r\ndefenseclaw: Ctrl-Z cannot suspend a harness in an OpenShell sandbox "
                         b"(the sandbox refuses the signal); it keeps running.\r\n")
        except OSError:
            pass
        return None
    return _kill(pid, sig)


_os.kill = _defenseclaw_kill
`

// Hermes is the Hermes Agent harness.
var Hermes = register(&Spec{
	Name:           "hermes",
	DisplayName:    "Hermes Agent",
	Command:        "hermes",
	DefaultVersion: "0.19.0",
	Provider:       connector.NewHermesConnector(),
	// The hooks live in the root-owned managed layer, but Hermes reads .env
	// files, profiles and plugins from its workload-writable home at every
	// start; the launcher's checks keep them from switching the hooks off.
	TamperTier: connector.SandboxTamperTierUser,
	verification: Verification{Status: VerifiedLive,
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=hermes): hooks at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy with the blocklist and a sandbox unblock; hook-fire probe with a hostile user config.yaml and a planted sitecustomize in the launch environment, and launcher refusals of a planted .env (safe mode, managed dir), model-provider plugin and profile secrets section. Verified with the E2E mock model behind a --credential binding only: no curated provider profile has carried a real model inside a sandbox. The Mantle endpoint set (managed defenseclaw provider, bearer, Chat Completions) answered the pinned Hermes host-direct with openai.gpt-oss-20b; the OpenAI and Anthropic profiles are unverified"},
	probe: ProbeSpec{
		VersionArgv:     []string{"/usr/local/bin/hermes", "--version"},
		VersionRE:       regexp.MustCompile(`^Hermes Agent v([0-9]+\.[0-9]+\.[0-9]+)`),
		NetworkBinaries: hermesTool.networkBinaries(),
	},
	install: func(version string) ([]InstallStep, error) {
		return hermesTool.installSteps("Hermes Agent", version), nil
	},
	launcher: hermesLauncher,
	// A passthrough --yolo would skip Hermes' dangerous-command approvals;
	// Hermes' parsers (top level and chat) resolve every prefix down to --y.
	bypassFlags: []bypassFlag{{name: "--yolo", abbrev: "--y"}},
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
			Unverified: "no OpenAI account on the verification host; only the E2E mock was run",
		},
		{
			ProfileID:  profiles.AnthropicID,
			Hosts:      []string{"api.anthropic.com"},
			LaunchArgs: []string{"--provider", "anthropic"},
			Note:       "ANTHROPIC_API_KEY sent as x-api-key by Hermes' built-in anthropic provider",
			Unverified: "no Anthropic account on the verification host; only the E2E mock was run",
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
		"refuse --safe-mode and every prefix Hermes' argument parser resolves to it (--sa and longer): Hermes skips every shell hook in safe mode",
		"pin HOME and HERMES_HOME to the image home, and drop the variables that move the managed scope, the Hermes home or the code Hermes runs (HERMES_MANAGED_DIR, HERMES_PYTHON_SRC_ROOT, HERMES_LAZY_INSTALL_TARGET, the TUI's interpreter and directories, every PYTHON* variable) or switch the hooks off (HERMES_SAFE_MODE, HERMES_ENABLE_PROJECT_PLUGINS)",
		"refuse to start while a .env or .op.env of the Hermes home or one of its profiles names any of them (Hermes loads ~/.hermes/.env over the process environment at start)",
		"refuse to start while the Hermes home or a profile holds Python code under plugins/ (model-provider plugins are imported whatever plugins.enabled says; memory and cron providers load when the user config names them)",
		"refuse to start while a user config.yaml has a secrets section, as Hermes' YAML loader reads it, or is a file the loader cannot parse (its secret sources set environment variables before the managed .env applies)",
		"export HERMES_ACCEPT_HOOKS=1 so the managed hooks register without the first-use consent prompt (the managed layer pins hooks_auto_accept as well)",
		"copy the provider profile's credential placeholder (BEDROCK_MANTLE_API_KEY or OPENAI_API_KEY) into HERMES_DEFENSECLAW_API_KEY for the managed defenseclaw provider",
	},
})

// HermesLauncherPath is the in-image Hermes launcher.
const HermesLauncherPath = LauncherDir + "/hermes-launch"

// hermesEnvFileNames are the Hermes variables a Hermes .env or .op.env may
// not name (extended regular expressions), matched anywhere in the file
// with NUL bytes removed: Hermes strips NULs and splits KEY=VALUE pairs
// glued to a previous value (for the names it knows) before it loads a .env
// (utf-8, latin-1 or UTF-16), so such a name is still set.
var hermesEnvFileNames = []string{
	"HERMES_SAFE_MODE", "HERMES_MANAGED_DIR", "HERMES_HOME[A-Z_]*", "HERMES_ENABLE_PROJECT_PLUGINS", "HERMES_ACCEPT_HOOKS",
	"HERMES_PYTHON[A-Z_]*", "HERMES_TUI_DIR", "HERMES_NODE", "HERMES_LAZY_INSTALL_TARGET",
}

// hermesEnvFileGenericNames are the other variables the files may not name,
// matched where a name starts (Hermes does not split glued pairs for them):
// the Tirith scanner's, the interpreter's and the dynamic loader's.
var hermesEnvFileGenericNames = []string{"TIRITH_[A-Z_]*", "PYTHON[A-Z0-9_]*", "LD_[A-Z_]*"}

// hermesEnvFilePattern is the extended regular expression of both lists.
var hermesEnvFilePattern = strings.Join(hermesEnvFileNames, "|") +
	"|(^|[^A-Za-z0-9_])(" + strings.Join(hermesEnvFileGenericNames, "|") + ")"

var hermesLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v3
# DefenseClaw Hermes launcher (OpenShell sandbox images, root-owned). The
# managed layer in /etc/hermes registers DefenseClaw's hooks, but at every
# start Hermes also reads settings and imports code from its home, which the
# workload can write. Refuse what would switch the hooks off, move the
# managed scope or load code next to them, hand the managed defenseclaw
# provider its credential, then exec the pinned Hermes with the caller's
# arguments.
set -u
` + launcherPreamble + pythonStartupScrub + `refuse() {
  echo "defenseclaw: refusing to start Hermes: $1. $2" >&2
  exit 2
}
# Safe mode skips every shell hook, and DefenseClaw's hooks are the only gate
# on a sandboxed tool call. Hermes' parsers resolve every prefix of
# --safe-mode down to --sa.
for arg in "$@"; do
  case "${arg%%=*}" in
    --sa|--saf|--safe|--safe-|--safe-m|--safe-mo|--safe-mod|--safe-mode)
      refuse "$arg turns on Hermes' safe mode, which runs without DefenseClaw's hooks" "DefenseClaw's own --safe (keep the harness's prompts) goes before the harness name."
      ;;
  esac
done
unset HERMES_SAFE_MODE HERMES_MANAGED_DIR HERMES_ENABLE_PROJECT_PLUGINS HERMES_HOME_OVERRIDE \
  HERMES_PYTHON_SRC_ROOT HERMES_PYTHON HERMES_TUI_DIR HERMES_NODE HERMES_LAZY_INSTALL_TARGET
HOME=` + connector.SandboxHomeDir + `
HERMES_HOME="$HOME/.hermes"
HERMES_ACCEPT_HOOKS=1
export HOME HERMES_HOME HERMES_ACCEPT_HOOKS

# Hermes loads <home>/.env and .op.env into its own environment, over the
# launcher's, imports Python plugins from <home>/plugins, and runs the secret
# sources <home>/config.yaml names before the managed .env applies, for the
# Hermes home and whichever profile it selects.
check_home() {
  local h="${1%/}" f hit
  for f in "$h/.env" "$h/.op.env"; do
    [ -e "$f" ] || continue
    [ -f "$f" ] && [ -r "$f" ] || refuse "$f is not a readable regular file" "Remove it and start Hermes again."
    hit="$(/usr/bin/tr -d '\000' <"$f" | /usr/bin/grep -aoE '` + hermesEnvFilePattern + `' | /usr/bin/head -n 1 | /usr/bin/sed 's/^[^A-Z]*//')"
    [ -z "$hit" ] || refuse "$f sets $hit" "It could switch DefenseClaw's hooks off or load code next to them; remove it and start Hermes again."
  done
  if [ -e "$h/plugins" ]; then
    hit="$(/usr/bin/find -L "$h/plugins" -name '*.py' -print -quit 2>/dev/null)"
    [ -z "$hit" ] || refuse "$hit is a Hermes plugin" "Hermes imports plugins into the process that runs DefenseClaw's hooks; remove it and start Hermes again."
  fi
  # Parsed with the loader Hermes reads the secrets section with (libyaml's
  # safe loader when it is there), whatever bytes spell the key: a key in
  # double quotes can spell secrets with escapes or fold it across lines.
  f="$h/config.yaml"
  if [ -e "$f" ]; then
    ` + shellQuote(hermesTool.interpreter()) + ` -I -c 'import sys, yaml
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = yaml.load(f, Loader=getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader)
except Exception:
    sys.exit(4)
sys.exit(3 if isinstance(d, dict) and d.get("secrets") else 0)' "$f" 2>/dev/null
    case $? in
      0) ;;
      3) refuse "$f has a secrets section" "Hermes' secret sources set environment variables before DefenseClaw's managed settings apply; remove it and start Hermes again." ;;
      4) refuse "$f is not a YAML file Hermes' loader can read, so it cannot be checked for a secrets section" "Fix or remove it and start Hermes again." ;;
      *) refuse "$f could not be checked for a secrets section" "Start Hermes again." ;;
    esac
  fi
}
check_home "$HERMES_HOME"
for profile in "$HERMES_HOME"/profiles/*/; do
  [ -d "$profile" ] && check_home "$profile"
done
unset profile

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
