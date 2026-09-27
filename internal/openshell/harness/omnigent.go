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
	"strings"

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
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=omnigent, the sandbox agent on a Responses mock): policy events at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy from a tool command with the blocklist and a sandbox unblock; hook-fire probe with a hostile user config.yaml, a planted sitecustomize in the launch environment and a project config naming another server (refused). Verified with the E2E mock model behind a --credential binding only: no curated provider profile has carried a real model inside a sandbox. The Mantle profile's endpoint set answered a bare `omnigent run --model openai.gpt-oss-20b -p` of the pinned OmniGent host-direct, with the sandbox agent as default_agent; the OpenAI and Anthropic profiles are unverified"},
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
		// The sandbox agent names no model, and OmniGent routes a run
		// without one to Databricks: a profile brings its default model,
		// else the caller must pick one.
		if cp.ProfileID != "" && !hasFlag(opts.Args, "--model") {
			if !hasFlag(cp.LaunchArgs, "--model") {
				return nil, fmt.Errorf("harness omnigent: the %s profile has no default model; pass --model <model> after the harness name", cp.ProfileID)
			}
			argv = append(argv, cp.LaunchArgs...)
		}
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.BedrockMantleOpenAIID,
			Hosts:      []string{bedrockHostToken},
			Env:        map[string]string{"OPENAI_BASE_URL": "https://" + bedrockHostToken + "/v1"},
			LaunchArgs: []string{"--model", omnigentMantleModel},
			Note:       "Bedrock API key copied to OPENAI_API_KEY and sent as a bearer to the Mantle Responses route by the sandbox agent's openai-agents harness (default model " + omnigentMantleModel + ")",
		},
		{
			ProfileID: profiles.OpenAIID, Hosts: []string{"api.openai.com"},
			Note:       "OPENAI_API_KEY, which OmniGent's openai-agents harness sends as a bearer (pick a model with --model)",
			Unverified: "no OpenAI account on the verification host; only the E2E mock was run",
		},
		{
			ProfileID: profiles.AnthropicID, Hosts: []string{"api.anthropic.com"},
			Note:       "ANTHROPIC_API_KEY for a model named anthropic/<model> (pick one with --model)",
			Unverified: "the sandbox agent runs on the openai-agents harness; Anthropic models through it were not run (no Anthropic account on the verification host)",
		},
	},
	customization: []CustomizationPath{
		{Host: "omnigent", Sandbox: "/sandbox/omnigent", Dir: true, Note: "agent workspace (agent YAML files and their assets)"},
	},
	preseedRefresh: []string{
		"point OMNIGENT_CONFIG_HOME at the root-owned " + connector.OmnigentSandboxConfigHome + " (policy_modules, the server-wide DefenseClaw policy and the sandbox agent as default_agent) and drop OMNIGENT_CONFIG, OMNIGENT_DATA_DIR and every PYTHON* variable",
		"refuse --server with a URL and a project .omnigent/config.yaml that sets server (sessions stay on the local server, which loads DefenseClaw's policy)",
		"stop, and stop reusing, any OmniGent server or host daemon its records in ~/.omnigent name that is not the pinned OmniGent started with that configuration (OmniGent reuses a live one whatever configuration it started with)",
		"copy BEDROCK_MANTLE_API_KEY into OPENAI_API_KEY for the Mantle profile",
		"set OMNIGENT_NO_UPDATE_CHECK=1 (the pinned install cannot upgrade itself)",
	},
})

// omnigentMantleModel is the Mantle model the Bedrock profile defaults to:
// an OpenAI open-weight model Mantle serves on its Responses route.
const omnigentMantleModel = "openai.gpt-oss-20b"

// hasFlag reports whether args pass the long option name, alone or as
// name=value.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// OmniGentLauncherPath is the in-image OmniGent launcher.
const OmniGentLauncherPath = LauncherDir + "/omnigent-launch"

var omnigentLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v3
# DefenseClaw OmniGent launcher (OpenShell sandbox images, root-owned).
# OmniGent evaluates policies in the server that ` + "`omnigent run`" + ` starts,
# which reads $OMNIGENT_CONFIG_HOME/config.yaml; this pins that to the
# image's root-owned configuration, makes sure no OmniGent server or host
# daemon started without it is reused, then execs the pinned OmniGent.
set -u
` + launcherPreamble + pythonStartupScrub + `unset OMNIGENT_CONFIG OMNIGENT_DATA_DIR OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN
OMNIGENT_CONFIG_HOME=` + shellQuote(connector.OmnigentSandboxConfigHome) + `
OMNIGENT_NO_UPDATE_CHECK=1
export OMNIGENT_CONFIG_HOME OMNIGENT_NO_UPDATE_CHECK
# The Mantle profile delivers its key under its own name; the sandbox agent's
# openai-agents harness reads OPENAI_API_KEY.
if [ -z "${OPENAI_API_KEY:-}" ] && [ -n "${BEDROCK_MANTLE_API_KEY:-}" ]; then
  OPENAI_API_KEY="$BEDROCK_MANTLE_API_KEY"
  export OPENAI_API_KEY
fi
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
` + omnigentServerGuard + omnigentReuseGuard + launcherExec(`/usr/local/bin/omnigent "$@"`)

// omnigentServerGuard keeps sessions on the sandbox's local server, the one
// that loads DefenseClaw's policy: --server with a URL, or a server key in
// the project's .omnigent/config.yaml (which wins over the global
// configuration), would run them on a server the image does not configure.
var omnigentServerGuard = `og_refuse() {
  echo "defenseclaw: refusing to start OmniGent: $1. A DefenseClaw sandbox runs OmniGent sessions on its local server, which loads DefenseClaw's policy." >&2
  exit 2
}
og_prev=""
for og_arg in "$@"; do
  if [ "$og_prev" = --server ]; then
    case "$og_arg" in ''|local) ;; *) og_refuse "--server $og_arg names another server" ;; esac
  fi
  case "$og_arg" in
    --server=*) case "${og_arg#--server=}" in ''|local) ;; *) og_refuse "$og_arg names another server" ;; esac ;;
  esac
  og_prev="$og_arg"
done
og_project="$(pwd -P 2>/dev/null)/.omnigent/config.yaml"
if [ -e "$og_project" ] && /usr/bin/grep -aq server "$og_project" 2>/dev/null; then
  ` + shellQuote(omnigentTool.interpreter()) + ` -I -c 'import sys, yaml
try:
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
s = d.get("server") if isinstance(d, dict) else None
sys.exit(0 if s in (None, "", "local") else 3)' "$og_project" 2>/dev/null
  case $? in
    0) ;;
    3) og_refuse "$og_project sets server" ;;
    *) og_refuse "$og_project could not be checked for a server setting" ;;
  esac
fi
unset og_prev og_arg og_project
unset -f og_refuse
`

// omnigentReuseGuard keeps OmniGent from reusing a server or host daemon the
// DefenseClaw configuration did not start. OmniGent reuses a live local
// server whose pidfile (~/.omnigent/local_server.pid: PID and port) and
// config signature match, and a live host daemon from its records
// (~/.omnigent/daemons/*.json, the legacy host.pid) as is; the signature
// covers the auth mode, release features, title instructions and version,
// not the configuration file, so a server the workload started itself
// without DefenseClaw's policy would serve every later session. The guard
// accepts a recorded process only when it is the pinned interpreter running
// OmniGent (`-m omnigent.cli`, `-m omnigent.host._daemon_entry` or the entry
// point), started with OMNIGENT_CONFIG_HOME set to the image's configuration
// and none of the variables that move it or load other code, with no other
// --config, and, for the server, when no other process listens on the
// recorded port (a port nobody listens on is not reused). Otherwise
// it runs `omnigent stop --force` with the launcher's environment and drops
// any record still naming such a process, so OmniGent starts its own.
// Processes OmniGent does not record are never reused: a server it spawns
// refuses a port another process owns.
var omnigentReuseGuard = `if [ -d /proc/self ]; then
  og_data="${HOME:-/sandbox}/.omnigent"
  og_py="$(/usr/bin/readlink -f ` + shellQuote(omnigentTool.interpreter()) + ` 2>/dev/null)"
  og_cfg=` + shellQuote(connector.OmnigentSandboxConfigPath) + `
  og_ours() {
    local pid="$1" i=1 a
    local -a argv
    [ -n "$og_py" ] && [ "$(/usr/bin/readlink "/proc/$pid/exe" 2>/dev/null)" = "$og_py" ] || return 1
    /usr/bin/grep -qzx 'OMNIGENT_CONFIG_HOME=` + connector.OmnigentSandboxConfigHome + `' "/proc/$pid/environ" 2>/dev/null || return 1
    ! /usr/bin/grep -qzE '^(OMNIGENT_CONFIG|OMNIGENT_DATA_DIR|PYTHON[A-Z0-9_]*|LD_[A-Z_]+)=' "/proc/$pid/environ" 2>/dev/null || return 1
    mapfile -d '' -t argv <"/proc/$pid/cmdline" 2>/dev/null || return 1
    case "${argv[1]:-}" in
      -m)
        case "${argv[2]:-}" in omnigent.cli|omnigent.host._daemon_entry) i=3 ;; *) return 1 ;; esac ;;
      /usr/local/bin/omnigent|` + omnigentTool.root() + `/bin/omnigent|` + omnigentTool.toolDir() + `/bin/omnigent) i=2 ;;
      *) return 1 ;;
    esac
    for ((; i < ${#argv[@]}; i++)); do
      a="${argv[$i]}"
      case "$a" in
        -c|--config) i=$((i + 1)); [ "${argv[$i]:-}" = "$og_cfg" ] || return 1 ;;
        --config=*) [ "${a#--config=}" = "$og_cfg" ] || return 1 ;;
      esac
    done
    return 0
  }
  # og_port_foreign: something listens on the recorded port, and it is not
  # the recorded process. A port nobody listens on yet (a server still
  # starting) is not reused: OmniGent requires its /health first.
  og_port_foreign() {
    local hex inode fd found=0
    case "$2" in ''|*[!0-9]*) return 0 ;; esac
    hex="$(printf '%04X' "$2" 2>/dev/null)" || return 0
    for inode in $(/usr/bin/awk -v p=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == p { print $10 }' /proc/net/tcp /proc/net/tcp6 2>/dev/null); do
      found=1
      for fd in /proc/"$1"/fd/*; do
        [ "$(/usr/bin/readlink "$fd" 2>/dev/null)" = "socket:[$inode]" ] && return 1
      done
    done
    [ "$found" = 1 ]
  }
  # og_foreign prints the records naming a live process that is not ours.
  og_foreign() {
    local f pid port
    f="$og_data/local_server.pid"
    if [ -f "$f" ]; then
      { read -r pid; read -r port; } <"$f" 2>/dev/null
      case "$pid$port" in *[!0-9]*|'') ;; *)
        if [ -d "/proc/$pid" ] && { ! og_ours "$pid" || og_port_foreign "$pid" "$port"; }; then echo "$f"; fi ;;
      esac
    fi
    f="$og_data/host.pid"
    if [ -f "$f" ]; then
      read -r pid <"$f" 2>/dev/null
      case "$pid" in *[!0-9]*|'') ;; *)
        if [ -d "/proc/$pid" ] && ! og_ours "$pid"; then echo "$f"; fi ;;
      esac
    fi
    for f in "$og_data"/daemons/*.json; do
      [ -f "$f" ] || continue
      pid="$(/usr/bin/jq -r '.pid // empty' "$f" 2>/dev/null)"
      case "$pid" in *[!0-9]*|'') continue ;; esac
      if [ -d "/proc/$pid" ] && ! og_ours "$pid"; then echo "$f"; fi
    done
  }
  og_records="$(og_foreign)"
  if [ -n "$og_records" ]; then
    echo "defenseclaw: stopping the OmniGent server or host daemon that was not started with DefenseClaw's configuration" >&2
    ` + strings.TrimSuffix(strings.TrimPrefix(launcherExec(`/usr/local/bin/omnigent stop --force`), "exec "), "\n") + ` </dev/null >/dev/null 2>&1
    for f in $(og_foreign); do
      /bin/rm -f "$f" "${f%.pid}.sig" "${f%.pid}.logpath" 2>/dev/null
    done
    if [ -n "$(og_foreign)" ]; then
      echo "defenseclaw: an OmniGent server or host daemon not started with DefenseClaw's configuration is still recorded in $og_data; refusing to start OmniGent" >&2
      exit 2
    fi
  fi
  unset og_data og_py og_cfg og_records f
  unset -f og_ours og_port_foreign og_foreign
fi
`

// omnigentRunnerProxyPassthrough lists the proxy variables OmniGent's host
// daemon keeps (_HOST_DAEMON_PROXY_ENV_ALLOWLIST in omnigent/cli.py) that
// the launcher preamble exports.
const omnigentRunnerProxyPassthrough = "HTTPS_PROXY,HTTP_PROXY,NO_PROXY,https_proxy,http_proxy,no_proxy"
