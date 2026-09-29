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

// openHandsTool is the OpenHands CLI from PyPI. 1.16.0 is the newest release
// and the one openhands-hooks-v1 (>=1.12.0) was source-reviewed against.
var openHandsTool = uvTool{
	harness:      "openhands",
	dist:         "openhands",
	commands:     []string{"openhands"},
	versionCheck: `OPENHANDS_SUPPRESS_BANNER=1 /usr/local/bin/openhands --version | awk '/^OpenHands CLI /{print $3; exit}'`,
	extra: pyShimInstall(InstallRootBase+"/openhands/tools/openhands/bin/python", InstallRootBase+"/openhands", "OpenHands",
		pyShim{name: openHandsSessionEndModuleName, source: openHandsSessionEndModule}),
}

// openHandsSessionEndModuleName is the root-owned module the OpenHands tool
// environment imports at start.
const openHandsSessionEndModuleName = "defenseclaw_openhands_session_end"

// openHandsSessionEndModule keeps the end of an OpenHands session free of a
// traceback. OpenHands 1.16.0 closes the conversation from an atexit
// callback (LocalConversation.close), after its Textual app has stopped;
// close runs the SessionEnd hooks (DefenseClaw's among them) and then hands
// each result to the app as a HookExecutionEvent, which raises "App is not
// running". Python printed "Exception ignored in atexit callback" and the
// traceback just above DefenseClaw's session summary, and the rest of close
// (the agent and tool executors) never ran. The shim runs
// HookEventProcessor.run_session_end as it is and drops only a display event
// the stopped app cannot take; the hooks' own results and every other
// event are unchanged.
const openHandsSessionEndModule = `"""DefenseClaw: end an OpenHands session without a traceback.

OpenHands closes a conversation at interpreter exit, after its TUI stopped,
and hands the SessionEnd hook results to that TUI, which raises. Run the
SessionEnd hooks and drop only the display event the stopped TUI refuses.
"""
` + pyOnImport + `

def _defenseclaw_patch_hooks(hooks):
    cls = hooks.HookEventProcessor
    run = cls.run_session_end

    def run_session_end(self):
        emit = self._emit_hook_execution_event

        def _emit(*args, **kwargs):
            try:
                emit(*args, **kwargs)
            except Exception:
                pass

        self._emit_hook_execution_event = _emit
        try:
            return run(self)
        finally:
            self.__dict__.pop("_emit_hook_execution_event", None)

    run_session_end.__wrapped__ = run
    run_session_end.__doc__ = run.__doc__
    cls.run_session_end = run_session_end


_defenseclaw_on_import("openhands.sdk.hooks.conversation_hooks", _defenseclaw_patch_hooks)
`

// OpenHands is the OpenHands CLI harness. OpenHands takes its model only
// from saved settings or, with --override-with-envs, from LLM_MODEL,
// LLM_API_KEY and LLM_BASE_URL; every DefenseClaw credential profile passes
// the flag and the launcher fills LLM_API_KEY from the profile's placeholder.
// The model itself is the caller's choice (LLM_MODEL, a LiteLLM model name
// such as openai/<model> or anthropic/<model>).
var OpenHands = register(&Spec{
	Name:           "openhands",
	DisplayName:    "OpenHands",
	Command:        "openhands",
	DefaultVersion: "1.16.0",
	Provider:       connector.NewOpenHandsConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	verification: Verification{Status: VerifiedLive,
		Note: "test/e2e/openshell TestSandboxHookOnlyHarness (DEFENSECLAW_E2E_HARNESS=openhands): hooks at the ingress with the model key substituted, a DefenseClaw-blocked command denied with the rule's reason, egress through the proxy with the blocklist and a sandbox unblock; hook-fire probe with a replaced user hooks.json, a planted sitecustomize in the launch environment and a hooks path replaced by a directory (refused). Verified with the E2E mock model behind a --credential binding only: no curated provider profile has carried a real model inside a sandbox. The Mantle endpoint set (LiteLLM openai/<model>, bearer) answered the pinned OpenHands host-direct with openai.gpt-oss-20b; the OpenAI and Anthropic profiles are unverified"},
	probe: ProbeSpec{
		VersionArgv:     []string{"/usr/bin/env", "OPENHANDS_SUPPRESS_BANNER=1", "/usr/local/bin/openhands", "--version"},
		VersionRE:       regexp.MustCompile(`^OpenHands CLI ([0-9]+\.[0-9]+\.[0-9]+)`),
		NetworkBinaries: openHandsTool.networkBinaries(),
	},
	install: func(version string) ([]InstallStep, error) {
		return openHandsTool.installSteps("OpenHands CLI", version), nil
	},
	launcher: openHandsLauncher,
	// --always-approve (alias --yolo) approves every action, --llm-approve
	// every action its LLM analyzer does not rate high risk.
	// OpenHands' parser resolves the prefixes down to --a, --y and --ll.
	bypassFlags: []bypassFlag{{name: "--always-approve", abbrev: "--a"}, {name: "--yolo", abbrev: "--y"}, {name: "--llm-approve", abbrev: "--ll"}},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{OpenHandsLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "--headless", "--exit-without-confirmation", "-t", opts.Prompt)
		}
		if opts.Yolo {
			argv = append(argv, "--always-approve")
		}
		argv = append(argv, cp.LaunchArgs...)
		return append(argv, opts.Args...), nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID:  profiles.OpenAIID,
			Hosts:      []string{"api.openai.com"},
			LaunchArgs: []string{"--override-with-envs"},
			Note:       "OPENAI_API_KEY copied to LLM_API_KEY and sent as a bearer by LiteLLM (LLM_MODEL=openai/<model>)",
			Unverified: "no OpenAI account on the verification host; only the E2E mock was run",
		},
		{
			ProfileID:  profiles.AnthropicID,
			Hosts:      []string{"api.anthropic.com"},
			LaunchArgs: []string{"--override-with-envs"},
			Note:       "ANTHROPIC_API_KEY copied to LLM_API_KEY and sent as x-api-key by LiteLLM (LLM_MODEL=anthropic/<model>)",
			Unverified: "no Anthropic account on the verification host; only the E2E mock was run",
		},
		{
			ProfileID:  profiles.BedrockMantleOpenAIID,
			Hosts:      []string{bedrockHostToken},
			Env:        map[string]string{"LLM_BASE_URL": "https://" + bedrockHostToken + "/v1"},
			LaunchArgs: []string{"--override-with-envs"},
			Note:       "Bedrock API key copied to LLM_API_KEY and sent as a bearer to the Mantle Chat Completions route (LLM_MODEL=openai/<mantle model id>)",
		},
	},
	customization: []CustomizationPath{
		{Host: ".openhands/skills", Sandbox: "/sandbox/.openhands/skills", Dir: true, Note: "user skills"},
		{Host: ".openhands/microagents", Sandbox: "/sandbox/.openhands/microagents", Dir: true, Note: "user microagents"},
		{Host: ".agents/skills", Sandbox: "/sandbox/.agents/skills", Dir: true, Note: "shared agent skills"},
	},
	preseedRefresh: []string{
		"restore ~/.openhands/hooks.json from the root-owned canonical copy (OpenHands loads hooks once per conversation, so an edit made during a session is undone at the next start)",
		"refuse to start when the working directory's .openhands/hooks.json exists (OpenHands would load it instead of DefenseClaw's)",
		"copy the provider profile's credential placeholder into LLM_API_KEY for --override-with-envs",
	},
})

// OpenHandsLauncherPath is the in-image OpenHands launcher.
const OpenHandsLauncherPath = LauncherDir + "/openhands-launch"

var openHandsLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v3
# DefenseClaw OpenHands launcher (OpenShell sandbox images, root-owned).
# OpenHands has no managed hook tier: it loads the first of
# <workdir>/.openhands/hooks.json and ~/.openhands/hooks.json. Before every
# start this restores the user file from the root-owned canonical copy and
# refuses a working directory whose own hooks file would replace it, then
# execs the pinned OpenHands CLI with the caller's arguments.
set -u
` + launcherPreamble + pythonStartupScrub + `home="${HOME:-/sandbox}"
workdir="${OPENHANDS_WORK_DIR:-$(pwd -P 2>/dev/null || pwd)}"
# Started in HOME, the "project" hooks file is the user file restored below.
workdir_real="$(cd "$workdir" 2>/dev/null && pwd -P)" || workdir_real="$workdir"
home_real="$(cd "$home" 2>/dev/null && pwd -P)" || home_real="$home"
if [ "$workdir_real" != "$home_real" ] && { [ -e "$workdir/.openhands/hooks.json" ] || [ -L "$workdir/.openhands/hooks.json" ]; }; then
  echo "defenseclaw: $workdir/.openhands/hooks.json would replace DefenseClaw's hooks (OpenHands loads only the first hooks file it finds); rename it to run OpenHands in this sandbox" >&2
  exit 2
fi
` + restoreUserHooksScript("OpenHands", connector.OpenHandsSandboxCanonicalHooksPath, "$home/.openhands", "$home/.openhands/hooks.json",
	"$home/.openhands", "$home/.openhands/hooks.json") + `
# --override-with-envs reads the key from LLM_API_KEY; the sandbox's provider
# profile delivers the placeholder under its own name.
if [ -z "${LLM_API_KEY:-}" ]; then
  for name in BEDROCK_MANTLE_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY; do
    value="${!name:-}"
    if [ -n "$value" ]; then
      LLM_API_KEY="$value"
      export LLM_API_KEY
      break
    fi
  done
  unset name value
fi
OPENHANDS_SUPPRESS_BANNER=1
export OPENHANDS_SUPPRESS_BANNER
` + launcherExec(`/usr/local/bin/openhands "$@"`)
