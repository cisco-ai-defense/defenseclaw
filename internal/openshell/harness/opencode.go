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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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
// registered from the managed /etc/opencode/opencode.json, which user and
// project config cannot remove. The tier is still user: OpenCode imports
// every other plugin and custom tool into the same process, where it could
// answer for the bridge. The launcher refuses to start when it finds one
// (see openCodeLauncher), and refuses `--pure` and OPENCODE_PURE, which load
// no external plugin at all, as well as the managed-config test override.
var OpenCode = register(&Spec{
	Name:           "opencode",
	DisplayName:    "OpenCode",
	Command:        "opencode",
	DefaultVersion: openCodePin.Version,
	Provider:       connector.NewOpenCodeConnector(),
	TamperTier:     connector.SandboxTamperTierUser,
	Verification: Verification{
		Status: Verified,
		Reason: "hook-fire probe (built-in mock LLM through OpenCode's bundled Anthropic SDK): the managed plugin loads, tool.execute.before/after reach the ingress with the sandbox token and an idempotency key, a BLOCKME tool call is denied and has no side effect, user and project config plugin:[] cannot remove it, and the launcher refuses to start, naming the file, with a planted fetch-replacing project plugin, a planted user plugin or a project config entry naming one (its unit tests also cover ancestor, ~/.opencode and OPENCODE_CONFIG_DIR plugins, custom tools, JSONC, TUI and OPENCODE_CONFIG_CONTENT plugin entries, unbundled provider SDKs and wellknown remote-config logins); live OpenShell 0.1.1 run (TestLiveSandboxHookOnlyHarness) with the DefenseClaw ingress and egress proxy: every hook reaches the ingress authenticated and keyed, an allowed tool call runs, with the shell tool on DefenseClaw's block list the DCBLOCK tool call gets the real gateway's block verdict, has no side effect and OpenCode shows the reason and passes it to the model, a tool call's plain curl reaches example.org through the proxy the launcher exports, the proxy blocks webhook.site, a connection around the proxy is refused",
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
		"refuse to start while any other plugin or custom tool would load into the OpenCode process (plugin and tool directories of every config directory, plugin entries of every config layer, OPENCODE_CONFIG_CONTENT), naming the file",
	},
	env: map[string]string{
		// OpenCode fetches the models.dev catalog on start; keep it (models
		// need it) but never let it pull an auto-update.
		"OPENCODE_DISABLE_AUTOUPDATE": "1",
	},
})

// OpenCodeLauncherPath is the in-image OpenCode launcher.
const OpenCodeLauncherPath = LauncherDir + "/opencode-launch"

// openCodeBundledProviderSDKs are the provider SDK packages OpenCode 1.18.31
// ships inside its executable. A provider (in config or the model catalog)
// that names any other package, or a file:// URL, makes OpenCode install and
// import that code into its own process.
var openCodeBundledProviderSDKs = []string{
	"@ai-sdk/alibaba", "@ai-sdk/amazon-bedrock", "@ai-sdk/amazon-bedrock/mantle", "@ai-sdk/anthropic",
	"@ai-sdk/azure", "@ai-sdk/cerebras", "@ai-sdk/cohere", "@ai-sdk/deepinfra", "@ai-sdk/gateway",
	"@ai-sdk/github-copilot", "@ai-sdk/google", "@ai-sdk/google-vertex", "@ai-sdk/google-vertex/anthropic",
	"@ai-sdk/groq", "@ai-sdk/mistral", "@ai-sdk/openai", "@ai-sdk/openai-compatible", "@ai-sdk/perplexity",
	"@ai-sdk/togetherai", "@ai-sdk/vercel", "@ai-sdk/xai", "@openrouter/ai-sdk-provider",
	"gitlab-ai-provider", "venice-ai-sdk-provider",
}

// jsonStringArray renders values as a JSON array that fits in a
// single-quoted shell word.
func jsonStringArray(values []string) string {
	b, err := json.Marshal(values)
	if err != nil || strings.Contains(string(b), "'") {
		panic(fmt.Sprintf("harness: %v cannot be a single-quoted JSON array (%v)", values, err))
	}
	return string(b)
}

// openCodeLauncher refuses to start OpenCode when it would load code other
// than the DefenseClaw plugin. OpenCode 1.18 imports every plugin and custom
// tool into one process: the files matching {plugin,plugins}/*.{js,ts} and
// {tool,tools}/*.{js,ts} in each config directory (the global
// ~/.config/opencode, every .opencode from the working directory up to the
// worktree root, ~/.opencode and OPENCODE_CONFIG_DIR), the plugin entries of
// every config layer (global config.json, opencode.json[c] and tui.json[c],
// OPENCODE_CONFIG, the opencode.json[c] and tui.json[c] found walking up
// from the project, the config directories, OPENCODE_TUI_CONFIG and
// OPENCODE_CONFIG_CONTENT), the provider SDK a config layer names when it is
// not one OpenCode bundles, and the plugins of the remote config a
// "wellknown" login entry fetches. Such code shares globals with the policy
// plugin (the plugin reaches the ingress through the global fetch), so it
// could answer for it. The launcher checks the superset (every ancestor up
// to /, also of any directory argument) and names what it found.
//
// Config text is read the way OpenCode reads it: {env:NAME} is substituted
// into the raw text first, JSONC comments and trailing commas are dropped,
// and {file:...} is left alone (OpenCode inserts the file JSON-escaped, so it
// cannot add keys). Text jq still cannot parse is refused when it mentions
// plugin or npm, or has a \u escape that could spell either; a legacy TOML
// config and anything else it cannot read are refused rather than guessed
// at.
//
// The check covers starts through this launcher (every DefenseClaw launch)
// and the directories they name. Starting the pinned binary directly or
// nested inside the sandbox skips it, as it skips the --pure refusal, and so
// do directories OpenCode opens later (a server's per-request directory) and
// code added while it runs; so the tier stays user.
var openCodeLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw OpenCode launcher (OpenShell sandbox images, root-owned).
# The DefenseClaw policy plugin is registered from the managed
# /etc/opencode/opencode.json. Refuse the switches that would run OpenCode
# without it, and every other plugin, custom tool or provider SDK OpenCode
# would load into the same process, then exec the pinned OpenCode binary
# with the caller's arguments.
set -u
` + launcherPreamble + `for arg in "$@"; do
  case "$arg" in
    --pure|--pure=*)
      echo "defenseclaw: opencode --pure runs without the DefenseClaw policy plugin; refusing" >&2
      exit 2
      ;;
  esac
done
# OPENCODE_TEST_HOME moves the home OpenCode reads ~/.opencode from.
unset OPENCODE_PURE OPENCODE_TEST_MANAGED_CONFIG_DIR OPENCODE_TEST_HOME
OPENCODE_DISABLE_AUTOUPDATE=1
export OPENCODE_DISABLE_AUTOUPDATE

refuse() {
  echo "defenseclaw: refusing to start OpenCode: $1 $2. OpenCode loads plugins, custom tools and provider SDKs into the process that runs the DefenseClaw policy plugin, where they could switch it off. Remove it and start OpenCode again." >&2
  exit 2
}
bundled='` + jsonStringArray(openCodeBundledProviderSDKs) + `'
# config_verdict reads config text on stdin and prints ok, plugin, npm,
# unchecked or error.
config_verdict() {
  /usr/bin/jq -Rrs --argjson bundled "$bundled" '
    def outside_strings(re): gsub("(?<s>\"(?:[^\"\\\\]|\\\\.)*\")|" + re; .s // "");
    gsub("\\{env:(?<n>[^}]+)\\}"; ($ENV[.n] // "")) as $t
    | (try ($t | outside_strings("//[^\n]*|/\\*(?:[^*]|\\*+[^*/])*\\*+/") | outside_strings(",(?=\\s*[\\]}])") | fromjson) catch null) as $doc
    | if ($doc | type) == "object" then
        if (($doc.plugin // []) | length) > 0 then "plugin"
        elif any($doc | .. | objects | select(has("npm")) | .npm; (type != "string") or (. as $n | any($bundled[]; . == $n) | not)) then "npm"
        else "ok" end
      elif ($t | test("plugin|npm|\\\\u"; "i")) then "unchecked"
      else "ok" end' 2>/dev/null || echo error
}
config_refuse() {
  case "$2" in
    ok) ;;
    plugin) refuse "$1" "registers plugins" ;;
    npm) refuse "$1" "names a provider SDK OpenCode does not bundle" ;;
    unchecked) refuse "$1" "could not be parsed to check it for plugins" ;;
    *) refuse "$1" "could not be checked for plugins" ;;
  esac
}
check_config_file() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    [ -x /usr/bin/jq ] || refuse "$1" "could not be checked for plugins (no jq)"
    [ -f "$1" ] || refuse "$1" "is not a regular file"
    config_refuse "$1" "$(config_verdict <"$1")"
  fi
}
check_config_dir() {
  local sub file name
  for sub in plugin plugins tool tools; do
    [ -d "$1/$sub" ] || continue
    for file in "$1/$sub"/*.js "$1/$sub"/*.ts "$1/$sub"/.*.js "$1/$sub"/.*.ts; do
      if [ -e "$file" ] || [ -L "$file" ]; then
        refuse "$file" "is a plugin or custom tool"
      fi
    done
  done
  for name in opencode.json opencode.jsonc tui.json tui.jsonc; do
    check_config_file "$1/$name"
  done
}
check_tree() {
  local d="$1" name
  while :; do
    for name in opencode.json opencode.jsonc tui.json tui.jsonc; do
      check_config_file "${d%/}/$name"
    done
    check_config_dir "${d%/}/.opencode"
    [ "$d" = / ] && break
    d="${d%/*}"
    [ -n "$d" ] || d=/
  done
}
# auth_verdict reads OpenCode's login store on stdin and prints ok or
# wellknown: a "wellknown" entry makes OpenCode fetch a remote config, whose
# plugins this launcher cannot see. OpenCode ignores a store it cannot parse.
auth_verdict() {
  /usr/bin/jq -Rrs '(try fromjson catch null) as $d
    | if ($d | type) == "object" and any($d[]; type == "object" and .type == "wellknown") then "wellknown" else "ok" end' 2>/dev/null || echo error
}
auth_refuse() {
  case "$2" in
    ok) ;;
    wellknown) refuse "$1" "logs in to a remote OpenCode config (wellknown) whose plugins this launcher cannot check" ;;
    *) refuse "$1" "could not be checked for a remote config" ;;
  esac
}

home="${HOME:-` + connector.SandboxHomeDir + `}"
global="${XDG_CONFIG_HOME:-$home/.config}/opencode"
check_config_dir "$global"
check_config_file "$global/config.json"
if [ -e "$global/config" ] || [ -L "$global/config" ]; then
  refuse "$global/config" "is a legacy TOML config this launcher cannot check"
fi
check_config_dir "$home/.opencode"
if [ -n "${OPENCODE_CONFIG_DIR:-}" ]; then check_config_dir "$OPENCODE_CONFIG_DIR"; fi
if [ -n "${OPENCODE_CONFIG:-}" ]; then check_config_file "$OPENCODE_CONFIG"; fi
if [ -n "${OPENCODE_TUI_CONFIG:-}" ]; then check_config_file "$OPENCODE_TUI_CONFIG"; fi
if [ -n "${OPENCODE_CONFIG_CONTENT:-}" ]; then
  [ -x /usr/bin/jq ] || refuse OPENCODE_CONFIG_CONTENT "could not be checked for plugins (no jq)"
  config_refuse OPENCODE_CONFIG_CONTENT "$(printf '%s' "$OPENCODE_CONFIG_CONTENT" | config_verdict)"
fi
# OpenCode reads its login store from OPENCODE_AUTH_CONTENT when set.
if [ -n "${OPENCODE_AUTH_CONTENT:-}" ]; then
  [ -x /usr/bin/jq ] || refuse OPENCODE_AUTH_CONTENT "could not be checked for a remote config (no jq)"
  auth_refuse OPENCODE_AUTH_CONTENT "$(printf '%s' "$OPENCODE_AUTH_CONTENT" | auth_verdict)"
else
  auth="${XDG_DATA_HOME:-$home/.local/share}/opencode/auth.json"
  if [ -e "$auth" ] || [ -L "$auth" ]; then
    [ -x /usr/bin/jq ] || refuse "$auth" "could not be checked for a remote config (no jq)"
    [ -f "$auth" ] || refuse "$auth" "is not a regular file"
    auth_refuse "$auth" "$(auth_verdict <"$auth")"
  fi
fi
cwd="$(pwd -P 2>/dev/null)" || refuse "the working directory" "cannot be resolved"
check_tree "$cwd"
# A directory argument (the TUI's project, run --dir) is a project too.
for arg in "$@"; do
  value="${arg#--*=}"
  if [ -d "$value" ]; then
    project="$(cd "$value" 2>/dev/null && pwd -P)" || refuse "$value" "cannot be resolved"
    check_tree "$project"
  fi
done
` + launcherExec(`/usr/local/bin/opencode "$@"`)
