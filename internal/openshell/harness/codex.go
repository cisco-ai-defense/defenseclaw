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
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// Codex is the Codex CLI harness. The base image's Codex 0.117 is outside
// every reviewed hook contract, so the pinned release is always installed
// from npm (and the base copy removed).
var Codex = register(&Spec{
	Name:           "codex",
	DisplayName:    "Codex",
	Command:        "codex",
	DefaultVersion: "0.146.0",
	Provider:       connector.NewCodexConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification:   Verification{Status: VerifiedLive, Note: "OpenShell 0.1.1 harness spike (hooks fired, deny honoured, Bedrock Mantle gpt-oss-20b) and the image hook-fire probe (allow, BLOCKME, hostile settings)"},
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/codex", "--version"},
		VersionRE:   regexp.MustCompile(`^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)`),
		// codex is a node wrapper that spawns the platform-native binary;
		// that binary makes every model request.
		NetworkBinaries: `find ` + InstallRootBase + `/codex -type f -path '*/vendor/*/bin/codex' -exec readlink -f {} \; | sort -u`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/codex"
		return []InstallStep{{
			Comment: "Replace the base image's Codex with the pinned " + version + " in a root-owned prefix",
			Run: `set -eu; root=` + shellQuote(root) + `; ` +
				`npm uninstall -g @openai/codex >/dev/null 2>&1 || true; ` +
				`install -d -o root -g root -m 0755 "$root"; ` +
				`npm install -g --no-fund --no-audit --prefix "$root" ` + shellQuote("@openai/codex@"+version) + `; ` +
				`ln -sfn "$root/bin/codex" /usr/local/bin/codex; ` +
				`got="$(/usr/local/bin/codex --version 2>/dev/null | awk 'NR==1{print $NF}')"; ` +
				`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Codex '$got' is not the pinned ` + version + `" >&2; exit 1; }; ` +
				`[ -n "$(find "$root" -type f -path '*/vendor/*/bin/codex' | head -n 1)" ] || { echo "Codex native binary missing" >&2; exit 1; }`,
		}}, nil
	},
	launcher: codexLauncher,
	bypassFlags: []bypassFlag{
		{name: "--dangerously-bypass-approvals-and-sandbox"},
		{name: "--yolo"},
		// Workspace-write sandboxing plus on-request approvals: Codex's own
		// sandbox cannot run inside OpenShell.
		{name: "--full-auto"},
		{name: "-a", value: func(v string) bool { return tomlStringIs(v, "never") }},
		{name: "--ask-for-approval", value: func(v string) bool { return tomlStringIs(v, "never") }},
		{name: "-c", value: codexApprovalNever},
		{name: "--config", value: codexApprovalNever},
	},
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		argv := []string{CodexLauncherPath}
		if opts.Mode == Headless {
			argv = append(argv, "exec", "--skip-git-repo-check")
		}
		if opts.Yolo {
			argv = append(argv, "--dangerously-bypass-approvals-and-sandbox")
		} else {
			// Codex's own bubblewrap/Landlock sandbox cannot nest inside
			// OpenShell; keep its approval prompts but not its sandbox.
			argv = append(argv, "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="on-request"`)
		}
		argv = append(argv, cp.LaunchArgs...)
		argv = append(argv, opts.Args...)
		if opts.Mode == Headless {
			argv = append(argv, opts.Prompt)
		}
		return argv, nil
	},
	credentialProfiles: []CredentialProfile{
		{
			ProfileID: profiles.OpenAIID, Hosts: []string{"api.openai.com"},
			ModelProvider: &connector.SandboxModelProvider{ID: connector.SandboxModelProviderOpenAI, BaseURL: "https://api.openai.com/v1"},
			Note:          "OPENAI_API_KEY sent as a bearer; the launcher exports it as CODEX_API_KEY for codex exec",
		},
		{
			ProfileID: profiles.CodexBedrockMantleID,
			Hosts:     []string{bedrockHostToken},
			LaunchArgs: append(codexProviderArgs(codexMantleProvider),
				// Mantle's OpenAI-compatible models do not serve these tools.
				"--disable", "multi_agent",
				"-c", `web_search="disabled"`,
			),
			ModelProvider: &codexMantleProvider,
			Note:          "Bedrock API key sent as a bearer to a Codex custom provider on the Mantle Responses route",
		},
	},
	customization: []CustomizationPath{
		{Host: ".codex/AGENTS.md", Sandbox: "/sandbox/.codex/AGENTS.md", Note: "user instructions"},
		{Host: ".codex/prompts", Sandbox: "/sandbox/.codex/prompts", Dir: true, Note: "user custom prompts"},
		{Host: ".codex/skills", Sandbox: "/sandbox/.codex/skills", Dir: true, Note: "user skills"},
	},
	preseedRefresh: []string{
		"export CODEX_API_KEY from the OPENAI_API_KEY placeholder (codex exec ignores OPENAI_API_KEY)",
		"trust the exact working directory under /work or /sandbox in ~/.codex/config.toml (the TUI trusts exact paths only)",
		"store the OPENAI_API_KEY placeholder with `codex login --with-api-key` before interactive runs",
		"add the OTLP Authorization header from DEFENSECLAW_SANDBOX_TOKEN with -c flags after the subcommand (managed_config.toml cannot carry a revision-scoped value)",
	},
})

// CodexLauncherPath is the in-image Codex launcher.
const CodexLauncherPath = LauncherDir + "/codex-launch"

// codexMantleProvider is the Codex custom provider on the Bedrock Mantle
// Responses route (the host is resolved per region).
var codexMantleProvider = connector.SandboxModelProvider{
	ID: "mantle", Name: "mantle", BaseURL: "https://" + bedrockHostToken + "/v1",
	EnvKey: "BEDROCK_MANTLE_API_KEY", WireAPI: "responses",
}

// codexProviderArgs selects a custom provider with session -c flags.
func codexProviderArgs(p connector.SandboxModelProvider) []string {
	return []string{
		"-c", `model_provider="` + p.ID + `"`,
		"-c", `model_providers.` + p.ID + `.name="` + p.Name + `"`,
		"-c", `model_providers.` + p.ID + `.base_url="` + p.BaseURL + `"`,
		"-c", `model_providers.` + p.ID + `.env_key="` + p.EnvKey + `"`,
		"-c", `model_providers.` + p.ID + `.wire_api="` + p.WireAPI + `"`,
	}
}

// codexApprovalNever matches a -c override that sets approval_policy to
// never.
func codexApprovalNever(v string) bool {
	key, value, ok := strings.Cut(v, "=")
	return ok && strings.TrimSpace(key) == "approval_policy" && tomlStringIs(value, "never")
}

var codexLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v2
# DefenseClaw Codex launcher (OpenShell sandbox images, root-owned). Adds the
# runtime-only settings that cannot live in static configuration, then execs
# the pinned Codex binary with the caller's arguments.
set -u
` + launcherPreamble + `if [ -z "${CODEX_API_KEY:-}" ] && [ -n "${OPENAI_API_KEY:-}" ]; then
  CODEX_API_KEY="$OPENAI_API_KEY"
  export CODEX_API_KEY
fi

sub=()
case "${1:-}" in
  exec|e|resume|review) sub=("$1"); shift ;;
esac

# The TUI trusts exact project paths only.
dir="$(pwd -P 2>/dev/null || true)"
home="${CODEX_HOME:-${HOME:-/sandbox}/.codex}"
case "$dir" in
  /work/*|/sandbox/*)
    case "$dir" in
      *[!A-Za-z0-9._/@+-]*) ;;
      *)
        if /bin/mkdir -p "$home" 2>/dev/null && [ ! -L "$home/config.toml" ]; then
          if ! /usr/bin/grep -qxF "[projects.\"$dir\"]" "$home/config.toml" 2>/dev/null; then
            printf '\n[projects."%s"]\ntrust_level = "trusted"\n' "$dir" >>"$home/config.toml" 2>/dev/null || true
          fi
        fi
        ;;
    esac
    ;;
esac

# The interactive client with the built-in OpenAI provider needs a stored
# login; refresh it with this start's placeholder.
if [ "${#sub[@]}" -eq 0 ] && [ -n "${OPENAI_API_KEY:-}" ]; then
  printf '%s' "$OPENAI_API_KEY" | /usr/local/bin/codex login --with-api-key >/dev/null 2>&1 || true
fi

# OTLP Authorization from the revision-scoped binding token placeholder.
# managed_config.toml does not define the key, so the session flags merge
# into its exporters; they must follow the subcommand.
otel=()
token="${DEFENSECLAW_SANDBOX_TOKEN:-}"
case "$token" in
  ''|*[!A-Za-z0-9:._-]*) ;;
  *)
    for exporter in exporter trace_exporter metrics_exporter; do
      otel+=(-c "otel.${exporter}.otlp-http.headers.authorization=\"Bearer ${token}\"")
    done
    ;;
esac
` + launcherExec(`/usr/local/bin/codex "${sub[@]+"${sub[@]}"}" "${otel[@]+"${otel[@]}"}" "$@"`)
