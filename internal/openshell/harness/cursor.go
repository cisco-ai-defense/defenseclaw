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

// cursorPin is the Cursor Agent CLI build the cursor-hooks-v1 contract
// reviewed (its only accepted Agent CLI build). Cursor publishes no digests;
// these are the sha256 of the archives Cursor's installer
// (cursor.com/install) downloads for this build, measured by DefenseClaw on
// 2026-09-27.
var cursorPin = tarballPin{
	Version: "2026.07.23-e383d2b",
	Archives: map[string]tarballArchive{
		"aarch64": {URL: "https://downloads.cursor.com/lab/2026.07.23-e383d2b/linux/arm64/agent-cli-package.tar.gz", SHA256: "f40b99647cb24e0da885e97620a2048034f1fe8961910d573d827d77c4d26dcb"},
		"x86_64":  {URL: "https://downloads.cursor.com/lab/2026.07.23-e383d2b/linux/x64/agent-cli-package.tar.gz", SHA256: "702ad595213bee5df0268be9f80a19f29fcceaa2a42fc55e39f2b5199051f0c4"},
	},
	Strip:        1,
	DigestSource: "measured by DefenseClaw (Cursor publishes no archive digests)",
}

// cursorVersionRE matches Cursor Agent's date-hash builds.
var cursorVersionRE = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-f]{7,40}$`)

// Cursor is the Cursor Agent CLI harness. Its hooks are the root-owned
// enterprise /etc/cursor/hooks.json, which the CLI runs ahead of team, user
// and project hooks and whose deny wins (tamper tier managed).
//
// The Agent CLI sends every model request through Cursor's service
// (api2.cursor.sh), after a Cursor login or with CURSOR_API_KEY, and offers
// no local or bring-your-own model endpoint, so neither the hook-fire probe's
// mock nor a Bedrock model can drive it and its images stay unverified until
// a probe runs with a Cursor key.
var Cursor = register(&Spec{
	Name:           "cursor",
	DisplayName:    "Cursor Agent",
	Command:        "cursor-agent",
	DefaultVersion: cursorPin.Version,
	Provider:       connector.NewCursorConnector(),
	TamperTier:     connector.SandboxTamperTierManaged,
	verification: Verification{
		Status: Unverified,
		Note:   "the Cursor Agent CLI needs a Cursor account (CURSOR_API_KEY or `cursor-agent login`) before any agent turn: without one it stops with \"Authentication required\" and fires no hook, and it has no local or bring-your-own model endpoint a mock or Bedrock could serve. Measured on the pin: it reads /etc/cursor/hooks.json as the enterprise tier. Measured on Cursor's agent-cli-local build of the same release (authless, local model; not what the image ships): the enterprise hooks fire (sessionStart, preToolUse, beforeShellExecution, afterShellExecution, postToolUse, sessionEnd), a deny object or exit 2 blocks the shell call, a failing hook blocks only with failClosed (the image sets it), and user and project hooks.json that answer allow, plus a Claude settings disableAllHooks, change nothing. Hook firing at the ingress and blocking with the pinned build, and the Cursor endpoint set, need a Cursor key",
	},
	versionPattern: cursorVersionRE,
	probe: ProbeSpec{
		VersionArgv: []string{"/usr/local/bin/cursor-agent", "--version"},
		VersionRE:   regexp.MustCompile(`^([0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-f]+)$`),
		// cursor-agent is a shell wrapper around the bundled node, which
		// makes every request.
		NetworkBinaries: `readlink -f ` + InstallRootBase + `/cursor/node`,
	},
	install: func(version string) ([]InstallStep, error) {
		root := InstallRootBase + "/cursor"
		run, err := cursorPin.installRun(root, version)
		if err != nil {
			return nil, err
		}
		link := `for b in cursor-agent node index.js; do [ -e "$root/$b" ] || { echo "Cursor Agent archive lacks $b" >&2; exit 1; }; done; ` +
			`ln -sfn "$root/cursor-agent" /usr/local/bin/cursor-agent; ln -sfn "$root/cursor-agent" /usr/local/bin/agent; ` +
			`h="$(mktemp -d)"; got="$(HOME="$h" /usr/local/bin/cursor-agent --version 2>/dev/null | head -n 1)"; rm -rf "$h"; ` +
			`[ "$got" = ` + shellQuote(version) + ` ] || { echo "Cursor Agent '$got' is not the pinned ` + version + `" >&2; exit 1; }`
		return []InstallStep{{
			Comment: "Install Cursor Agent " + version + " from its release archive into a root-owned prefix (sha256 checked)",
			Run:     run + "; " + link,
		}}, nil
	},
	launcher: cursorLauncher,
	launchArgv: func(opts LaunchOptions, cp CredentialProfile) ([]string, error) {
		// The workspace is trusted without a prompt (every project is
		// mounted under /work) and Cursor's own sandbox is off: it cannot
		// nest inside OpenShell, which is the boundary.
		argv := []string{CursorLauncherPath, "--trust", "--sandbox", "disabled"}
		if opts.Yolo {
			argv = append(argv, "--force")
		}
		if opts.Mode == Headless {
			argv = append(argv, "-p", "--output-format", "text")
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
			ProfileID:  profiles.CursorID,
			Hosts:      []string{"api2.cursor.sh", "api3.cursor.sh", "repo42.cursor.sh"},
			Note:       "CURSOR_API_KEY (a Cursor user or team API key) sent to Cursor's service, which serves authentication and every model request",
			Unverified: "no Cursor account key was available: the host set is the service endpoints the pinned CLI names (api2.cursor.sh is its default endpoint), not a live run",
		},
	},
	login: &LoginOption{
		Argv:       []string{CursorLauncherPath, "login"},
		Note:       "browser login inside the sandbox (cursor-agent login through the launcher); the session stays in the sandbox HOME, where the workload can read it and send it out, so prefer the CURSOR_API_KEY provider profile",
		Unverified: "no Cursor account was available to complete a login",
	},
	customization: []CustomizationPath{
		{Host: ".cursor/rules", Sandbox: "/sandbox/.cursor/rules", Dir: true, Note: "user rules"},
		{Host: ".cursor/commands", Sandbox: "/sandbox/.cursor/commands", Dir: true, Note: "user slash commands"},
	},
	preseedRefresh: []string{
		"trust the working directory with --trust (every project is mounted under /work) and switch Cursor's own sandbox off with --sandbox disabled",
		"switch Node's compile cache off (NODE_DISABLE_COMPILE_CACHE=1): the cursor-agent wrapper points NODE_COMPILE_CACHE at ~/.cache/cursor-compile-cache, and Node runs the V8 code cached there in place of the root-owned index.js chunks, hooks runner included",
	},
})

// CursorLauncherPath is the in-image Cursor Agent launcher.
const CursorLauncherPath = LauncherDir + "/cursor-launch"

var cursorLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-launcher v1
# DefenseClaw Cursor Agent launcher (OpenShell sandbox images, root-owned).
# The DefenseClaw hooks are Cursor's enterprise /etc/cursor/hooks.json, which
# no environment or user setting moves; export the egress proxy, keep Node's
# compile cache off (see launcherPreamble) and exec the pinned Cursor Agent
# with the caller's arguments.
set -u
` + launcherPreamble + launcherExec(`/usr/local/bin/cursor-agent "$@"`)
