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

package cli

import (
	"slices"
	"strings"
)

// managedAvailability is what a standard user gets from one `defenseclaw`
// command on a managed computer.
type managedAvailability string

const (
	// managedOffered: the command runs for the user.
	managedOffered managedAvailability = "Offered"
	// managedRefused: the command answers with a refusal that names the
	// managed alternative.
	managedRefused managedAvailability = "Refused"
	// managedAdminOnly: the command runs only from an elevated prompt; a
	// standard account is told so.
	managedAdminOnly managedAvailability = "Administrators only"
	// managedUnsupported: the platform cannot run the command at all.
	managedUnsupported managedAvailability = "Not supported"
)

// launcherPattern matches the arguments of one command the managed launcher
// (the standard user's `defenseclaw` on Linux and macOS, launcher.go) runs:
// words are a prefix of the arguments, or all of them when exact is set.
type launcherPattern struct {
	words []string
	exact bool
}

func (p launcherPattern) matches(args []string) bool {
	if len(args) < len(p.words) || (p.exact && len(args) != len(p.words)) {
		return false
	}
	return slices.Equal(args[:len(p.words)], p.words)
}

// managedCommand is one row of the managed command-availability table. The
// table is the single source of three things that used to be written apart:
// the commands the launcher runs (launcherOffers reads Launcher), the names
// the managed Windows binary answers instead of running (Windows), and the
// documentation page that says which command is available where
// (docs-site/content/docs/enterprise/managed-commands.mdx is generated from
// testdata/managed_commands.json, which TestManagedCommandsGolden pins).
type managedCommand struct {
	// Command is what a user types, as the documentation shows it.
	Command string
	// Launcher lists the arguments the Linux and macOS launcher runs; a
	// command with none is refused there.
	Launcher []launcherPattern
	// Windows is the standard user's answer on a managed Windows computer.
	// Offered means the installed defenseclaw.exe has the command and runs it
	// for a standard account; TestManagedCommandsMatchTheWindowsBinary checks
	// every value against the command tree.
	Windows managedAvailability
	// Probes are the command paths the Windows check looks up (empty for the
	// help row, which every cobra root has).
	Probes [][]string
	// PerUser names the operating systems whose per-user install has the
	// command. Every per-user command is checked against the Python CLI.
	PerUser string
	// PerUserPath is the Python command path that PerUser claims.
	PerUserPath []string
	// Note is one plain sentence for the table.
	Note string
}

const perUserEverywhere = "Linux, macOS, Windows"

// managedCommands is ordered as the documentation table is.
var managedCommands = []managedCommand{
	{
		Command: "defenseclaw --help, --version, help",
		Launcher: []launcherPattern{
			{words: nil, exact: true},
			{words: []string{"-h"}}, {words: []string{"--help"}}, {words: []string{"--version"}},
			{words: []string{"help"}, exact: true},
			{words: []string{"help", "sandbox"}}, {words: []string{"help", "status"}},
			{words: []string{"help", "-h"}}, {words: []string{"help", "--help"}},
		},
		Windows: managedOffered,
		PerUser: perUserEverywhere,
		Note:    "The launcher shows its own help; `help` explains the sandbox and status commands.",
	},
	{
		Command:  "defenseclaw status",
		Launcher: []launcherPattern{{words: []string{"status"}}},
		Windows:  managedOffered,
		Probes:   [][]string{{"status"}},
		PerUser:  perUserEverywhere, PerUserPath: []string{"status"},
		Note: "Shows your own protection state: `protected`, `not protected`, `not confirmed`, or `excluded` for an account named in `enterprise.enrollment.exclude_users`; the reason says whether the machine policy still inspects its calls. An administrator's run shows the deployment.",
	},
	{
		Command: "defenseclaw routing status, routing budgets list, routing explain",
		Launcher: []launcherPattern{
			{words: []string{"routing", "status"}}, {words: []string{"routing", "budgets", "list"}},
			{words: []string{"routing", "explain"}},
		},
		Windows: managedOffered,
		Probes:  [][]string{{"routing", "status"}, {"routing", "budgets", "list"}, {"routing", "explain"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"routing", "status"},
		Note: "Shows your own model routing decisions and budgets, read from the managed gateway; every other routing command is set in the administrator's config.",
	},
	{
		Command:  "defenseclaw sandbox ...",
		Launcher: []launcherPattern{{words: []string{"sandbox"}}},
		Windows:  managedUnsupported,
		Probes:   [][]string{{"sandbox"}},
		PerUser:  "Linux, macOS", PerUserPath: []string{"sandbox"},
		Note: "OpenShell sandboxes run on Linux and macOS only.",
	},
	{
		Command:  "defenseclaw guardrail profile explain",
		Launcher: []launcherPattern{{words: []string{"guardrail", "profile", "explain"}}},
		Windows:  managedRefused,
		Probes:   [][]string{{"guardrail", "profile", "explain"}},
		PerUser:  perUserEverywhere, PerUserPath: []string{"guardrail", "profile", "explain"},
		Note: "Shows the guardrail profile that applies to your agents. On Windows the answer points to the administrator's policy view.",
	},
	{
		Command: "defenseclaw guardrail",
		Windows: managedRefused,
		Probes:  [][]string{{"guardrail"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"guardrail", "status"},
		Note: "Every guardrail command except `profile explain`, which the row above offers. The guardrail is set in the administrator's config.",
	},
	{
		Command: "defenseclaw doctor",
		Windows: managedRefused,
		Probes:  [][]string{{"doctor"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"doctor"},
		Note: "An administrator reads the deployment with the enterprise status and verify commands.",
	},
	{
		Command: "defenseclaw alerts",
		Windows: managedRefused,
		Probes:  [][]string{{"alerts"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"alerts"},
		Note: "The per-user alerts view is not part of a managed install; an administrator reads the deployment with the enterprise status command.",
	},
	{
		Command: "defenseclaw tui",
		Windows: managedRefused,
		Probes:  [][]string{{"tui"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"tui"},
		Note: "The terminal UI is part of the per-user install.",
	},
	{
		Command: "defenseclaw upgrade",
		Windows: managedRefused,
		Probes:  [][]string{{"upgrade"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"upgrade"},
		Note: "The administrator's lifecycle applies updates.",
	},
	{
		Command: "defenseclaw rollback",
		Windows: managedRefused,
		Probes:  [][]string{{"rollback"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"rollback"},
		Note: "The administrator's lifecycle applies rollbacks.",
	},
	{
		Command: "defenseclaw setup ...",
		Windows: managedRefused,
		Probes:  [][]string{{"setup"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"setup"},
		Note: "Setup belongs to the per-user install.",
	},
	{
		Command: "defenseclaw config set",
		Windows: managedRefused,
		Probes:  [][]string{{"config", "set"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"config", "set"},
		Note: "The configuration is changed in the administrator's config.",
	},
	{
		Command: "defenseclaw config unset",
		Windows: managedRefused,
		Probes:  [][]string{{"config", "unset"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"config", "unset"},
		Note: "The configuration is changed in the administrator's config.",
	},
	{
		Command: "defenseclaw skill ...",
		Windows: managedRefused,
		Probes:  [][]string{{"skill"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"skill"},
		Note: "The admission policy is set in the administrator's config; an administrator scans an asset from an elevated prompt.",
	},
	{
		Command: "defenseclaw mcp ...",
		Windows: managedRefused,
		Probes:  [][]string{{"mcp"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"mcp"},
		Note: "Same as `skill`.",
	},
	{
		Command: "defenseclaw plugin ...",
		Windows: managedRefused,
		Probes:  [][]string{{"plugin"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"plugin"},
		Note: "Same as `skill`.",
	},
	{
		Command: "defenseclaw tool ...",
		Windows: managedRefused,
		Probes:  [][]string{{"tool"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"tool"},
		Note: "Same as `skill`.",
	},
	{
		Command: "defenseclaw <other per-user command>",
		Windows: managedRefused,
		Probes:  [][]string{{"acp"}, {"agent"}, {"aibom"}, {"codeguard"}, {"edge-connector"}, {"init"}, {"keys"}, {"migrate"}, {"observability"}, {"quickstart"}, {"registry"}, {"reset"}, {"settings"}, {"uninstall"}, {"version"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"agent"},
		Note: "Every other per-user command (acp, agent, aibom, codeguard, edge-connector, init, keys, migrate, observability, quickstart, registry, reset, settings, uninstall, version) belongs to the per-user install; each answers with the managed message and changes nothing.",
	},
	{
		Command: "defenseclaw policy show",
		Windows: managedAdminOnly,
		Probes:  [][]string{{"policy", "show"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"policy", "show"},
		Note: "A standard account is told to use an elevated prompt.",
	},
	{
		Command: "defenseclaw audit export",
		Windows: managedAdminOnly,
		Probes:  [][]string{{"audit", "export"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"audit", "export"},
		Note: "The managed audit log is administrator-only.",
	},
	{
		Command: "defenseclaw audit compact",
		Windows: managedAdminOnly,
		Probes:  [][]string{{"audit", "compact"}},
		PerUser: perUserEverywhere, PerUserPath: []string{"audit", "compact"},
		Note: "Gives the disk space of deleted audit history back. An administrator runs it after stopping the gateway service.",
	},
}

// launcherOffers reports whether the launcher runs args at all. The bare
// command and the help and version requests show the launcher's own text.
// The table above decides; there is no second list.
func launcherOffers(args []string) bool {
	for _, command := range managedCommands {
		for _, pattern := range command.Launcher {
			if pattern.matches(args) {
				return true
			}
		}
	}
	return false
}

// managedCommandsDoc is the JSON the documentation generator reads.
type managedCommandsDoc struct {
	// Refusal is the launcher's answer on each operating system, from
	// launcherRefusalFor.
	Refusal map[string]string `json:"refusal"`
	// Commands is the table, one row per command.
	Commands []managedCommandDocRow `json:"commands"`
}

type managedCommandDocRow struct {
	Command     string `json:"command"`
	Linux       string `json:"managed_linux"`
	MacOS       string `json:"managed_macos"`
	Windows     string `json:"managed_windows"`
	PerUser     string `json:"per_user"`
	PerUserPath string `json:"per_user_path,omitempty"`
	Note        string `json:"note"`
}

// buildManagedCommandsDoc evaluates the table. The Linux and macOS cells come
// from running launcherOffers on the row's own arguments, so a pattern that
// stops matching changes the page.
func buildManagedCommandsDoc() managedCommandsDoc {
	doc := managedCommandsDoc{Refusal: map[string]string{}}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		doc.Refusal[goos] = launcherRefusalFor(goos)
	}
	for _, command := range managedCommands {
		launcher := managedRefused
		if len(command.Launcher) > 0 {
			launcher = managedOffered
			for _, pattern := range command.Launcher {
				if !launcherOffers(pattern.words) {
					launcher = managedRefused
				}
			}
		}
		doc.Commands = append(doc.Commands, managedCommandDocRow{
			Command:     command.Command,
			Linux:       string(launcher),
			MacOS:       string(launcher),
			Windows:     string(command.Windows),
			PerUser:     command.PerUser,
			PerUserPath: strings.Join(command.PerUserPath, " "),
			Note:        command.Note,
		})
	}
	return doc
}
