// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The identity views of a managed host. A managed install ships this Go CLI
// only, without the Python `defenseclaw guardrail profile explain`, `agent
// identities` and `agent ide-plugins`, so an administrator had no command
// for them (GAP-0022, GAP-0023). These read the same gateway routes with
// the deployment's service token, as `enterprise <platform> discovery` does,
// and print the gateway's JSON answer.

// enterpriseIdentityView is one read-only view: its command, the gateway
// route it reads and the query flags it forwards.
type enterpriseIdentityView struct {
	use, short, path string
	// flags maps a flag name to its query parameter and usage.
	flags [][3]string
}

var enterpriseIdentityViews = []enterpriseIdentityView{
	{
		use:   "profile-explain",
		short: "Show which guardrail profile a user, connector or agent gets, and why (read-only)",
		path:  "/api/v1/guardrail/profiles/resolve",
		flags: [][3]string{
			{"user", "user", "account name, uid, SID or principal"},
			{"connector", "connector", "connector name, for example codex"},
			{"agent", "agent", "agent identity (agt- and 16 hex digits)"},
		},
	},
	{
		use:   "agent-identities",
		short: "List the agent identities the gateway has seen (read-only)",
		path:  "/api/v1/agents/identities",
		flags: [][3]string{
			{"user", "user", "only this account (name or id)"},
			{"connector", "connector", "only this connector"},
			{"cursor", "cursor", "the next_cursor of the previous page"},
		},
	},
	{
		use:   "ide-plugins",
		short: "List the IDE extensions and plugins of the last AI Discovery scan (read-only)",
		path:  "/api/v1/ai-usage/ide-plugins",
		flags: [][3]string{
			{"user", "user", "only this account (name or id)"},
			{"ide", "ide", "only this IDE product or family, for example vscode or jetbrains"},
			{"cursor", "cursor", "the next_cursor of the previous page"},
		},
	},
}

// enterpriseIdentityViewAnnotation marks the identity view commands.
const enterpriseIdentityViewAnnotation = "defenseclaw.identity-view"

// secureClientAbsentAnnotation marks a command or flag main does not have,
// which a Secure Client computer drops; secureClientHiddenAnnotation a
// command main does not have that a Secure Client computer keeps runnable
// but leaves out of its help (config migrate answers that its config stays
// on config_version 8); secureClientShortAnnotation holds the help line and
// secureClientLongAnnotation the help text of main for a command whose help
// changed, and the flag annotation secureClientUsageAnnotation the usage
// line of main for a flag (issue #1092).
const (
	secureClientAbsentAnnotation = "defenseclaw.secure-client-absent"
	secureClientHiddenAnnotation = "defenseclaw.secure-client-hidden"
	secureClientShortAnnotation  = "defenseclaw.secure-client-short"
	secureClientLongAnnotation   = "defenseclaw.secure-client-long"
	secureClientUsageAnnotation  = "defenseclaw.secure-client-usage"
)

// keepCommandTreeOfMainOnSecureClient gives a Secure Client computer the
// command tree of main (issue #1092): it removes the identity views of the
// `enterprise <platform>` groups, whose routes its gateway does not serve,
// and every command or flag marked secureClientAbsentAnnotation (policy
// digest, scan skill|mcp|plugin, enterprise acp setup, audit export --db),
// hides the commands marked secureClientHiddenAnnotation (config), and puts
// back the help of main where a command carries secureClientShortAnnotation
// (policy show, policy validate) or secureClientLongAnnotation (enterprise
// acp, audit export, rulepack), or a flag carries secureClientUsageAnnotation
// (enterprise windows discovery --user, sandbox setup --no-mounts).
func keepCommandTreeOfMainOnSecureClient(root *cobra.Command) {
	if !secureClientHost() {
		return
	}
	var keep func(parent *cobra.Command)
	keep = func(parent *cobra.Command) {
		for _, cmd := range parent.Commands() {
			if cmd.Annotations[enterpriseIdentityViewAnnotation] != "" || cmd.Annotations[secureClientAbsentAnnotation] != "" {
				parent.RemoveCommand(cmd)
				continue
			}
			if short := cmd.Annotations[secureClientShortAnnotation]; short != "" {
				cmd.Short = short
			}
			if long := cmd.Annotations[secureClientLongAnnotation]; long != "" {
				cmd.Long = long
			}
			if cmd.Annotations[secureClientHiddenAnnotation] != "" {
				cmd.Hidden = true
			}
			dropSecureClientAbsentFlags(cmd)
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				if usage := flag.Annotations[secureClientUsageAnnotation]; len(usage) == 1 {
					flag.Usage = usage[0]
				}
			})
			keep(cmd)
		}
	}
	keep(root)
}

// dropSecureClientAbsentFlags removes the flags of cmd that main does not
// have, so a Secure Client computer refuses them as unknown flags, as main
// does. pflag cannot delete a flag, so the command gets new flag sets with
// every other flag (and its value binding) kept.
func dropSecureClientAbsentFlags(cmd *cobra.Command) {
	absent := func(flag *pflag.Flag) bool { return len(flag.Annotations[secureClientAbsentAnnotation]) > 0 }
	found := false
	for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags()} {
		set.VisitAll(func(flag *pflag.Flag) { found = found || absent(flag) })
	}
	if !found {
		return
	}
	var local, persistent []*pflag.Flag
	cmd.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) { local = append(local, flag) })
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) { persistent = append(persistent, flag) })
	cmd.ResetFlags()
	for _, flag := range local {
		if !absent(flag) {
			cmd.Flags().AddFlag(flag)
		}
	}
	for _, flag := range persistent {
		if !absent(flag) {
			cmd.PersistentFlags().AddFlag(flag)
		}
	}
}

// newEnterpriseIdentityViewCommands returns the identity views of
// `enterprise <platform>`.
func newEnterpriseIdentityViewCommands(platform string) []*cobra.Command {
	commands := make([]*cobra.Command, 0, len(enterpriseIdentityViews))
	for _, view := range enterpriseIdentityViews {
		commands = append(commands, newEnterpriseIdentityViewCommand(platform, view))
	}
	return commands
}

func newEnterpriseIdentityViewCommand(platform string, view enterpriseIdentityView) *cobra.Command {
	values := make([]string, len(view.flags))
	aiOnly := false
	cmd := &cobra.Command{
		Use:   view.use,
		Short: view.short,
		Long: view.short + `.

It asks the managed deployment's local gateway and prints its JSON answer;
it changes nothing. Run it as root on Linux and macOS, or from an elevated
Administrator prompt (or as LocalSystem from an MDM script) on Windows.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{enterpriseIdentityViewAnnotation: view.use},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if goos := enterprisePlatformGOOS(platform); runtime.GOOS != goos {
				return invalidLifecycleArguments(fmt.Errorf("`enterprise %s %s` reads %s hosts; this host is %s", platform, view.use, goos, runtime.GOOS))
			}
			query := url.Values{}
			for i, flag := range view.flags {
				if values[i] != "" {
					query.Set(flag[1], values[i])
				}
			}
			if view.use == "profile-explain" && query.Get("user") == "" {
				return invalidLifecycleArguments(fmt.Errorf("--user is required to explain a guardrail profile"))
			}
			if aiOnly {
				query.Set("ai_only", "true")
			}
			path := view.path
			if len(query) > 0 {
				path += "?" + query.Encode()
			}
			// A standard user cannot read the administrator's deployment: say
			// so and name the administrator command, as status and audit
			// export do, instead of a raw config permission error (GAP-0610).
			if err := refuseEnterpriseIdentityViewForStandardUser(cmd); err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			runtimeCommand = cmd
			if err := writeEnterpriseIdentityView(cmd.OutOrStdout(), path); err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			return nil
		},
	}
	for i, flag := range view.flags {
		cmd.Flags().StringVar(&values[i], flag[0], "", flag[2])
	}
	if view.use == "ide-plugins" {
		cmd.Flags().BoolVar(&aiOnly, "ai-only", false, "only AI plugins")
	}
	return cmd
}

// enterpriseIdentityViewGet reads one gateway route; replaceable in tests.
var enterpriseIdentityViewGet = enterpriseGatewayGet

// writeEnterpriseIdentityView prints the gateway's answer to path, indented.
func writeEnterpriseIdentityView(w io.Writer, path string) error {
	var answer json.RawMessage
	if _, err := enterpriseIdentityViewGet(path, &answer); err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(answer)
}

// enterprisePlatformGOOS is the GOOS of an `enterprise <platform>` group.
func enterprisePlatformGOOS(platform string) string {
	if platform == "macos" {
		return "darwin"
	}
	return platform
}
