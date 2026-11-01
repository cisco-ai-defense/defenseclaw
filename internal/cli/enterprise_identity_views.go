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
	// These views only read registrations and policy; they do not start
	// sandboxes, so Windows exposes the administrator's views too.
	commands = append(commands, newEnterpriseSandboxCommand(platform))
	if platform == "windows" {
		policy, _, _, _ := newEnterprisePolicyGroup(platform)
		commands = append(commands, policy)
	}
	return commands
}

func newEnterpriseIdentityViewCommand(platform string, view enterpriseIdentityView) *cobra.Command {
	values := make([]string, len(view.flags))
	aiOnly, asJSON := false, false
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
			if view.use == "profile-explain" {
				if refusal := refuseEnterpriseIdentityViewForStandardUser(cmd); refusal != nil {
					// A standard user explains their own profile (GAP-0431, GAP-0422).
					return explainOwnGuardrailProfile(cmd, values[0], values[1], values[2], refusal, refusal, asJSON)
				}
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
			if view.use == "profile-explain" {
				// The account as root resolves it, so explain needs no root-only
				// lookup in the gateway service (GAP-0500).
				if facts := enterpriseExplainCallerFacts(query.Get("user")); facts != "" {
					query.Set("caller_facts", facts)
				}
			}
			if view.use == "agent-identities" && query.Get("user") != "" {
				// root's proof of the account's home tells an account deleted
				// and created again under the same name and uid from the one
				// before it, also before the guardian's next pass (GAP-0422).
				if proof := enterpriseIdentityViewHolderProof(query.Get("user")); proof != "" {
					query.Set("holder_proof", proof)
				}
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
				return managedAdminViewRefusal(cmd, err, asJSON)
			}
			runtimeCommand = cmd
			if view.use == "agent-identities" && query.Get("user") != "" {
				// The rows carry the bare account name and the gateway matches it
				// as ide-plugins does, so the listing decides; only an empty one
				// asks whether the account exists, and a name that resolves to
				// no account is refused with its reason (GAP-1081).
				var answer json.RawMessage
				if _, err := enterpriseIdentityViewGet(path, &answer); err != nil {
					return enterpriseIdentityViewError(err)
				}
				var listed struct {
					Total int `json:"total"`
				}
				if json.Unmarshal(answer, &listed) == nil && listed.Total == 0 {
					if err := refuseUnknownIdentityViewAccount(query.Get("user")); err != nil {
						return err
					}
				}
				return printEnterpriseIdentityView(cmd.OutOrStdout(), answer)
			}
			if view.use == "profile-explain" {
				// The gateway answers the guardrail side; the administrator
				// also wants the sandbox policy of the matched profile.
				var answer json.RawMessage
				if _, err := enterpriseIdentityViewGet(path, &answer); err != nil {
					return enterpriseIdentityViewError(err)
				}
				if err := printEnterpriseIdentityView(cmd.OutOrStdout(), addSandboxToProfileExplain(answer, cfg)); err != nil {
					return err
				}
				// The gateway answers an account it cannot resolve with
				// lookup_error and no user id; the answer is printed and the
				// command fails, as `defenseclaw guardrail profile explain`
				// does. A resolved account with no matching profile succeeds.
				if lookupErr := unresolvedProfileExplainAccount(answer); lookupErr != "" {
					failure := withExitCode(fmt.Errorf("user lookup failed: %s", lookupErr), enterprisestatus.UnixExitFailure)
					silenceJSONReportedError(cmd, asJSON, failure)
					return failure
				}
				return nil
			}
			if err := writeEnterpriseIdentityView(cmd.OutOrStdout(), path); err != nil {
				return enterpriseIdentityViewError(err)
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
	// The answer is always JSON; --json is accepted as on the other managed
	// views, and makes a refusal JSON too (GAP-0333).
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON (the default); a refusal is printed as JSON too")
	return cmd
}

// managedAdminViewRefusal is a standard user's refusal of an administrator
// view (err names the administrator command): exit failure, the code
// elevation_required, and for a --json caller the errors[] document on
// stdout instead of a bare line, so every view refuses alike (GAP-0333).
func managedAdminViewRefusal(cmd *cobra.Command, err error, asJSON bool) error {
	refusal := withExitCode(&managedViewRefusal{code: "elevation_required", message: err.Error()}, enterprisestatus.UnixExitFailure)
	if asJSON {
		writeManagedViewRefusalJSON(cmd.OutOrStdout(), refusal)
		silenceJSONReportedError(cmd, true, refusal)
	}
	return refusal
}

// enterpriseIdentityViewGet reads one gateway route; replaceable in tests.
var enterpriseIdentityViewGet = enterpriseGatewayGet

// writeEnterpriseIdentityView prints the gateway's answer to path, indented.
func writeEnterpriseIdentityView(w io.Writer, path string) error {
	var answer json.RawMessage
	if _, err := enterpriseIdentityViewGet(path, &answer); err != nil {
		return err
	}
	return printEnterpriseIdentityView(w, answer)
}

func printEnterpriseIdentityView(w io.Writer, answer json.RawMessage) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(answer)
}

// enterpriseIdentityViewError keeps an invalid-arguments refusal's exit code
// and gives any other failure the platform's failure code.
func enterpriseIdentityViewError(err error) error {
	if commandExitCode(err) == enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
		return err
	}
	return withExitCode(err, enterprisestatus.UnixExitFailure)
}

// unresolvedProfileExplainAccount returns the gateway's lookup_error when
// the account it was asked about did not resolve. A numeric uid may still
// appear in subject.user_id for comparison with a hook call from that uid.
func unresolvedProfileExplainAccount(answer json.RawMessage) string {
	var resolved struct {
		LookupError       string `json:"lookup_error"`
		AccountUnresolved bool   `json:"account_unresolved"`
		Subject           struct {
			UserID string `json:"user_id"`
		} `json:"subject"`
	}
	if json.Unmarshal(answer, &resolved) != nil || resolved.Subject.UserID != "" && !resolved.AccountUnresolved {
		return ""
	}
	return resolved.LookupError
}

// refuseUnknownIdentityViewAccount refuses a --user that names no account,
// with the reason profile-explain gives and the spellings the view takes. It
// sends the account as root resolves it, as profile-explain does (GAP-0500):
// the gateway service cannot look up a bare directory name on an
// SSSD-joined host itself, and refused an existing account whose listing
// was empty (GAP-2035).
func refuseUnknownIdentityViewAccount(user string) error {
	query := url.Values{"user": {user}}
	if facts := enterpriseExplainCallerFacts(user); facts != "" {
		query.Set("caller_facts", facts)
	}
	var answer json.RawMessage
	if _, err := enterpriseIdentityViewGet("/api/v1/guardrail/profiles/resolve?"+query.Encode(), &answer); err != nil {
		return enterpriseIdentityViewError(err)
	}
	lookupErr := unresolvedProfileExplainAccount(answer)
	if lookupErr == "" {
		return nil
	}
	spellings := "the account name, user@domain as id prints it, DOMAIN\\name or the uid"
	if runtime.GOOS == "windows" {
		spellings = "the account name, DOMAIN\\name, .\\name or the SID"
	}
	return invalidLifecycleArguments(fmt.Errorf("%s; --user takes %s", lookupErr, spellings))
}

// enterprisePlatformGOOS is the GOOS of an `enterprise <platform>` group.
func enterprisePlatformGOOS(platform string) string {
	if platform == "macos" {
		return "darwin"
	}
	return platform
}
