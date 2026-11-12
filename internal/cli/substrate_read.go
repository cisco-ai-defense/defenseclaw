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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// actorRef is how a person names an actor: "name" or "atespace/name".
func resolveSubstrateActor(ctx context.Context, cl *api.Client, ref string) (api.Actor, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return api.Actor{}, errors.New("name the agent; list yours with: defenseclaw substrate list")
	}
	actors, err := cl.List(ctx, api.ListOptions{})
	if err != nil {
		return api.Actor{}, err
	}
	var hits []api.Actor
	for _, a := range actors {
		if a.Deleted {
			continue
		}
		if ref == a.Name || ref == a.Atespace+"/"+a.Name {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 0:
		return api.Actor{}, fmt.Errorf("you have no agent named %q; list yours with: defenseclaw substrate list", ref)
	case 1:
		return hits[0], nil
	}
	var names []string
	for _, a := range hits {
		names = append(names, a.Atespace+"/"+a.Name)
	}
	return api.Actor{}, fmt.Errorf("%q matches more than one agent (%s); name it as ATESPACE/NAME", ref, strings.Join(names, ", "))
}

func substrateAge(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func substrateDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- list -------------------------------------------------------------------

func newSubstrateListCmd() *cobra.Command {
	var (
		out   substrateOutput
		com   substrateCommon
		batch string
		all   bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your agents in the cluster",
		Long: `Lists the agents you started: their name, the coding agent, the profile that guards
them and how long ago they started. Administrators see only their own agents unless they pass --all.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			actors, err := s.Client.List(ctx, api.ListOptions{Batch: batch, All: all})
			if err != nil {
				return substrateFail(err)
			}
			live := actors[:0]
			for _, a := range actors {
				if !a.Deleted {
					live = append(live, a)
				}
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), map[string]any{"actors": live})
			}
			if len(live) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "You have no agents running. Start one with: defenseclaw substrate run claude")
				return nil
			}
			now := time.Now()
			rows := make([][]string, 0, len(live))
			for _, a := range live {
				rows = append(rows, []string{a.Atespace + "/" + a.Name, substrateDash(a.Connector), substrateDash(a.Profile), substrateAge(a.CreatedAt, now), substrateDash(a.BatchID)})
			}
			substrateTable(cmd.OutOrStdout(), []string{"NAME", "AGENT", "PROFILE", "AGE", "BATCH"}, rows)
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&batch, "batch", "", "only the agents of this batch")
	cmd.Flags().BoolVar(&all, "all", false, "every person's agents (administrators only)")
	return cmd
}

// --- status -----------------------------------------------------------------

func newSubstrateStatusCmd() *cobra.Command {
	var (
		out     substrateOutput
		cf      substrateClusterFlags
		batch   string
		cluster bool
	)
	com := &cf.com
	cmd := &cobra.Command{
		Use:   "status [name]",
		Short: "Show who you are signed in as, or one agent or batch in detail",
		Long: `Without a name, shows the cluster and account in use and how many agents you have.
With a name, shows that agent: where it runs, which profile guards it and its batch.
With --batch, shows every agent of a batch run.

For administrators, --cluster shows the health of the whole setup: gateway, leader, controller and callout,
the agents in the cluster and the setup checks. It reads the cluster with kubectl (give --install-file), or
with --api from the DefenseClaw gateway. Exit 75 means the cluster could not be reached; there is no document.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cluster {
				if len(args) > 0 || batch != "" {
					return withExitCode(errors.New("--cluster shows the whole cluster; leave the name and --batch out"), 2)
				}
				return runSubstrateFleet(cmd, "status", &out, &cf)
			}
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			w := cmd.OutOrStdout()
			switch {
			case batch != "":
				b, err := s.Client.Batch(ctx, batch)
				if err != nil {
					return substrateFail(err)
				}
				if asJSON {
					return writeSubstrateJSON(w, b)
				}
				printSubstrateMap(w, b, "")
				return nil
			case len(args) == 1:
				a, err := resolveSubstrateActor(ctx, s.Client, args[0])
				if err != nil {
					return substrateFail(err)
				}
				if asJSON {
					return writeSubstrateJSON(w, a)
				}
				fmt.Fprintf(w, "Agent:     %s/%s\n", a.Atespace, a.Name)
				fmt.Fprintf(w, "Coding agent: %s\n", substrateDash(a.Connector))
				fmt.Fprintf(w, "Profile:   %s\n", substrateDash(a.Profile))
				fmt.Fprintf(w, "Template:  %s\n", substrateDash(a.Template))
				fmt.Fprintf(w, "Started:   %s ago\n", substrateAge(a.CreatedAt, time.Now()))
				if a.BatchID != "" {
					fmt.Fprintf(w, "Batch:     %s\n", a.BatchID)
				}
				if a.Unattended {
					fmt.Fprintln(w, "Mode:      unattended (asks are denied)")
				}
				fmt.Fprintf(w, "Come back: defenseclaw substrate connect %s\n", a.Name)
				return nil
			}
			actors, err := s.Client.List(ctx, api.ListOptions{})
			if err != nil {
				return substrateFail(err)
			}
			n := 0
			for _, a := range actors {
				if !a.Deleted {
					n++
				}
			}
			tok, _ := s.Source.Current(ctx)
			who := ""
			if tok != nil {
				who = substrateDash(tok.Principal)
			}
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{"context": s.Name, "admin_url": s.Ctx.AdminURL, "signed_in_as": who, "agents": n})
			}
			fmt.Fprintf(w, "Cluster:    %s (%s)\n", s.Name, s.Ctx.AdminURL)
			fmt.Fprintf(w, "Signed in:  %s\n", who)
			fmt.Fprintf(w, "Agents:     %d\n", n)
			return nil
		},
	}
	out.add(cmd)
	cf.add(cmd)
	cmd.Flags().BoolVar(&cluster, "cluster", false, "administrators: show the health and setup checks of the whole cluster")
	cmd.Flags().StringVar(&batch, "batch", "", "show every agent of this batch")
	return cmd
}

// printSubstrateMap writes a JSON-shaped document as indented "key: value"
// lines, for the usage and batch views.
func printSubstrateMap(w io.Writer, m map[string]any, indent string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := m[k].(type) {
		case map[string]any:
			fmt.Fprintf(w, "%s%s:\n", indent, k)
			printSubstrateMap(w, v, indent+"  ")
		case []any:
			fmt.Fprintf(w, "%s%s:\n", indent, k)
			for _, item := range v {
				if im, ok := item.(map[string]any); ok {
					fmt.Fprintf(w, "%s  -\n", indent)
					printSubstrateMap(w, im, indent+"    ")
					continue
				}
				fmt.Fprintf(w, "%s  - %v\n", indent, item)
			}
		default:
			fmt.Fprintf(w, "%s%s: %v\n", indent, k, v)
		}
	}
}

// --- delete -----------------------------------------------------------------

func newSubstrateDeleteCmd() *cobra.Command {
	var (
		com   substrateCommon
		yes   bool
		batch string
	)
	cmd := &cobra.Command{
		Use:   "delete [name...]",
		Short: "Delete agents with their work and snapshots",
		Long: `Deletes the named agents (or every agent of --batch) and the snapshots the cluster
holds for them. Pull the changes first with "defenseclaw substrate pull": what is not pulled
is gone.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 && batch == "" {
				return errors.New("name the agents to delete (list them with: defenseclaw substrate list), or pass --batch ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			var targets []api.Actor
			if batch != "" {
				list, err := s.Client.List(ctx, api.ListOptions{Batch: batch})
				if err != nil {
					return substrateFail(err)
				}
				for _, a := range list {
					if !a.Deleted {
						targets = append(targets, a)
					}
				}
				if len(targets) == 0 {
					return fmt.Errorf("batch %q has no agents of yours", batch)
				}
			}
			for _, ref := range args {
				a, err := resolveSubstrateActor(ctx, s.Client, ref)
				if err != nil {
					return substrateFail(err)
				}
				targets = append(targets, a)
			}
			w := cmd.OutOrStdout()
			if !yes {
				var names []string
				for _, a := range targets {
					names = append(names, a.Atespace+"/"+a.Name)
				}
				ok, err := substrateConfirm(cmd, fmt.Sprintf("Delete %s? Changes you have not pulled will be lost.", strings.Join(names, ", ")))
				if err != nil {
					return err
				}
				if !ok {
					fmt.Fprintln(w, "Nothing deleted.")
					return nil
				}
			}
			var failed []string
			for _, a := range targets {
				if err := s.Client.Delete(ctx, a.Atespace, a.Name); err != nil {
					failed = append(failed, fmt.Sprintf("%s/%s: %v", a.Atespace, a.Name, substrateFail(err)))
					continue
				}
				fmt.Fprintf(w, "Deleted %s/%s\n", a.Atespace, a.Name)
			}
			if len(failed) > 0 {
				return fmt.Errorf("could not delete:\n  %s", strings.Join(failed, "\n  "))
			}
			return nil
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	cmd.Flags().StringVar(&batch, "batch", "", "delete every agent of this batch")
	return cmd
}

// substrateConfirm asks a yes/no question on a terminal; without one it
// refuses and names --yes.
func substrateConfirm(cmd *cobra.Command, q string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("this needs a yes: pass --yes to answer it from a script")
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", q)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// --- migrate ----------------------------------------------------------------

func newSubstrateMigrateCmd() *cobra.Command {
	var com substrateCommon
	cmd := &cobra.Command{
		Use:   "migrate <name>",
		Short: "Move an agent made by an older DefenseClaw kit to the current kit",
		Long: `An agent that was suspended for weeks may carry an older DefenseClaw kit. The cluster keeps
running the current kit and the one before it; "migrate" moves an agent that is older than
that onto the current kit without losing its work.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			a, err := resolveSubstrateActor(ctx, s.Client, args[0])
			if err != nil {
				return substrateFail(err)
			}
			res, err := s.Client.Migrate(ctx, a.Atespace, a.Name)
			if err != nil {
				return substrateFail(err)
			}
			kit, _ := res["kit_version"].(string)
			fmt.Fprintf(cmd.OutOrStdout(), "Moved %s/%s to kit %s. Come back with: defenseclaw substrate connect %s\n", a.Atespace, a.Name, substrateDash(kit), a.Name)
			return nil
		},
	}
	com.add(cmd)
	return cmd
}

// --- approvals --------------------------------------------------------------

func newSubstrateApprovalsCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List what your agents are waiting for you to approve",
		Long: `Lists the questions your agents asked that nobody has answered yet. Answer with
"defenseclaw substrate approve ID" or "defenseclaw substrate reject ID". An agent attached to your
terminal shows the same question on its last line. An unattended run (--task) never waits:
its asks are denied.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			asks, err := s.Client.Asks(ctx)
			if err != nil {
				return substrateFail(err)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{"asks": asks})
			}
			if len(asks) == 0 {
				fmt.Fprintln(w, "Nothing is waiting for you.")
				return nil
			}
			now := time.Now()
			rows := make([][]string, 0, len(asks))
			for _, a := range asks {
				rows = append(rows, []string{a.ID, substrateDash(a.Actor), substrateDash(a.Summary), substrateDash(a.Severity), substrateAge(a.Created, now)})
			}
			substrateTable(w, []string{"ID", "AGENT", "WHAT", "SEVERITY", "AGE"}, rows)
			fmt.Fprintln(w, "\nAnswer with: defenseclaw substrate approve ID   or   defenseclaw substrate reject ID")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

func newSubstrateApproveCmd() *cobra.Command {
	var (
		com    substrateCommon
		always bool
		reason string
	)
	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a waiting question",
		Long:  `Approves one question from "defenseclaw substrate approvals" once, or with --always for every later run that asks the same thing.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return substrateDecide(cmd, &com, args[0], "approve", always, reason)
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVar(&always, "always", false, "keep this approval for later runs")
	cmd.Flags().StringVar(&reason, "reason", "", "note recorded with the decision")
	return cmd
}

func newSubstrateRejectCmd() *cobra.Command {
	var (
		com    substrateCommon
		reason string
	)
	cmd := &cobra.Command{
		Use:   "reject <id>",
		Short: "Deny a waiting question",
		Long:  `Denies one question from "defenseclaw substrate approvals". The agent is told no.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return substrateDecide(cmd, &com, args[0], "deny", false, reason)
		},
	}
	com.add(cmd)
	cmd.Flags().StringVar(&reason, "reason", "", "note recorded with the decision")
	return cmd
}

func substrateDecide(cmd *cobra.Command, com *substrateCommon, id, decision string, always bool, reason string) error {
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	if err := s.Client.Decide(ctx, id, decision, always, reason); err != nil {
		return substrateFail(err)
	}
	verb := map[string]string{"approve": "Approved", "deny": "Denied"}[decision]
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s.\n", verb, id)
	return nil
}

// --- usage ------------------------------------------------------------------

func newSubstrateUsageCmd() *cobra.Command {
	var (
		out   substrateOutput
		com   substrateCommon
		batch string
		all   bool
	)
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Show what your agents used: model calls, tokens and cost",
		Long:  `Shows the model use of your agents, grouped the way the cluster reports it. You see only your own use.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			u, err := s.Client.Usage(ctx, batch, all)
			if err != nil {
				return substrateFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), u)
			}
			if len(u) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No use recorded yet.")
				return nil
			}
			printSubstrateMap(cmd.OutOrStdout(), u, "")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&batch, "batch", "", "only this batch")
	cmd.Flags().BoolVar(&all, "all", false, "everyone's use (administrators only)")
	return cmd
}

// --- secrets ----------------------------------------------------------------

func newSubstrateSecretsCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "secrets",
		Short: "Manage the secrets your agents may use (values never enter an agent)",
		Long: `A secret is a key an agent can use without ever seeing it: the cluster adds the real value
to requests to the hosts the secret is bound to. These commands list the names you can use,
store your own, and remove or test them. Values are never shown.`,
	}
	parent.AddCommand(newSubstrateSecretsListCmd(), newSubstrateSecretsSetCmd(), newSubstrateSecretsRmCmd(), newSubstrateSecretsTestCmd())
	return parent
}

func newSubstrateSecretsListCmd() *cobra.Command {
	var (
		out  substrateOutput
		com  substrateCommon
		mine bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret names you can use",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			list, err := s.Client.Secrets(ctx, mine)
			if err != nil {
				return substrateFail(err)
			}
			w := cmd.OutOrStdout()
			if asJSON {
				return writeSubstrateJSON(w, map[string]any{"secrets": list})
			}
			if len(list) == 0 {
				fmt.Fprintln(w, "No secrets are available to you.")
				return nil
			}
			rows := make([][]string, 0, len(list))
			for _, sec := range list {
				rows = append(rows, []string{sec.Name, substrateDash(sec.Scope), substrateDash(strings.Join(sec.Hosts, ",")), substrateDash(sec.Status)})
			}
			substrateTable(w, []string{"NAME", "SCOPE", "HOSTS", "STATUS"}, rows)
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().BoolVar(&mine, "mine", false, "only secrets you stored yourself")
	return cmd
}

func newSubstrateSecretsSetCmd() *cobra.Command {
	var (
		com       substrateCommon
		fromEnv   string
		fromStdin bool
	)
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Store one of your own secrets",
		Long: `Stores the value for NAME, bound to the hosts your administrator allowed for it. The value
is read from the terminal without echo, from standard input with --stdin, or from an environment
variable with --from-env VAR. It is never put on the command line.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := readSubstrateSecret(cmd, fromEnv, fromStdin)
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			if err := s.Client.SetSecret(ctx, args[0], value); err != nil {
				return substrateFail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored %s. Check it with: defenseclaw substrate secrets test %s\n", args[0], args[0])
			return nil
		},
	}
	com.add(cmd)
	cmd.Flags().StringVar(&fromEnv, "from-env", "", "read the value from this environment variable")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the value from standard input")
	return cmd
}

func readSubstrateSecret(cmd *cobra.Command, fromEnv string, fromStdin bool) (string, error) {
	switch {
	case fromEnv != "":
		v := os.Getenv(fromEnv)
		if v == "" {
			return "", fmt.Errorf("the environment variable %s is empty or not set", fromEnv)
		}
		return v, nil
	case fromStdin:
		b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
		if err != nil {
			return "", err
		}
		v := strings.TrimRight(string(b), "\r\n")
		if v == "" {
			return "", errors.New("standard input was empty")
		}
		return v, nil
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(cmd.ErrOrStderr(), "Secret value (not shown): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", errors.New("no value entered")
		}
		return string(b), nil
	}
	return "", errors.New("give the value with --stdin or --from-env VAR (there is no terminal to ask on)")
}

func newSubstrateSecretsRmCmd() *cobra.Command {
	var (
		com substrateCommon
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove one of your own secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			if !yes {
				ok, err := substrateConfirm(cmd, "Remove the secret "+args[0]+"?")
				if err != nil {
					return err
				}
				if !ok {
					fmt.Fprintln(cmd.OutOrStdout(), "Nothing removed.")
					return nil
				}
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			if err := s.Client.RemoveSecret(ctx, args[0]); err != nil {
				return substrateFail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s.\n", args[0])
			return nil
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	return cmd
}

func newSubstrateSecretsTestCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Check that a secret is bound and the cluster can use it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			res, err := s.Client.TestSecret(ctx, args[0])
			if err != nil {
				return substrateFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), res)
			}
			printSubstrateMap(cmd.OutOrStdout(), res, "")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

// --- policy -----------------------------------------------------------------

func newSubstratePolicyCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "policy",
		Short: "See the rules that guard your agents",
		Long:  `Shows the rules that apply to your own agents: what they may reach, what asks you, what is refused. You see only your own policy.`,
	}
	parent.AddCommand(newSubstratePolicyExplainCmd(), newSubstratePolicyShowCmd(), newSubstratePolicyTestCmd())
	return parent
}

func newSubstratePolicyExplainCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "explain <name>",
		Short: "Explain the rules and recent decisions for one agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return substratePolicyCall(cmd, &out, &com, args[0], nil)
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

func newSubstratePolicyShowCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the rules that apply to you by default",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return substratePolicyCall(cmd, &out, &com, "", nil)
		},
	}
	out.add(cmd)
	com.add(cmd)
	return cmd
}

func newSubstratePolicyTestCmd() *cobra.Command {
	var (
		out    substrateOutput
		com    substrateCommon
		host   string
		method string
		tool   string
	)
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Ask what the rules would do for a host or tool, without running anything",
		Long:  `Asks the cluster what one of your agents would be allowed to do for a host (with --host) or a tool call (with --tool). Nothing is run.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" && tool == "" {
				return errors.New("say what to test: --host HOST or --tool NAME")
			}
			extra := map[string]string{"host": host, "method": method, "tool": tool}
			return substratePolicyCall(cmd, &out, &com, args[0], extra)
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&host, "host", "", "a host the agent might call, for example registry.example.test")
	cmd.Flags().StringVar(&method, "method", "", "the HTTP method for --host (default: any)")
	cmd.Flags().StringVar(&tool, "tool", "", "a tool the agent might call")
	return cmd
}

func substratePolicyCall(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, ref string, extra map[string]string) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return err
	}
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	actor := ""
	if ref != "" {
		a, err := resolveSubstrateActor(ctx, s.Client, ref)
		if err != nil {
			return substrateFail(err)
		}
		actor = a.Atespace + "/" + a.Name
	}
	res, err := s.Client.PolicyQuery(ctx, actor, extra)
	if err != nil {
		return substrateFail(err)
	}
	if asJSON {
		return writeSubstrateJSON(cmd.OutOrStdout(), res)
	}
	printSubstrateMap(cmd.OutOrStdout(), res, "")
	return nil
}
