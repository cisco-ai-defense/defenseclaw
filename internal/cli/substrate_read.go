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
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
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
	// run gives every agent a fresh suffix (GAP-0133), so the --name a
	// person chose is a prefix: it names the one agent that has it.
	if len(hits) == 0 && !strings.Contains(ref, "/") {
		for _, a := range actors {
			if rest, ok := strings.CutPrefix(a.Name, ref+"-"); ok && !a.Deleted && substrateIsSuffix(rest) {
				hits = append(hits, a)
			}
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

// substrateIsSuffix reports the random suffix run puts after a name
// (newSubstrateID(4): eight hex digits).
func substrateIsSuffix(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// substrateUnattendedMode is the Mode line of an unattended agent: what its
// asks do, as its profile's unattended_asks says (D12, GAP-0388).
func substrateUnattendedMode(a api.Actor) string {
	profile := substrateDash(a.Profile)
	if a.UnattendedAsks != "queue" {
		return "unattended (asks are denied: profile " + profile + " has unattended_asks: deny)"
	}
	wait := ""
	if a.AskTimeoutSeconds > 0 {
		wait = ", denied after " + substrateAge(time.Unix(0, 0), time.Unix(a.AskTimeoutSeconds, 0)) + " without an answer"
	}
	return "unattended (asks are queued for approval: profile " + profile + " has unattended_asks: queue" + wait +
		"; answer them with defenseclaw substrate approvals)"
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

// substrateAskRun is the RUN column of approvals: "unattended" for an ask
// an unattended run queued (with the time left before it is denied), else
// "attached".
func substrateAskRun(a api.Ask, now time.Time) string {
	if !a.Unattended {
		return "attached"
	}
	if a.Expires.IsZero() {
		return "unattended"
	}
	return "unattended, " + substrateAge(now, a.Expires) + " left"
}

// substrateActorState is the STATE column: the actor's state, and
// policy_conflict while the controller keeps it on the DefenseClaw rule only
// (GAP-0398).
func substrateActorState(a api.Actor) string {
	if a.PolicyConflict == nil {
		return substrateDash(a.State)
	}
	if st := safetext.Line(a.State); st != "" {
		return st + ", policy_conflict"
	}
	return "policy_conflict"
}

// substratePolicyConflictLine says what policy_conflict means for the agent
// and how it is cleared, "" when it is not in conflict (GAP-0398).
func substratePolicyConflictLine(a api.Actor) string {
	pc := a.PolicyConflict
	if pc == nil {
		return ""
	}
	fix := pc.Fix
	if fix == "" {
		fix = "defenseclaw substrate policy reset " + a.Atespace + "/" + a.Name
	}
	since := ""
	if !pc.Since.IsZero() {
		since = " since " + pc.Since.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("policy_conflict%s: %d foreign change(s) to its network policy were reverted, so it may reach only DefenseClaw until an administrator clears it with: %s",
		since, pc.Reverts, fix)
}

// substrateDash shows a value the cluster sent, as one safe line, or "-".
func substrateDash(s string) string {
	if s = safetext.Line(s); s == "" {
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
			printSubstrateActors(cmd.OutOrStdout(), live, all, time.Now())
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&batch, "batch", "", "only the agents of this batch")
	cmd.Flags().BoolVar(&all, "all", false, "every person's agents (administrators only)")
	return cmd
}

// printSubstrateActors is the table of substrate list.
func printSubstrateActors(w io.Writer, live []api.Actor, all bool, now time.Time) {
	rows := make([][]string, 0, len(live))
	for _, a := range live {
		row := []string{a.Atespace + "/" + a.Name, substrateDash(a.Connector), substrateDash(a.Profile), substrateActorState(a), substrateActivityCell(a, now), substrateAge(a.CreatedAt, now), substrateDash(a.BatchID), substrateDash(safetext.Line(a.Budget))}
		if all {
			row = append(row, substrateListOwner(a))
		}
		rows = append(rows, row)
	}
	header := []string{"NAME", "AGENT", "PROFILE", "STATE", "ACTIVITY", "AGE", "BATCH", "BUDGET"}
	if all {
		header = append(header, "OWNER")
	}
	substrateTable(w, header, rows)
}

// substrateListOwner is list --all's OWNER column: the person, or that the
// agent was made outside DefenseClaw and belongs to its atespace only
// (GAP-0419).
func substrateListOwner(a api.Actor) string {
	if a.Foreign || a.Attribution == "atespace" {
		return "not launcher (atespace only)"
	}
	return substrateDash(a.Owner)
}

// --- status -----------------------------------------------------------------

func newSubstrateStatusCmd() *cobra.Command {
	var (
		out     substrateOutput
		com     = &substrateCommon{}
		cf      substrateClusterFlags
		batch   string
		cluster bool
	)
	cmd := &cobra.Command{
		Use:   "status [name]",
		Short: "Show who you are signed in as, or one agent or batch in detail",
		Long: `Without a name, shows the cluster and account in use and how many agents you have.
With a name, shows that agent: where it runs, which profile guards it and its batch.
With --batch, shows every agent of a batch run.

For administrators, --cluster shows the health of the whole setup: gateway, leader, controller and callout,
the agents and templates in the cluster (agents by state, also per launcher and managed atespace), the agents
in policy_conflict per atespace and the setup checks. It reads the cluster with kubectl (give --install-file),
and the agents in policy_conflict with your DefenseClaw sign-in (sign in as an administrator, or the count is
unknown).
Exit 75 means the cluster could not be reached; there is no document.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cluster {
				if len(args) > 0 || batch != "" {
					return cliusage.WithExitCode(errors.New("--cluster shows the whole cluster; leave the name and --batch out"), 2)
				}
				return runSubstrateFleet(cmd, "status", &out, &cf, com)
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
				// Only the one-agent answer names the pending asks.
				if one, err := s.Client.Get(ctx, a.Atespace, a.Name); err == nil && one.Activity != nil {
					a.Activity = one.Activity
				}
				if asJSON {
					return writeSubstrateJSON(w, a)
				}
				fmt.Fprintf(w, "Agent:     %s/%s\n", a.Atespace, a.Name)
				fmt.Fprintf(w, "Coding agent: %s\n", substrateDash(a.Connector))
				fmt.Fprintf(w, "Profile:   %s\n", substrateDash(a.Profile))
				fmt.Fprintf(w, "Template:  %s\n", substrateDash(a.Template))
				fmt.Fprintf(w, "Started:   %s ago\n", substrateAge(a.CreatedAt, time.Now()))
				if a.State != "" {
					fmt.Fprintf(w, "State:     %s\n", a.State)
				}
				for _, line := range substrateActivityLines(a, time.Now()) {
					fmt.Fprintln(w, line)
				}
				if a.BatchID != "" {
					fmt.Fprintf(w, "Batch:     %s\n", a.BatchID)
				}
				if a.Budget != "" {
					fmt.Fprintf(w, "Budget:    %s\n", safetext.Line(a.Budget))
				}
				if a.Unattended {
					fmt.Fprintf(w, "Mode:      %s\n", substrateUnattendedMode(a))
				}
				if line := substratePolicyConflictLine(a); line != "" {
					fmt.Fprintln(w, "Policy:    "+line)
				}
				if e := substrateEgressInfo(ctx, s); e.Replaced() {
					// GAP-0497: say which protections are off.
					fmt.Fprintf(w, "Egress:    %s\n", substrateEgressSummary(e))
				}
				if a.State == substrateStateCrashed {
					// GAP-0410: say it crashed and the way back.
					fmt.Fprintf(w, "Crashed:   its worker went away. Bring it back with: defenseclaw substrate undo %s\n", a.Name)
					if a.Unattended {
						// GAP-0420: the run and log of a headless task were in
						// the crashed actor. undo starts the task again from
						// the record run --task keeps on the computer that
						// started it (at least once).
						if _, ok := loadSubstrateTaskRecord(auth.StateDir(), a); ok {
							fmt.Fprintf(w, "Task:      lost in the crash. undo starts it again from the beginning on a fresh copy of its folder: defenseclaw substrate undo %s\n", a.Name)
						} else {
							agent := a.Connector
							if spec, err := sandboxcli.ResolveHarness(a.Connector); err == nil {
								agent = spec.Command
							}
							fmt.Fprintf(w, "Task:      lost in the crash. Run defenseclaw substrate undo %s on the computer that started it to start the task again, or re-run it with: defenseclaw substrate run %s --task ...\n", a.Name, substrateDash(agent))
						}
					}
					return nil
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
			egress := substrateEgressInfo(ctx, s)
			if asJSON {
				doc := map[string]any{"context": s.Name, "admin_url": s.Ctx.AdminURL, "signed_in_as": who, "agents": n}
				if egress != nil {
					doc["egress_callout"] = egress
				}
				return writeSubstrateJSON(w, doc)
			}
			fmt.Fprintf(w, "Cluster:    %s (%s)\n", s.Name, s.Ctx.AdminURL)
			fmt.Fprintf(w, "Signed in:  %s\n", who)
			fmt.Fprintf(w, "Agents:     %d\n", n)
			if egress.Replaced() {
				// GAP-0497: not "all is well" while another callout holds
				// Substrate's egress slot.
				fmt.Fprintf(w, "Egress:     %s\n", substrateEgressSummary(egress))
			}
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cf.addKube(cmd)
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
			fmt.Fprintf(w, "%s%s:\n", indent, safetext.Line(k))
			printSubstrateMap(w, v, indent+"  ")
		case []any:
			fmt.Fprintf(w, "%s%s:\n", indent, safetext.Line(k))
			for _, item := range v {
				if im, ok := item.(map[string]any); ok {
					fmt.Fprintf(w, "%s  -\n", indent)
					printSubstrateMap(w, im, indent+"    ")
					continue
				}
				fmt.Fprintf(w, "%s  - %s\n", indent, safetext.Line(fmt.Sprint(item)))
			}
		default:
			fmt.Fprintf(w, "%s%s: %s\n", indent, safetext.Line(k), safetext.Line(fmt.Sprint(v)))
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
		Long: `Deletes the named agents (or every agent of --batch), the snapshots the cluster
holds for them and the checkpoints saved inside them. The question and the output say how
many snapshots each agent had. Pull the changes first with "defenseclaw substrate pull":
what is not pulled is gone.`,
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
				// One actor's status carries its snapshot count (GAP-0474).
				for i, a := range targets {
					if got, err := s.Client.Get(ctx, a.Atespace, a.Name); err == nil && got.Snapshots != nil {
						targets[i].Snapshots = got.Snapshots
					}
				}
				ok, err := substrateConfirm(cmd, substrateDeletePrompt(targets))
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
				got, err := s.Client.Delete(ctx, a.Atespace, a.Name)
				if err != nil {
					failed = append(failed, fmt.Sprintf("%s/%s: %v", a.Atespace, a.Name, substrateFail(err)))
					continue
				}
				fmt.Fprintf(w, "Deleted %s/%s: %s\n", a.Atespace, a.Name, substratePurged(got.Snapshots))
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

// substratePurged names what a delete removes with an agent: its snapshots
// (with the count when the cluster gave one) and the checkpoints saved
// inside it (GAP-0474).
func substratePurged(snapshots *int) string {
	switch {
	case snapshots == nil:
		return "the agent, its snapshots and the checkpoints saved inside it"
	case *snapshots == 1:
		return "the agent, 1 snapshot and the checkpoints saved inside it"
	default:
		return fmt.Sprintf("the agent, %d snapshots and the checkpoints saved inside it", *snapshots)
	}
}

// substrateDeletePrompt is the delete question: every agent with what goes
// with it, and what is lost (GAP-0474).
func substrateDeletePrompt(targets []api.Actor) string {
	var b strings.Builder
	if len(targets) == 1 {
		a := targets[0]
		fmt.Fprintf(&b, "Delete %s/%s? This removes %s. ", a.Atespace, a.Name, substratePurged(a.Snapshots))
	} else {
		fmt.Fprintf(&b, "Delete %d agents? This removes:", len(targets))
		for _, a := range targets {
			fmt.Fprintf(&b, "\n  %s/%s: %s", a.Atespace, a.Name, substratePurged(a.Snapshots))
		}
		b.WriteString("\n")
	}
	b.WriteString("Changes you have not pulled will be lost.")
	return b.String()
}

// substrateConfirm asks a yes/no question on a terminal; without one it
// refuses and names --yes.
func substrateConfirm(cmd *cobra.Command, q string) (bool, error) {
	if !substrateInteractive() {
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
		out      substrateOutput
		com      substrateCommon
		all      bool
		standing bool
	)
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List what your agents are waiting for you to approve",
		Long: `Lists the questions your agents asked that nobody has answered yet. Answer with
"defenseclaw substrate approve ID" or "defenseclaw substrate reject ID". An agent attached to your
terminal shows the same question on its last line. An unattended run (--task, --batch)
denies its asks unless its profile sets unattended_asks: queue; a queued ask is marked
"unattended" in the RUN column and is denied when its time runs out.

With --standing it lists the approvals given with "approve --always" that are still in force:
the agent, the host, what the approval covers, who approved it and when. Take one back with
"defenseclaw substrate revoke NAME HOST".`,
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
			if standing {
				return printSubstrateStanding(ctx, cmd, s.Client, all, asJSON)
			}
			asks, err := s.Client.AsksOf(ctx, all)
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
				rows = append(rows, []string{a.ID, substrateDash(a.Actor), substrateDash(a.Summary), substrateDash(a.Severity),
					substrateAge(a.Created, now), substrateAskRun(a, now)})
			}
			substrateTable(w, []string{"ID", "AGENT", "WHAT", "SEVERITY", "AGE", "RUN"}, rows)
			fmt.Fprintln(w, "\nAnswer with: defenseclaw substrate approve ID   or   defenseclaw substrate reject ID")
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().BoolVar(&all, "all", false, "every person's, not only yours (administrators only)")
	cmd.Flags().BoolVar(&standing, "standing", false, "list the approvals given with --always that are still in force")
	return cmd
}

// printSubstrateStanding lists the standing (always) approvals (GAP-0492).
func printSubstrateStanding(ctx context.Context, cmd *cobra.Command, cl *api.Client, all, asJSON bool) error {
	list, err := cl.StandingApprovals(ctx, all)
	if err != nil {
		return substrateFail(err)
	}
	w := cmd.OutOrStdout()
	if asJSON {
		return writeSubstrateJSON(w, map[string]any{"approvals": list})
	}
	if len(list) == 0 {
		fmt.Fprintln(w, "No approval given with --always is in force.")
		return nil
	}
	now := time.Now()
	header := []string{"AGENT", "HOST", "COVERS", "APPROVED BY", "AGE"}
	if all {
		header = append(header, "OWNER")
	}
	rows := make([][]string, 0, len(list))
	for _, a := range list {
		covers := a.Scope
		if covers == "" || covers == "host" {
			covers = "every request to the host"
		}
		row := []string{substrateDash(a.Atespace + "/" + a.Actor), substrateDash(a.Host), substrateDash(covers),
			substrateDash(a.ApprovedBy), substrateAge(a.ApprovedAt, now)}
		if all {
			row = append(row, substrateDash(a.Owner))
		}
		rows = append(rows, row)
	}
	substrateTable(w, header, rows)
	fmt.Fprintln(w, "\nTake one back with: defenseclaw substrate revoke NAME HOST")
	return nil
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
		Long:  `Approves one question from "defenseclaw substrate approvals" for one request: the next request asks again. With --always it covers every later request of the agent that asks the same thing.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return substrateDecide(cmd, &com, args[0], "approve", always, reason)
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVar(&always, "always", false, "keep this approval for every later request of the agent")
	cmd.Flags().StringVar(&reason, "reason", "", "note recorded with the decision")
	return cmd
}

func newSubstrateRevokeCmd() *cobra.Command {
	var com substrateCommon
	cmd := &cobra.Command{
		Use:   "revoke <name> <host>",
		Short: "Take back an approval given with --always",
		Long: `Takes back what "defenseclaw substrate approve --always" allowed for one agent and host: the agent's
next request to the host asks you again. The cluster drops the host from the agent's network rules
within about a minute. List the approvals in force with "defenseclaw substrate approvals --standing".
An administrator names another person's agent as ATESPACE/NAME; the revoke is recorded under their
own name.`,
		Example: "defenseclaw substrate revoke fix-tests-7f3a registry.example.test",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			atespace, name, ok := strings.Cut(strings.TrimSpace(args[0]), "/")
			if !ok || atespace == "" || name == "" || strings.Contains(name, "/") {
				a, err := resolveSubstrateActor(ctx, s.Client, args[0])
				if err != nil {
					return substrateFail(err)
				}
				atespace, name = a.Atespace, a.Name
			}
			host := strings.ToLower(strings.TrimSpace(args[1]))
			if _, err := s.Client.Revoke(ctx, atespace, name, host); err != nil {
				if e, ok := api.AsError(err); ok && e.Status == 404 && e.Reason == "approval_not_found" {
					return cliusage.WithExitCode(fmt.Errorf("%s/%s has no approval of %s in force; list them with: defenseclaw substrate approvals --standing",
						atespace, name, safetext.Line(host)), substrateExitRefused)
				}
				return substrateFail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Took back the approval of %s for %s/%s. Its next request there asks you again.\n", safetext.Line(host), atespace, name)
			return nil
		},
	}
	com.add(cmd)
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
	note, err := s.Client.Decide(ctx, id, decision, always, reason)
	if err != nil {
		return substrateFail(err)
	}
	verb := map[string]string{"approve": "Approved", "deny": "Denied"}[decision]
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s.\n", verb, id)
	if note != "" {
		// The answer is recorded but moved nothing (GAP-0973): say so.
		fmt.Fprintln(cmd.OutOrStdout(), note)
	}
	return nil
}

// --- usage ------------------------------------------------------------------

// substrateUsageBys are the rollups of substrate usage, with the heading and
// column word of each.
var substrateUsageBys = map[string][2]string{
	"actor": {"agent", "AGENT"}, "model": {"model", "MODEL"}, "batch": {"batch", "BATCH"},
	"atespace": {"group", "GROUP"}, "day": {"day", "DAY"}, "connector": {"connector", "CONNECTOR"},
	"provider": {"provider", "PROVIDER"}, "person": {"person", "PERSON"},
}

// substrateUsageSince validates --since (<n>h or <n>d, at most 31 days, the
// usage retention) and returns the window for the heading.
func substrateUsageSince(v string) error {
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(v, "h"), "d"))
	if err != nil || n <= 0 || (!strings.HasSuffix(v, "h") && !strings.HasSuffix(v, "d")) {
		return cliusage.WithExitCode(errors.New("--since takes a window such as 24h or 7d"), 2)
	}
	if (strings.HasSuffix(v, "h") && n > 31*24) || (strings.HasSuffix(v, "d") && n > 31) {
		return cliusage.WithExitCode(errors.New("--since can reach back at most 31 days (the usage retention)"), 2)
	}
	return nil
}

func newSubstrateUsageCmd() *cobra.Command {
	var (
		out       substrateOutput
		com       substrateCommon
		batch, by string
		since     string
		all       bool
	)
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Show what your agents used: model calls, tokens and cost",
		Long: `Shows the model use of your agents and what it cost, rolled up by agent (the default),
model, batch, atespace, day, connector or provider. You see only your own use; an
administrator adds --all for everyone and --by person for one line per person.
Calls whose model is not in the price table show no cost and are not in the total.`,
		Example: `  defenseclaw substrate usage
  defenseclaw substrate usage --by model --since 24h
  defenseclaw substrate usage --all --by person`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := out.wantJSON()
			if err != nil {
				return err
			}
			words, ok := substrateUsageBys[by]
			if !ok {
				return cliusage.WithExitCode(errors.New("--by is one of actor, model, batch, atespace, day, connector, provider or person"), 2)
			}
			if by == "person" && !all {
				return cliusage.WithExitCode(errors.New("--by person needs --all (administrators only)"), 2)
			}
			if err := substrateUsageSince(since); err != nil {
				return err
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			u, err := s.Client.Usage(ctx, api.UsageQuery{By: by, Since: since, Batch: batch, All: all})
			if err != nil {
				return substrateFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), u)
			}
			printSubstrateUsage(cmd.OutOrStdout(), u, words, since, all)
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&by, "by", "actor", "roll up by actor, model, batch, atespace, day, connector, provider or person (person needs --all)")
	cmd.Flags().StringVar(&since, "since", "7d", "window, as <n>h or <n>d (at most 31d)")
	cmd.Flags().StringVar(&batch, "batch", "", "only this batch")
	cmd.Flags().BoolVar(&all, "all", false, "everyone's use (administrators only)")
	return cmd
}

// printSubstrateUsage writes the usage table: one line per key, a total, the
// budget lines the caller may see, and a note for calls with no known cost.
func printSubstrateUsage(w io.Writer, u api.UsageAnswer, words [2]string, since string, all bool) {
	who := "Your"
	if all {
		who = "Everyone's"
	}
	if len(u.Rows) == 0 {
		fmt.Fprintf(w, "No use recorded in the last %s.\n", since)
	} else {
		fmt.Fprintf(w, "%s usage by %s, last %s (UTC):\n", who, words[0], since)
		person := words[1] == "PERSON"
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if person {
			fmt.Fprintf(tw, "  %s\tCALLS\tCOST\n", words[1])
		} else {
			fmt.Fprintf(tw, "  %s\tCALLS\tINPUT\tOUTPUT\tCOST\n", words[1])
		}
		var calls, in, outTok, noCost int64
		var total float64
		for _, r := range u.Rows {
			name := safetext.Line(r.Key)
			if r.Name != "" {
				name = safetext.Line(r.Name)
			}
			if name == "" {
				name = "(none)"
			}
			calls, in, outTok = calls+r.Calls, in+r.Input, outTok+r.Output
			if d := r.UsageCalls - r.CostCalls; d > 0 {
				noCost += d
			}
			if r.CostUSD != nil {
				total += *r.CostUSD
			}
			if person {
				fmt.Fprintf(tw, "  %s\t%d\t%s\n", name, r.Calls, substrateUSD(r.CostUSD))
			} else {
				fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\n", name, r.Calls, substrateTokens(r.Input), substrateTokens(r.Output), substrateUSD(r.CostUSD))
			}
		}
		t := total
		if person {
			fmt.Fprintf(tw, "  total\t%d\t%s\n", calls, substrateUSD(&t))
		} else {
			fmt.Fprintf(tw, "  total\t%d\t%s\t%s\t%s\n", calls, substrateTokens(in), substrateTokens(outTok), substrateUSD(&t))
		}
		_ = tw.Flush()
		if noCost > 0 {
			noun := "calls had"
			if noCost == 1 {
				noun = "call had"
			}
			fmt.Fprintf(w, "%d %s no known cost (the model is not in the price table); not in the total.\n", noCost, noun)
		}
	}
	for _, b := range u.Budgets {
		if b.SpentUSD == nil {
			continue
		}
		pct := 0.0
		if b.PercentUsed != nil {
			pct = *b.PercentUsed
		}
		state := fmt.Sprintf("(%.0f %%)", pct)
		if b.Exceeded {
			state = "(used up)"
		}
		fmt.Fprintf(w, "Budget %s: $%.2f of $%.2f %s %s, resets %s\n", safetext.Line(b.ID), *b.SpentUSD, b.LimitUSD,
			map[string]string{"day": "today", "week": "this week", "month": "this month"}[b.Period], state, safetext.Line(b.ResetsAt))
	}
}

func substrateUSD(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("$%.2f", *v)
}

// substrateTokens writes a token count as 412, 88.1K or 2.2M.
func substrateTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return strconv.FormatInt(n, 10)
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
	parent.AddCommand(newSubstrateSecretsTemplatesCmd(), newSubstrateSecretsAddCmd(), newSubstrateSecretsListCmd(), newSubstrateSecretsSetCmd(), newSubstrateSecretsRmCmd(), newSubstrateSecretsTestCmd())
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
			now := time.Now()
			rows := make([][]string, 0, len(list))
			for _, sec := range list {
				agents := "-"
				if len(sec.Agents) > 0 {
					agents = strings.Join(sec.Agents, ",")
				}
				rows = append(rows, []string{sec.Name, substrateDash(strings.Join(sec.Hosts, ",")), substrateSecretKind(sec),
					substrateDash(sec.Status), substrateSince(sec.LastUsed, now), substrateUntil(sec.Expires, now), agents})
			}
			substrateTable(w, []string{"NAME", "HOST", "KIND", "STATUS", "LAST USED", "EXPIRES", "AGENTS"}, rows)
			for _, sec := range list {
				if days, soon := substrateExpiresSoon(sec, now); soon {
					fmt.Fprintf(w, "warning: %s expires in %d days. Renew it: remove it with defenseclaw substrate secrets rm %s and add it again with --expires.\n",
						sec.Name, days, sec.Name)
				}
			}
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
		com substrateCommon
		src substrateSecretSource
	)
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Store one of your own secrets",
		Long: `Stores the value for NAME, bound to the hosts your administrator allowed for it.

` + substrateSourceHelp,
		Example: "defenseclaw substrate secrets set GITHUB_TOKEN --from-gh\n" +
			"defenseclaw substrate secrets set GITLAB_TOKEN --from-op op://eng/gitlab/token\n" +
			"defenseclaw substrate secrets set NPM_TOKEN --from-keychain npm-publish",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, _, err := src.read(cmd)
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
	src.add(cmd)
	// A no-op kept so older scripts that pass it still run (1.0.10 shipped it);
	// hidden from help, docs and the TUI (GAP-0786). The stub manifest records it
	// as hidden, and the Python stub accepts it and forwards it (GAP-0904).
	cmd.Flags().BoolVar(new(bool), "mine", true, "your own secret (the only kind this command acts on)")
	_ = cmd.Flags().MarkHidden("mine")
	return cmd
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
	// A no-op kept so older scripts that pass it still run (1.0.10 shipped it);
	// hidden from help, docs and the TUI (GAP-0786). The stub manifest records it
	// as hidden, and the Python stub accepts it and forwards it (GAP-0904).
	cmd.Flags().BoolVar(new(bool), "mine", true, "your own secret (the only kind this command acts on)")
	_ = cmd.Flags().MarkHidden("mine")
	return cmd
}

func newSubstrateSecretsTestCmd() *cobra.Command {
	var (
		out   substrateOutput
		com   substrateCommon
		agent string
	)
	cmd := &cobra.Command{
		Use:   "test <name>",
		Short: "Check that a secret is stored and usable, and whether an agent gets it",
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
			ref := ""
			if agent != "" {
				a, err := resolveSubstrateActor(ctx, s.Client, agent)
				if err != nil {
					return substrateFail(err)
				}
				ref = a.Atespace + "/" + a.Name
			}
			res, err := s.Client.TestSecret(ctx, args[0], ref)
			if err != nil {
				return substrateFail(err)
			}
			if asJSON {
				return writeSubstrateJSON(cmd.OutOrStdout(), res)
			}
			printSubstrateSecretTest(cmd.OutOrStdout(), res, time.Now())
			return nil
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().StringVar(&agent, "agent", "", "also say whether this agent's policy carries the secret")
	// A no-op kept so older scripts that pass it still run (1.0.10 shipped it);
	// hidden from help, docs and the TUI (GAP-0786). The stub manifest records it
	// as hidden, and the Python stub accepts it and forwards it (GAP-0904).
	cmd.Flags().BoolVar(new(bool), "mine", true, "your own secret (the only kind this command acts on)")
	_ = cmd.Flags().MarkHidden("mine")
	return cmd
}

// --- policy -----------------------------------------------------------------

func newSubstratePolicyCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "policy",
		Short: "See the rules that guard your agents",
		Long:  `Shows the rules that apply to your own agents: what they may reach, what asks you, what is refused. You see only your own policy.`,
	}
	parent.AddCommand(newSubstratePolicyExplainCmd(), newSubstratePolicyShowCmd(), newSubstratePolicyTestCmd(), newSubstratePolicyResetCmd())
	return parent
}

func newSubstratePolicyExplainCmd() *cobra.Command {
	var (
		out substrateOutput
		com substrateCommon
	)
	cmd := &cobra.Command{
		Use:   "explain [name]",
		Short: "Explain the rules and recent decisions for one agent, or the profile you get",
		Long: `With an agent name, explains the rules and recent decisions for that agent. With no name, explains the profile you get
for a new agent: the profile and where it came from (the profile assignment that selected you, or default_profile when none
did), default_profile, and the assignments that were checked first and did not select you (by place and the selector that
failed, never another person's group or account).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := ""
			if len(args) == 1 {
				ref = args[0]
			}
			return substratePolicyCall(cmd, &out, &com, ref, nil)
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

func newSubstratePolicyResetCmd() *cobra.Command {
	var (
		com    substrateCommon
		yes    bool
		reason string
	)
	cmd := &cobra.Command{
		Use:   "reset <actor>",
		Short: "Clear a policy conflict on an agent (administrators only)",
		Long: `For administrators. When something outside DefenseClaw keeps rewriting an agent's network policy,
three reverts in ten minutes mark the agent policy_conflict and put it on deny-only: it keeps only the
DefenseClaw rule, and each later change by the other writer is replaced with deny-only again, so a foreign
policy never stays in force. Once the other writer is stopped, "reset" clears that state so the controller
writes the full policy again. Name the agent as ATESPACE/NAME. The reset is recorded in the audit log under
your own name.`,
		Example: "defenseclaw substrate policy reset eng-web/fix-tests-7f3a --reason \"removed the GitOps rule\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := strings.TrimSpace(args[0])
			if at, name, ok := strings.Cut(ref, "/"); !ok || at == "" || name == "" || strings.Contains(name, "/") {
				return cliusage.WithExitCode(errors.New("name the agent as ATESPACE/NAME (list agents with: defenseclaw substrate list --all)"), 2)
			}
			s, err := substrateOpen(cmd, &com)
			if err != nil {
				return err
			}
			if !yes {
				ok, err := substrateConfirm(cmd, "Clear the policy conflict on "+ref+"? The controller will write its policy again.")
				if err != nil {
					return err
				}
				if !ok {
					fmt.Fprintln(cmd.OutOrStdout(), "Nothing changed.")
					return nil
				}
			}
			ctx, stop := substrateContext(cmd)
			defer stop()
			if _, err := s.Client.PolicyReset(ctx, ref, reason); err != nil {
				if e, ok := api.AsError(err); ok && e.Status == 403 {
					return cliusage.WithExitCode(errors.New("only administrators may reset a policy conflict"), substrateExitRefused)
				}
				return substrateFail(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Cleared the policy conflict on %s. The controller writes its policy again on its next pass.\n", ref)
			return nil
		},
	}
	com.add(cmd)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	cmd.Flags().StringVar(&reason, "reason", "", "note recorded with the reset")
	return cmd
}
