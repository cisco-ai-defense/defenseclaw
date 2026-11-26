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
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/config"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// substratePushWait bounds how long pull --push-branch waits for someone to
// answer its ask when no terminal can (the ask's own expiry is 30 min).
const substratePushWait = 30 * time.Minute

// substratePushPoll is how often it reads the ask again while it waits.
var substratePushPoll = 3 * time.Second

// runSubstratePushBranch is pull NAME --push-branch BR (B2 2.4): review what
// the push would carry, ask the gateway (allow, ask or deny), and push the
// actor's work as BR, from inside the actor, to the origin this computer
// recorded for the copy (never one the actor's git config names).
func runSubstratePushBranch(ctx context.Context, cmd *cobra.Command, f *substratePullFlags, s *substrateSession, a api.Actor, asJSON bool) error {
	branch := strings.TrimSpace(f.pushBranch)
	if err := workspace.CheckCloneRef(branch); err != nil || strings.HasPrefix(branch, "refs/") {
		return cliusage.WithExitCode(fmt.Errorf("--push-branch %q is not a branch name git takes", branch), 2)
	}
	settings, err := s.Client.Launcher(ctx)
	if err != nil {
		// RV4-9: without them neither push_branch nor https_rewrite is known.
		return fmt.Errorf("could not read the cluster's settings, so nothing was pushed: %w", substrateFail(err))
	}
	if strings.EqualFold(settings.Git.PushBranch, config.SubstrateGitPushDeny) {
		return cliusage.WithExitCode(errors.New("this cluster turned off pull --push-branch (substrate.git.push_branch: deny); "+
			"bring the work home with --branch NAME and push from your computer"), substrateExitRefused)
	}
	dataDir, copyName := auth.StateDir(), substrateCopyName(a)
	if err := substratePushBranchReplaced(dataDir, copyName, a.Name, branch); err != nil {
		return err
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	root, err := rel.Client.Root(ctx)
	if err != nil {
		return substrateFail(err)
	}
	errw, w := cmd.ErrOrStderr(), cmd.OutOrStdout()
	fmt.Fprintln(errw, "Reading the agent's work...")
	p, err := workspace.PrepareBranchPush(ctx, rel.Client.BranchExec, root, a.Name, workspace.RecordedOrigin(dataDir, copyName),
		substrateGitFrom(settings).HTTPSRewrite)
	if err != nil {
		var pe *workspace.BranchPushError
		if errors.As(err, &pe) {
			return cliusage.WithExitCode(err, substrateExitRefused)
		}
		return substrateFail(err)
	}
	// The review copied the objects origin lacks into a folder in the
	// actor, which the push sends from; remove it when this run ends.
	defer p.Discard(context.WithoutCancel(ctx), rel.Client.BranchExec)
	if p.Warning != "" {
		fmt.Fprintln(errw, "warning: "+p.Warning+".")
	}
	target := p.PushURL
	if p.Commits == 0 {
		fmt.Fprintf(w, "Nothing to push: %s already has all of the agent's work.\n", target)
		return nil
	}
	if !asJSON {
		substratePushReview(w, p, branch, target)
	}
	if p.Flagged() && !f.allowFlagged {
		q := "Some of these changes need a careful look before they land on " + p.Host + ". Push anyway?"
		if f.yes || !substrateInteractive() {
			return cliusage.WithExitCode(errors.New("not pushed: the review flagged files; look at them, then run again with --allow-flagged"), substrateExitRefused)
		}
		ok, err := substrateConfirm(cmd, q)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(errw, "Not pushed.")
			return cliusage.WithExitCode(errors.New("not pushed"), substrateExitRefused)
		}
	}
	if err := substratePushDecide(ctx, cmd, f, s, a, api.PushRequest{
		Host: p.Host, Repo: p.Repo, URL: p.PushURL, Branch: branch, Head: p.Commit, Commits: p.Commits, Files: len(p.Files),
	}); err != nil {
		return err
	}
	fmt.Fprintf(errw, "Pushing %s to %s...\n", branch, target)
	if err := p.Push(ctx, rel.Client.BranchExec, branch, a.Name, workspace.PushedBefore(dataDir, copyName, p.Host, p.Repo, branch)); err != nil {
		var pe *workspace.BranchPushError
		if errors.As(err, &pe) {
			return cliusage.WithExitCode(err, substrateExitRefused)
		}
		return substrateFail(err)
	}
	if err := workspace.RecordPushed(dataDir, copyName, p.Host, p.Repo, branch, p.Commit); err != nil {
		fmt.Fprintf(errw, "warning: could not record the push on this computer (%v); a later push to %s from here is refused as an existing branch\n", err, branch)
	}
	link := workspace.CompareLink(p.Host, p.Repo, branch)
	if asJSON {
		return writeSubstrateJSONCompact(w, map[string]any{"pushed": true, "branch": branch, "host": p.Host, "repo": p.Repo, "commit": p.Commit,
			"commits": p.Commits, "files": len(p.Files), "compare": link})
	}
	fmt.Fprintf(w, "Pushed %s to %s (%s).", branch, target, substratePlural(p.Commits, "commit", "commits"))
	if link != "" {
		fmt.Fprintf(w, " Open a pull request: %s", link)
	}
	fmt.Fprintln(w)
	return nil
}

// substratePushBranchReplaced refuses pull --push-branch, before anything
// reaches the agent, for a copy whose tracked files this computer sent with
// credentials replaced (S9a, RV6-4): the sandbox's HEAD starts at the
// placeholder commit, so every agent commit carries DC_SECRET_<n> where the
// person's lines were (osw.CheckPushFromSandbox). A copy whose only replaced
// files are untracked is not refused: no commit holds them, and a commit the
// agent makes of one is refused by the placeholder scan in
// workspace.PrepareBranchPush. A record that cannot be read refuses nothing
// here; PrepareBranchPush refuses the same commits on any computer.
func substratePushBranchReplaced(dataDir, copyName, actor, branch string) error {
	rec, err := osw.LoadCopy(dataDir, copyName)
	if err != nil {
		return nil
	}
	if err := osw.CheckPushFromSandbox(rec); err != nil {
		return cliusage.WithExitCode(fmt.Errorf("not pushed: %w: defenseclaw substrate pull %s --branch %s", err, actor, branch), substrateExitRefused)
	}
	return nil
}

// substratePushReview prints what the push carries and what is flagged.
func substratePushReview(w io.Writer, p *workspace.BranchPush, branch, target string) {
	fmt.Fprintf(w, "Push %s (%s, %s) to %s\n", branch, substratePlural(p.Commits, "commit", "commits"), substratePlural(len(p.Files), "file", "files"), target)
	if p.Made {
		fmt.Fprintln(w, "  The agent's uncommitted work goes in one commit, \"defenseclaw: work of agent ...\".")
	}
	for i, name := range p.Files {
		if i == 20 {
			fmt.Fprintf(w, "  ... and %d more\n", len(p.Files)-20)
			break
		}
		fmt.Fprintf(w, "  %s\n", workspace.DisplayName(name))
	}
	for _, name := range p.Placeholder {
		fmt.Fprintf(w, "  ! %s writes the cluster's credential placeholder; the repository should not hold it\n", workspace.DisplayName(name))
	}
	for _, name := range p.RunsCode {
		fmt.Fprintf(w, "  ! %s can run code where the branch lands (CI, hooks, scripts)\n", workspace.DisplayName(name))
	}
	for _, sf := range p.Secrets {
		fmt.Fprintf(w, "  ! %s: %s\n", workspace.DisplayName(sf.Path), sf.Title)
	}
}

// substratePushDecide asks the gateway and, for an ask, the person: inline
// [y/N/a] on a terminal, else it waits for an answer from
// `substrate approve` (the person's, or an administrator's).
func substratePushDecide(ctx context.Context, cmd *cobra.Command, f *substratePullFlags, s *substrateSession, a api.Actor, req api.PushRequest) error {
	errw := cmd.ErrOrStderr()
	deadline := time.Now().Add(substratePushWait)
	asked := false
	for {
		d, err := s.Client.PushIntent(ctx, a.Atespace, a.Name, req)
		if err != nil {
			return substrateFail(err)
		}
		switch d.Decision {
		case config.SubstrateGitPushAllow:
			return nil
		case config.SubstrateGitPushAsk:
		default:
			msg := "your profile turned off pull --push-branch (git_push: deny)"
			if d.Reason == "ask_denied" {
				msg = "the push was denied"
			}
			return cliusage.WithExitCode(errors.New(msg+"; bring the work home with --branch NAME and push from your computer"), substrateExitRefused)
		}
		req.AskID = d.AskID
		if f.yes {
			return cliusage.WithExitCode(fmt.Errorf("not pushed: pushing needs an answer (--yes takes no). Answer it with: defenseclaw substrate approve %s", d.AskID), substrateExitRefused)
		}
		if !asked && term.IsTerminal(int(os.Stdin.Fd())) {
			asked = true
			fmt.Fprintf(errw, "%s [y/N/a] ", strings.TrimSuffix(d.Summary, "?")+"?")
			line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			var note string
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				note, err = s.Client.Decide(ctx, d.AskID, "approve", false, "")
			case "a", "always":
				note, err = s.Client.Decide(ctx, d.AskID, "approve", true, "")
			default:
				_, _ = s.Client.Decide(ctx, d.AskID, "deny", false, "")
				fmt.Fprintln(errw, "Not pushed.")
				return cliusage.WithExitCode(errors.New("not pushed"), substrateExitRefused)
			}
			if err != nil {
				return substrateFail(err)
			}
			if note != "" {
				// The answer is recorded but moved nothing (GAP-0973): say so.
				fmt.Fprintln(errw, note)
			}
			continue
		}
		if !asked {
			asked = true
			fmt.Fprintf(errw, "%s Waiting for an answer: defenseclaw substrate approve %s\n", d.Summary, d.AskID)
		}
		if time.Now().After(deadline) {
			return cliusage.WithExitCode(fmt.Errorf("not pushed: nobody answered ask %s", d.AskID), substrateExitRefused)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(substratePushPoll):
		}
	}
}
