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
	"context"
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"

	"golang.org/x/term"
)

// --- logs -------------------------------------------------------------------

func runSubstrateLogs(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, ref string, follow bool, task string) error {
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
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	if a.State == substrateStateCrashed {
		// GAP-0420: no wait for an agent that cannot answer.
		return substrateFail(substrateCrashedErr(a))
	}
	o, err := substrateAttachOptions(cmd, s, a, "auto", true, attach.KeyReplayOff)
	if err != nil {
		return err
	}
	o.NoBanner = true
	id := task
	if id == "" {
		st, err := attach.Status(ctx, o)
		if err != nil {
			return substrateFail(err)
		}
		if id = latestSubstrateTask(st); id == "" {
			if a.Unattended {
				// GAP-0420: a headless run whose actor crashed and came back
				// lost its run and its log with the worker.
				if _, ok := loadSubstrateTaskRecord(auth.StateDir(), a); ok {
					return fmt.Errorf("%s/%s has no headless task now: its run and log were lost when it crashed and was brought back to an earlier snapshot. "+
						"Start the task again from the beginning with: defenseclaw substrate undo %s", a.Atespace, a.Name, a.Name)
				}
				return fmt.Errorf("%s/%s has no headless task now: its run and log were lost when it crashed and was brought back to an earlier snapshot. "+
					"Start it again with defenseclaw substrate undo %s on the computer that started it, or start the task again in a new agent", a.Atespace, a.Name, a.Name)
			}
			return fmt.Errorf("%s/%s has no headless task; start one with: defenseclaw substrate run AGENT --task \"...\"", a.Atespace, a.Name)
		}
	}
	emit := attach.TextEmitter(cmd.OutOrStdout(), cmd.ErrOrStderr())
	if asJSON {
		emit = func(e relay.TaskEvent) { _ = writeSubstrateJSONCompact(cmd.OutOrStdout(), e) }
	}
	var code int
	if follow {
		defer substratePresence(cmd, a)()
		code, err = attach.FollowTask(ctx, o, id, emit)
	} else {
		// A snapshot: read what is there, then stop once nothing new comes.
		// Only the open log is timed, never the wait for the agent to wake
		// and answer: that wait cut a finished task's log off unread, and
		// logs printed nothing with exit 0 (GAP-0406).
		code, err = attach.SnapshotTask(ctx, o, id, attach.Quiet{First: 3 * time.Second, Then: 2 * time.Second}, emit)
		if errors.Is(err, attach.ErrTaskStillRunning) {
			if !asJSON {
				fmt.Fprintf(cmd.ErrOrStderr(), "The task is still running. Follow it with: defenseclaw substrate logs -f %s\n", a.Name)
			}
			return nil
		}
	}
	if err != nil {
		return substrateFail(err)
	}
	if err == nil && code != 0 && !asJSON {
		fmt.Fprintf(cmd.ErrOrStderr(), "The task ended with exit code %d.\n", code)
	}
	return nil
}

// latestSubstrateTask picks the newest task id from a relay status document.
func latestSubstrateTask(st map[string]any) string {
	tasks, _ := st["tasks"].(map[string]any)
	type item struct {
		id      string
		started string
	}
	var items []item
	for id, v := range tasks {
		m, _ := v.(map[string]any)
		started, _ := m["started"].(string)
		items = append(items, item{id, started})
	}
	if len(items) == 0 {
		return ""
	}
	sort.Slice(items, func(i, j int) bool { return items[i].started > items[j].started })
	return items[0].id
}

// --- pull -------------------------------------------------------------------

func runSubstratePull(cmd *cobra.Command, f *substratePullFlags, ref string) error {
	asJSON, err := f.out.wantJSON()
	if err != nil {
		return err
	}
	modes := 0
	for _, on := range []bool{f.apply, f.branch != "", f.patch != "", f.pushBranch != ""} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return cliusage.WithExitCode(errors.New("choose one of --apply, --branch NAME, --patch-out FILE or --push-branch NAME"), 2)
	}
	if len(f.exclude) > 0 && f.noExclude {
		return cliusage.WithExitCode(errors.New("choose --exclude GLOB (what run left out) or --no-exclude (run left out nothing), not both"), 2)
	}
	if f.allowFlagged && !f.apply && f.pushBranch == "" {
		// Refused before anything is read, also on an empty pull
		// (GAP-0531).
		return cliusage.WithExitCode(errors.New("--allow-flagged goes with --apply or --push-branch (a branch or a patch writes nothing that runs)"), 2)
	}
	s, err := substrateOpen(cmd, &f.com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	if a.State == substrateStateCrashed {
		return substrateFail(substrateCrashedErr(a))
	}
	if f.pushBranch != "" {
		return runSubstratePushBranch(ctx, cmd, f, s, a, asJSON)
	}
	name := substrateCopyName(a)
	dataDir := auth.StateDir()
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	w := cmd.OutOrStdout()
	fmt.Fprintln(cmd.ErrOrStderr(), "Reading the agent's work...")
	rev, err := workspace.Pull(ctx, workspace.PullOptions{Exec: rel.Client, DataDir: dataDir, Name: name, Label: a.Name, Timeout: f.timeout, Project: ".",
		RestoreSecretLines: f.restoreSecrets, Exclude: f.exclude, ExcludesStated: len(f.exclude) > 0 || f.noExclude})
	if err != nil {
		var nr *workspace.NoRecordError
		if errors.As(err, &nr) {
			return substratePullElsewhere(a, nr)
		}
		return fmt.Errorf("could not read the agent's work: %w", err)
	}
	if asJSON {
		files := make([]map[string]any, 0, len(rev.Changed))
		for _, c := range rev.Changed {
			files = append(files, map[string]any{"path": c.Path, "status": c.Status, "flags": c.Flags})
		}
		doc := map[string]any{"agent": a.Atespace + "/" + a.Name, "summary": rev.Summary, "flagged": rev.Flagged, "empty": rev.Empty, "files": files, "sensitive": rev.Sensitive, "blocking": rev.Blocking}
		if f.diff {
			doc["diff"] = string(rev.Diff)
		}
		if modes == 0 {
			return writeSubstrateJSON(w, doc)
		}
		defer func() { _ = writeSubstrateJSON(w, doc) }()
	} else {
		fmt.Fprint(w, safetext.Clean(rev.Text))
		if f.diff && len(rev.Diff) > 0 {
			fmt.Fprintf(w, "\n%s", safetext.Visible(string(rev.Diff)))
		}
	}
	if rev.Empty {
		return nil
	}
	mode, branch, patch := workspace.ModeApply, f.branch, f.patch
	switch {
	case f.apply:
		// Flagged files land only on an explicit yes: --allow-flagged, or
		// the question answered y. --yes takes the safe answer, no
		// (GAP-0472); Apply then refuses and names the files.
		accept, write, err := substratePullAccept(f, rev.Sensitive, substrateInteractive(), func() (bool, error) {
			return substrateConfirm(cmd, "Some of these changes can run code on this computer. Write them into this folder anyway?")
		})
		if err != nil {
			return err
		}
		if !write {
			fmt.Fprintln(cmd.ErrOrStderr(), "Nothing was written to this folder. Look at them first with --branch NAME or --patch-out FILE, or pass --allow-flagged.")
			return nil
		}
		return substrateApply(cmd, dataDir, name, mode, branch, patch, accept)
	case f.branch != "":
		mode = workspace.ModeBranch
	case f.patch != "":
		mode = workspace.ModePatch
	default:
		return substratePullChoose(cmd, f, a, name, dataDir, rev)
	}
	// A branch or a patch runs nothing; Apply still refuses a branch whose
	// history would keep a secret.
	return substrateApply(cmd, dataDir, name, mode, branch, patch, false)
}

// substratePullAccept decides whether pull --apply may write files flagged
// as able to run code: --allow-flagged says yes; otherwise a terminal asks
// (the default answer is no). --yes takes that safe answer and never says
// yes for the user (GAP-0472): Apply then refuses and names the files.
// write is false when the user answered no.
func substratePullAccept(f *substratePullFlags, sensitive, interactive bool, ask func() (bool, error)) (accept, write bool, err error) {
	if !sensitive || f.allowFlagged {
		return f.allowFlagged, true, nil
	}
	if f.yes || !interactive {
		return false, true, nil
	}
	ok, err := ask()
	if err != nil {
		return false, false, err
	}
	return ok, ok, nil
}

// substratePullElsewhere is pull's refusal on a computer that keeps no
// record of the copy and where the folder pull runs in cannot stand in for
// it (GAP-0489): it is not a git checkout with a commit, or the agent has no
// folder of its name. The copy of the baseline in the agent's sandbox is the
// agent's to rewrite, so it is never used. The refusal names what works.
// Exit 3: running it again in this folder cannot help.
func substratePullElsewhere(a api.Actor, why *workspace.NoRecordError) error {
	return cliusage.WithExitCode(fmt.Errorf("%s/%s: %s. "+
		"Run pull in a git checkout of the folder you sent (it compares the agent's work with that checkout's last commit), or on the computer you ran \"defenseclaw substrate run\" on. "+
		"Or connect to the agent (defenseclaw substrate connect %s), commit its work and git push it from inside the agent, then git pull it here. "+
		"If it was started with run --clone, push the work to its origin as a branch: defenseclaw substrate pull %s --push-branch NAME",
		a.Atespace, a.Name, why.Error(), a.Name, a.Name), substrateExitRefused)
}

// substratePullChoose asks what to do with the changes on a terminal; with
// no terminal it says how to choose.
func substratePullChoose(cmd *cobra.Command, f *substratePullFlags, a api.Actor, name, dataDir string, rev *workspace.Review) error {
	hint := fmt.Sprintf("Nothing was written to this folder. Bring the changes home with:\n  defenseclaw substrate pull %s --apply            write them into this folder\n  defenseclaw substrate pull %s --branch NAME      put them on a new git branch\n  defenseclaw substrate pull %s --patch-out FILE   write a patch", a.Name, a.Name, a.Name)
	if f.yes {
		// The safe default is a branch, which runs nothing; a secret still
		// keeps it out of the branch's history (Apply decides).
		return substrateApply(cmd, dataDir, name, workspace.ModeBranch, "", "", false)
	}
	if !substrateInteractive() {
		fmt.Fprintln(cmd.ErrOrStderr(), hint)
		return nil
	}
	q := "Write these changes into this folder?"
	if rev.Sensitive {
		q = "Some of these changes can run code on this computer. Write them into this folder anyway?"
	}
	ok, err := substrateConfirm(cmd, q)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), hint)
		return nil
	}
	return substrateApply(cmd, dataDir, name, workspace.ModeApply, "", "", true)
}

// substrateInteractive is true when stdin is a terminal. A char device is
// not enough: /dev/null is one, and a script that gives pull no input must
// get the hint, not a question. Tests replace it.
var substrateInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func substrateApply(cmd *cobra.Command, dataDir, name string, mode workspace.ApplyMode, branch, patch string, accept bool) error {
	ctx, stop := substrateContext(cmd)
	defer stop()
	res, err := workspace.Apply(ctx, workspace.ApplyOptions{DataDir: dataDir, Name: name, Mode: mode, Branch: branch, PatchPath: patch, AcceptSensitive: accept})
	if err != nil {
		var sens *workspace.SensitiveError
		var unknown *workspace.ExcludesUnknownError
		if errors.As(err, &sens) || errors.As(err, &unknown) {
			// The refusal already names --allow-flagged, --branch and
			// --patch-out; the advice is said once (GAP-0531).
			return cliusage.WithExitCode(err, substrateExitRefused)
		}
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), strings.TrimRight(safetext.Clean(res.Text), "\n")+"\n")
	return nil
}

// --- checkpoint and undo ----------------------------------------------------

func substrateRemoteDir(a api.Actor) (string, error) {
	dir := workspace.RemoteDirOf(auth.StateDir(), substrateCopyName(a))
	if dir == "" {
		return "", fmt.Errorf("this computer has no record of where %s/%s keeps your folder. Run checkpoint and undo on the computer you started it from", a.Atespace, a.Name)
	}
	return dir, nil
}

func runSubstrateCheckpoint(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, ref string, every time.Duration) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return err
	}
	if every < 0 || (every > 0 && every < time.Minute) {
		return cliusage.WithExitCode(errors.New("--every must be at least 1m, for example --every 1h"), 2)
	}
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	dir, err := substrateRemoteDir(a)
	if err != nil {
		return err
	}
	take := func() error {
		info, err := func() (*workspace.CheckpointInfo, error) {
			rel, err := substrateOpenRelay(ctx, s, a)
			if err != nil {
				return nil, err
			}
			defer rel.Close()
			return workspace.Checkpoint(ctx, workspace.CheckpointOptions{Exec: rel.Client, Dir: dir, DataDir: auth.StateDir(), Name: substrateCopyName(a)})
		}()
		if err != nil {
			return err
		}
		// GAP-0410: the restore point is a file in the agent. Only a
		// snapshot the cluster stores brings it back after the agent's
		// worker goes away; without one a crash returns the agent to its
		// template's start, without the folder.
		kept, note, kerr := substrateKeepSnapshot(ctx, s, a, info.ID)
		if asJSON {
			if err := writeSubstrateJSONCompact(cmd.OutOrStdout(), map[string]any{"id": info.ID, "files": info.Files, "agent": a.Atespace + "/" + a.Name, "kept": kept, "time": time.Now().UTC()}); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Saved restore point %s (%d files). Go back to it with: defenseclaw substrate undo %s --to %s\n", info.ID, info.Files, a.Name, info.ID)
		}
		if note != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), note)
		}
		return kerr
	}
	if err := take(); err != nil {
		return err
	}
	if every == 0 {
		return nil
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := take(); errors.Is(err, errSubstrateNotKept) {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", err)
			} else if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not save a restore point: %v\n", err)
			}
		}
	}
}

// runSubstrateRecover is substrate recover (GAP-0930): the gateway's
// recover route clears the relay certificate record, and brings a crashed
// agent back to its last snapshot.
func runSubstrateRecover(cmd *cobra.Command, com *substrateCommon, ref string, yes bool) error {
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	if a.State == substrateStateCrashed && !yes {
		ok, err := substrateConfirm(cmd, fmt.Sprintf("%s/%s crashed. Bring it back to its last snapshot? What it did after that snapshot is lost.", a.Atespace, a.Name))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing changed.")
			return nil
		}
	}
	_, err = s.Client.Recover(ctx, a.Atespace, a.Name)
	var ae *api.Error
	switch {
	case err == nil:
		fmt.Fprintf(cmd.OutOrStdout(), "%s/%s crashed; it is back at its last snapshot and starting, and its relay certificate record is cleared.\n", a.Atespace, a.Name)
		return nil
	case errors.As(err, &ae) && ae.Reason == "not_crashed":
		if !ae.RelayCertCleared {
			fmt.Fprintf(cmd.OutOrStdout(), "%s/%s is running and this cluster keeps no relay certificate record; nothing changed.\n", a.Atespace, a.Name)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s/%s: its relay certificate record is cleared. The relay asks for a new certificate when a connect refuses its old one, so the first connect can still fail; connect again, and if that fails too, wait a minute.\n", a.Atespace, a.Name)
		return nil
	case errors.As(err, &ae) && ae.NotImplemented():
		return substrateFail(fmt.Errorf("this cluster cannot recover agents yet; ask your administrator to upgrade DefenseClaw"))
	}
	return substrateFail(fmt.Errorf("recovering %s/%s: %w", a.Atespace, a.Name, err))
}

func runSubstrateUndo(cmd *cobra.Command, com *substrateCommon, ref, to string, yes bool) error {
	s, err := substrateOpen(cmd, com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	if a.State == substrateStateCrashed {
		// GAP-0410: a crashed agent has no worker to run the restore in.
		// The gateway first brings it back to its last snapshot.
		if !yes {
			ok, err := substrateConfirm(cmd, fmt.Sprintf("%s/%s crashed. Bring it back to its last snapshot? What it did after that snapshot is lost.", a.Atespace, a.Name))
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintln(cmd.OutOrStdout(), "Nothing changed.")
				return nil
			}
		}
		rec, err := s.Client.Recover(ctx, a.Atespace, a.Name)
		if err != nil {
			var ae *api.Error
			if errors.As(err, &ae) && ae.NotImplemented() {
				return substrateFail(fmt.Errorf("this cluster cannot bring a crashed agent back yet; ask your administrator to upgrade DefenseClaw (or to run: kubectl ate revert actor %s -a %s)", a.Name, a.Atespace))
			}
			return substrateFail(fmt.Errorf("bringing %s/%s back from its crash: %w", a.Atespace, a.Name, err))
		}
		if rec.RecoveredFrom == "template" {
			// GAP-0410: no snapshot of its own was stored, so it came back
			// at its template's start and there is nothing to undo to.
			return substrateFail(substrateFolderLost(a, workspace.RemoteDirOf(auth.StateDir(), substrateCopyName(a))))
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "%s/%s crashed; it is back at its last snapshot and starting.\n", a.Atespace, a.Name)
	}
	if a.Unattended && to == "" {
		// GAP-0420: a --task agent this computer started whose run was lost
		// (a crash, or an administrator's revert) starts its task again on a
		// fresh copy of its folder: at least once, never silently dropped.
		if rec, ok := loadSubstrateTaskRecord(auth.StateDir(), a); ok {
			lost, err := substrateTaskLost(ctx, cmd, s, a, rec.Transport)
			if err != nil {
				return err
			}
			if lost {
				return substrateRerunTask(ctx, cmd, s, a, rec, yes)
			}
		}
	}
	dir, err := substrateRemoteDir(a)
	if err != nil {
		return err
	}
	if !yes {
		which := "the last restore point"
		if to != "" {
			which = "restore point " + to
		}
		ok, err := substrateConfirm(cmd, fmt.Sprintf("Put %s/%s back to %s? What the agent changed since is lost.", a.Atespace, a.Name, which))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(cmd.OutOrStdout(), "Nothing changed.")
			return nil
		}
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	opts := workspace.UndoOptions{Exec: rel.Client, Dir: dir, ID: to, DataDir: auth.StateDir(), Name: substrateCopyName(a)}
	info, err := workspace.Undo(ctx, opts)
	for try := 1; err != nil && a.State == substrateStateCrashed && try <= substrateUndoStartTries && substrateRelayStarting(err); try++ {
		// The recovered agent's relay may need a moment to answer.
		if serr := substrateSleep(ctx, 2*time.Second); serr != nil {
			return serr
		}
		info, err = workspace.Undo(ctx, opts)
	}
	if errors.Is(err, workspace.ErrNoFolder) && a.State == substrateStateCrashed {
		// An older gateway does not say where the recovery went; the
		// missing folder does (GAP-0410).
		return substrateFail(substrateFolderLost(a, dir))
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Put %s/%s back to restore point %s.\n", a.Atespace, a.Name, info.ID)
	if info.Pushes > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "It also took back %d push(es) made after that point.\n", info.Pushes)
	}
	// GAP-0415: what the agent was asking about is gone with the folder it
	// changed; its pending asks close now instead of waiting out their time.
	if n := substrateCloseAsks(ctx, s.Client, a, "the agent was put back to a restore point with undo"); n > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "Closed %d pending question(s) of %s.\n", n, a.Name)
	}
	return nil
}

// substrateFolderLost is the undo of an agent that came back from a crash
// at its template's start: no snapshot of its own was stored, so the folder
// copied into it and its restore points are gone (GAP-0410).
func substrateFolderLost(a api.Actor, dir string) error {
	folder := "its folder"
	if dir != "" {
		folder += " " + dir
	}
	return fmt.Errorf("%s/%s crashed before the cluster stored a snapshot of its work, so it came back at its template's start: %s and its restore points are lost, and there is nothing to undo to. "+
		"The folder on your computer is unchanged. Start a new agent on it from that folder with \"defenseclaw substrate run <agent>%s\", and remove this one with \"defenseclaw substrate delete %s\". "+
		"Restore points saved with \"defenseclaw substrate checkpoint\" are stored by the cluster and survive a crash",
		a.Atespace, a.Name, folder, substrateTemplateFlag(a), a.Name)
}

// substrateTemplateFlag is " --template T" for the agent's template, "" when
// it is not known.
func substrateTemplateFlag(a api.Actor) string {
	t := a.Template
	if i := strings.LastIndex(t, "/"); i >= 0 {
		t = t[i+1:]
	}
	if t == "" {
		return ""
	}
	return " --template " + t
}

// substrateKeepSnapshot has the cluster store the agent's state after the
// restore point id was saved in it (GAP-0410). kept is whether it did; note
// is a line for the person; err is set when the snapshot failed in a way a
// script should see (the restore point itself was saved).
func substrateKeepSnapshot(ctx context.Context, s *substrateSession, a api.Actor, id string) (kept bool, note string, err error) {
	res, err := s.Client.Snapshot(ctx, a.Atespace, a.Name)
	if err == nil {
		if res.State == "suspended" {
			if res.ResumeError == "no_worker" {
				return true, fmt.Sprintf("The cluster stored it, but it has no free worker to start %s again now; it is suspended at that snapshot, and \"defenseclaw substrate connect %s\" starts it when a worker is free.", a.Name, a.Name), nil
			}
			return true, fmt.Sprintf("The cluster stored it; %s is suspended at that snapshot and \"defenseclaw substrate connect %s\" starts it again.", a.Name, a.Name), nil
		}
		return true, "", nil
	}
	if ae, ok := api.AsError(err); ok {
		switch {
		case ae.NotImplemented():
			return false, "Note: this cluster cannot store a snapshot of the agent yet, so this restore point is lost if the agent's worker crashes. Ask your administrator to upgrade DefenseClaw.", nil
		case ae.Status == http.StatusConflict:
			return false, "Note: the agent stopped running before the cluster could store a snapshot, so this restore point is lost if it crashes before its next one. Run checkpoint again after connect.", nil
		}
	}
	// The suspend may have taken effect before it failed: the gateway
	// starts the agent again when it can, and says when it could not
	// (snapshot_failed_may_be_suspended); with no answer nobody knows
	// (GAP-0649).
	hint := ""
	if ae, ok := api.AsError(err); !ok || ae.Reason != "snapshot_failed" {
		hint = fmt.Sprintf(". %s may be suspended now; \"defenseclaw substrate connect %s\" starts it again", a.Name, a.Name)
	}
	return false, "", fmt.Errorf("%w: restore point %s is saved in the agent, but the cluster could not store a snapshot of it (%w), so it is lost if the agent crashes. Run checkpoint again%s", errSubstrateNotKept, id, err, hint)
}

// errSubstrateNotKept marks a checkpoint whose restore point was saved but
// not stored by the cluster.
var errSubstrateNotKept = errors.New("not stored by the cluster")

// substrateUndoStartTries bounds the retries of an undo while a recovered
// agent starts (2 s apart).
const substrateUndoStartTries = 30

// substrateRelayStarting reports an error of an agent that is still
// starting (HTTP 502, 503 or 504 from the route or the relay).
func substrateRelayStarting(err error) bool {
	if errors.Is(err, attach.ErrStarting) || errors.Is(err, attach.ErrClusterFull) {
		return true
	}
	msg := err.Error()
	for _, code := range []string{"HTTP 502", "HTTP 503", "HTTP 504"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

func substrateSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// substrateCloseAsks denies a's pending asks with why and returns how many
// it closed. Best effort: an ask it cannot close expires as before.
func substrateCloseAsks(ctx context.Context, cl *api.Client, a api.Actor, why string) int {
	asks, err := cl.Asks(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, k := range asks {
		if k.Actor != a.Name || (k.Atespace != "" && k.Atespace != a.Atespace) {
			continue
		}
		if _, err := cl.Decide(ctx, k.ID, "deny", false, why); err == nil {
			n++
		}
	}
	return n
}
