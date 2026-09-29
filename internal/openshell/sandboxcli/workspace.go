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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// CopyWorkspace is the copy-mode surface of package workspace.
type CopyWorkspace interface {
	Stage(ctx context.Context, opts workspace.StageOptions) (*workspace.CopyRecord, error)
	Upload(ctx context.Context, dataDir, name string, up workspace.Uploader) (*workspace.CopyRecord, error)
	Baseline(ctx context.Context, dataDir, name string, ex workspace.Execer) (*workspace.CopyRecord, error)
	Refresh(ctx context.Context, opts workspace.RefreshOptions) (*workspace.CopyRecord, error)
	Pull(ctx context.Context, opts workspace.PullOptions) (*workspace.PullResult, error)
	Apply(ctx context.Context, opts workspace.ApplyOptions) (*workspace.ApplyResult, error)
	UndoApply(ctx context.Context, opts workspace.UndoApplyOptions) (*workspace.UndoApplyResult, error)
	// Discard removes a copy this run staged for a sandbox that was never
	// created.
	Discard(dataDir, name string) error
	// PendingWork reports the work a sandbox's copy holds that was never
	// brought back (workspace.PendingWork; a nil ex for a stopped one).
	PendingWork(ctx context.Context, dataDir, name string, ex workspace.Execer) (workspace.CopyWork, error)
}

type defaultCopyWorkspace struct{}

func (defaultCopyWorkspace) Stage(ctx context.Context, o workspace.StageOptions) (*workspace.CopyRecord, error) {
	return workspace.Stage(ctx, o)
}
func (defaultCopyWorkspace) Upload(ctx context.Context, dataDir, name string, up workspace.Uploader) (*workspace.CopyRecord, error) {
	return workspace.Upload(ctx, dataDir, name, up)
}
func (defaultCopyWorkspace) Baseline(ctx context.Context, dataDir, name string, ex workspace.Execer) (*workspace.CopyRecord, error) {
	return workspace.EstablishBaseline(ctx, dataDir, name, ex)
}
func (defaultCopyWorkspace) Refresh(ctx context.Context, o workspace.RefreshOptions) (*workspace.CopyRecord, error) {
	return workspace.Refresh(ctx, o)
}
func (defaultCopyWorkspace) Pull(ctx context.Context, o workspace.PullOptions) (*workspace.PullResult, error) {
	return workspace.Pull(ctx, o)
}
func (defaultCopyWorkspace) Apply(ctx context.Context, o workspace.ApplyOptions) (*workspace.ApplyResult, error) {
	return workspace.Apply(ctx, o)
}
func (defaultCopyWorkspace) UndoApply(ctx context.Context, o workspace.UndoApplyOptions) (*workspace.UndoApplyResult, error) {
	return workspace.UndoApply(ctx, o)
}
func (defaultCopyWorkspace) Discard(dataDir, name string) error {
	if err := workspace.DeleteCopy(dataDir, name); err != nil && !errors.Is(err, workspace.ErrCopyNotFound) {
		return err
	}
	return nil
}
func (defaultCopyWorkspace) PendingWork(ctx context.Context, dataDir, name string, ex workspace.Execer) (workspace.CopyWork, error) {
	return workspace.PendingWork(ctx, dataDir, name, ex)
}

// UndoOptions are the `sandbox undo` flags.
type UndoOptions struct {
	Name     string
	Yes      bool
	Preview  bool
	Restart  bool
	KeepRefs bool
	Output   OutputFormat
}

// Undo restores a mounted project to its pre-session snapshot after a
// preview, or for a copy-mode sandbox reverts its last `pull --apply`.
// With -o json stdout carries the restore's response, or the preview's
// (result.preview true) when nothing was restored.
func (a *App) Undo(ctx context.Context, o UndoOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	if sb, err := api.Get(ctx, o.Name); err == nil && sb.WorkdirMode == config.OpenShellWorkdirCopy {
		return a.undoApply(ctx, api, sb, o)
	}
	preview, err := api.Undo(ctx, o.Name, sandboxapi.UndoRequest{Preview: true, KeepRefs: o.KeepRefs})
	if err != nil {
		return apiError(err)
	}
	stdout, restore := a.jsonOutput(o.Output)
	defer restore()
	empty := preview.Result == nil || preview.Result.Empty()
	if stdout != nil && (o.Preview || empty) {
		return writeJSON(stdout, preview)
	}
	if empty {
		if preview.Result != nil && len(preview.Result.Unrestored()) > 0 {
			// Not a clean result: the session changed what undo cannot
			// put back.
			a.printUnrestored(preview.Result.Unrestored())
			a.note("nothing else to undo: the rest of " + o.Name + "'s folder matches its undo point")
			return nil
		}
		a.ok("nothing to undo: " + o.Name + "'s folder matches its undo point")
		return nil
	}
	a.printUndo(preview.Result, true)
	// Undo stops a running sandbox first (the agent could race the
	// restore): say so, and what it ends, before asking.
	sb, _ := api.Get(ctx, o.Name)
	running := sb != nil && sb.Phase == "ready"
	var cli *openshell.CLI
	run := detachedRun{State: runNone}
	if running {
		if gateway, err := a.gatewayName(ctx); err == nil {
			c := a.cli(gateway)
			cli = &c
			if r, err := a.detachedRun(ctx, c, sb); err == nil {
				run = r
			}
		}
		ends := "its harness session ends"
		if run.State == runRunning {
			ends = "its detached run" + a.startedText(run.Started) + " ends unfinished"
		}
		a.line("  stop " + o.Name + " first (" + ends + ")")
	}
	if o.Preview {
		return nil
	}
	question := "Restore " + a.tildePath(preview.Result.Project) + " to its undo point?"
	if running {
		question = "Stop " + o.Name + " and restore " + a.tildePath(preview.Result.Project) + " to its undo point?"
	}
	yes, err := a.confirm(question, o.Yes)
	if err != nil {
		return err
	}
	if !yes {
		a.note("nothing changed")
		if stdout != nil {
			return writeJSON(stdout, preview)
		}
		return nil
	}
	if cli != nil {
		a.keepRunLog(ctx, *cli, sb, run)
	}
	res, err := api.Undo(ctx, o.Name, sandboxapi.UndoRequest{Stop: true, Restart: o.Restart, KeepRefs: o.KeepRefs})
	if err != nil {
		return apiError(err)
	}
	if stdout != nil {
		return writeJSON(stdout, res)
	}
	if res.Stopped {
		a.note("stopped " + o.Name)
	}
	a.ok("restored: " + undoDone(res, "see above"))
	if res.Result != nil {
		if c := res.Result.PostCommit; c != "" {
			a.note("the session's state is kept in commit " + shortOID(c) + ": `git -C " + a.tildePath(firstNonEmpty(res.Result.Project, preview.Result.Project)) +
				" checkout " + shortOID(c) + " -- .` brings its files back")
		}
		for _, w := range res.Result.Warnings {
			a.warn(w)
		}
	}
	if res.Restarted {
		a.ok("restarted " + o.Name)
	}
	return nil
}

// undoDone is what a finished mount-mode undo restored: the daemon's
// summary, or the snapshot, except the places it could not restore (where
// says where the output lists them).
func undoDone(res *sandboxapi.UndoResponse, where string) string {
	msg := firstNonEmpty(res.Summary, "the folder is back at its undo point")
	if res.Result == nil {
		return msg
	}
	var left []string
	for _, c := range res.Result.Unrestored() {
		left = append(left, c.Path)
	}
	if len(left) == 0 {
		return msg
	}
	return msg + ", except " + strings.Join(firstN(left, 6), ", ") + " (" + where + ")"
}

// undoApply reverts a copy-mode sandbox's last `pull --apply` after a
// preview. It runs in the CLI, as the apply did, and reports the result to
// the daemon. Edits made in the folder since the apply stay; when they
// overlap the apply's changes nothing is changed.
func (a *App) undoApply(ctx context.Context, api API, sb *sandboxapi.Sandbox, o UndoOptions) error {
	stdout, restore := a.jsonOutput(o.Output)
	defer restore()
	if o.KeepRefs || o.Restart {
		a.warn("--keep-refs and --restart apply to mounted projects; " + sb.Name + " works on a copy")
	}
	opts := workspace.UndoApplyOptions{DataDir: a.dataDir(), Name: sb.Name, Preview: true}
	preview, err := a.Workspace.UndoApply(ctx, opts)
	if errors.Is(err, workspace.ErrNothingApplied) {
		if stdout != nil {
			return writeJSON(stdout, sandboxapi.UndoResponse{Name: sb.Name, Apply: &workspace.UndoApplyResult{Name: sb.Name, Project: sb.Project, Preview: true}})
		}
		a.ok("nothing to undo: " + sb.Name + " works on a copy, and no `pull --apply` of its work is left to revert")
		a.note("a branch or patch file its work went to is yours to delete")
		return nil
	}
	if err != nil {
		return fmt.Errorf("undo %s: %w", sb.Name, err)
	}
	resp := sandboxapi.UndoResponse{Name: sb.Name, Apply: preview}
	if len(preview.Conflicts) > 0 {
		if stdout != nil {
			_ = writeJSON(stdout, resp)
		}
		return a.undoApplyConflict(preview)
	}
	if len(preview.Changes) == 0 {
		if stdout != nil {
			return writeJSON(stdout, resp)
		}
		a.ok("nothing to undo: " + a.tildePath(preview.Project) + " no longer has the changes of " + sb.Name + "'s last apply")
		return nil
	}
	if stdout != nil && o.Preview {
		return writeJSON(stdout, resp)
	}
	a.line(a.bold("Undo will revert the last `pull --apply` of "+sb.Name+" in "+a.tildePath(preview.Project)) +
		fmt.Sprintf(" (%s):", plural(int64(len(preview.Changes)), "path", "paths")))
	for i, c := range preview.Changes {
		if i == 20 {
			a.line(fmt.Sprintf("  … %d more", len(preview.Changes)-20))
			break
		}
		// Changes run from the folder now to the folder without the apply.
		verb := "revert "
		switch c.Status {
		case "A":
			verb = "restore"
		case "D":
			verb = "remove "
		}
		a.line("  " + verb + " " + c.Path)
	}
	a.note("edits you made since the apply stay")
	if o.Preview {
		return nil
	}
	yes, err := a.confirm("Revert the apply in "+a.tildePath(preview.Project)+"?", o.Yes)
	if err != nil {
		return err
	}
	if !yes {
		a.note("nothing changed")
		if stdout != nil {
			return writeJSON(stdout, resp)
		}
		return nil
	}
	opts.Preview = false
	res, err := a.Workspace.UndoApply(ctx, opts)
	report := sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUndo}
	switch {
	case err != nil:
		report.Result, report.FailureClass = "failed", "undo_failed"
	case len(res.Conflicts) > 0:
		report.Result = "skipped"
	default:
		files := int64(len(res.Changes))
		report.FileCount = &files
		if files == 0 {
			report.Result = "no_change"
		}
	}
	if rerr := api.ReportWorkspace(context.WithoutCancel(ctx), sb.Name, report); rerr != nil {
		a.warn("could not record the undo with the daemon: " + apiError(rerr).Error())
	}
	if err != nil {
		return fmt.Errorf("undo %s: %w", sb.Name, err)
	}
	if len(res.Conflicts) > 0 {
		return a.undoApplyConflict(res)
	}
	if res.Undone {
		// The undone work is in the sandbox alone again.
		a.forgetCleanCopy(sb.Name)
	}
	if stdout != nil {
		return writeJSON(stdout, sandboxapi.UndoResponse{Name: sb.Name, Apply: res})
	}
	a.ok(fmt.Sprintf("reverted the last apply: %s in %s", plural(int64(len(res.Changes)), "path", "paths"), a.tildePath(res.Project)))
	a.note("bring the work back with `" + CommandName + " pull " + sb.Name + " --apply`")
	return nil
}

// undoApplyConflict is the error for an apply undo that would overwrite
// the operator's edits.
func (a *App) undoApplyConflict(r *workspace.UndoApplyResult) error {
	kept := "DefenseClaw keeps the folder as it was before the apply"
	if r.PreApplyRef != "" {
		kept = "the folder as it was before the apply is kept at " + r.PreApplyRef +
			" (`git -C " + a.tildePath(r.Project) + " diff " + r.PreApplyRef + "` shows what changed since)"
	}
	return fmt.Errorf("you also changed %s since the apply, so undo cannot revert it without losing your edits; nothing changed. %s",
		strings.Join(firstN(r.Conflicts, 6), ", "), kept)
}

func shortOID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func (a *App) printUndo(r *workspace.UndoResult, preview bool) {
	verb := "Undo will"
	if !preview {
		verb = "Undo"
	}
	a.line(a.bold(verb+" restore "+a.tildePath(r.Project)) + fmt.Sprintf(" (%s):", plural(int64(len(r.Changes)), "path", "paths")))
	for i, c := range r.Changes {
		if i == 20 {
			a.line(fmt.Sprintf("  … %d more", len(r.Changes)-20))
			break
		}
		a.line("  " + undoVerb(c.Status) + " " + c.Path)
	}
	switch {
	case r.BranchBefore != "" && r.BranchBefore != r.BranchAfter:
		a.line("  switch back to branch " + r.BranchBefore + " at " + firstNonEmpty(shortCommit(r.HeadBefore), "its undo point's commit"))
	case r.HeadBefore != r.HeadAfter && r.HeadBefore != "":
		on := ""
		if r.BranchBefore != "" {
			on = " (" + r.BranchBefore + ")"
		}
		a.line("  reset HEAD" + on + " from " + firstNonEmpty(shortCommit(r.HeadAfter), "none") + " back to " + shortCommit(r.HeadBefore) +
			" (undo saves the session's state first)")
	}
	if n := len(r.RefChanges); n > 0 {
		var refs []string
		for _, rc := range r.RefChanges {
			refs = append(refs, strings.TrimPrefix(strings.TrimPrefix(rc.Ref, "refs/heads/"), "refs/tags/"))
		}
		a.line("  restore " + plural(int64(n), "branch or tag", "branches and tags") + ": " + strings.Join(firstN(refs, 6), ", "))
	}
	if n := len(r.ControlChanges); n > 0 {
		a.line("  reset " + plural(int64(n), "git control file", "git control files") + ": " + strings.Join(firstN(r.ControlChanges, 6), ", "))
	}
	if n := len(r.LostObjects); n > 0 {
		a.line("  bring back " + plural(int64(n), "pre-session commit", "pre-session commits") + " the session deleted")
	}
	if n := len(r.HiddenRemoved); n > 0 {
		a.line("  remove " + plural(int64(n), "file", "files") + " the session hid from git with changed ignore rules")
	}
	for _, n := range r.NestedRepos {
		a.line("  remove nested repository " + n)
	}
	for _, c := range r.Ignored {
		if c.Removed {
			a.line(fmt.Sprintf("  remove  %s the session wrote to %s (a Python bytecode cache)", plural(int64(c.Added+c.Modified), "file", "files"), c.Path))
		}
	}
	for _, p := range r.PinnedChanges {
		a.warn(p + " changed on this machine during the session; it is kept")
	}
	a.printUnrestored(r.Unrestored())
}

// printUnrestored warns about each change undo cannot put back (files the
// snapshot holds no copy of) and what to do about it.
func (a *App) printUnrestored(list []workspace.IgnoredChange) {
	const shown = 8
	for i, c := range list {
		if i == shown {
			a.warn(fmt.Sprintf("… and %d more places undo cannot restore (`%s review` lists them)", len(list)-shown, CommandName))
			break
		}
		what := c.Summary() + " during the session"
		if c.ExecutableCount > 0 {
			ex := make([]string, len(c.Executables))
			for j, p := range c.Executables {
				ex[j] = strings.TrimPrefix(p, c.Path)
			}
			what += ", including " + strings.Join(ex, ", ")
			if c.ExecutableCount > len(ex) {
				what += fmt.Sprintf(" and %d more that run on this machine", c.ExecutableCount-len(ex))
			}
		}
		a.warn(fmt.Sprintf("undo cannot restore %s (%s): %s", c.Path, what, c.Remedy))
	}
}

func undoVerb(status string) string {
	switch status {
	case "A":
		return "remove "
	case "D":
		return "restore"
	default:
		return "revert "
	}
}

// ReviewOptions are the `sandbox review` flags.
type ReviewOptions struct {
	Name   string
	Diff   bool
	Output OutputFormat
}

// Review prints the end-of-session review of a mounted project. For a
// copy-mode sandbox (every sandbox on a gateway that mounts no host
// folders) it previews what `pull` would bring back, applying nothing.
func (a *App) Review(ctx context.Context, o ReviewOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	if sb, err := api.Get(ctx, o.Name); err == nil && sb.WorkdirMode == config.OpenShellWorkdirCopy {
		if o.Diff && o.Output != OutputJSON {
			a.note("--diff: the changes of a copy come back as a patch; `" + CommandName + " pull " + o.Name + " --patch-out FILE` writes one")
		}
		return a.Pull(ctx, PullOptions{Name: o.Name, Output: o.Output, preview: true})
	}
	rev, err := api.Review(ctx, o.Name, sandboxapi.ReviewRequest{Diff: o.Diff})
	if err != nil {
		return apiError(err)
	}
	sb, _ := api.Get(ctx, o.Name)
	if o.Output == OutputJSON {
		out := struct {
			*sandboxapi.ReviewResponse
			NestedRepos []sandboxapi.NestedRepo `json:"nested_repos,omitempty"`
		}{ReviewResponse: rev}
		if sb != nil {
			out.NestedRepos = sb.NestedRepos
		}
		return writeJSON(a.IO.Out, out)
	}
	summary := rev.Summary
	if r := rev.Report; r != nil {
		if moved := headMoved(r.BranchBefore, r.BranchAfter, r.HeadBefore, r.HeadAfter); moved != "" {
			summary += " · " + moved
		}
	}
	a.line(a.bold(o.Name) + ": " + summary)
	if line := firstNonEmpty(riskLine(rev.Report), rev.RiskLine); line != "" {
		a.line(a.style(line, ansiYellow))
	}
	if r := rev.Report; r != nil {
		for _, f := range mergeFlags(r.Flags) {
			a.line(fmt.Sprintf("  %-8s %s — %s", strings.ToUpper(string(f.severity)), f.name, strings.Join(f.details, "; ")))
		}
		for _, f := range r.Findings {
			a.line(findingLine(f))
		}
		for _, w := range r.Warnings {
			a.warn(w)
		}
	}
	if sb != nil {
		(&session{app: a}).printNested(sb)
	}
	if o.Diff && rev.Diff != "" {
		a.println(strings.TrimRight(rev.Diff, "\n"))
	}
	return nil
}

// ExitPullConflict is the exit status of a `sandbox pull --apply` that left
// the working tree alone (a 3-way conflict, or a git too old to merge in
// place): the changes went to a branch and a patch instead.
const ExitPullConflict = 4

// PullOptions are the `sandbox pull` flags (copy mode).
type PullOptions struct {
	Name     string
	Apply    bool
	Branch   bool
	BranchAs string
	PatchOut string
	Force    bool
	// AcceptSensitive brings back changes that can run code on this
	// machine.
	AcceptSensitive bool
	Yes             bool
	Output          OutputFormat
	// preview is `review` of a copy-mode sandbox: a pull without a mode,
	// whose way on names `pull`.
	preview bool
}

// Pull brings a copy-mode sandbox's work back: review, then apply (3-way),
// a dc/<name> branch, or a patch file. With -o json stdout carries the
// pull's result, or with a mode the apply's (applied false when nothing
// was brought back).
func (a *App) Pull(ctx context.Context, o PullOptions) error {
	modes := 0
	for _, set := range []bool{o.Apply, o.Branch || o.BranchAs != "", o.PatchOut != ""} {
		if set {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("choose one of --apply, --branch and --patch-out")
	}
	api, err := a.api()
	if err != nil {
		return err
	}
	stdout, restore := a.jsonOutput(o.Output)
	defer restore()
	sb, err := api.Get(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if sb.WorkdirMode != config.OpenShellWorkdirCopy {
		return fmt.Errorf("%s works on your folder directly; use `%s review %s` or `%s undo %s`", o.Name, CommandName, o.Name, CommandName, o.Name)
	}
	gateway, err := a.gatewayName(ctx)
	if err != nil {
		return err
	}
	cli := a.cli(gateway)
	// handedOver is set once nothing of the sandbox's work is left to bring
	// back; a sandbox this pull started, and stops again, is then marked so
	// (markCleanCopy), and `delete` of it stopped need not warn.
	handedOver := false
	if sb.Phase != "ready" {
		a.note("starting " + o.Name + " to read its work…")
		if sb, err = api.Start(ctx, o.Name, sandboxapi.StartRequest{}); err != nil {
			return apiError(err)
		}
		defer func() {
			if handedOver {
				a.markCleanCopy(sb)
			}
		}()
		// Leave it as it was found.
		defer func() {
			if _, err := api.Stop(context.WithoutCancel(ctx), o.Name); err != nil {
				a.warn("could not stop " + o.Name + " again: " + apiError(err).Error())
				return
			}
			a.note("stopped " + o.Name + " again")
		}()
	}
	res, err := a.pull(ctx, api, cli, sb, true)
	if err != nil {
		return err
	}
	if res.Kind == workspace.CopyPlain && o.applyMode() == workspace.ApplyBranch {
		return fmt.Errorf("%s works on a copy of a folder that is not a git repository, so there is no branch to put its changes on; "+
			"bring them back with --apply or --patch-out FILE", o.Name)
	}
	if res.Empty() && res.Effective != "" && len(res.Blocking) == 0 {
		handedOver = true
	}
	if stdout != nil && modes == 0 {
		return writeJSON(stdout, res)
	}
	a.line(a.bold(o.Name) + ": " + pullSummary(res))
	if line := riskLine(&res.Review); line != "" {
		a.line(a.style(line, ansiYellow))
	}
	for _, c := range res.Changes {
		a.line(fmt.Sprintf("  %s %s", c.Status, c.Path))
	}
	for _, d := range res.Dropped {
		a.warn(d + " is held back from the sandbox; its change is not brought back")
	}
	for _, b := range res.Blocking {
		a.warn(b)
	}
	if modes == 0 {
		switch {
		case o.preview && res.Kind == workspace.CopyPlain:
			a.note("nothing was applied; bring it back with `" + CommandName + " pull " + o.Name + " --apply` (or --patch-out FILE)")
		case o.preview:
			a.note("nothing was applied; bring it back with `" + CommandName + " pull " + o.Name + " --apply` (or --branch or --patch-out FILE)")
		case res.Kind == workspace.CopyPlain:
			a.note("bring it back with --apply or --patch-out FILE")
		default:
			a.note("bring it back with --apply, --branch or --patch-out FILE")
		}
		return nil
	}
	nothing := func() error {
		if stdout == nil {
			return nil
		}
		return writeJSON(stdout, &workspace.ApplyResult{Mode: o.applyMode()})
	}
	if res.Empty() {
		if res.Since != "" {
			a.ok("nothing new since the last apply to " + a.tildePath(sb.Project))
		} else {
			a.ok("nothing to bring back")
		}
		return nothing()
	}
	if res.Review.Sensitive() && !o.AcceptSensitive {
		yes, err := a.ask(a.bringBackQuestion(&res.Review), false, false)
		if err != nil {
			if errors.Is(err, ErrNoTerminal) {
				return errors.New("some changes can run code on this machine; review them and pass --accept-sensitive")
			}
			return err
		}
		if !yes {
			return nothing()
		}
		o.AcceptSensitive = true
	}
	applied, err := a.applyPull(ctx, api, sb, res, o)
	if err != nil {
		return err
	}
	handedOver = true
	if stdout != nil {
		if err := writeJSON(stdout, applied); err != nil {
			return err
		}
	}
	if fellBack(applied) {
		// The work did not land in the working tree: scripts tell by the
		// status.
		return &ExitError{Code: ExitPullConflict, Err: &Silent{Err: errors.New("the changes were not applied to the working tree")}}
	}
	return nil
}

// fellBack reports an --apply that left the working tree alone (a 3-way
// conflict, or a git too old to merge without touching it) and put the
// changes on a branch and in a patch instead.
func fellBack(r *workspace.ApplyResult) bool {
	return r != nil && r.Mode == workspace.ApplyMerge && !r.Applied && (len(r.Conflicts) > 0 || r.Branch != "" || r.PatchPath != "")
}

// applyMode is how --apply, --branch or --patch-out brings the work back
// (a patch when none is set).
func (o PullOptions) applyMode() workspace.ApplyMode {
	switch {
	case o.Apply:
		return workspace.ApplyMerge
	case o.Branch || o.BranchAs != "":
		return workspace.ApplyBranch
	}
	return workspace.ApplyPatch
}

// pull captures the sandbox's work, saying so when announce is set.
func (a *App) pull(ctx context.Context, api API, cli openshell.CLI, sb *sandboxapi.Sandbox, announce bool) (*workspace.PullResult, error) {
	var review []string
	if eff, _, err := packs.Resolve(a.Cfg, packs.Flags{Pack: sb.Pack, Harness: sb.Harness, Project: sb.Project, Profile: sb.Profile, Copy: true}); err == nil {
		review = eff.Workspace.Review
	}
	if announce {
		a.note("Pulling " + sb.Name + "'s work…")
	}
	res, err := a.Workspace.Pull(ctx, workspace.PullOptions{DataDir: a.dataDir(), Name: sb.Name, Exec: a.transport(cli), SensitiveGlobs: review})
	if err != nil {
		return nil, workspaceFailure("pull "+sb.Name, err, a.sandboxDiskHint(ctx, api, err))
	}
	return res, nil
}

// lowDiskBytes is the free space under which a failed write is taken for
// a full disk: git names only the file it could not write.
const lowDiskBytes = 64 << 20

// sandboxDiskHint is diskFullHint for a step that also writes inside the
// sandbox (the upload, the pull's bundle). A disk full while this machine's
// is not, and not full from a write of this process, is the sandbox's own:
// on a driver that gives each sandbox a disk of its own (a MicroVM's
// overlay) the hint names that disk and its size setting instead.
func (a *App) sandboxDiskHint(ctx context.Context, api API, err error) string {
	hint := a.diskFullHint(err)
	if hint == "" || isNoSpace(err) {
		return hint
	}
	if free, known := freeBytes(a.dataDir()); !known || free < lowDiskBytes {
		return hint
	}
	disk := sandboxDisk(statusDriver(context.WithoutCancel(ctx), api))
	if disk == "" {
		return hint
	}
	return "the sandbox's own disk is full (no space left on device): a MicroVM writes to an overlay disk sized by " + disk +
		"; free some space in the sandbox, or raise that size for new sandboxes (`" + CommandName + " doctor` shows it)"
}

// diskFullHint names a full disk as the cause of a workspace failure (no
// space left on device), which git's own message does not say.
func (a *App) diskFullHint(err error) string {
	dir := a.dataDir()
	free, known := freeBytes(dir)
	full := isNoSpace(err) || strings.Contains(strings.ToLower(err.Error()), "no space left on device")
	if !full && (!known || free >= lowDiskBytes) {
		return ""
	}
	msg := "the disk holding " + a.tildePath(dir) + " is full (no space left on device)"
	if known {
		msg = "the disk holding " + a.tildePath(dir) + " is full (no space left on device: " + humanBytes(int64(free)) + " free)"
	}
	return msg + "; free some space, then retry"
}

// applyPull lands a pull and records it with the daemon.
func (a *App) applyPull(ctx context.Context, api API, sb *sandboxapi.Sandbox, res *workspace.PullResult, o PullOptions) (*workspace.ApplyResult, error) {
	opts := workspace.ApplyOptions{DataDir: a.dataDir(), Name: sb.Name, Mode: o.applyMode(), AcceptSensitive: o.AcceptSensitive, Force: o.Force}
	switch opts.Mode {
	case workspace.ApplyBranch:
		opts.Branch = o.BranchAs
	case workspace.ApplyPatch:
		p, err := filepath.Abs(o.PatchOut)
		if err != nil {
			return nil, err
		}
		opts.PatchPath = p
	}
	applied, err := a.Workspace.Apply(ctx, opts)
	report := sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspacePull, PullMode: string(opts.Mode)}
	files := int64(len(res.Changes))
	var added, removed int64
	for _, c := range res.Changes {
		added += int64(c.Added)
		removed += int64(c.Deleted)
	}
	flagged := int64(len(res.Review.Flags))
	report.FileCount, report.LinesAdded, report.LinesRemoved, report.FlaggedCount = &files, &added, &removed, &flagged
	for _, f := range res.Review.Flags {
		report.Paths = append(report.Paths, f.Path)
	}
	switch {
	case err != nil:
		report.Result, report.FailureClass = "failed", "apply_failed"
	case applied != nil && len(applied.Conflicts) > 0:
		report.Result = "partial"
	case applied != nil && !applied.Applied:
		report.Result = "no_change"
	}
	if rerr := api.ReportWorkspace(context.WithoutCancel(ctx), sb.Name, report); rerr != nil {
		a.warn("could not record the pull with the daemon: " + apiError(rerr).Error())
	}
	if err != nil {
		return nil, workspaceFailure("bring back "+sb.Name+"'s changes", err, firstNonEmpty(applyHint(opts.Mode, err), a.diskFullHint(err)))
	}
	switch {
	case fellBack(applied):
		if len(applied.Conflicts) > 0 {
			a.warn(fmt.Sprintf("the 3-way apply conflicted in %s; your working tree is unchanged", strings.Join(firstN(applied.Conflicts, 6), ", ")))
		} else {
			a.warn("the changes could not be applied to your working tree, which is unchanged")
		}
		if applied.Branch != "" {
			a.ok("the changes are on branch " + applied.Branch + " instead")
		}
		if applied.PatchPath != "" {
			a.ok("and in " + applied.PatchPath)
		}
		switch {
		case applied.Branch != "":
			a.note("merge them when you are ready: git merge " + applied.Branch + "   (or pick hunks: git checkout -p " + applied.Branch + " -- .)")
		case applied.PatchPath != "":
			a.note("apply them when you are ready: git apply --3way " + applied.PatchPath)
		}
	case applied.Mode == workspace.ApplyMerge && applied.UpToDate:
		a.ok("nothing to apply: " + a.tildePath(sb.Project) + " already has these changes")
	case applied.Mode == workspace.ApplyMerge:
		a.ok(fmt.Sprintf("applied %s to %s", plural(int64(len(applied.Changes)), "change", "changes"), a.tildePath(sb.Project)))
		undo := "`" + CommandName + " undo " + sb.Name + "` reverts the apply"
		if applied.PreApplyRef != "" {
			a.note("your previous working tree is kept at " + applied.PreApplyRef + "; " + undo)
		} else {
			a.note(undo)
		}
	case applied.Mode == workspace.ApplyBranch:
		a.ok("the changes are on branch " + applied.Branch + " (your checkout is unchanged)")
	default:
		a.ok("wrote " + applied.PatchPath)
	}
	for _, w := range applied.Warnings {
		a.warn(w)
	}
	return applied, nil
}

// findingLine renders a scanner finding like the flag lines above it:
// "  CRITICAL config/dev.env:3 — clawshield-secrets: AWS access key".
func findingLine(f workspace.ScanFinding) string {
	where := firstNonEmpty(f.Location, f.Path)
	sev := strings.ToUpper(firstNonEmpty(f.Severity, "finding"))
	text := where + " — " + f.Scanner
	if title := firstNonEmpty(f.Title, f.RuleID); title != "" {
		text += ": " + title
	}
	return fmt.Sprintf("  %-8s %s", sev, truncate(text, 160))
}

// wsError is a workspace failure as people read it: what failed, then
// why, without package workspace's "workspace:" prefixes, and the way on.
type wsError struct {
	msg string
	err error
}

func (e *wsError) Error() string { return e.msg }
func (e *wsError) Unwrap() error { return e.err }

func workspaceFailure(what string, err error, hint string) error {
	msg := what + ": " + strings.ReplaceAll(err.Error(), "workspace: ", "")
	if hint != "" {
		msg += "; " + hint
	}
	return &wsError{msg: msg, err: err}
}

// applyHint is the way on after a pull could not land.
func applyHint(mode workspace.ApplyMode, err error) string {
	if !strings.Contains(err.Error(), "already exists") {
		return ""
	}
	switch mode {
	case workspace.ApplyBranch:
		return "pass --branch-name NAME for another branch, or --force to move this one"
	case workspace.ApplyPatch:
		return "pass another --patch-out FILE, or --force to overwrite this one"
	}
	return ""
}

// fileFlag is every review flag of one path: package.json's changed
// install scripts and bin entries are one line, not three.
type fileFlag struct {
	name     string
	severity workspace.Severity
	details  []string
}

var severityRank = map[workspace.Severity]int{
	workspace.SeverityInfo: 0, workspace.SeverityMedium: 1, workspace.SeverityHigh: 2, workspace.SeverityCritical: 3,
}

// mergeFlags groups review flags by path, in the review's order (most
// severe first), with each path's details once.
func mergeFlags(flags []workspace.Flag) []fileFlag {
	var out []fileFlag
	index := map[string]int{}
	for _, f := range flags {
		name, detail := f.Label, f.Detail
		if f.Path != "" && strings.HasPrefix(f.Label, f.Path+"#") {
			name = f.Path
			detail = strings.TrimPrefix(f.Label, f.Path+"#") + ": " + detail
		}
		i, ok := index[name]
		if !ok {
			i = len(out)
			index[name] = i
			out = append(out, fileFlag{name: name, severity: f.Severity})
		}
		if severityRank[f.Severity] > severityRank[out[i].severity] {
			out[i].severity = f.Severity
		}
		if detail != "" && !slices.Contains(out[i].details, detail) {
			out[i].details = append(out[i].details, detail)
		}
	}
	return out
}

// bringBackQuestion warns about what looks like a secret the sandbox
// wrote and returns the question that confirms bringing sensitive changes
// back: the same at a session's end and for `sandbox pull`.
func (a *App) bringBackQuestion(r *workspace.ReviewReport) string {
	secrets := r.SecretPaths()
	if len(secrets) > 0 {
		a.warn("the sandbox wrote what looks like a secret: " + strings.Join(firstN(secrets, 4), ", "))
		if riskLine(r) == "" {
			return "Some changes hold what looks like a secret. Bring them back anyway?"
		}
	}
	return "Some changes can run code on this machine. Bring them back anyway?"
}

// riskLine is the review's warning about changed files that can run code
// on this machine, one name per file, or "".
func riskLine(r *workspace.ReviewReport) string {
	if r == nil {
		return ""
	}
	var names []string
	for _, f := range mergeFlags(r.Flags) {
		if severityRank[f.severity] >= severityRank[workspace.SeverityMedium] {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "⚠ Changed files that can run code on your machine: " + strings.Join(firstN(names, 6), ", ") + "  → review before running"
}
