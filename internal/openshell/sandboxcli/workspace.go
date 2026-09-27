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
	// Discard removes a staged copy no sandbox was created for.
	Discard(dataDir, name string) error
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
	return workspace.DeleteCopy(dataDir, name)
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
			a.note("nothing else to undo: the rest of " + o.Name + "'s folder matches its pre-session snapshot")
			return nil
		}
		a.ok("nothing to undo: " + o.Name + "'s folder matches its pre-session snapshot")
		return nil
	}
	a.printUndo(preview.Result, true)
	if o.Preview {
		return nil
	}
	yes, err := a.confirm("Restore "+a.tildePath(preview.Result.Project)+" to the snapshot? (the sandbox is stopped first)", o.Yes)
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
	a.ok("restored: " + firstNonEmpty(res.Summary, "the folder is back to its pre-session snapshot"))
	if res.Result != nil {
		if res.Result.PostCommit != "" {
			a.note("the session's state is kept in commit " + shortOID(res.Result.PostCommit))
		}
		for _, w := range res.Result.Warnings {
			a.warn(w)
		}
		if left := res.Result.Unrestored(); len(left) > 0 {
			paths := make([]string, len(left))
			for i, c := range left {
				paths[i] = c.Path
			}
			a.warn("not restored (see above): " + strings.Join(firstN(paths, 6), ", "))
		}
	}
	if res.Restarted {
		a.ok("restarted " + o.Name)
	}
	return nil
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
	if r.BranchBefore != "" && r.BranchBefore != r.BranchAfter {
		a.line("  switch back to branch " + r.BranchBefore)
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

// Review prints the end-of-session review of a mounted project.
func (a *App) Review(ctx context.Context, o ReviewOptions) error {
	api, err := a.api()
	if err != nil {
		return err
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
	a.line(a.bold(o.Name) + ": " + rev.Summary)
	if rev.RiskLine != "" {
		a.line(a.style(rev.RiskLine, ansiYellow))
	}
	if r := rev.Report; r != nil {
		for _, f := range r.Flags {
			a.line(fmt.Sprintf("  %-8s %s — %s", strings.ToUpper(string(f.Severity)), f.Label, f.Detail))
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
	if sb.Phase != "ready" {
		a.note("starting " + o.Name + " to read its work…")
		if sb, err = api.Start(ctx, o.Name, sandboxapi.StartRequest{}); err != nil {
			return apiError(err)
		}
		// Leave it as it was found.
		defer func() {
			if _, err := api.Stop(context.WithoutCancel(ctx), o.Name); err != nil {
				a.warn("could not stop " + o.Name + " again: " + apiError(err).Error())
				return
			}
			a.note("stopped " + o.Name + " again")
		}()
	}
	res, err := a.pull(ctx, api, cli, sb)
	if err != nil {
		return err
	}
	if res.Kind == workspace.CopyPlain && o.applyMode() == workspace.ApplyBranch {
		return fmt.Errorf("%s works on a copy of a folder that is not a git repository, so there is no branch to put its changes on; "+
			"bring them back with --apply or --patch-out FILE", o.Name)
	}
	if stdout != nil && modes == 0 {
		return writeJSON(stdout, res)
	}
	a.line(a.bold(o.Name) + ": " + res.Review.SummaryLine())
	if line := res.Review.RiskLine(); line != "" {
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
		if res.Kind == workspace.CopyPlain {
			a.note("bring it back with --apply or --patch-out FILE")
		} else {
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
		a.ok("nothing to bring back")
		return nothing()
	}
	if res.Review.Sensitive() && !o.AcceptSensitive {
		yes, err := a.ask("Some changes can run code on this machine. Bring them back anyway?", false, false)
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
	if stdout != nil {
		return writeJSON(stdout, applied)
	}
	return nil
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

// pull captures the sandbox's work.
func (a *App) pull(ctx context.Context, api API, cli openshell.CLI, sb *sandboxapi.Sandbox) (*workspace.PullResult, error) {
	var review []string
	if eff, _, err := packs.Resolve(a.Cfg, packs.Flags{Pack: sb.Pack, Harness: sb.Harness, Project: sb.Project, Profile: sb.Profile, Copy: true}); err == nil {
		review = eff.Workspace.Review
	}
	a.note("Pulling " + sb.Name + "'s work…")
	res, err := a.Workspace.Pull(ctx, workspace.PullOptions{DataDir: a.dataDir(), Name: sb.Name, Exec: a.transport(cli), SensitiveGlobs: review})
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", sb.Name, err)
	}
	return res, nil
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
		return nil, fmt.Errorf("bring back %s's changes: %w", sb.Name, err)
	}
	switch {
	case len(applied.Conflicts) > 0:
		a.warn(fmt.Sprintf("the 3-way apply conflicted in %s", strings.Join(firstN(applied.Conflicts, 6), ", ")))
		if applied.Branch != "" {
			a.ok("the changes are on branch " + applied.Branch + " instead")
		}
		if applied.PatchPath != "" {
			a.ok("and in " + applied.PatchPath)
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
