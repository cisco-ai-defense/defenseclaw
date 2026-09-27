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
// preview. With -o json stdout carries the restore's response, or the
// preview's (result.preview true) when nothing was restored.
func (a *App) Undo(ctx context.Context, o UndoOptions) error {
	api, err := a.api()
	if err != nil {
		return err
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
	}
	if res.Restarted {
		a.ok("restarted " + o.Name)
	}
	return nil
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
	for _, p := range r.PinnedChanges {
		a.warn(p + " changed on this machine during the session; it is kept")
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
			a.line(fmt.Sprintf("  %-8s %s", "FINDING", truncate(fmt.Sprintf("%+v", f), 160)))
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
	}
	res, err := a.pull(ctx, api, cli, sb)
	if err != nil {
		return err
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
		a.note("bring it back with --apply, --branch or --patch-out FILE")
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
	case applied.Mode == workspace.ApplyMerge:
		a.ok(fmt.Sprintf("applied %s to %s", plural(int64(len(applied.Changes)), "change", "changes"), a.tildePath(sb.Project)))
		if applied.PreApplyRef != "" {
			a.note("your previous working tree is kept at " + applied.PreApplyRef)
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
