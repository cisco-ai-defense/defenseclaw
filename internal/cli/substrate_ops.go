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
	o, err := substrateAttachOptions(cmd, s, a, "auto", true)
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
			return fmt.Errorf("%s/%s has no headless task; start one with: defenseclaw substrate run AGENT --task \"...\"", a.Atespace, a.Name)
		}
	}
	emit := attach.TextEmitter(cmd.OutOrStdout(), cmd.ErrOrStderr())
	if asJSON {
		emit = func(e relay.TaskEvent) { _ = writeSubstrateJSONCompact(cmd.OutOrStdout(), e) }
	}
	fctx := ctx
	if !follow {
		// A snapshot: read what is there, then stop once nothing new comes.
		var cancel context.CancelFunc
		fctx, cancel = context.WithCancel(ctx)
		defer cancel()
		idle := time.AfterFunc(3*time.Second, cancel)
		defer idle.Stop()
		inner := emit
		emit = func(e relay.TaskEvent) {
			idle.Reset(2 * time.Second)
			inner(e)
		}
	}
	if follow {
		defer substratePresence(cmd, a)()
	}
	code, err := attach.FollowTask(fctx, o, id, emit)
	if err != nil && (!errors.Is(err, context.Canceled) || follow) {
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
	for _, on := range []bool{f.apply, f.branch != "", f.patch != ""} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return withExitCode(errors.New("choose one of --apply, --branch NAME or --patch-out FILE"), 2)
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
	name := substrateCopyName(a)
	dataDir := auth.StateDir()
	if !workspace.HasCopy(dataDir, name) {
		return fmt.Errorf("this computer has no record of the folder you sent to %s/%s, so it cannot tell what the agent changed. "+
			"Pull from the computer you ran it on, or push from inside the agent (defenseclaw substrate connect %s, then git push)", a.Atespace, a.Name, a.Name)
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	w := cmd.OutOrStdout()
	fmt.Fprintln(cmd.ErrOrStderr(), "Reading the agent's work...")
	rev, err := workspace.Pull(ctx, workspace.PullOptions{Exec: rel.Client, DataDir: dataDir, Name: name, Label: a.Name, Timeout: f.timeout, Project: "."})
	if err != nil {
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
	case f.branch != "":
		mode = workspace.ModeBranch
	case f.patch != "":
		mode = workspace.ModePatch
	default:
		return substratePullChoose(cmd, f, a, name, dataDir, rev)
	}
	return substrateApply(cmd, dataDir, name, mode, branch, patch, f.yes)
}

// substratePullChoose asks what to do with the changes on a terminal; with
// no terminal it says how to choose.
func substratePullChoose(cmd *cobra.Command, f *substratePullFlags, a api.Actor, name, dataDir string, rev *workspace.Review) error {
	hint := fmt.Sprintf("Nothing was written to this folder. Bring the changes home with:\n  defenseclaw substrate pull %s --apply            write them into this folder\n  defenseclaw substrate pull %s --branch NAME      put them on a new git branch\n  defenseclaw substrate pull %s --patch-out FILE   write a patch", a.Name, a.Name, a.Name)
	if f.yes {
		return substrateApply(cmd, dataDir, name, workspace.ModeBranch, "", "", true)
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
// get the hint, not a question.
func substrateInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func substrateApply(cmd *cobra.Command, dataDir, name string, mode workspace.ApplyMode, branch, patch string, accept bool) error {
	ctx, stop := substrateContext(cmd)
	defer stop()
	res, err := workspace.Apply(ctx, workspace.ApplyOptions{DataDir: dataDir, Name: name, Mode: mode, Branch: branch, PatchPath: patch, AcceptSensitive: accept})
	if err != nil {
		var sens *workspace.SensitiveError
		if errors.As(err, &sens) {
			return withExitCode(fmt.Errorf("%w; choose --branch NAME or --patch-out FILE to look at them first", err), substrateExitRefused)
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
		return withExitCode(errors.New("--every must be at least 1m, for example --every 1h"), 2)
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
		rel, err := substrateOpenRelay(ctx, s, a)
		if err != nil {
			return err
		}
		defer rel.Close()
		info, err := workspace.Checkpoint(ctx, workspace.CheckpointOptions{Exec: rel.Client, Dir: dir, DataDir: auth.StateDir(), Name: substrateCopyName(a)})
		if err != nil {
			return err
		}
		if asJSON {
			return writeSubstrateJSONCompact(cmd.OutOrStdout(), map[string]any{"id": info.ID, "files": info.Files, "agent": a.Atespace + "/" + a.Name, "time": time.Now().UTC()})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved restore point %s (%d files). Go back to it with: defenseclaw substrate undo %s --to %s\n", info.ID, info.Files, a.Name, info.ID)
		return nil
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
			if err := take(); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Could not save a restore point: %v\n", err)
			}
		}
	}
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
	info, err := workspace.Undo(ctx, workspace.UndoOptions{Exec: rel.Client, Dir: dir, ID: to, DataDir: auth.StateDir(), Name: substrateCopyName(a)})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Put %s/%s back to restore point %s.\n", a.Atespace, a.Name, info.ID)
	return nil
}
