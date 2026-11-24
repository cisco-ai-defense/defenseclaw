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
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// substratePushFlags are the flags of push.
type substratePushFlags struct {
	out     substrateOutput
	com     substrateCommon
	unmask  []string
	exclude []string
	mine    bool
	replace bool
	theirs  bool
	patch   string
	dryRun  bool
}

func newSubstratePushCmd() *cobra.Command {
	var f substratePushFlags
	cmd := &cobra.Command{
		Use:   "push <name> [path...]",
		Short: "Send your newer changes into a running agent (Preview)",
		Long: `Sends the changes you made in this folder since the last send (the run or an earlier push) into the
agent's copy. Paths limit it to those files or folders. The rules of run apply: secret files are held
back (share one with --unmask), --exclude holds more back, and the cluster's upload limit counts.

Before it writes, it saves a restore point: "defenseclaw substrate undo NAME --to N" goes back to it.
When the agent also changed a file you changed, nothing is sent and the files are listed (exit 3).
Then choose: --mine sends yours (the agent's version stays in the restore point), --theirs keeps the
agent's and sends the rest, and --patch-out FILE keeps the agent's and writes your change to FILE.
When sending yours would remove an agent file or folder in its way (a file where you made a folder, or
a folder where you made a file), --mine names it and sends nothing; add --replace to send yours anyway.
What you send is not shown as the agent's work in a later pull. This command is a Preview.`,
		Example: "defenseclaw substrate push fix-tests-7f3a\ndefenseclaw substrate push fix-tests-7f3a src/app.py --mine",
		Args:    cobra.MinimumNArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstratePush(cmd, &f, args[0], args[1:]) },
	}
	f.out.add(cmd)
	f.com.add(cmd)
	fl := cmd.Flags()
	fl.StringArrayVar(&f.unmask, "unmask", nil, "send a held-back secret file or pattern anyway (repeatable)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "hold a path or glob back too (repeatable, for example 'data/**')")
	fl.BoolVar(&f.mine, "mine", false, "on a conflict, send your version (the agent's stays in the restore point)")
	fl.BoolVar(&f.replace, "replace", false, "with --mine, also remove an agent file or folder in the way of yours (it stays in the restore point)")
	fl.BoolVar(&f.theirs, "theirs", false, "on a conflict, keep the agent's version and send the rest")
	fl.StringVar(&f.patch, "patch-out", "", "on a conflict, keep the agent's version and write your change to this file")
	fl.BoolVar(&f.dryRun, "dry-run", false, "show what would be sent and the conflicts; send nothing")
	return cmd
}

func runSubstratePush(cmd *cobra.Command, f *substratePushFlags, ref string, paths []string) error {
	asJSON, err := f.out.wantJSON()
	if err != nil {
		return err
	}
	modes := 0
	for _, on := range []bool{f.mine, f.theirs, f.patch != ""} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return cliusage.WithExitCode(errors.New("choose one of --mine, --theirs or --patch-out FILE"), 2)
	}
	if f.replace && !f.mine {
		return cliusage.WithExitCode(errors.New("--replace goes with --mine"), 2)
	}
	mode := osw.PushRefuse
	switch {
	case f.mine && f.replace:
		mode = osw.PushMineReplace
	case f.mine:
		mode = osw.PushMine
	case f.theirs:
		mode = osw.PushTheirs
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
	name := substrateCopyName(a)
	dataDir := auth.StateDir()
	if !workspace.HasCopy(dataDir, name) {
		return fmt.Errorf("this computer has no record of the folder you sent to %s/%s. Push from the computer you ran it on", a.Atespace, a.Name)
	}
	limit, settings, err := substrateUploadLimit(ctx, cmd, s)
	if err != nil {
		return err
	}
	if settings.Files != nil && !settings.Files.Push {
		return cliusage.WithExitCode(errors.New("your administrator turned off sending more files into a running agent (substrate.files.push); run the agent again to send a new copy"), substrateExitRefused)
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	home, _ := os.UserHomeDir()
	n := osw.NextPushNumber(dataDir, name)
	w, ew := cmd.OutOrStdout(), cmd.ErrOrStderr()
	out, err := workspace.Push(ctx, workspace.PushOptions{
		Start: workspace.StartOptions{DataDir: dataDir, Home: home, MaxBytes: limit, Masks: f.exclude, Unmask: f.unmask},
		Name:  name, Transport: rel.Client, Paths: paths, Mode: mode, PatchOut: f.patch, DryRun: f.dryRun,
		Label: fmt.Sprintf("before push %d", n),
	})
	if out != nil && out.Checkpoint != "" && !asJSON {
		fmt.Fprintf(ew, "Saved restore point %s (before push %d).\n", out.Checkpoint, n)
	}
	if err != nil {
		return substratePushErr(cmd, a.Name, err, asJSON, out)
	}
	if asJSON {
		return writeSubstrateJSON(w, substratePushDoc(a.Atespace+"/"+a.Name, out, f.dryRun))
	}
	if line := out.HeldBackLine(); line != "" {
		defer fmt.Fprintln(ew, line)
	}
	switch {
	case len(out.Plan.Changes) == 0:
		fmt.Fprintln(w, "Nothing to send: no changes since the last send.")
	case f.dryRun:
		if line := out.SendLine("Would send"); line != "" {
			fmt.Fprintln(w, line)
		}
		if conf := out.Plan.Conflicts(); len(conf) > 0 {
			fmt.Fprintf(w, "The agent also changed %d of these files since your last send:\n", len(conf))
			for _, c := range conf {
				fmt.Fprintf(w, "  %s\n", substrateConflictLine(out.Plan, c))
			}
		}
		fmt.Fprintln(w, "Nothing was sent (--dry-run).")
	default:
		if line := out.SendLine("Sent"); line != "" {
			fmt.Fprintln(w, line)
		} else {
			fmt.Fprintln(w, "The agent already has these changes; nothing to write.")
		}
		if kept := out.Result.Kept; len(kept) > 0 {
			fmt.Fprintf(w, "Kept the agent's version of %d file(s): %v.\n", len(kept), kept)
			if f.patch != "" {
				fmt.Fprintf(w, "Your change to them is in %s.\n", f.patch)
			}
		}
		if out.Checkpoint != "" {
			fmt.Fprintf(w, "Undo with: defenseclaw substrate undo %s --to %s\n", a.Name, out.Checkpoint)
		}
	}
	return nil
}

func substratePushDoc(agent string, out *workspace.PushOutcome, dry bool) map[string]any {
	files := make([]map[string]any, 0, len(out.Plan.Changes))
	for _, c := range out.Plan.Changes {
		f := map[string]any{"path": c.Path, "status": c.Status, "bytes": c.Bytes, "conflict": c.Conflict, "same": c.Same}
		if c.Replaces != "" {
			f["replaces"] = c.Replaces
		}
		files = append(files, f)
	}
	doc := map[string]any{"agent": agent, "files": files, "held_back": out.Plan.HeldBack, "conflicts": out.Plan.Conflicts(), "dry_run": dry, "sent": out.Result != nil}
	if out.Checkpoint != "" {
		doc["restore_point"] = out.Checkpoint
	}
	if out.Result != nil {
		doc["kept"] = out.Result.Kept
	}
	return doc
}

// substrateConflictLine is one conflict as push lists it: the path, and
// what sending yours would remove in the agent when that is more than the
// path itself (RV2 N2).
func substrateConflictLine(plan *osw.PushPlan, path string) string {
	if plan != nil {
		for _, c := range plan.Changes {
			if c.Path == path {
				if n := c.ReplaceNote(); n != "" {
					return path + " (" + n + ")"
				}
				break
			}
		}
	}
	return path
}

// substratePushErr says a push refusal in plain words; a conflict or an
// admin switch exits substrateExitRefused.
func substratePushErr(cmd *cobra.Command, agent string, err error, asJSON bool, out *workspace.PushOutcome) error {
	var conf *osw.PushConflictError
	if errors.As(err, &conf) {
		if asJSON && out != nil {
			_ = writeSubstrateJSON(cmd.OutOrStdout(), substratePushDoc(agent, out, false))
		} else {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "The agent also changed %d of these files since your last send:\n", len(conf.Paths))
			var plan *osw.PushPlan
			if out != nil {
				plan = out.Plan
			}
			for _, p := range conf.Paths {
				fmt.Fprintf(w, "  %s\n", substrateConflictLine(plan, p))
			}
		}
		return cliusage.WithExitCode(errors.New("nothing was sent. Choose: --mine (send yours), --theirs (keep the agent's) or --patch-out FILE"), substrateExitRefused)
	}
	var repl *osw.PushReplaceError
	if errors.As(err, &repl) {
		if asJSON && out != nil {
			_ = writeSubstrateJSON(cmd.OutOrStdout(), substratePushDoc(agent, out, false))
		} else {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Sending your version of %d file(s) removes agent files in the way:\n", len(repl.Changes))
			for _, c := range repl.Changes {
				fmt.Fprintf(w, "  %s (%s)\n", c.Path, c.ReplaceNote())
			}
		}
		return cliusage.WithExitCode(errors.New("nothing was sent. Add --replace to send yours anyway (the agent's stays in the restore point), or choose --theirs or --patch-out FILE"), substrateExitRefused)
	}
	var big *workspace.TooLargeError
	if errors.As(err, &big) {
		return cliusage.WithExitCode(big, substrateExitRefused)
	}
	var refused *workspace.HTTPError
	if errors.As(err, &refused) && refused.Status == http.StatusForbidden && (refused.Reason == "push_disabled" || refused.Reason == "sync_disabled") {
		return cliusage.WithExitCode(errors.New("your administrator turned off sending more files into a running agent (substrate.files.push); nothing was sent"), substrateExitRefused)
	}
	if errors.Is(err, workspace.ErrPushHostCopy) {
		return cliusage.WithExitCode(err, substrateExitRefused)
	}
	var moved *osw.BaselineMovedError
	if errors.As(err, &moved) {
		return cliusage.WithExitCode(errors.New(moved.Error()[len("workspace: "):]), substrateExitRefused)
	}
	return fmt.Errorf("could not push: %w", err)
}

// substrateSyncFlags are the flags of sync.
type substrateSyncFlags struct {
	com     substrateCommon
	unmask  []string
	exclude []string
	watch   bool
	dur     time.Duration
}

func newSubstrateSyncCmd() *cobra.Command {
	var f substrateSyncFlags
	cmd := &cobra.Command{
		Use:   "sync <name>",
		Short: "Keep sending your changes into a running agent while you work (Preview)",
		Long: `Watches this folder and sends each change into the agent's copy, one way, until Ctrl-C, --for, or
the agent is deleted. It sends 1 second after the last change, and at most 5 seconds after the first.
Each batch follows the rules of push: secret files are held back, ignored files, .git and package
caches are not sent, and a file the agent also changed keeps the agent's version (it is named once;
send yours with push NAME --mine FILE). It saves a restore point at the start, then one every
10 minutes in which something was sent. A suspended agent is not woken: changes wait until it is back.
Nothing keeps running after it stops. --watch is required. This command is a Preview.`,
		Example: "defenseclaw substrate sync fix-tests-7f3a --watch\ndefenseclaw substrate sync fix-tests-7f3a --watch --for 2h",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstrateSync(cmd, &f, args[0]) },
	}
	f.com.add(cmd)
	fl := cmd.Flags()
	fl.BoolVar(&f.watch, "watch", false, "watch the folder and send changes as you save (required)")
	fl.DurationVar(&f.dur, "for", 0, "stop after this long, for example 2h")
	fl.StringArrayVar(&f.unmask, "unmask", nil, "send a held-back secret file or pattern anyway (repeatable)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "hold a path or glob back too (repeatable, for example 'data/**')")
	return cmd
}

func runSubstrateSync(cmd *cobra.Command, f *substrateSyncFlags, ref string) error {
	if !f.watch {
		return cliusage.WithExitCode(errors.New("sync runs with --watch; to send your changes once, use push"), 2)
	}
	if f.dur < 0 {
		return cliusage.WithExitCode(errors.New("--for must be a positive duration, for example 2h"), 2)
	}
	s, err := substrateOpen(cmd, &f.com)
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()
	if f.dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.dur)
		defer cancel()
	}
	a, err := resolveSubstrateActor(ctx, s.Client, ref)
	if err != nil {
		return substrateFail(err)
	}
	name := substrateCopyName(a)
	dataDir := auth.StateDir()
	if !workspace.HasCopy(dataDir, name) {
		return fmt.Errorf("this computer has no record of the folder you sent to %s/%s. Sync from the computer you ran it on", a.Atespace, a.Name)
	}
	limit, settings, err := substrateUploadLimit(ctx, cmd, s)
	if err != nil {
		return err
	}
	if settings.Files != nil && !settings.Files.Sync {
		return cliusage.WithExitCode(errors.New("your administrator turned off syncing into a running agent (substrate.files.sync); push still sends changes when allowed"), substrateExitRefused)
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		return err
	}
	defer rel.Close()
	home, _ := os.UserHomeDir()
	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "Syncing this folder into %s/%s. Stop with Ctrl-C.\n", a.Atespace, a.Name)
	err = workspace.Sync(ctx, workspace.SyncOptions{
		Push: workspace.PushOptions{
			Start: workspace.StartOptions{DataDir: dataDir, Home: home, MaxBytes: limit, Masks: f.exclude, Unmask: f.unmask},
			Name:  name, Transport: rel.Client,
		},
		Out: w, Label: a.Name, HourBytes: 4 * limit,
		State: func(ctx context.Context) (string, error) {
			actors, err := s.Client.List(ctx, api.ListOptions{})
			if err != nil {
				return "", err
			}
			for _, cur := range actors {
				if !cur.Deleted && cur.Atespace == a.Atespace && cur.Name == a.Name {
					if cur.State == "suspended" {
						return workspace.SyncActorSuspended, nil
					}
					return workspace.SyncActorRunning, nil
				}
			}
			return workspace.SyncActorGone, nil
		},
	})
	if errors.Is(err, workspace.ErrSyncActorGone) {
		fmt.Fprintln(w, "The agent is gone; sync stopped.")
		return nil
	}
	if err != nil {
		return substratePushErr(cmd, a.Name, err, false, nil)
	}
	fmt.Fprintln(w, "Sync stopped.")
	return nil
}
