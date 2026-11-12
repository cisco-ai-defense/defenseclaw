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
	"errors"
	"time"

	"github.com/spf13/cobra"
)

// substrateRunFlags are the flags of run.
type substrateRunFlags struct {
	out         substrateOutput
	com         substrateCommon
	profile     string
	template    string
	name        string
	task        string
	batch       string
	parallel    int
	detach      bool
	clone       string
	ref         string
	noUpload    bool
	unmask      []string
	exclude     []string
	maxUploadMB int
	secrets     []string
	transport   string
	noAsks      bool
	keep        bool
	yes         bool
	workload    string
	remoteDir   string
	timeout     time.Duration
}

func newSubstrateRunCmd() *cobra.Command {
	var f substrateRunFlags
	cmd := &cobra.Command{
		Use:   "run <agent> [agent_args...]",
		Short: "Run a coding agent in the cluster on a copy of this folder",
		Long: `Starts the coding agent in a sandbox in the cluster, on a copy of the current folder (secret
files such as .env and keys are held back), and puts the agent on your terminal. The agent is claude,
codex, copilot, opencode, kiro, hermes or antigravity (amp, cursor-agent and devin are not verified yet, so
they do not run). A banner shows the guard profile, model, allowed hosts and how to leave. Questions the
guard asks appear on the last line: [o]nce [a]lways [d]eny.

Press Ctrl-] to detach; the agent keeps running and suspends when idle. Come back from any machine with
"defenseclaw substrate connect NAME". Bring the changes home with "defenseclaw substrate pull NAME".

With --task the agent runs headless without you: asks are denied and the run is checked as strictly as
an unattended job. Add --detach to leave it running and follow it with "defenseclaw substrate logs -f NAME".
With --batch FILE every task gets its own agent on the same folder; --parallel limits how many run at once.
With --clone URL the agent starts from a repository instead of a copy of the folder. Arguments after -- go
to the agent.`,
		Example: "defenseclaw substrate run claude\n" +
			"defenseclaw substrate run codex --task \"fix the failing tests\" --detach\n" +
			"defenseclaw substrate run claude --batch tasks.yaml --parallel 5\n" +
			"defenseclaw substrate run claude --clone https://git.example.test/team/app.git",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("name the agent: claude, codex, copilot, opencode, kiro, hermes or antigravity")
			}
			if len(args) > 1 && cmd.ArgsLenAtDash() != 1 {
				return errors.New("pass agent arguments after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error { return runSubstrateRun(cmd, &f, args) },
	}
	f.out.add(cmd)
	f.com.add(cmd)
	fl := cmd.Flags()
	fl.StringVar(&f.profile, "profile", "", "guard profile to run under (default: the one from login)")
	fl.StringVar(&f.template, "template", "", "agent image template (default: the one from login, else the agent's name)")
	fl.StringVar(&f.name, "name", "", "name for the agent (default: chosen by the cluster)")
	fl.StringVar(&f.task, "task", "", "run headless with this task and no terminal")
	fl.StringVar(&f.batch, "batch", "", "run every task in this YAML file, one agent each")
	fl.IntVar(&f.parallel, "parallel", 0, "with --batch, how many agents run at once (default 4)")
	fl.BoolVarP(&f.detach, "detach", "d", false, "with --task, start it and return; follow it with logs -f")
	fl.StringVar(&f.clone, "clone", "", "start from this repository instead of a copy of the folder")
	fl.StringVar(&f.ref, "ref", "", "with --clone, the branch, tag or commit")
	fl.BoolVar(&f.noUpload, "no-upload", false, "start with an empty folder; upload nothing")
	fl.StringArrayVar(&f.unmask, "unmask", nil, "send a held-back secret file or pattern anyway (repeatable)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "hold a path or pattern back from the copy (repeatable)")
	fl.IntVar(&f.maxUploadMB, "max-upload-mb", 0, "refuse a copy larger than this many MB (default 500)")
	fl.StringArrayVar(&f.secrets, "secret", nil, "a secret name the agent may use, as listed by secrets list (repeatable)")
	fl.StringVar(&f.transport, "transport", "auto", "how to carry the terminal: auto, websocket or longpoll")
	fl.BoolVar(&f.noAsks, "no-asks", false, "do not show guard questions on this terminal")
	fl.BoolVar(&f.keep, "keep", false, "keep the agent after a finished --task (default: it stays until you delete it)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "answer questions with their defaults")
	fl.StringVar(&f.workload, "workload-token-file", "", "CI: file holding the workload identity token")
	fl.StringVar(&f.remoteDir, "remote-dir", "", "where in the agent to put the copy (default: the image's working folder)")
	_ = fl.MarkHidden("remote-dir")
	fl.DurationVar(&f.timeout, "timeout", 0, "with --task, stop waiting after this long (default: wait)")
	return cmd
}

// substrateAttachFlags are the flags connect and run share for the terminal.
type substrateAttachFlags struct {
	com       substrateCommon
	transport string
	noAsks    bool
}

func newSubstrateConnectCmd() *cobra.Command {
	var f substrateAttachFlags
	cmd := &cobra.Command{
		Use:   "connect <name>",
		Short: "Come back to an agent and put it on this terminal",
		Long: `Attaches your terminal to a running or suspended agent from any machine you are signed in on.
A suspended agent wakes in about a fifth of a second and shows the screen as you left it. Press Ctrl-]
to detach again. If the connection drops, it reconnects by itself.`,
		Example: "defenseclaw substrate connect fix-tests-7f3a",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstrateConnect(cmd, &f, args[0]) },
	}
	f.com.add(cmd)
	cmd.Flags().StringVar(&f.transport, "transport", "auto", "how to carry the terminal: auto, websocket or longpoll")
	cmd.Flags().BoolVar(&f.noAsks, "no-asks", false, "do not show guard questions on this terminal")
	return cmd
}

func newSubstrateLogsCmd() *cobra.Command {
	var (
		out    substrateOutput
		com    substrateCommon
		follow bool
		task   string
	)
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Show what a headless run printed, and follow it",
		Long: `Shows the output of the agent's headless task: what it printed and its exit code. With -f it
keeps following until the task ends (Ctrl-C stops following; the task keeps running).`,
		Example: "defenseclaw substrate logs -f fix-tests-7f3a",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubstrateLogs(cmd, &out, &com, args[0], follow, task)
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep following until the task ends")
	cmd.Flags().StringVar(&task, "task", "", "a task id (default: the latest)")
	return cmd
}

// substratePullFlags are the flags of pull.
type substratePullFlags struct {
	out     substrateOutput
	com     substrateCommon
	apply   bool
	branch  string
	patch   string
	diff    bool
	yes     bool
	timeout time.Duration
}

func newSubstratePullCmd() *cobra.Command {
	var f substratePullFlags
	cmd := &cobra.Command{
		Use:   "pull <name>",
		Short: "Review what the agent changed and bring it home",
		Long: `Reads the agent's work back to this machine and shows what changed, with the files that need a
careful look first (scripts, CI and hook files, dotfiles, secrets in the text, large or binary files,
links that leave the folder). Nothing touches your folder until you choose: --apply writes the changes
into the folder, --branch NAME puts them on a new git branch, --patch-out FILE writes a patch.`,
		Example: "defenseclaw substrate pull fix-tests-7f3a\ndefenseclaw substrate pull fix-tests-7f3a --branch agent/fix-tests",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstratePull(cmd, &f, args[0]) },
	}
	f.out.add(cmd)
	f.com.add(cmd)
	fl := cmd.Flags()
	fl.BoolVar(&f.apply, "apply", false, "write the changes into this folder")
	fl.StringVar(&f.branch, "branch", "", "put the changes on a new git branch of this name")
	fl.StringVar(&f.patch, "patch-out", "", "write the changes as a patch to this file")
	fl.BoolVar(&f.diff, "diff", false, "print the full diff")
	fl.BoolVarP(&f.yes, "yes", "y", false, "take the safe default at each question")
	fl.DurationVar(&f.timeout, "timeout", 0, "stop reading the agent's work after this long (default 10m)")
	return cmd
}

func newSubstrateCheckpointCmd() *cobra.Command {
	var (
		out   substrateOutput
		com   substrateCommon
		every time.Duration
	)
	cmd := &cobra.Command{
		Use:   "checkpoint <name>",
		Short: "Save the agent's work so you can undo back to it",
		Long: `Saves a restore point of the agent's folder inside the agent. "defenseclaw substrate undo NAME"
goes back to the last one. With --every 1h it saves one on that schedule for as long as the command runs.`,
		Example: "defenseclaw substrate checkpoint fix-tests-7f3a\ndefenseclaw substrate checkpoint fix-tests-7f3a --every 1h",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubstrateCheckpoint(cmd, &out, &com, args[0], every)
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().DurationVar(&every, "every", 0, "save one on this schedule, for example 1h")
	return cmd
}

func newSubstrateUndoCmd() *cobra.Command {
	var (
		com substrateCommon
		to  string
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "undo <name>",
		Short: "Put the agent's folder back to a restore point",
		Long:  `Goes back to the last restore point (or --to ID) inside the agent and discards what the agent changed since. It asks first.`,
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runSubstrateUndo(cmd, &com, args[0], to, yes) },
	}
	com.add(cmd)
	cmd.Flags().StringVar(&to, "to", "", "restore point id (default: the last)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	return cmd
}
