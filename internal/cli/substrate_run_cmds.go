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

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
)

// substrateRunFlags are the flags of run.
type substrateRunFlags struct {
	out      substrateOutput
	com      substrateCommon
	git      *api.LauncherGit // substrate.git, read once (substrateGitSettings)
	profile  string
	template string
	name     string
	task     string
	batch    string
	parallel int
	detach   bool
	clone    string
	// cloneHere: --clone named this checkout and the folder copy carries
	// its upstream (set by substratePrepareCloneHere, not a flag).
	cloneHere   bool
	ref         string
	noUpload    bool
	unmask      []string
	exclude     []string
	maxUploadMB int
	secrets     []string
	transport   string
	keyReplay   string
	noAsks      bool
	keep        bool
	yes         bool
	workload    string
	remoteDir   string
	timeout     time.Duration
	mcp         []string
	mcpSpecs    []attach.MCPSpec
}

func newSubstrateRunCmd() *cobra.Command {
	var f substrateRunFlags
	cmd := &cobra.Command{
		Use:   "run <agent> [agent_args...]",
		Short: "Run a coding agent in the cluster on a copy of this folder",
		Long: `Starts the coding agent in a sandbox in the cluster, on a copy of the current folder (secret
files such as .env and keys are held back), and puts the agent on your terminal. The agent is claude,
codex, copilot, opencode, hermes, kiro, antigravity, cursor-agent, amp or devin. The agents that sign in to a
vendor account (kiro, antigravity, cursor-agent, amp, devin) start in open source only after you say yes to a
warning (or pass --yes), because the sign-in token stays in the agent and its snapshots; a managed cluster refuses them. A banner shows the guard profile, model, allowed hosts and how to leave. When the
guard asks before a step, the question appears on the last line: press Ctrl-\ to answer once, always or deny.

Press Ctrl-] to detach; the agent keeps running and suspends when idle. Come back from any machine with
"defenseclaw substrate connect NAME". Bring the changes home with "defenseclaw substrate pull NAME".

With --task the agent runs headless without you: asks are denied, or queued for approval when the profile's
unattended_asks is queue, and the run is checked as strictly as an unattended job. Add --detach to leave it
running and follow it with "defenseclaw substrate logs -f NAME".
With --batch FILE every task gets its own agent on the same folder; --parallel limits how many run at once.
With --clone URL the agent starts from a repository instead of a copy of the folder. With --clone . (Preview)
it starts from this checkout: the agent fetches the branch's history from its remote, and only the unpushed
commits and uncommitted changes are sent from here. Arguments after -- go to the agent.

With --mcp NAME=COMMAND (Preview, repeatable) the agent can use an MCP server that runs on this computer. This command
starts COMMAND when the agent opens the server NAME and carries its messages through the cluster while this command is
attached; every tool call goes through the cluster's guard first. COMMAND is split like a shell would split it, with
quotes and backslashes only, and runs without a shell. NAME is a-z, 0-9, _ and -, up to 32 characters. --mcp does not
go with --detach or --batch.`,
		Example: "defenseclaw substrate run claude\n" +
			"defenseclaw substrate run codex --task \"fix the failing tests\" --detach\n" +
			"defenseclaw substrate run claude --batch tasks.yaml --parallel 5\n" +
			"defenseclaw substrate run claude --clone https://git.example.test/team/app.git\n" +
			"defenseclaw substrate run claude --clone .\n" +
			"defenseclaw substrate run claude --mcp \"files=npx -y @modelcontextprotocol/server-filesystem .\"",
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
	fl.StringVar(&f.profile, "profile", "", "guard profile to run under (default: the one the cluster gives you)")
	fl.StringVar(&f.template, "template", "", "agent image template (default: the one from login, else the agent's name)")
	fl.StringVar(&f.name, "name", "", "a readable start for the agent's name; a random suffix is added, so a name is never used twice (default: the agent's command)")
	fl.StringVar(&f.task, "task", "", "run headless with this task and no terminal")
	fl.StringVar(&f.batch, "batch", "", "run every task in this YAML file, one agent each")
	fl.IntVar(&f.parallel, "parallel", 0, "with --batch, how many agents run at once (default 4)")
	fl.BoolVarP(&f.detach, "detach", "d", false, "with --task, start it and return; follow it with logs -f")
	fl.StringVar(&f.clone, "clone", "", "start from this repository instead of a copy of the folder; . for this checkout with its history (Preview)")
	fl.StringVar(&f.ref, "ref", "", "with --clone, the branch, tag or commit")
	fl.BoolVar(&f.noUpload, "no-upload", false, "start with an empty folder; upload nothing")
	fl.StringArrayVar(&f.unmask, "unmask", nil, "send a held-back secret file or pattern anyway (repeatable)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "exclude a path or glob from the copy (repeatable, for example 'data/**')")
	fl.IntVar(&f.maxUploadMB, "max-upload-mb", 0, "lower the cluster upload limit for this copy, in MiB")
	fl.StringArrayVar(&f.secrets, "secret", nil, "a secret name the agent may use, as listed by secrets list (repeatable)")
	fl.StringVar(&f.transport, "transport", "auto", "how to carry the terminal: auto, websocket or longpoll")
	fl.BoolVar(&f.noAsks, "no-asks", false, "do not show guard questions on this terminal")
	fl.StringVar(&f.keyReplay, "key-replay", "", keyReplayHelp)
	fl.BoolVar(&f.keep, "keep", false, "keep the agent after a finished --task (default: it stays until you delete it)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "say yes to the vendor sign-in warning without asking")
	fl.StringVar(&f.workload, "workload-token-file", "", "CI: file holding the workload identity token")
	fl.StringVar(&f.remoteDir, "remote-dir", "", "where in the agent to put the copy (default: the image's working folder)")
	_ = fl.MarkHidden("remote-dir")
	fl.StringArrayVar(&f.mcp, "mcp", nil, substrateMCPFlagHelp)
	fl.DurationVar(&f.timeout, "timeout", 0, "with --task, stop waiting after this long (default: wait)")
	return cmd
}

// substrateAttachFlags are the flags connect and run share for the terminal.
type substrateAttachFlags struct {
	com       substrateCommon
	transport string
	noAsks    bool
	keyReplay string
	mcp       []string
}

func newSubstrateConnectCmd() *cobra.Command {
	var f substrateAttachFlags
	cmd := &cobra.Command{
		Use:   "connect <name>",
		Short: "Come back to an agent and put it on this terminal",
		Long: `Attaches your terminal to a running or suspended agent from any machine you are signed in on.
A suspended agent wakes in about a fifth of a second and shows the screen as you left it. Press Ctrl-]
to detach again. If the connection drops, it reconnects by itself. NAME is the name "defenseclaw substrate list"
shows, or the --name you gave run when only one agent has it.

With --mcp NAME=COMMAND (Preview, repeatable) the agent can use an MCP server that runs on this computer, while this
command is attached. See "defenseclaw substrate run --help". An agent that is already running reads its MCP servers
when it starts, so start a new session in it to see NAME.`,
		Example: "defenseclaw substrate connect fix-tests-7f3a\ndefenseclaw substrate connect fix-tests",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstrateConnect(cmd, &f, args[0]) },
	}
	f.com.add(cmd)
	cmd.Flags().StringVar(&f.transport, "transport", "auto", "how to carry the terminal: auto, websocket or longpoll")
	cmd.Flags().BoolVar(&f.noAsks, "no-asks", false, "do not show guard questions on this terminal")
	cmd.Flags().StringVar(&f.keyReplay, "key-replay", "", keyReplayHelp)
	cmd.Flags().StringArrayVar(&f.mcp, "mcp", nil, substrateMCPFlagHelp)
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
	out    substrateOutput
	com    substrateCommon
	apply  bool
	branch string
	patch  string
	diff   bool
	yes    bool
	// allowFlagged writes flagged files with --apply (GAP-0472).
	allowFlagged bool
	timeout      time.Duration
	// pushBranch pushes the agent's work to its origin as this branch
	// (B2 2.4, Preview).
	pushBranch string
	// restoreSecrets is --restore-secret-lines (B1 S9a).
	restoreSecrets bool
	// exclude and noExclude say, on another computer, what run left out
	// with --exclude (GAP-0489).
	exclude   []string
	noExclude bool
}

func newSubstratePullCmd() *cobra.Command {
	var f substratePullFlags
	cmd := &cobra.Command{
		Use:   "pull <name>",
		Short: "Review what the agent changed and bring it home",
		Long: `Reads the agent's work back to this machine and shows what changed, with the files that need a
careful look first (scripts, CI and hook files, dotfiles, secrets in the text, large or binary files,
links that leave the folder, agent settings, MCP servers, shell startup files). Nothing touches your folder
until you choose: --apply writes the changes into the folder, --branch NAME puts them on a new git branch,
--patch-out FILE writes a patch. --push-branch NAME (Preview) pushes the agent's work from inside the
agent to its checkout's origin as a new branch, with the credential the cluster adds for that host; it
asks first unless your profile allows it, and never forces.

When a change can run code on this machine, --apply asks first (the default answer is no). --yes takes
that safe answer, so --apply --yes writes nothing and says why; after you reviewed the flagged files,
--allow-flagged writes them too.

On the computer you started the agent from, it compares the changes with the folder you sent. On
another computer, run it in a git checkout of that folder: it compares the agent's work with the
checkout's last commit, so files sent that were not committed show as added. That computer cannot know
what run left out with --exclude, so repeat it (--exclude GLOB, once for each) or say there was none
(--no-exclude) before --apply or --branch; until then they refuse, and --patch-out still works.`,
		Example: "defenseclaw substrate pull fix-tests-7f3a\ndefenseclaw substrate pull fix-tests-7f3a --branch agent/fix-tests\n" +
			"defenseclaw substrate pull fix-tests-7f3a --push-branch agent/fix-tests",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return runSubstratePull(cmd, &f, args[0]) },
	}
	f.out.add(cmd)
	f.com.add(cmd)
	fl := cmd.Flags()
	fl.BoolVar(&f.apply, "apply", false, "write the changes into this folder")
	fl.StringVar(&f.branch, "branch", "", "put the changes on a new git branch of this name")
	fl.StringVar(&f.patch, "patch-out", "", "write the changes as a patch to this file")
	fl.BoolVar(&f.diff, "diff", false, "print the full diff")
	fl.BoolVarP(&f.yes, "yes", "y", false, "take the safe default at each question")
	fl.BoolVar(&f.allowFlagged, "allow-flagged", false, "with --apply or --push-branch: also take the flagged files (review them first)")
	fl.StringVar(&f.pushBranch, "push-branch", "", "push the agent's work to its origin as a new branch of this name (Preview)")
	fl.DurationVar(&f.timeout, "timeout", 0, "stop reading the agent's work after this long (default 10m)")
	fl.StringArrayVar(&f.exclude, "exclude", nil, "on another computer: a path or glob run was given with --exclude, held back on both sides (repeatable)")
	fl.BoolVar(&f.noExclude, "no-exclude", false, "on another computer: run was given no --exclude")
	fl.BoolVar(&f.restoreSecrets, "restore-secret-lines", false, "in files uploaded with credentials replaced, keep the agent's changed lines with the value put back (default: keep your line)")
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
		Long: `Saves a restore point of the agent's folder inside the agent, then has the cluster store a snapshot of
the agent (it pauses for a few seconds), so the restore point survives a crash of the agent's worker.
"defenseclaw substrate undo NAME" goes back to the last one; after a crash it first brings the agent back to
that snapshot. With --every 1h it saves one on that schedule for as long as the command runs.`,
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

func newSubstrateRecoverCmd() *cobra.Command {
	var (
		com substrateCommon
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "recover <name>",
		Short: "Let the agent's relay get a new certificate; bring a crashed agent back",
		Long: `Clears the cluster's record of the agent's relay certificate, so the relay's next request
gets a first certificate and no certificate issued before it can renew. Use it when
"defenseclaw substrate connect" fails because the relay restarted inside the agent, or after an
emergency relay CA rotation, while substrate.relay_cert_reissue is refuse (the managed default).
A crashed agent is also brought back to its last snapshot, as "defenseclaw substrate undo" does;
what it did after that snapshot is lost, so it asks first. Only the agent's owner or an
administrator can run it.`,
		Example: "defenseclaw substrate recover fix-tests-7f3a",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return runSubstrateRecover(cmd, &com, args[0], yes) },
	}
	com.add(cmd)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
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
		Long:  `Goes back to the last restore point (or --to ID) inside the agent and discards what the agent changed since. It asks first. After a crash it first brings the agent back to its last snapshot; a --task agent this computer started whose task was lost then starts that task again from the beginning, on a fresh copy of its folder.`,
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runSubstrateUndo(cmd, &com, args[0], to, yes) },
	}
	com.add(cmd)
	cmd.Flags().StringVar(&to, "to", "", "restore point id (default: the last)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask")
	return cmd
}

// keyReplayHelp is the --key-replay help of run and connect (B3.1).
const keyReplayHelp = "keys typed while the connection is down: ask (show them, Enter sends), on (send) or off (drop); only tightens the cluster setting"
