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
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// newSandboxApp builds the command implementation for one invocation;
// tests replace it to inject fakes.
var newSandboxApp = func(cmd *cobra.Command) *sandboxcli.App {
	return &sandboxcli.App{
		Cfg: cfg,
		IO: sandboxcli.IO{
			In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(),
			TTY:    term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())),
			OutTTY: term.IsTerminal(int(os.Stdout.Fd())),
			ErrTTY: term.IsTerminal(int(os.Stderr.Fd())),
			Color:  ColorEnabled(),
		},
	}
}

// sandboxConfigOptional marks commands that run without a DefenseClaw
// configuration (teardown during an uninstall of a half-installed host).
const sandboxConfigOptional = "defenseclaw.sandbox.config-optional"

// sandboxConfigDefault marks read-only commands that use the default
// configuration when there is no config.yaml yet (an administrator reads a
// pack's digest before writing the file that pins it).
const sandboxConfigDefault = "defenseclaw.sandbox.config-default"

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Run coding agents in NVIDIA OpenShell sandboxes",
	Long: `Run Claude Code, Codex and other hooks-only harnesses inside an NVIDIA OpenShell
sandbox: the agent sees only your project folder (on Linux live, with secret files
masked, git internals read-only and a snapshot for undo; on macOS, where sandboxes
are OpenShell MicroVMs, a copy you pull the changes back from), reaches the web
through DefenseClaw's egress proxy, and every tool call still goes through DefenseClaw.

Start with "defenseclaw sandbox setup", then run "defenseclaw sandbox run claude"
in a project folder.`,
	PersistentPreRunE: sandboxPreRun,
	// The sandbox commands never open the audit store.
	PersistentPostRun: func(*cobra.Command, []string) {},
	SilenceUsage:      true,
}

func sandboxPreRun(cmd *cobra.Command, _ []string) error {
	if err := sandboxHostRefusal(runtime.GOOS, runtime.GOARCH, cmd.Annotations[sandboxConfigOptional] == "true"); err != nil {
		return withExitCode(err, 3)
	}
	// A nested `sandbox run` inside a sandbox runs the harness natively and
	// needs no configuration (there is none inside the sandbox).
	if cmd.Name() == "run" && os.Getenv(openshell.EnvSandboxID) != "" {
		return nil
	}
	if err := loadGatewayCommandConfigOnly(); err != nil {
		if cmd.Annotations[sandboxConfigOptional] == "true" {
			cfg = nil
			return nil
		}
		if cmd.Annotations[sandboxConfigDefault] == "true" {
			if _, statErr := os.Stat(config.ConfigPath()); errors.Is(statErr, os.ErrNotExist) {
				cfg = config.DefaultConfig()
				return nil
			}
		}
		return err
	}
	return nil
}

// sandboxHostRefusal refuses, before any sandbox command runs, a machine
// sandboxes do not run on: an operating system other than Linux and macOS,
// and a Mac that is not Apple silicon, where OpenShell's MicroVM driver
// does not run. cleanup marks teardown, which only removes what an earlier
// setup left, and still runs on such a Mac.
func sandboxHostRefusal(goos, goarch string, cleanup bool) error {
	if err := openshell.CheckPlatform(goos); err != nil {
		return errors.New("OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported")
	}
	if err := openshell.CheckHost(goos, goarch); err != nil && !cleanup {
		return fmt.Errorf("OpenShell sandboxes do not run on this machine: %s; `defenseclaw sandbox teardown` still removes what an earlier setup left",
			strings.TrimPrefix(err.Error(), "openshell: "))
	}
	return nil
}

// sandboxRunE adapts a command to cobra: it prints the error once, styled,
// and turns harness exit statuses into the process's.
func sandboxRunE(fn func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		app := newSandboxApp(cmd)
		err := fn(cmd.Context(), app, cmd, args)
		if err == nil {
			return nil
		}
		cmd.SilenceErrors = true
		var exit *sandboxcli.ExitError
		var silent *sandboxcli.Silent
		switch {
		case errors.As(err, &exit):
			if exit.Err != nil && !errors.As(exit.Err, &silent) {
				fmt.Fprintln(cmd.ErrOrStderr(), Style("✗", "fg=red", "bold")+" "+exit.Err.Error())
			}
			return withExitCode(err, exit.Code)
		case errors.As(err, &silent):
			return withExitCode(err, 1)
		case errors.Is(err, context.Canceled):
			return withExitCode(err, 130)
		}
		fmt.Fprintln(cmd.ErrOrStderr(), Style("✗", "fg=red", "bold")+" "+err.Error())
		if errors.Is(err, sandboxcli.ErrUnsupported) {
			return withExitCode(err, 3)
		}
		return withExitCode(err, 1)
	}
}

func outputFlag(cmd *cobra.Command) *string {
	return cmd.Flags().StringP("output", "o", "text", "output format: text or json")
}

func parseOutput(s string) (sandboxcli.OutputFormat, error) { return sandboxcli.ParseOutput(s) }

func newSandboxSetupCmd() *cobra.Command {
	var o sandboxcli.SetupOptions
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "One-time setup: OpenShell, bind mounts, telemetry, harnesses, wrappers, images",
		Long: `Checks this machine, installs OpenShell with NVIDIA's installer when you agree and
configures your local OpenShell gateway (backed up and restored by "sandbox teardown"):
on Linux it enables project-folder bind mounts and turns OpenShell's upstream telemetry
off unless you keep it; on a Mac it switches the gateway to OpenShell's MicroVM driver.
Then it records the harnesses, offers shell wrappers and builds the harness images.`,
		Args: cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, _ []string) error {
			return app.Setup(ctx, o)
		}),
	}
	f := cmd.Flags()
	f.BoolVar(&o.InstallOpenShell, "install-openshell", false, "install OpenShell with NVIDIA's pinned, sha256-verified installer (uses sudo)")
	f.BoolVar(&o.NoMounts, "no-mounts", false, "leave bind mounts off (Linux); every run then works on a copy")
	f.BoolVar(&o.Wrappers, "wrappers", false, "make the harness commands run sandboxed without asking")
	f.BoolVar(&o.NoWrappers, "no-wrappers", false, "do not offer the shell wrappers")
	f.BoolVar(&o.NonInteractive, "non-interactive", false, "never prompt: take the defaults and skip steps that need consent")
	f.BoolVarP(&o.Yes, "yes", "y", false, "answer every question with its default")
	f.StringSliceVar(&o.Harnesses, "harness", nil, "harness to set up, added to openshell.harnesses (repeatable; default: openshell.harnesses, else claude and codex)")
	f.BoolVar(&o.UpstreamTelemetry, "upstream-telemetry", false, "keep OpenShell's anonymous usage telemetry on")
	f.BoolVar(&o.SkipImages, "skip-images", false, "do not build the harness images now (the first run builds them)")
	f.BoolVar(&o.RestartGateway, "restart-gateway", false, "restart the OpenShell gateway to apply its configuration even while sandboxes run on it")
	return cmd
}

func newSandboxDoctorCmd() *cobra.Command {
	var o sandboxcli.DoctorOptions
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this machine can run sandboxes",
		Long: `Checks the platform, Landlock, Docker, the OpenShell service, CLI, registration,
version and compute driver (on a Mac, the MicroVM driver: e2fsprogs, its signature,
the sandbox identity and resources), bind mounts, telemetry, ports, the DefenseClaw
daemon, harness images, shell wrappers and the organization policy. Exits 1 when a
check fails (with --output json the result is printed and the exit status is 0; read
"ok").`,
		Args: cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			if jsonOut {
				out = sandboxcli.OutputJSON
			}
			o.Output = out
			return app.RunDoctor(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "same as --output json")
	cmd.Flags().BoolVar(&o.Fix, "fix", false, "apply the fixes doctor can make as your user (asks first)")
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "apply fixes without asking")
	return cmd
}

func newSandboxRunCmd() *cobra.Command {
	var o sandboxcli.RunOptions
	cmd := &cobra.Command{
		Use:   "run <harness> [flags] [-- harness-args...]",
		Short: "Run a harness in a sandbox on this folder",
		Long: `Runs the harness in a new sandbox on the current folder: on Linux (the Docker driver)
live-mounted by default with a pre-session snapshot, or a copy with --copy; on macOS
(the MicroVM driver) every run works on a copy. The harness is claude, codex,
copilot, opencode, kiro, hermes, openhands, omnigent or antigravity (its command, agy,
works too; amp, cursor-agent and devin are not verified yet, so they do not run).
Skip-permissions mode is on by default;
--safe keeps the harness's own prompts. The harness gets your terminal; when it exits
you get a summary, a review of changed files that can run code on your machine, and
the choice to keep or undo the changes (from a copy: to bring them back, or leave them
in the sandbox for pull). Arguments after -- go to the harness.

A headless run in the foreground (--prompt, or the harness's own print flag after --)
deletes its sandbox when it ends and nothing is left in it to bring back or undo, as
--rm does; --keep (or openshell.keep_headless) keeps it. Interactive sessions and
--detach runs keep their sandbox.`,
		Example: `  defenseclaw sandbox run claude
  defenseclaw sandbox run codex --copy --name fix-tests
  defenseclaw sandbox run claude --detach --prompt "fix the failing tests"
  defenseclaw sandbox run claude --credential STRIPE_API_KEY=api.stripe.com -- --model sonnet`,
		Args: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			before := args
			if dash >= 0 {
				before = args[:dash]
			}
			switch {
			case len(before) == 0:
				return errors.New("name the harness to run, for example: defenseclaw sandbox run claude")
			case len(before) > 1:
				return fmt.Errorf("unexpected argument %q; pass harness arguments after --", before[1])
			}
			return nil
		},
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			o.Harness = args[0]
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				o.Args = append([]string(nil), args[dash:]...)
			}
			return app.Run(ctx, o)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&o.Name, "name", "", "sandbox name, at most 19 lowercase letters, digits and '-' (default <folder>-<random>)")
	f.BoolVar(&o.Copy, "copy", false, "work on a copy of the folder with secrets held back; bring changes back with pull")
	f.BoolVar(&o.Safe, "safe", false, "keep the harness's own permission prompts (skip-permissions off)")
	f.StringVar(&o.Pack, "pack", "", "sandbox policy pack (open, balanced, strict, or a custom pack)")
	f.StringVar(&o.Profile, "profile", "", "network profile: open, balanced or strict")
	f.StringArrayVar(&o.Context, "context", nil, "extra folder mounted read-only (repeatable; mount mode only)")
	f.StringArrayVar(&o.Unmask, "unmask", nil, "share a masked secret file or glob with the sandbox (repeatable)")
	f.IntSliceVar(&o.HostPorts, "host-port", nil, "open this localhost port on your machine to the sandbox (repeatable)")
	f.StringArrayVar(&o.Credentials, "credential", nil, "NAME=host[:port]: give the sandbox a placeholder for $NAME that works only against that host (repeatable)")
	f.BoolVar(&o.GitHubWrite, "github-write", false, "bind your GitHub token (GH_TOKEN or GITHUB_TOKEN) to api.github.com so gh can call the GitHub API (for example to open pull requests) with everything the token may do; git push over HTTPS is not covered")
	f.BoolVar(&o.NoMCP, "no-mcp", false, "leave the harness's MCP servers behind")
	f.BoolVarP(&o.Detach, "detach", "d", false, "run in the background (needs --prompt); follow with sandbox logs -f")
	f.BoolVar(&o.Rm, "rm", false, "delete the sandbox when the session ends")
	f.BoolVar(&o.Keep, "keep", false, "keep the sandbox of a headless run (--prompt), which is otherwise deleted at its end when nothing is left in it to bring back or undo")
	f.StringVarP(&o.Prompt, "prompt", "p", "", "run the harness headless with this prompt")
	f.StringArrayVar(&o.Env, "env", nil, "KEY=VALUE non-secret variable for the sandbox (repeatable)")
	f.StringVar(&o.LLM, "llm", "", "model credential to share: auto, none, anthropic, claude-oauth, openai, bedrock or gemini (default: openshell.llm, which is auto unless set)")
	f.StringVar(&o.BedrockRegion, "bedrock-region", "", "Amazon Bedrock region for --llm bedrock (default $AWS_REGION, then $AWS_DEFAULT_REGION, then us-east-1)")
	f.BoolVar(&o.NoSnapshot, "no-snapshot", false, "skip the pre-session snapshot (and so undo)")
	f.BoolVar(&o.NoBuild, "no-build", false, "fail instead of building a missing harness image")
	f.BoolVar(&o.New, "new", false, "start a new sandbox even when one already holds this folder")
	f.BoolVar(&o.Refresh, "refresh", false, "when resuming a copy-mode sandbox, copy the folder again")
	f.StringVar(&o.CPU, "cpu", "", "CPU limit, for example 2 or 500m")
	f.StringVar(&o.Memory, "memory", "", "memory limit, for example 4Gi")
	f.BoolVarP(&o.Yes, "yes", "y", false, sessionYesUsage)
	return cmd
}

// sessionYesUsage is the --yes of run and connect: a mount's changes are
// kept, a copy's stay in the sandbox (nothing comes back unreviewed).
const sessionYesUsage = "take the defaults at the end of the session (mount: keep the changes; copy: leave them in the sandbox for pull)"

func nameArg(what string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("name the %s (see `defenseclaw sandbox list`)", what)
		}
		return nil
	}
}

func newSandboxListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sandboxes",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.List(ctx, out)
		}),
	}
	outputFlag(cmd)
	return cmd
}

func newSandboxStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status [name]",
		Short: "Show the sandbox subsystem, or one sandbox in detail",
		Args:  cobra.MaximumNArgs(1),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return app.Status(ctx, name, out)
		}),
	}
	outputFlag(cmd)
	return cmd
}

func newSandboxConnectCmd() *cobra.Command {
	var o sandboxcli.ConnectOptions
	cmd := &cobra.Command{
		Use:   "connect <name> [-- harness-args...]",
		Short: "Resume a sandbox: start it if stopped and attach the harness",
		Long: `Resumes a sandbox: starts it when it is stopped and attaches the harness to your
terminal, or with --prompt (or the harness's own print flag after --) runs one prompt
headless, which needs no terminal. A sandbox this command started is stopped again when
the session ends; one that was already running, whose detached run is still going, or
that another session is attached to keeps running. --shell opens a login shell instead,
reviewed at its end like a harness session.`,
		Example: `  defenseclaw sandbox connect myapp-7f3a
  defenseclaw sandbox connect myapp-7f3a --prompt "now add the tests"
  defenseclaw sandbox connect myapp-7f3a --shell`,
		Args: func(cmd *cobra.Command, args []string) error {
			if n := cmd.ArgsLenAtDash(); n == 1 || (n < 0 && len(args) == 1) {
				return nil
			}
			return errors.New("name the sandbox (see `defenseclaw sandbox list`); harness arguments go after --")
		},
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			o.Name = args[0]
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				o.Args = args[dash:]
			}
			return app.Connect(ctx, o)
		}),
	}
	cmd.Flags().BoolVar(&o.Shell, "shell", false, "open a shell in the sandbox instead of the harness")
	cmd.Flags().BoolVar(&o.Refresh, "refresh", false, "copy-mode: copy the folder into the sandbox again first")
	cmd.Flags().BoolVar(&o.Rm, "rm", false, "delete the sandbox when the session ends")
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, sessionYesUsage)
	cmd.Flags().StringVarP(&o.Prompt, "prompt", "p", "", "run the harness headless with this prompt")
	return cmd
}

func newSandboxExecCmd() *cobra.Command {
	var o sandboxcli.ExecOptions
	cmd := &cobra.Command{
		Use:   "exec <name> -- <command> [args...]",
		Short: "Run a command in a sandbox",
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 || len(args) < 2 {
				return errors.New("usage: defenseclaw sandbox exec <name> -- <command> [args...]")
			}
			return nil
		},
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			o.Name, o.Command = args[0], args[1:]
			return app.Exec(ctx, o)
		}),
	}
	cmd.Flags().StringVar(&o.Workdir, "workdir", "", "working directory in the sandbox (default: the project)")
	cmd.Flags().BoolVar(&o.TTY, "tty", false, "allocate a terminal even when this one is not")
	cmd.Flags().BoolVar(&o.NoTTY, "no-tty", false, "never allocate a terminal")
	return cmd
}

func newSandboxStopCmd() *cobra.Command {
	var o sandboxcli.StopOptions
	cmd := &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop a sandbox (it is kept for start or connect)",
		Long: `Stops a sandbox and keeps it for start or connect. When its detached run is still
going, the stop ends it: stop asks first on a terminal (--yes does not), marks the run
interrupted and keeps its log, so "sandbox logs" still shows it.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Name = args[0]
			return app.Stop(ctx, o)
		}),
	}
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "stop without asking when a detached run is still going")
	return cmd
}

func newSandboxStartCmd() *cobra.Command {
	var o sandboxcli.StartOptions
	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "Start a stopped sandbox for a new session",
		Long: `Starts a stopped sandbox for a new session. A mounted project gets a fresh undo
snapshot, unless the folder still holds changes an earlier session made that were
neither undone nor kept at its end (a detached run, or one without a terminal to ask
on): then the earlier undo point stays, so "sandbox undo" still reverts them.
--new-snapshot accepts those changes and takes a fresh snapshot.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.Start(ctx, args[0], o)
		}),
	}
	cmd.Flags().BoolVar(&o.NoSnapshot, "no-snapshot", false, "keep the previous session's snapshot instead of taking a new one")
	cmd.Flags().BoolVar(&o.NewSnapshot, "new-snapshot", false,
		"take a new snapshot even if the folder still has an earlier session's changes (undo no longer reverts them)")
	return cmd
}

func newSandboxDeleteCmd() *cobra.Command {
	var o sandboxcli.DeleteOptions
	cmd := &cobra.Command{
		Use:   "delete <name>...",
		Short: "Delete sandboxes with their providers, credentials and snapshots",
		Args:  cobra.MinimumNArgs(1),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Names = args
			return app.Delete(ctx, o)
		}),
	}
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "do not ask")
	cmd.Flags().BoolVar(&o.KeepSnapshot, "keep-snapshot", false, "keep the pre-session snapshot")
	return cmd
}

func newSandboxLogsCmd() *cobra.Command {
	var o sandboxcli.LogsOptions
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Show the output of a sandbox's detached run",
		Args:  nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Name = args[0]
			return app.Logs(ctx, o)
		}),
	}
	cmd.Flags().BoolVarP(&o.Follow, "follow", "f", false, "keep following the output")
	cmd.Flags().IntVarP(&o.Lines, "lines", "n", 200, "lines to show")
	return cmd
}

func newSandboxActivityCmd() *cobra.Command {
	var o sandboxcli.ActivityOptions
	cmd := &cobra.Command{
		Use:   "activity",
		Short: "Show the live activity feed: destinations, blocks, asks, tool blocks, findings",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Output = out
			return app.Activity(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().StringVar(&o.Sandbox, "sandbox", "", "only this sandbox")
	cmd.Flags().BoolVarP(&o.Follow, "follow", "f", false, "keep following the feed")
	cmd.Flags().Uint64Var(&o.Since, "since", 0, "start after this event sequence number")
	return cmd
}

func newSandboxUndoCmd() *cobra.Command {
	var o sandboxcli.UndoOptions
	cmd := &cobra.Command{
		Use:   "undo <name>",
		Short: "Restore the project folder to its pre-session snapshot",
		Long: "Restore a mounted project folder to its pre-session snapshot, after a preview. Files git ignores\n" +
			"(dependency directories, build output) have no copy in the snapshot: undo deletes what the session\n" +
			"wrote to Python bytecode caches and names the rest, with what to do about them, unless\n" +
			"openshell.workdir.undo_ignored has the snapshot keep a copy of node_modules, .venv and the like,\n" +
			"which undo then restores.\n\n" +
			"For a copy-mode sandbox (every sandbox on macOS), undo reverts its last `pull --apply` instead; edits you\n" +
			"made since stay.",
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Name, o.Output = args[0], out
			return app.Undo(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "do not ask after the preview")
	cmd.Flags().BoolVar(&o.Preview, "preview", false, "only show what undo would change")
	cmd.Flags().BoolVar(&o.Restart, "restart", false, "start the sandbox again afterwards")
	cmd.Flags().BoolVar(&o.KeepRefs, "keep-refs", false, "leave branches and tags as the session left them")
	return cmd
}

func newSandboxReviewCmd() *cobra.Command {
	var o sandboxcli.ReviewOptions
	cmd := &cobra.Command{
		Use:   "review <name>",
		Short: "Review the session's changes, flagging files that can run code on this machine",
		Long: `Reviews what changed in a mounted project since its pre-session snapshot, flagging
files that can run code on this machine. For a copy-mode sandbox (every sandbox on
macOS) it previews what "sandbox pull" would bring back and applies nothing; with
--output json it prints the pull's result.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Name, o.Output = args[0], out
			return app.Review(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().BoolVar(&o.Diff, "diff", false, "print the unified diff too")
	return cmd
}

func newSandboxApprovalsCmd() *cobra.Command {
	var o sandboxcli.ApprovalsOptions
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List the asks waiting for you (doors into your machine or network)",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Output = out
			return app.Approvals(ctx, o)
		}),
	}
	outputFlag(cmd)
	cmd.Flags().StringVar(&o.Sandbox, "sandbox", "", "only this sandbox")
	cmd.Flags().BoolVar(&o.Watch, "watch", false, "keep watching for new asks")
	return cmd
}

func newSandboxDecideCmd(approve bool) *cobra.Command {
	var o sandboxcli.DecideOptions
	use, short := "reject <name> <id>", "Reject an ask"
	if approve {
		use, short = "approve <name> <id>", "Approve an ask"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Sandbox, o.ID, o.Approve = args[0], args[1], approve
			return app.Decide(ctx, o)
		}),
	}
	cmd.Flags().BoolVar(&o.Always, "always", false, "keep the decision for future sandboxes")
	cmd.Flags().StringVar(&o.Reason, "reason", "", "note recorded with the decision")
	return cmd
}

func newSandboxUnblockCmd() *cobra.Command {
	var o sandboxcli.UnblockOptions
	cmd := &cobra.Command{
		Use:   "unblock <host>",
		Short: "Lift an egress block for one sandbox or for every sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Host = args[0]
			return app.Unblock(ctx, o)
		}),
	}
	cmd.Flags().StringVar(&o.Sandbox, "sandbox", "", "unblock for this sandbox only")
	cmd.Flags().BoolVar(&o.Always, "always", false, "unblock for every sandbox from now on")
	return cmd
}

func newSandboxPullCmd() *cobra.Command {
	var o sandboxcli.PullOptions
	cmd := &cobra.Command{
		Use:   "pull <name>",
		Short: "Bring a copy-mode sandbox's work back (3-way apply, a branch, or a patch)",
		Long: `Brings a copy-mode sandbox's work back after a review: --apply merges it into your
working tree (3-way), --branch puts it on branch dc/<name>, --patch-out writes a patch.
When --apply cannot merge (a conflict, or git older than 2.38), your working tree is
left as it was, the changes go to branch dc/<name> and a patch instead, and pull exits
with status 4.`,
		Args: nameArg("sandbox"),
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Name, o.Output = args[0], out
			return app.Pull(ctx, o)
		}),
	}
	outputFlag(cmd)
	f := cmd.Flags()
	f.BoolVar(&o.Apply, "apply", false, "merge the changes into your working tree (3-way)")
	f.BoolVar(&o.Branch, "branch", false, "put the changes on branch dc/<name>")
	f.StringVar(&o.BranchAs, "branch-name", "", "put the changes on this branch")
	f.StringVar(&o.PatchOut, "patch-out", "", "write the changes to this patch file")
	f.BoolVar(&o.Force, "force", false, "override blocking review gates, an existing branch or patch file")
	f.BoolVar(&o.AcceptSensitive, "accept-sensitive", false, "bring back changes that can run code on this machine")
	return cmd
}

func policyFlags(cmd *cobra.Command, o *sandboxcli.PolicyOptions) {
	f := cmd.Flags()
	f.StringVar(&o.Sandbox, "sandbox", "", "the policy of this sandbox")
	f.StringVar(&o.Harness, "harness", "", "resolve for this harness")
	f.StringVar(&o.Pack, "pack", "", "resolve with this pack")
	f.StringVar(&o.Profile, "profile", "", "resolve with this profile")
	f.BoolVar(&o.Copy, "copy", false, "resolve for a copy-mode run")
	f.BoolVar(&o.Safe, "safe", false, "resolve for a --safe run")
	f.StringArrayVar(&o.Unmask, "unmask", nil, "resolve with these --unmask globs")
}

func newSandboxPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Show, explain and adjust the sandbox policy",
	}
	for _, explain := range []bool{false, true} {
		var o sandboxcli.PolicyOptions
		sub := &cobra.Command{
			Use:   "show",
			Short: "Show the effective sandbox policy",
			Args:  cobra.NoArgs,
		}
		if explain {
			sub.Use, sub.Short = "explain", "Show every resolved setting and where it comes from (pack, config, flag, organization)"
		}
		explain := explain
		sub.RunE = sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			o.Output = out
			if explain {
				return app.PolicyExplain(ctx, o)
			}
			return app.PolicyShow(ctx, o)
		})
		outputFlag(sub)
		policyFlags(sub, &o)
		cmd.AddCommand(sub)
	}
	var so sandboxcli.SuggestOptions
	suggest := &cobra.Command{
		Use:   "suggest",
		Short: "Suggest an egress allowlist from the destinations sandboxes reached",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			so.Output = out
			return app.PolicySuggest(ctx, so)
		}),
	}
	outputFlag(suggest)
	suggest.Flags().StringVar(&so.Sandbox, "sandbox", "", "only this sandbox's destinations")
	cmd.AddCommand(suggest)
	for _, list := range []string{"allow", "block"} {
		list := list
		short := "Add hosts to openshell.egress.allow (used by the balanced and strict profiles)"
		if list == "block" {
			short = "Add hosts to openshell.egress.block"
		}
		cmd.AddCommand(&cobra.Command{
			Use:   list + " <host>...",
			Short: short,
			Args:  cobra.MinimumNArgs(1),
			RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
				return app.PolicyEdit(ctx, list, args)
			}),
		})
	}
	return cmd
}

func newSandboxPackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Inspect sandbox policy packs",
	}
	list := &cobra.Command{
		Use:         "list",
		Short:       "List the built-in and custom packs with their sha256 digests",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{sandboxConfigDefault: "true"},
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.PackList(sandboxcli.PackOptions{Output: out})
		}),
	}
	outputFlag(list)
	show := &cobra.Command{
		Use:         "show <pack>",
		Short:       "Print a pack and its sha256 digest (for openshell.admin.required_pack_digest)",
		Args:        cobra.ExactArgs(1),
		Annotations: map[string]string{sandboxConfigDefault: "true"},
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.PackShow(args[0], sandboxcli.PackOptions{Output: out})
		}),
	}
	outputFlag(show)
	validate := &cobra.Command{
		Use:         "validate <path>",
		Short:       "Validate a pack file strictly",
		Args:        cobra.ExactArgs(1),
		Annotations: map[string]string{sandboxConfigDefault: "true"},
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.PackValidate(args[0])
		}),
	}
	cmd.AddCommand(list, show, validate)
	return cmd
}

func newSandboxImageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "image",
		Short: "Build, list and prune the harness images",
	}
	var bo sandboxcli.ImageBuildOptions
	build := &cobra.Command{
		Use:   "build [harness...]",
		Short: "Build and hook-verify harness images (default: the configured harnesses)",
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			bo.Harnesses = args
			return app.ImageBuild(ctx, bo)
		}),
	}
	build.Flags().BoolVar(&bo.Force, "force", false, "rebuild even when a verified image is current")
	build.Flags().BoolVar(&bo.Verbose, "verbose", false, "stream the docker build output")
	list := &cobra.Command{
		Use:   "list",
		Short: "List the harness images",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.ImageList(ctx, out)
		}),
	}
	outputFlag(list)
	var dryRun bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Remove superseded harness images",
		Args:  cobra.NoArgs,
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, _ []string) error {
			return app.ImagePrune(ctx, dryRun)
		}),
	}
	prune.Flags().BoolVar(&dryRun, "dry-run", false, "only show what would be removed")
	cmd.AddCommand(build, list, prune)
	return cmd
}

func newSandboxWrapperCmd(enable bool) *cobra.Command {
	var o sandboxcli.WrapperOptions
	use, short := "disable <harness>", "Stop the harness command from running sandboxed (removes the shell wrapper)"
	if enable {
		use, short = "enable <harness>", "Make the harness command run sandboxed (a marked block in your shell rc)"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			o.Harness = args[0]
			if enable {
				return app.Enable(o)
			}
			return app.Disable(o)
		}),
	}
	cmd.Flags().StringVar(&o.Shell, "shell", "", "bash, zsh or fish (default: $SHELL)")
	cmd.Flags().StringVar(&o.RC, "rc", "", "rc file to edit (default: the shell's)")
	return cmd
}

func newSandboxTeardownCmd() *cobra.Command {
	var o sandboxcli.TeardownOptions
	cmd := &cobra.Command{
		Use:   "teardown",
		Short: "Remove every DefenseClaw sandbox, provider, profile, image, gateway change and wrapper",
		Long: `Deletes DefenseClaw's sandboxes, OpenShell providers and provider profiles and its
harness images, restores the OpenShell gateway configuration that setup changed (when
nobody changed it since), removes the shell wrappers and turns openshell.enabled off.
OpenShell itself stays installed. "defenseclaw uninstall" runs it.`,
		Args:        cobra.NoArgs,
		Annotations: map[string]string{sandboxConfigOptional: "true"},
		RunE: sandboxRunE(func(ctx context.Context, app *sandboxcli.App, _ *cobra.Command, _ []string) error {
			return app.Teardown(ctx, o)
		}),
	}
	cmd.Flags().BoolVarP(&o.Yes, "yes", "y", false, "do not ask")
	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, "only show what would be removed")
	cmd.Flags().BoolVar(&o.KeepImages, "keep-images", false, "keep the harness images")
	return cmd
}

func init() {
	sandboxCmd.AddCommand(
		newSandboxSetupCmd(), newSandboxDoctorCmd(), newSandboxRunCmd(), newSandboxListCmd(), newSandboxStatusCmd(),
		newSandboxConnectCmd(), newSandboxExecCmd(), newSandboxStopCmd(), newSandboxStartCmd(), newSandboxDeleteCmd(),
		newSandboxLogsCmd(), newSandboxActivityCmd(), newSandboxUndoCmd(), newSandboxReviewCmd(),
		newSandboxApprovalsCmd(), newSandboxDecideCmd(true), newSandboxDecideCmd(false), newSandboxUnblockCmd(),
		newSandboxPullCmd(), newSandboxPolicyCmd(), newSandboxPackCmd(), newSandboxImageCmd(),
		newSandboxWrapperCmd(true), newSandboxWrapperCmd(false), newSandboxTeardownCmd(),
	)
	rootCmd.AddCommand(sandboxCmd)
}
