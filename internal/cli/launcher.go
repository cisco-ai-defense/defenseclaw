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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

// The launcher is the standard user's `defenseclaw` on a standalone managed
// Linux or macOS computer. The enterprise package installs it as a root-owned
// symlink, /usr/bin/defenseclaw (Linux) or /usr/local/bin/defenseclaw
// (macOS), to defenseclaw-gateway. Started under that name on a host with a
// trusted managed runtime descriptor, the binary offers the `sandbox` tree
// and nothing else: the gateway commands and the administrator lifecycle stay
// with `defenseclaw-gateway`, whose own guards still apply to anyone who runs
// it directly. The launcher narrows what a user is shown; it is not an
// access boundary. Windows has no launcher: its defenseclaw.exe is the
// administrator command.

const (
	launcherCommand = "defenseclaw"

	// launcherRefusal answers every command the launcher does not offer.
	launcherRefusal = "This computer is managed; use `defenseclaw sandbox status` for your read-only status and `defenseclaw sandbox policy explain` for your policy. Other commands require an administrator."
)

// launcherArgv0 is the name the process was started under; a seam for tests.
var launcherArgv0 = func() string {
	if len(os.Args) == 0 {
		return ""
	}
	return os.Args[0]
}

// launcherInvoked reports whether argv0 names the launcher on goos. The
// release binary's own name, defenseclaw-gateway, never does.
func launcherInvoked(goos, argv0 string) bool {
	if goos != "linux" && goos != "darwin" {
		return false
	}
	return filepath.Base(argv0) == launcherCommand
}

// launcherActive reports whether this process is the launcher on a managed
// host. A host without a trusted runtime descriptor is not managed, so a
// binary named defenseclaw there (a developer build, say) keeps the full
// command tree.
func launcherActive() bool {
	if !launcherInvoked(runtime.GOOS, launcherArgv0()) {
		return false
	}
	_, managedHost := managedHostUnixRecord(os.Stderr)
	return managedHost
}

// launcherOffers reports whether the launcher runs args at all. The bare
// command and the help and version requests show the launcher's own text.
func launcherOffers(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch args[0] {
	case "sandbox", "-h", "--help", "--version":
		return true
	case "guardrail":
		// The user's own guardrail profile (GAP-0431, GAP-0422), and nothing
		// else of the guardrail tree.
		return len(args) >= 3 && args[1] == "profile" && args[2] == "explain"
	case "help":
		// `help` explains the sandbox tree; cobra would answer `help status`
		// with the root help, as if status existed. `help --help` is the
		// help command's own usage: the root help lists `help`, so asking
		// about it must answer (GAP-0471).
		if len(args) == 1 {
			return true
		}
		switch args[1] {
		case "sandbox", "-h", "--help":
			return true
		}
		return false
	}
	return false
}

// prepareLauncherRoot cuts root down to the sandbox tree: the other commands
// are removed, the gateway's daemon bootstrap and the sidecar run are
// replaced by the launcher's help, and the help describes the launcher.
func prepareLauncherRoot(root *cobra.Command) {
	var others []*cobra.Command
	for _, command := range root.Commands() {
		if command.Name() != "sandbox" {
			others = append(others, command)
		}
	}
	root.RemoveCommand(others...)
	if guardrail := newLauncherGuardrailCommand(); guardrail != nil {
		root.AddCommand(guardrail)
	}
	root.Use = launcherCommand
	root.Short = "Run coding agents in sandboxes on this managed computer"
	root.Long = `Your organization manages DefenseClaw on this computer. Here defenseclaw runs
your coding agents in sandboxes under the policy your organization set for you:

  defenseclaw sandbox run claude     run Claude Code in a sandbox
  defenseclaw sandbox status         show your sandbox and managed policy state
  defenseclaw sandbox policy explain show the policy that applies to you

"defenseclaw guardrail profile explain" shows the guardrail profile that
applies to your agents. Every other DefenseClaw command is for administrators.`
	root.CompletionOptions.DisableDefaultCmd = true
	// The gateway's own flags (--host, --port, --version-json, ...) belong to
	// the commands removed above; the launcher refuses them, so its help does
	// not advertise them.
	root.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name != "help" && flag.Name != "version" {
			flag.Hidden = true
		}
	})
	// The gateway's bootstrap (process registration, config load, audit
	// store) is not the launcher's: the sandbox tree has its own pre-run.
	root.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }
	root.PersistentPostRun = func(*cobra.Command, []string) {}
	root.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	root.Args = cobra.NoArgs
	if sandbox, _, err := root.Find([]string{"sandbox"}); err == nil && sandbox != root {
		sandbox.PersistentPreRunE = launcherSandboxPreRun
		sandbox.Long = launcherSandboxLong
		// The organization sets sandboxes up: `setup` stays callable, to
		// answer so, but is not offered (GAP-0249).
		if setup, _, err := sandbox.Find([]string{"setup"}); err == nil && setup != sandbox {
			setup.Hidden = true
		}
		// `run --help` described Linux live mounts and their snapshot too
		// (GAP-0249): a managed workspace is always a copy.
		if run, _, err := sandbox.Find([]string{"run"}); err == nil && run != sandbox {
			run.Long = launcherRunLong
			for _, name := range []string{"context", "no-snapshot"} {
				// Mount-mode flags, which a copy never takes.
				if flag := run.Flags().Lookup(name); flag != nil {
					flag.Hidden = true
				}
			}
			if flag := run.Flags().Lookup("copy"); flag != nil {
				flag.Usage = "work on a copy of the folder (every run on this computer does)"
			}
		}
	}
}

// launcherRunLong is the help of `sandbox run` on a managed computer: the
// gateway's text describes live mounts with a pre-session snapshot on
// Linux, which a managed workspace never is.
const launcherRunLong = `Runs the harness in a new sandbox on a copy of the current folder: your
organization manages sandboxes on this computer, so every run works on a copy,
with secret files held back, that you bring the changes back from after a review.
The harness is claude, codex, copilot, opencode, kiro, hermes
or antigravity, as far as your organization allows it for you ("defenseclaw sandbox
policy explain" lists them). The harness gets your terminal; when it exits you get a
summary, a review of the changed files, and the choice to bring the changes back or
leave them in the sandbox for pull. Arguments after -- go to the harness.

A headless run in the foreground (--prompt, or the harness's own print flag after --)
deletes its sandbox when it ends and nothing is left in it to bring back, as --rm
does; --keep keeps it. Interactive sessions and --detach runs keep their sandbox.`

// launcherSandboxLong is the help of the sandbox tree on a managed computer.
// The gateway's text starts with `sandbox setup`, describes live mounts on
// Linux, and none of it holds there: the organization sets sandboxes up, and
// a managed workspace is always a copy.
const launcherSandboxLong = `Your organization manages sandboxes on this computer. Run Claude Code, Codex and
other hooks-only harnesses inside an NVIDIA OpenShell sandbox: the agent works
on a copy of your project folder that you pull the changes back from, reaches
the web through DefenseClaw's egress proxy under the policy your organization
set for you, and every tool call still goes through DefenseClaw.

Run "defenseclaw sandbox run claude" in a project folder. "defenseclaw sandbox
policy explain" shows the policy that applies to you, and "defenseclaw sandbox
doctor" checks that sandboxes work for you. Your organization sets up and
repairs sandboxes, so there is nothing to set up here: if doctor reports a
problem, ask your administrator.`

// launcherManagedClient is the client of the caller's own sandbox daemon; a
// seam for tests.
var launcherManagedClient = sandboxapi.ClientForHost

// launcherClient is set by the sandbox pre-run and handed to every command.
var launcherClient *sandboxapi.Client

// launcherSandboxPreRun replaces the sandbox tree's pre-run on a managed
// host. The policy comes from the user's own sandbox daemon, which the
// managed gateway feeds, so a per-user config.yaml is never read; the daemon
// is started when it is not running.
func launcherSandboxPreRun(cmd *cobra.Command, args []string) error {
	cleanup := cmd.Annotations[sandboxConfigOptional] == "true"
	if err := sandboxHostRefusal(runtime.GOOS, runtime.GOARCH, cleanup); err != nil {
		return withExitCode(err, 3)
	}
	// The configuration of a managed computer, which the commands read as
	// such: no per-user config.yaml is written, and `sandbox setup` and the
	// wrapper commands answer for the organization-run service (GAP-0292,
	// GAP-0362).
	cfg = managedSandboxCommandConfig()
	client, err := launcherManagedClient(runtime.GOOS)
	if err != nil {
		return withExitCode(err, 3)
	}
	launcherClient = client
	// A run the organization does not allow the account at all starts no
	// sandbox daemon: the run refuses it in the daemon's words (GAP-0534).
	if !cleanup && !launcherRunForbidden(cmd, args) {
		status, err := launcherEnsureDaemon(cmd.Context(), client, runtime.GOOS, os.Getuid(), cmd.ErrOrStderr())
		if err != nil {
			// The command that follows reports the unreachable daemon in its
			// own words (doctor explains it); this line says what was tried.
			fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw: %v\n", err)
		}
		// What a command takes from Cfg (ports, gateway, pack) is what the
		// daemon runs with, not the built-in defaults.
		cfg = launcherManagedConfig(cfg, status)
	}
	return nil
}

// launcherAccountPolicy is the managed gateway's own policy view of the
// caller's new run of a harness, asked without the account's sandbox daemon
// (sandboxManagedAccountPolicy); a seam for tests.
var launcherAccountPolicy = sandboxManagedAccountPolicy

// launcherRunForbidden reports a `sandbox run` (args: its harness first) of
// an account whose organization does not allow it sandboxes, by the managed
// gateway's settled view: probing the daemon's socket would start it, which
// then stayed running and wrote its state for an account that can run no
// sandbox (GAP-0534). A provisional view, an allowed one and a gateway that
// does not answer leave it to the daemon, as before.
func launcherRunForbidden(cmd *cobra.Command, args []string) bool {
	if cmd == nil || cmd.Name() != "run" || cmd.Parent() == nil || cmd.Parent().Name() != "sandbox" || len(args) == 0 {
		return false
	}
	spec, err := sandboxcli.ResolveHarness(args[0])
	if err != nil {
		return false
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	view, err := launcherAccountPolicy(ctx, spec.Name)
	return err == nil && view != nil && !view.Provisional && !view.Allowed
}

// launcherManagedConfig overlays the settings the user's sandbox daemon runs
// with, as its status reports them, on base: the OpenShell ports, the gateway
// registration and the configured pack and profile. The managed gateway, not
// the user's ~/.defenseclaw, decides them; a daemon that has not bound its
// lazy ports yet leaves the defaults for those.
func launcherManagedConfig(base *config.Config, status *sandboxapi.Status) *config.Config {
	if base == nil || status == nil {
		return base
	}
	out := *base
	if port := launcherAddrPort(status.IngressAddr); port > 0 {
		out.OpenShell.IngressPort = port
	}
	if port := launcherAddrPort(status.EgressAddr); port > 0 {
		out.OpenShell.EgressPort = port
	}
	if gateway := status.Gateway; gateway != nil {
		if gateway.Name != "" {
			out.OpenShell.Gateway.Name = gateway.Name
		}
		if gateway.Workspace != "" {
			out.OpenShell.Gateway.Workspace = gateway.Workspace
		}
	}
	if packs.IsBuiltin(status.Pack) {
		// An organization pack is the administrator's file, which this
		// process cannot read: the daemon applies it, and a command that
		// needs its settings asks the daemon (GAP-0478).
		out.OpenShell.Pack = status.Pack
	}
	if status.Profile != "" {
		out.OpenShell.Profile = status.Profile
	}
	out.OpenShell.Enabled = status.Enabled
	return &out
}

// launcherAddrPort is the port of a host:port listener address, 0 when addr
// has none.
func launcherAddrPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// withLauncherClient hands the sandbox commands the daemon client the
// pre-run chose.
func withLauncherClient(newApp func(*cobra.Command) *sandboxcli.App) func(*cobra.Command) *sandboxcli.App {
	return func(cmd *cobra.Command) *sandboxcli.App {
		app := newApp(cmd)
		if launcherClient != nil {
			app.API = launcherClient
		}
		return app
	}
}

// launcherWriters are the commands that change policy or configuration: a
// refusal of one is a row in the managed audit store, as it was when the
// per-user CLI refused it (mp0.GAP-0002). Reads and other commands record
// nothing. The words come from this table, never from the arguments.
var launcherWriters = map[string]map[string]bool{
	"config": {"set": true, "unset": true},
	"guardrail": {
		"alert-at": true, "allow-private-upstream": true, "block-at": true, "block-message": true, "disable": true,
		"enable": true, "fail-mode": true, "hilt": true, "judge": true, "mode": true, "protection": true,
		"rule": true, "suppress": true, "use-pack": true,
	},
	"policy": {"activate": true, "create": true, "delete": true, "edit": true},
}

// launcherAuditedWriter returns the command words of a refused writer.
func launcherAuditedWriter(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	if args[0] == "uninstall" {
		return "uninstall", true
	}
	if len(args) > 1 && launcherWriters[args[0]][args[1]] {
		if args[0] == "guardrail" && args[1] == "protection" && len(args) > 2 && args[2] == "list" {
			return "", false
		}
		return args[0] + " " + args[1], true
	}
	return "", false
}

// executeLauncher runs the launcher over root with args and returns the exit
// code.
func executeLauncher(ctx context.Context, root *cobra.Command, args []string) int {
	if !launcherOffers(args) {
		if command, ok := launcherAuditedWriter(args); ok {
			reportManagedCommandRefusal(command, "")
		}
		fmt.Fprintln(root.ErrOrStderr(), launcherRefusal)
		return 2
	}
	prepareLauncherRoot(root)
	newSandboxApp = withLauncherClient(newSandboxApp)
	installUsageArgChecks(root)
	root.SetArgs(args)
	pendingUnknownSubcommand = nil
	return executeResult(root, root.ExecuteContext(ctx))
}
