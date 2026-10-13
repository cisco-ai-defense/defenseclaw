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
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// sandboxDaemonCmd runs this account's sandbox daemon on a standalone
// managed computer: the user unit defenseclaw-sandbox.service (Linux,
// socket-activated) or the LaunchAgent com.cisco.defenseclaw.sandbox
// (macOS, bootstrapped on demand by the launcher). It runs as the user and
// takes no config file: the managed gateway's hook socket gives it its
// settings and judges everything its sandboxes do.
var sandboxDaemonCmd = &cobra.Command{
	Use:               "sandbox-daemon",
	Short:             "Run this account's sandbox daemon (standalone managed computers)",
	Hidden:            true,
	Args:              cobra.NoArgs,
	SilenceUsage:      true,
	Annotations:       map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(*cobra.Command, []string) {},
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return runSandboxDaemon(ctx, cmd.ErrOrStderr())
	},
}

// sandboxDaemonStopCmd is the user unit's ExecStop: it stops this account's
// running sandboxes through the daemon before the daemon stops (docker
// would keep their containers running otherwise).
var sandboxDaemonStopCmd = &cobra.Command{
	Use:          "stop-sandboxes",
	Short:        "Stop this account's running sandboxes (the sandbox daemon's ExecStop)",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if sandboxDaemonExitedOnItsOwn(os.Getenv) {
			// systemd runs ExecStop after a daemon that exited by itself
			// too (idle, or a deferred restart): it did so with no sandbox
			// running, and connecting would only activate it again.
			return nil
		}
		if sandboxDaemonRestarting(cmd.Context()) {
			// A restart of the daemon (`systemctl --user restart`, a
			// package's try-restart) keeps the sandboxes: the next daemon
			// binds their ports again at once and their hooks fail closed
			// in between, so a running agent session goes on (GAP-0534).
			fmt.Fprintln(cmd.OutOrStdout(), "the sandbox daemon restarts: your sandboxes keep running")
			return nil
		}
		path, _, err := sandboxDaemonPaths(runtime.GOOS)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
		defer cancel()
		return stopManagedSandboxes(ctx, sandboxapi.NewUnixClient(path), cmd.OutOrStdout())
	},
}

func init() {
	sandboxDaemonCmd.AddCommand(sandboxDaemonStopCmd)
	rootCmd.AddCommand(sandboxDaemonCmd)
}

// sandboxDaemonHost is what the daemon learns of the managed deployment; a
// seam for tests.
var sandboxDaemonHost = func(goos string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return managed.StandaloneLayout{}, nil, err
	}
	d, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath)
	return layout, d, err
}

// errNotStandaloneManaged refuses the daemon on a computer DefenseClaw does
// not manage: there the per-user gateway runs sandboxes.
var errNotStandaloneManaged = errors.New("the sandbox daemon runs only on a computer whose DefenseClaw your organization manages; " +
	"run sandboxes with `defenseclaw sandbox run` and the per-user gateway here")

// sandboxPrerequisiteExit is the exit status of the sandbox daemon and the
// OpenShell exec shim when this computer or account cannot run them at all
// (sysexits EX_CONFIG): not a managed computer, an untrusted runtime
// descriptor, root, no home directory, a missing OpenShell install. The
// user units list it in RestartPreventExitStatus=, so systemd never
// restarts them for it.
const sandboxPrerequisiteExit = 78

// runSandboxDaemon runs the daemon. A daemon that cannot reach the managed
// gateway, or whose settings the gateway refuses, does not fail: it answers
// its CLI socket with the reason for a short while and exits 0, so neither
// the service manager nor socket activation restarts it in a loop.
func runSandboxDaemon(ctx context.Context, logw io.Writer) error {
	goos := runtime.GOOS
	if err := openshell.CheckPlatform(goos); err != nil {
		return withExitCode(errors.New("OpenShell sandboxes run on Linux and macOS only"), sandboxPrerequisiteExit)
	}
	if os.Getuid() == 0 {
		return withExitCode(errors.New("the sandbox daemon runs as your own user, not root"), sandboxPrerequisiteExit)
	}
	layout, descriptor, err := sandboxDaemonHost(goos)
	if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
		return withExitCode(errNotStandaloneManaged, sandboxPrerequisiteExit)
	}
	if err != nil {
		return withExitCode(fmt.Errorf("the managed runtime descriptor is not trusted: %w", err), sandboxPrerequisiteExit)
	}
	socketPath, stateDir, err := sandboxDaemonPaths(goos)
	if err != nil {
		return withExitCode(err, sandboxPrerequisiteExit)
	}
	ln, err := sandboxDaemonListener(socketPath)
	if err != nil {
		return err
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(logw, "[sandbox-daemon] "+format+"\n", args...)
	}
	unavailable := func(cause error) error {
		if ctx.Err() != nil {
			_ = ln.Close()
			return nil
		}
		logf("sandboxes cannot run now: %v", cause)
		return gateway.ServeSandboxDaemonUnavailable(ctx, ln, cause)
	}
	hookSocket := descriptor.HookSocket
	if hookSocket == "" {
		hookSocket = layout.HookSocketPath
	}
	var trusted []int
	if descriptor.ServiceUID > 0 {
		trusted = append(trusted, descriptor.ServiceUID)
	}
	relay, err := sandboxrelay.NewClient(sandboxrelay.ClientOptions{SocketPath: hookSocket, TrustedOwners: trusted})
	if err != nil {
		return unavailable(fmt.Errorf("the managed gateway's hook socket: %w", err))
	}
	defer relay.Close()
	settings, err := sandboxDaemonSettings(ctx, relay)
	if err != nil {
		return unavailable(err)
	}
	d, err := gateway.NewSandboxDaemon(gateway.SandboxDaemonOptions{
		RuntimeOptions: gateway.RuntimeOptions{Managed: true, Relay: relay, Settings: &settings},
		StateDir:       stateDir,
		Listener:       ln,
		Logf:           logf,
	})
	if err != nil {
		_ = ln.Close()
		return err
	}
	err = d.Run(ctx)
	if errors.Is(err, gateway.ErrSandboxDaemonRestart) {
		// The service manager starts the new daemon on the next connection.
		return nil
	}
	return err
}

// sandboxDaemonSettings reads the managed settings, waiting briefly for a
// gateway that is still starting.
func sandboxDaemonSettings(ctx context.Context, relay sandboxrelay.Client) (sandboxrelay.DaemonSettings, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		s, err := relay.Settings(ctx)
		if err == nil {
			return s, nil
		}
		var refused *sandboxrelay.Error
		if errors.As(err, &refused) || errors.Is(err, sandboxrelay.ErrSocketUntrusted) || time.Now().After(deadline) {
			return sandboxrelay.DaemonSettings{}, fmt.Errorf("read the managed sandbox settings: %w", err)
		}
		select {
		case <-ctx.Done():
			return sandboxrelay.DaemonSettings{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// sandboxDaemonListener is the CLI socket: the one the systemd socket unit
// passes (FileDescriptorName=sandbox), or one bound at path.
func sandboxDaemonListener(path string) (net.Listener, error) {
	ln, inherited, err := systemd.Listener("sandbox")
	if err != nil {
		return nil, err
	}
	if inherited {
		if _, ok := ln.Addr().(*net.UnixAddr); !ok {
			_ = ln.Close()
			return nil, fmt.Errorf("the socket-activated sandbox listener %s is not a unix socket", ln.Addr())
		}
		return ln, nil
	}
	return gateway.BindSandboxDaemonSocket(path)
}

// sandboxDaemonPaths are this account's daemon socket and state directory:
// Linux $XDG_RUNTIME_DIR/defenseclaw/sandbox.sock and
// ~/.local/state/defenseclaw-sandbox; macOS both under
// ~/Library/Application Support/DefenseClaw Sandbox. Neither is under
// ~/.defenseclaw.
func sandboxDaemonPaths(goos string) (socket, state string, err error) {
	home, err := sandboxAccountHome()
	if err != nil {
		return "", "", err
	}
	socket = sandboxapi.ManagedSocketPath(goos, os.Getuid(), home)
	if socket == "" {
		return "", "", errors.New("sandboxes do not run under this account here")
	}
	return socket, sandboxapi.ManagedStateDir(goos, home), nil
}

// sandboxAccountHome is the account's home directory: the account
// database's, or $HOME for a directory account the pure-Go lookup cannot
// see (CGO_ENABLED=0 release builds read only the local files).
func sandboxAccountHome() (string, error) {
	home := ""
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		home = u.HomeDir
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("your account has no home directory for the sandbox daemon's state")
	}
	return filepath.Clean(home), nil
}

// sandboxDaemonExitedOnItsOwn reports an ExecStop systemd runs after the
// daemon's main process already exited ($MAINPID is empty then).
func sandboxDaemonExitedOnItsOwn(getenv func(string) string) bool {
	return getenv("INVOCATION_ID") != "" && getenv("MAINPID") == ""
}

// sandboxDaemonUnit is the account's sandbox daemon unit (Linux).
const sandboxDaemonUnit = "defenseclaw-sandbox.service"

// sandboxDaemonJobs lists the account's user-manager jobs of unit, a line
// per job ("<id> <unit> <type> <state>"); a seam for tests.
var sandboxDaemonJobs = func(ctx context.Context, unit string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "--user", "list-jobs", "--no-legend", "--no-pager", unit)
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(os.Getuid()))
	}
	out, err := cmd.Output()
	return string(out), err
}

// sandboxDaemonRestarting reports an ExecStop that systemd runs for a
// restart of the sandbox daemon unit: its job is a restart then (a stop at
// logout or `systemctl --user stop` is a stop job), which is the only stop
// that keeps the account's sandboxes. Anything it cannot read is a stop.
func sandboxDaemonRestarting(ctx context.Context) bool {
	if runtime.GOOS != "linux" || os.Getenv("INVOCATION_ID") == "" {
		return false
	}
	out, err := sandboxDaemonJobs(ctx, sandboxDaemonUnit)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[1] == sandboxDaemonUnit && f[2] == "restart" {
			return true
		}
	}
	return false
}

// managedSandboxStopper is what stopping the account's sandboxes needs.
type managedSandboxStopper interface {
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
}

// stopManagedSandboxes stops every sandbox of the account that may be
// running. A daemon that is not running has nothing to stop.
func stopManagedSandboxes(ctx context.Context, c managedSandboxStopper, out io.Writer) error {
	list, err := c.List(ctx)
	if err != nil {
		if sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
			return nil
		}
		return err
	}
	var failed []error
	for _, sb := range list {
		switch audit.SandboxPhase(sb.Phase) {
		case audit.SandboxPhaseProvisioning, audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseUnknown:
		default:
			continue
		}
		if _, err := c.Stop(ctx, sb.Name); err != nil {
			failed = append(failed, fmt.Errorf("stop %s: %w", sb.Name, err))
			continue
		}
		fmt.Fprintf(out, "stopped sandbox %s\n", sb.Name)
	}
	return errors.Join(failed...)
}
