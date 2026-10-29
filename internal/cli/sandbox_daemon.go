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
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// sandboxDaemonCmd runs this account's sandbox daemon on a standalone
// managed computer: the user unit defenseclaw-sandbox.service (Linux,
// socket-activated) or the LaunchAgent com.cisco.defenseclaw.sandbox.<tag>
// (macOS, bootstrapped on demand by the launcher; openshell.LaunchAgentLabel).
// It runs as the user and takes no config file: the managed gateway's hook
// socket gives it its settings and judges everything its sandboxes do.
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

// sandboxDaemonSyncGateway is sync-sandboxes' --gateway, and
// sandboxDaemonSyncManaged its --managed.
var (
	sandboxDaemonSyncGateway string
	sandboxDaemonSyncManaged bool
)

// sandboxDaemonSyncCmd is the ExecStop DefenseClaw gives the OpenShell
// gateway service of a per-user gateway on the MicroVM driver (a systemd
// drop-in setup writes, openshell.StopSync) and, with --managed, the
// managed gateway unit of a standalone managed computer
// (defenseclaw-openshell-gateway.service, after stop-sandboxes): a stop or
// restart of the gateway ends every MicroVM on it, so it first syncs the
// disk of each one OpenShell lists ready, whoever started it and whoever
// stops the gateway (GAP-0380). The managed unit's stop-sandboxes stops
// only the sandboxes the account's daemon knows, as they were when it
// listed them: a sandbox a raw openshell client created, or started after
// that list, is still running when the gateway stops. It runs as the
// account, under the user manager.
var sandboxDaemonSyncCmd = &cobra.Command{
	Use:          "sync-sandboxes",
	Short:        "Sync each running MicroVM's disk before the OpenShell gateway stops (the gateway service's ExecStop)",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), openshell.StopSyncTimeout)
		defer cancel()
		opts := openshell.DiscoverOptions{Gateway: sandboxDaemonSyncGateway}
		dataDir := config.DefaultDataPath()
		if sandboxDaemonSyncManaged {
			target, err := managedStopSyncTarget(ctx, runtime.GOOS, sandboxOpenShellDaemonSettings)
			if err != nil {
				return err
			}
			if opts.Gateway == "" {
				opts.Gateway = target.gateway
			}
			dataDir = target.dataDir
		}
		err := openshell.SyncGatewaySandboxes(ctx, opts, cmd.OutOrStdout())
		// The gateway's stop ends each one it could not sync: the next
		// sandbox daemon's feed says what may be lost (stop_unflushed),
		// not only this unit's journal (GAP-2081). A managed account's
		// daemon reads its own state directory, not ~/.defenseclaw.
		if names := openshell.UnsyncedSandboxes(err); len(names) > 0 {
			if rerr := manager.RecordUnsyncedStops(dataDir, names, time.Now()); rerr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "could not record the unsynced stop for the sandbox feed: %v\n", rerr)
			}
		}
		return err
	},
}

// stopSyncTarget is what a managed gateway unit's stop sync dials and where
// it notes a sandbox it could not sync.
type stopSyncTarget struct {
	gateway string // the registration the account's daemon uses
	dataDir string // the account's sandbox daemon state directory
}

// managedStopSyncSettingsWait bounds the read of the managed settings in a
// stop: a managed gateway that does not answer leaves the default name.
const managedStopSyncSettingsWait = 5 * time.Second

// managedStopSyncTarget resolves the registration the account's sandbox
// daemon registered its managed gateway under (openshell.gateway.name of
// the managed settings, openshell.DefaultGatewayName when unset or when the
// managed gateway does not answer) and the daemon's state directory, whose
// feed reads RecordUnsyncedStops' file.
func managedStopSyncTarget(ctx context.Context, goos string, settings func(context.Context) (sandboxrelay.DaemonSettings, bool)) (stopSyncTarget, error) {
	_, state, err := sandboxDaemonPaths(goos)
	if err != nil {
		return stopSyncTarget{}, err
	}
	t := stopSyncTarget{gateway: openshell.DefaultGatewayName, dataDir: state}
	sctx, cancel := context.WithTimeout(ctx, managedStopSyncSettingsWait)
	defer cancel()
	if s, ok := settings(sctx); ok && s.Operational.GatewayName != "" {
		t.gateway = s.Operational.GatewayName
	}
	return t, nil
}

// sandboxDaemonDrainCmd is what the managed lifecycle runs as the account
// right before it stops the account's sandbox daemon and OpenShell gateway
// for a waiting change (a switch of its OpenShell setup, a stop, a
// LaunchAgent reload): the lifecycle's status check came earlier, and a
// sandbox started and ended since would be stopped with the gateway, its
// MicroVM with no flush. It takes the account's lifecycle lock
// (openshell.LockGatewayLifecycle), which keeps the account's DefenseClaw
// from creating or starting a sandbox, checks under it
// (openshell.CheckAccountGateways), prints openshell.LifecycleDrained, and
// holds the lock until its standard input ends: the lifecycle closes it
// once the units are stopped. It exits non-zero, holding nothing, when the
// check refuses.
var sandboxDaemonDrainCmd = &cobra.Command{
	Use:          "drain",
	Short:        "Hold this account's OpenShell gateway for the managed lifecycle's stop",
	Hidden:       true,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if os.Getuid() == 0 {
			return errors.New("the drain runs as the account whose gateway stops, not root")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return drainAccountGateway(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), sandboxDrain{
			lock:  func(ctx context.Context) (func(), error) { return openshell.LockGatewayLifecycle(ctx, "") },
			check: func(ctx context.Context) error { return openshell.CheckAccountGateways(ctx, sandboxDrainMicroVMs) },
			hold:  sandboxDrainHold,
		})
	},
}

// sandboxDrainMicroVMs counts the MicroVMs that run as this account; a seam
// for tests.
var sandboxDrainMicroVMs openshell.VMCount = func(ctx context.Context) (int, error) {
	return openshell.CountMicroVMs(ctx, openshell.ExecRunner{})
}

// sandboxDrainHold bounds how long a drain holds the lock when the
// lifecycle never closes its input: longer than the unit stops it covers.
var sandboxDrainHold = 15 * time.Minute

// sandboxDrain is what a drain needs.
type sandboxDrain struct {
	lock  func(context.Context) (unlock func(), err error)
	check func(context.Context) error
	hold  time.Duration
}

// drainAccountGateway takes the lock, checks under it and, when nothing
// would be lost, prints openshell.LifecycleDrained and holds the lock until
// in ends, ctx ends or d.hold passes.
func drainAccountGateway(ctx context.Context, in io.Reader, out io.Writer, d sandboxDrain) error {
	unlock, err := d.lock(ctx)
	if err != nil {
		return fmt.Errorf("hold this account's OpenShell gateway: %w", err)
	}
	defer unlock()
	if err := d.check(ctx); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, openshell.LifecycleDrained); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, in)
		close(done)
	}()
	t := time.NewTimer(d.hold)
	defer t.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("let the OpenShell gateway lifecycle go after %s: the managed lifecycle never said its stop was done", d.hold)
	}
}

func init() {
	sandboxDaemonCmd.AddCommand(sandboxDaemonStopCmd)
	sandboxDaemonSyncCmd.Flags().StringVar(&sandboxDaemonSyncGateway, "gateway", "", "the OpenShell gateway registration (default: the openshell CLI's active one)")
	sandboxDaemonSyncCmd.Flags().BoolVar(&sandboxDaemonSyncManaged, "managed", false, "the managed gateway unit's stop: the registration and state directory of the account's sandbox daemon")
	sandboxDaemonCmd.AddCommand(sandboxDaemonSyncCmd)
	sandboxDaemonCmd.AddCommand(sandboxDaemonDrainCmd)
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

// stopUnsyncedBudget bounds how long stopManagedSandboxes tries again the
// stop of a MicroVM whose disk could not be synced, and stopUnsyncedPause
// is the pause between tries: within the gateway unit's TimeoutStopSec (2
// minutes), after which systemd ends the gateway, and the VM with it.
var (
	stopUnsyncedBudget = 90 * time.Second
	stopUnsyncedPause  = 5 * time.Second
)

// stopManagedSandboxes stops every sandbox of the account that may be
// running. A daemon that is not running has nothing to stop. The daemon
// does not stop a MicroVM whose disk it could not sync first
// (sandboxapi.CodeUnsynced, GAP-0902), but what this runs for (a sign-out,
// a stop of the gateway unit) ends the gateway next, and the VM with it
// (GAP-0998): its stop, which syncs first, is tried again while there is
// time, and one still unsynced is named with what it may lose.
func stopManagedSandboxes(ctx context.Context, c managedSandboxStopper, out io.Writer) error {
	list, err := c.List(ctx)
	if err != nil {
		if sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
			return nil
		}
		return err
	}
	var failed []error
	var unsynced []string
	stop := func(name string) {
		if _, err := c.Stop(ctx, name); err != nil {
			if sandboxapi.IsCode(err, sandboxapi.CodeUnsynced) {
				unsynced = append(unsynced, name)
				return
			}
			failed = append(failed, fmt.Errorf("stop %s: %w", name, err))
			return
		}
		fmt.Fprintf(out, "stopped sandbox %s\n", name)
	}
	for _, sb := range list {
		switch audit.SandboxPhase(sb.Phase) {
		case audit.SandboxPhaseProvisioning, audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseUnknown:
		default:
			continue
		}
		stop(sb.Name)
	}
	deadline := time.Now().Add(stopUnsyncedBudget)
	for len(unsynced) > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(stopUnsyncedPause):
		}
		again := unsynced
		unsynced = nil
		for _, name := range again {
			stop(name)
		}
	}
	for _, name := range unsynced {
		failed = append(failed, fmt.Errorf("sandbox %s keeps running: its MicroVM's disk could not be synced, so DefenseClaw did not stop it; "+
			"what stops its OpenShell gateway now (a sign-out, a stop of the gateway unit) ends the VM, and what its guest wrote since its last sync may be lost", name))
	}
	return errors.Join(failed...)
}
