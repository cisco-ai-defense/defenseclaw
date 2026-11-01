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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The user's sandbox daemon is a user unit the package installs (Linux:
// /usr/lib/systemd/user, macOS: /Library/LaunchAgents) and the lifecycle
// enables for every account. An account that was already signed in when the
// package arrived has not started it, so the launcher starts it on demand,
// and applies a daemon update the lifecycle deferred while sandboxes ran.
const (
	launcherSocketUnit    = "defenseclaw-sandbox.socket"
	launcherServiceUnit   = "defenseclaw-sandbox.service"
	launcherRepairCommand = "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos repair"

	launcherSystemctl = "/usr/bin/systemctl"
	launcherLaunchctl = "/bin/launchctl"
)

// launcherAgentsDir holds the LaunchAgent plists; a var for tests.
var launcherAgentsDir = openshell.LaunchAgentsDir

// launcherAgent is the installed sandbox daemon job: its label carries the
// gateway program's tag (openshell.LaunchAgentLabel).
func launcherAgent() (label, plist string) {
	return openshell.FindLaunchAgent(launcherAgentsDir, openshell.SandboxAgentBase)
}

// Waits for the daemon; vars so tests run at speed.
var (
	// launcherProbeTimeout covers one status request, which on Linux can
	// include socket activation and the daemon's first settings fetch.
	launcherProbeTimeout = 15 * time.Second
	// launcherStartWait is how long a started daemon has to answer.
	launcherStartWait = 15 * time.Second
	launcherPollEvery = 250 * time.Millisecond
)

// launcherRun runs one service-manager command and returns its combined
// output; a seam for tests.
var launcherRun = func(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = launcherServiceEnv(os.Environ(), os.Getuid())
	out, err := command.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// launcherServiceEnv gives `systemctl --user` the runtime directory it finds
// the user's manager by when the login did not export one (su, sudo -u).
func launcherServiceEnv(env []string, uid int) []string {
	for _, entry := range env {
		if strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
			return env
		}
	}
	dir := "/run/user/" + strconv.Itoa(uid)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return env
	}
	return append(env, "XDG_RUNTIME_DIR="+dir)
}

// launcherStatusClient is the part of the daemon client the launcher uses.
type launcherStatusClient interface {
	Status(ctx context.Context) (*sandboxapi.Status, error)
}

// launcherEnsureDaemon makes sure the caller's sandbox daemon answers: it
// starts the daemon when it does not, and restarts one that waits for a
// restart while no sandbox of the caller runs. It returns the daemon's latest
// status (nil when it could not be reached) and why it could not be reached.
func launcherEnsureDaemon(ctx context.Context, client launcherStatusClient, goos string, uid int, stderr io.Writer) (*sandboxapi.Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	status, err := launcherProbe(ctx, client, launcherProbeTimeout)
	if err != nil {
		if startErr := launcherStartDaemon(ctx, goos, uid); startErr != nil {
			return nil, fmt.Errorf("your sandbox service is not running and could not be started: %v", startErr)
		}
		if status, err = launcherAwaitWithRecovery(ctx, client, goos, uid); err != nil {
			var reloadErr *launcherDaemonError
			if errors.As(err, &reloadErr) {
				return nil, err
			}
			return nil, &launcherDaemonError{msg: "your sandbox service was started but does not answer; `defenseclaw sandbox doctor` shows why", err: err}
		}
	}
	// Busy, not Running: the restart takes the account's OpenShell gateway
	// with it, which a MicroVM in OpenShell's error state, or a sandbox
	// that starts, may still run on (sandboxapi.Status.Live).
	if status.Managed != nil && status.Managed.PendingRestart && status.Busy() == 0 {
		fmt.Fprintln(stderr, "defenseclaw: restarting your sandbox service to apply an update (no sandbox of yours is running)")
		if err := launcherRestartDaemon(ctx, goos, uid); err != nil {
			return status, fmt.Errorf("your sandbox service waits for a restart that failed: %v", err)
		}
		restarted, err := launcherAwaitWithRecovery(ctx, client, goos, uid)
		if err != nil {
			var reloadErr *launcherDaemonError
			if errors.As(err, &reloadErr) {
				return nil, err
			}
			return nil, &launcherDaemonError{msg: "your sandbox service was restarted but does not answer; `defenseclaw sandbox doctor` shows why", err: err}
		}
		status = restarted
	}
	return status, nil
}

// launcherDaemonError is a sentence for the person about a sandbox service
// that does not answer. The transport error it wraps names the daemon's
// internal URL ("Get http://sandbox-daemon/api/v1/sandbox/status: context
// deadline exceeded"), which tells the person nothing; `sandbox doctor`
// has the detail (#1202).
type launcherDaemonError struct {
	msg string
	err error
}

func (e *launcherDaemonError) Error() string { return e.msg }
func (e *launcherDaemonError) Unwrap() error { return e.err }

// launcherProbe asks the daemon for its status within timeout.
func launcherProbe(ctx context.Context, client launcherStatusClient, timeout time.Duration) (*sandboxapi.Status, error) {
	probe, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return client.Status(probe)
}

// launcherAwait polls the daemon until it answers or launcherStartWait ends.
func launcherAwait(ctx context.Context, client launcherStatusClient) (*sandboxapi.Status, error) {
	deadline := time.Now().Add(launcherStartWait)
	for {
		status, err := launcherProbe(ctx, client, launcherPollEvery*4)
		if err == nil {
			return status, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(err, ctx.Err())
		case <-time.After(launcherPollEvery):
		}
	}
}

// launcherStartDaemon starts the caller's sandbox daemon through the user
// service manager of the operating system.
func launcherStartDaemon(ctx context.Context, goos string, uid int) error {
	switch goos {
	case "linux":
		// The socket unit holds the daemon's socket; a connection to it starts
		// the service.
		return launcherRunChecked(ctx, launcherSystemctl, "--user", "start", launcherSocketUnit)
	case "darwin":
		domain, listing := launcherLaunchDomain(ctx, uid)
		label, _ := launcherAgent()
		if _, err := launcherInspectAndReload(ctx, domain, listing, true, false); err != nil {
			return err
		}
		return launcherRunChecked(ctx, launcherLaunchctl, "kickstart", domain+"/"+label)
	}
	return fmt.Errorf("sandboxes run on Linux and macOS only")
}

// launcherRestartDaemon restarts the caller's sandbox daemon.
func launcherRestartDaemon(ctx context.Context, goos string, uid int) error {
	switch goos {
	case "linux":
		return launcherRunChecked(ctx, launcherSystemctl, "--user", "restart", launcherServiceUnit)
	case "darwin":
		domain, listing := launcherLaunchDomain(ctx, uid)
		label, _ := launcherAgent()
		if _, err := launcherInspectAndReload(ctx, domain, listing, false, true); err != nil {
			return err
		}
		return launcherRunChecked(ctx, launcherLaunchctl, "kickstart", "-k", domain+"/"+label)
	}
	return fmt.Errorf("sandboxes run on Linux and macOS only")
}

// launcherInspectAndReload refreshes only loaded failed DefenseClaw jobs in
// the caller's selected launchd domain. A missing sandbox job is bootstrapped
// on first start, as before; a missing gateway job is left to its daemon.
// A job of an earlier label that does not run is booted out first: its
// plist is gone, and the sandbox job of the current label is bootstrapped in
// its place (GAP-0206). One that runs is left to the lifecycle, which stops
// it when its sandboxes have stopped. listing is `launchctl print domain`.
//
// With restart (the daemon waits for a restart and no sandbox of the
// account runs: launcherEnsureDaemon), a sandbox job of an earlier label
// that runs is the daemon to restart when the installed label is not
// loaded: a package upgrade renamed the job while that daemon ran a
// sandbox, and a kickstart of the installed label found no job ("Could not
// find service", GAP-0049). It is booted out and the installed label is
// bootstrapped in its place, as its own exit and the next start would.
func launcherInspectAndReload(ctx context.Context, domain, listing string, bootstrapSandbox, restart bool) (bool, error) {
	reloaded := false
	for _, base := range openshell.LaunchAgentBases {
		label, plist := openshell.FindLaunchAgent(launcherAgentsDir, base)
		sandbox := base == openshell.SandboxAgentBase
		var runningOld []string
		for _, old := range openshell.LaunchAgentLabelsIn([]byte(listing), base) {
			if old == label {
				continue
			}
			out, err := launcherRun(ctx, launcherLaunchctl, "print", domain+"/"+old)
			if err != nil {
				continue
			}
			if openshell.ParseLaunchAgentState([]byte(out)).State == "running" {
				runningOld = append(runningOld, old)
				continue
			}
			_, _ = launcherRun(ctx, launcherLaunchctl, "bootout", domain+"/"+old)
			bootstrapSandbox = bootstrapSandbox || sandbox
		}
		target := domain + "/" + label
		out, err := launcherRun(ctx, launcherLaunchctl, "print", target)
		if err != nil {
			if restart && sandbox {
				for _, old := range runningOld {
					_, _ = launcherRun(ctx, launcherLaunchctl, "bootout", domain+"/"+old)
				}
			}
			if (bootstrapSandbox || restart) && sandbox {
				if err := launcherRunChecked(ctx, launcherLaunchctl, "bootstrap", domain, plist); err != nil {
					return false, err
				}
			}
			continue
		}
		if openshell.ParseLaunchAgentState([]byte(out)).Failure(false) == "" {
			continue
		}
		// A failed bootout may mean the job has already exited. Bootstrap
		// decides whether the account can recover it.
		_, _ = launcherRun(ctx, launcherLaunchctl, "bootout", target)
		if err := launcherRunChecked(ctx, launcherLaunchctl, "bootstrap", domain, plist); err != nil {
			return false, &launcherDaemonError{msg: "your DefenseClaw LaunchAgent could not be reloaded; run `" + launcherRepairCommand + "`", err: err}
		}
		reloaded = true
	}
	return reloaded, nil
}

// launcherAwaitWithRecovery checks for a code-signing kill that appeared only
// after the first kickstart. It makes one reload attempt and one retry.
func launcherAwaitWithRecovery(ctx context.Context, client launcherStatusClient, goos string, uid int) (*sandboxapi.Status, error) {
	status, awaitErr := launcherAwait(ctx, client)
	if awaitErr == nil || goos != "darwin" {
		return status, awaitErr
	}
	domain, listing := launcherLaunchDomain(ctx, uid)
	reloaded, err := launcherInspectAndReload(ctx, domain, listing, false, false)
	if err != nil {
		return nil, err
	}
	if !reloaded {
		return nil, awaitErr
	}
	label, _ := launcherAgent()
	if err := launcherRunChecked(ctx, launcherLaunchctl, "kickstart", domain+"/"+label); err != nil {
		return nil, err
	}
	return launcherAwait(ctx, client)
}

// launcherLaunchDomain is the launchd domain of the caller's sandbox agent
// (openshell.LaunchDomain): the one its job is loaded in, else the
// graphical session when the caller has one (the agent allows Aqua and
// Background sessions), else the background session of an ssh login. It
// also returns what `launchctl print` said of the domain, which lists the
// jobs loaded there.
func launcherLaunchDomain(ctx context.Context, uid int) (domain, listing string) {
	label, _ := launcherAgent()
	return openshell.LaunchDomain(uid, openshell.SandboxAgentBase, label, func(domain string) (string, error) {
		return launcherRun(ctx, launcherLaunchctl, "print", domain)
	})
}

// launcherRunChecked runs a service-manager command and folds its output
// into the error.
func launcherRunChecked(ctx context.Context, name string, args ...string) error {
	out, err := launcherRun(ctx, name, args...)
	if err == nil {
		return nil
	}
	if out != "" {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), firstLine(out))
	}
	return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
}

// firstLine is the first line of s.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}
