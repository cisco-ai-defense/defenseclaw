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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The user's sandbox daemon is a user unit the package installs (Linux:
// /usr/lib/systemd/user, macOS: /Library/LaunchAgents) and the lifecycle
// enables for every account. An account that was already signed in when the
// package arrived has not started it, so the launcher starts it on demand,
// and applies a daemon update the lifecycle deferred while sandboxes ran.
const (
	launcherSocketUnit  = "defenseclaw-sandbox.socket"
	launcherServiceUnit = "defenseclaw-sandbox.service"
	launcherAgentLabel  = "com.cisco.defenseclaw.sandbox"
	launcherAgentPlist  = "/Library/LaunchAgents/com.cisco.defenseclaw.sandbox.plist"

	launcherSystemctl = "/usr/bin/systemctl"
	launcherLaunchctl = "/bin/launchctl"
)

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
		if status, err = launcherAwait(ctx, client); err != nil {
			return nil, fmt.Errorf("your sandbox service was started but does not answer: %v; `defenseclaw sandbox doctor` shows why", err)
		}
	}
	if status.Managed != nil && status.Managed.PendingRestart && status.Running == 0 {
		fmt.Fprintln(stderr, "defenseclaw: restarting your sandbox service to apply an update (no sandbox of yours is running)")
		if err := launcherRestartDaemon(ctx, goos, uid); err != nil {
			return status, fmt.Errorf("your sandbox service waits for a restart that failed: %v", err)
		}
		restarted, err := launcherAwait(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("your sandbox service was restarted but does not answer: %v; `defenseclaw sandbox doctor` shows why", err)
		}
		status = restarted
	}
	return status, nil
}

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
		domain := launcherLaunchDomain(ctx, uid)
		target := domain + "/" + launcherAgentLabel
		if _, err := launcherRun(ctx, launcherLaunchctl, "print", target); err != nil {
			if err := launcherRunChecked(ctx, launcherLaunchctl, "bootstrap", domain, launcherAgentPlist); err != nil {
				return err
			}
		}
		return launcherRunChecked(ctx, launcherLaunchctl, "kickstart", target)
	}
	return fmt.Errorf("sandboxes run on Linux and macOS only")
}

// launcherRestartDaemon restarts the caller's sandbox daemon.
func launcherRestartDaemon(ctx context.Context, goos string, uid int) error {
	switch goos {
	case "linux":
		return launcherRunChecked(ctx, launcherSystemctl, "--user", "restart", launcherServiceUnit)
	case "darwin":
		return launcherRunChecked(ctx, launcherLaunchctl, "kickstart", "-k", launcherLaunchDomain(ctx, uid)+"/"+launcherAgentLabel)
	}
	return fmt.Errorf("sandboxes run on Linux and macOS only")
}

// launcherLaunchDomain is the launchd domain of the caller's sandbox agent:
// the graphical session when the caller has one (the agent allows Aqua and
// Background sessions), else the background session of an ssh login.
func launcherLaunchDomain(ctx context.Context, uid int) string {
	gui := "gui/" + strconv.Itoa(uid)
	if _, err := launcherRun(ctx, launcherLaunchctl, "print", gui); err == nil {
		return gui
	}
	return "user/" + strconv.Itoa(uid)
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
