// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Per-account sandbox lifecycle. The sandbox daemon, the account's OpenShell
// gateway and its sandboxes belong to the account, not to the deployment, so
// the lifecycle never stops one that runs a sandbox (spec D3): a change that
// needs a restart waits ("pending") until the account has no sandbox running,
// and is applied by the next lifecycle run that finds it idle. Everything the
// lifecycle does in an account runs as that account (runuser, sudo -u) or, for
// files, through descriptors that do not follow links and check the owner.

// Bounds on what runs as an account: the lifecycle holds its lock meanwhile,
// and the commands talk to processes the account controls.
const (
	userCommandTimeout = 30 * time.Second
	teardownTimeout    = 15 * time.Minute
	// stopSandboxesTimeout bounds `sandbox-daemon stop-sandboxes`, which
	// bounds itself at five minutes.
	stopSandboxesTimeout = 6 * time.Minute
)

// SandboxAccount is an account the sandbox lifecycle acts on.
type SandboxAccount struct {
	Name     string
	UID, GID int
	Home     string
}

// SandboxStatus is what an account's sandbox daemon reports.
type SandboxStatus struct {
	// Active says the account's sandbox daemon runs (or ran when its OpenShell
	// gateway did, and was started to count the sandboxes).
	Active bool
	// Running is the number of sandboxes that run.
	Running int
	// PendingRestart is the daemon's own report that it waits for a restart.
	PendingRestart bool
	// StartedAt is when the daemon started (zero when it does not say).
	StartedAt time.Time
}

// SandboxUserOps is how the lifecycle acts in accounts. Env.SandboxUsers
// replaces the command-based implementation in tests.
type SandboxUserOps interface {
	// Accounts lists the accounts that may have a sandbox daemon, OpenShell
	// files or sandboxes of their own: the enrolled accounts and every
	// account the sandbox registration store knows.
	Accounts(ctx context.Context) []SandboxAccount
	// LoggedIn lists the accounts whose user service manager runs (Linux).
	LoggedIn(ctx context.Context) []SandboxAccount
	// Status asks the account's daemon. An error means the lifecycle cannot
	// tell whether a sandbox runs, which it treats as running.
	Status(ctx context.Context, a SandboxAccount) (SandboxStatus, error)
	// Stop stops the account's units. Stopping the daemon stops the
	// account's sandboxes first (its ExecStop), so callers only stop an
	// account without running sandboxes.
	Stop(ctx context.Context, a SandboxAccount, scope StopScope) error
	// Reload makes the account's user manager read new unit files (Linux).
	Reload(ctx context.Context, a SandboxAccount) error
	// StopSandboxes stops the account's running sandboxes through its
	// sandbox daemon, as the daemon unit's ExecStop does at logout (a
	// MicroVM's disk is synced before its stop), and names the ones it
	// stopped. The sandboxes, their records and their work stay.
	StopSandboxes(ctx context.Context, a SandboxAccount) ([]string, error)
	// Teardown runs `defenseclaw sandbox teardown` as the account, which
	// deletes its sandboxes with their work, providers, profiles and
	// images: only a purge runs it.
	Teardown(ctx context.Context, a SandboxAccount) error
	// Groups lists the account's groups.
	Groups(ctx context.Context, a SandboxAccount) ([]string, error)
}

// StopScope selects the units Stop stops.
type StopScope int

const (
	// StopDaemon stops the sandbox daemon only; its socket keeps listening
	// and the launcher starts the daemon again on the next command.
	StopDaemon StopScope = 1 << iota
	// StopGateway stops the account's OpenShell gateway unit (setup mode).
	StopGateway
	// StopSocket stops the daemon's socket (Linux).
	StopSocket
)

func (e *Env) sandboxOps() SandboxUserOps {
	if e.SandboxUsers != nil {
		return e.SandboxUsers
	}
	return &commandUserOps{env: e}
}

// Where an account keeps what the sandbox subsystem created, relative to its
// home.
func (e *Env) daemonStateRel() string {
	if e.GOOS == "darwin" {
		return "Library/Application Support/DefenseClaw Sandbox"
	}
	return ".local/state/defenseclaw-sandbox"
}

const (
	openshellStateRel   = ".local/state/openshell"
	openshellVMStateRel = ".local/state/openshell/vm-driver"
	openshellShareRel   = ".local/share/openshell"
	installStateRel     = openshell.TarballStateDir
	// userSandboxDataRel is the sandbox CLI's data below ~/.defenseclaw.
	userSandboxDataRel = ".defenseclaw/sandboxes"
)

// tarballRels are the only files the tarball install places, relative to the
// home.
var tarballRels = []string{".local/bin/openshell", ".local/bin/openshell-gateway", ".local/libexec/openshell/openshell-driver-vm"}

// ---------------------------------------------------------------------------
// The command-based implementation.

type commandUserOps struct {
	env *Env
}

// runAs runs argv as the account.
func (o *commandUserOps) runAs(ctx context.Context, a SandboxAccount, timeout time.Duration, argv ...string) (CommandResult, error) {
	e := o.env
	uid := strconv.Itoa(a.UID)
	if e.GOOS == "darwin" {
		args := append([]string{"-n", "-u", a.Name, "-H", "/usr/bin/env", "HOME=" + a.Home}, argv...)
		return e.longRunner(timeout).Run(ctx, "sudo", args...)
	}
	args := append([]string{"-u", a.Name, "--", "/usr/bin/env", "HOME=" + a.Home, "XDG_RUNTIME_DIR=/run/user/" + uid,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus"}, argv...)
	return e.longRunner(timeout).Run(ctx, "runuser", args...)
}

// longRunner is the runner with a longer bound for commands that can take
// minutes (teardown removes images).
func (e *Env) longRunner(timeout time.Duration) Runner {
	if runner, ok := e.Runner.(ExecRunner); ok {
		runner.Timeout = timeout
		return runner
	}
	return e.Runner
}

// domain is the launchd domain of the account's sandbox agent.
func (o *commandUserOps) domain(ctx context.Context, a SandboxAccount) string {
	gui := "gui/" + strconv.Itoa(a.UID)
	if _, err := o.env.Runner.Run(ctx, "launchctl", "print", gui); err == nil {
		return gui
	}
	return "user/" + strconv.Itoa(a.UID)
}

// usableSandboxAccount reports whether a is an account the lifecycle acts in:
// a real user (never root or the service account) with an absolute home that
// is not the root folder.
func (e *Env) usableSandboxAccount(a SandboxAccount) bool {
	return a.UID > 0 && plainAccountName(a.Name) && a.Name != e.Layout.ServiceUser && filepath.IsAbs(a.Home) && filepath.Clean(a.Home) != "/"
}

func (o *commandUserOps) Accounts(ctx context.Context) []SandboxAccount {
	e := o.env
	seen := map[int]bool{}
	var out []SandboxAccount
	add := func(a SandboxAccount) {
		if seen[a.UID] || !e.usableSandboxAccount(a) {
			return
		}
		seen[a.UID] = true
		out = append(out, a)
	}
	for _, enrolled := range e.sessionFactsAccounts() {
		add(SandboxAccount{Name: enrolled.user, UID: enrolled.uid, Home: enrolled.home, GID: -1})
	}
	for _, dir := range []string{"registrations", "decisions"} {
		entries, err := os.ReadDir(e.P(filepath.Join(e.Layout.DataDir, "sandbox", dir)))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			uid, err := strconv.Atoi(strings.TrimSuffix(entry.Name(), ".json"))
			if err != nil || seen[uid] {
				continue
			}
			if a, ok := o.lookupUID(ctx, uid); ok {
				add(a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// lookupUID resolves an account by uid through the host's account database.
func (o *commandUserOps) lookupUID(ctx context.Context, uid int) (SandboxAccount, bool) {
	e := o.env
	if e.GOOS == "darwin" {
		res, err := e.Runner.Run(ctx, "dscl", ".", "-search", "/Users", "UniqueID", strconv.Itoa(uid))
		if err != nil {
			return SandboxAccount{}, false
		}
		name, _, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), "\t")
		name = strings.TrimSpace(name)
		if name == "" || !plainAccountName(name) {
			return SandboxAccount{}, false
		}
		home, err := e.Runner.Run(ctx, "dscl", ".", "-read", "/Users/"+name, "NFSHomeDirectory")
		if err != nil {
			return SandboxAccount{}, false
		}
		fields := strings.Fields(string(home.Stdout))
		if len(fields) < 2 {
			return SandboxAccount{}, false
		}
		return SandboxAccount{Name: name, UID: uid, GID: -1, Home: fields[len(fields)-1]}, true
	}
	res, err := e.Runner.Run(ctx, "getent", "passwd", strconv.Itoa(uid))
	if err != nil {
		return SandboxAccount{}, false
	}
	fields := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(fields) < 7 || !plainAccountName(fields[0]) {
		return SandboxAccount{}, false
	}
	gid, _ := strconv.Atoi(fields[3])
	return SandboxAccount{Name: fields[0], UID: uid, GID: gid, Home: fields[5]}, true
}

func (o *commandUserOps) LoggedIn(ctx context.Context) []SandboxAccount {
	if o.env.GOOS != "linux" {
		return nil
	}
	res, err := o.env.Runner.Run(ctx, "loginctl", "list-users", "--no-legend")
	if err != nil {
		return nil
	}
	var out []SandboxAccount
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil || uid <= 0 || fields[1] == o.env.Layout.ServiceUser {
			continue
		}
		if a, ok := o.lookupUID(ctx, uid); ok {
			out = append(out, a)
		}
	}
	return out
}

func (o *commandUserOps) Status(ctx context.Context, a SandboxAccount) (SandboxStatus, error) {
	e := o.env
	var st SandboxStatus
	st.Active = o.unitRunning(ctx, a, userUnitSandboxService, labelSandbox)
	if !st.Active {
		// A daemon that is not running does not mean no sandbox runs: it
		// crashed, was killed or (macOS) left when idle, and the account's
		// OpenShell gateway unit (setup mode) keeps hosting its sandboxes.
		// The launcher starts the daemon on demand and the daemon counts what
		// the gateway runs, so ask it; only an account with neither is idle.
		if !o.unitRunning(ctx, a, userUnitGatewayService, labelOpenShellGateway) {
			return st, nil
		}
	}
	res, err := o.runAs(ctx, a, userCommandTimeout, e.launcherPath(), "sandbox", "status", "--output", "json")
	if err != nil {
		return st, fmt.Errorf("ask the sandbox daemon of %s: %w", a.Name, err)
	}
	var reply struct {
		Running   int       `json:"running"`
		StartedAt time.Time `json:"started_at"`
		Managed   *struct {
			PendingRestart bool `json:"pending_restart"`
		} `json:"managed"`
	}
	if err := json.Unmarshal(res.Stdout, &reply); err != nil {
		return st, fmt.Errorf("read the sandbox status of %s: %w", a.Name, err)
	}
	// The launcher's command started the daemon when the gateway ran without
	// one.
	st.Active = true
	st.Running = reply.Running
	st.StartedAt = reply.StartedAt
	st.PendingRestart = reply.Managed != nil && reply.Managed.PendingRestart
	return st, nil
}

// unitRunning reports whether the account's user unit (systemd) or agent
// (launchd) is running.
func (o *commandUserOps) unitRunning(ctx context.Context, a SandboxAccount, unit, label string) bool {
	if o.env.GOOS == "darwin" {
		res, err := o.env.Runner.Run(ctx, "launchctl", "print", o.domain(ctx, a)+"/"+label)
		return err == nil && strings.Contains(string(res.Stdout), "state = running")
	}
	res, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "is-active", unit)
	return err == nil && strings.TrimSpace(string(res.Stdout)) == "active"
}

func (o *commandUserOps) Stop(ctx context.Context, a SandboxAccount, scope StopScope) error {
	e := o.env
	if e.GOOS == "darwin" {
		domain := o.domain(ctx, a)
		var errs []error
		for _, item := range []struct {
			label string
			scope StopScope
		}{{labelSandbox, StopDaemon | StopSocket}, {labelOpenShellGateway, StopGateway}} {
			if scope&item.scope == 0 {
				continue
			}
			res, err := e.Runner.Run(ctx, "launchctl", "bootout", domain+"/"+item.label)
			// An agent that is not loaded is stopped already.
			if err != nil && !launchdNotLoaded(err) && !strings.Contains(string(res.Stderr), "Could not find") && !strings.Contains(string(res.Stderr), "No such process") {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	var units []string
	if scope&StopSocket != 0 {
		units = append(units, userUnitSandboxSocket)
	}
	if scope&StopDaemon != 0 {
		units = append(units, userUnitSandboxService)
	}
	if scope&StopGateway != 0 {
		units = append(units, userUnitGatewayService)
	}
	if len(units) == 0 {
		return nil
	}
	if _, err := o.runAs(ctx, a, userCommandTimeout, append([]string{"/usr/bin/systemctl", "--user", "stop"}, units...)...); err != nil {
		// A user manager that is not running has nothing to stop.
		if res, serr := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "is-active", userUnitSandboxService); serr != nil && strings.TrimSpace(string(res.Stdout)) != "active" {
			return nil
		}
		return err
	}
	return nil
}

func (o *commandUserOps) Reload(ctx context.Context, a SandboxAccount) error {
	if o.env.GOOS != "linux" {
		return nil
	}
	_, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "daemon-reload")
	return err
}

func (o *commandUserOps) Teardown(ctx context.Context, a SandboxAccount) error {
	res, err := o.runAs(ctx, a, teardownTimeout, o.env.launcherPath(), "sandbox", "teardown", "--yes")
	if err == nil || res.ExitCode <= 0 {
		return err
	}
	return fmt.Errorf("`defenseclaw sandbox teardown` exited %d: %s", res.ExitCode, commandReason(res))
}

// StopSandboxes runs the daemon unit's ExecStop as the account. It goes
// without INVOCATION_ID: a lifecycle run that systemd started passes its own
// on, and the command then takes itself for the ExecStop of a daemon that
// exited by itself, which stops nothing.
func (o *commandUserOps) StopSandboxes(ctx context.Context, a SandboxAccount) ([]string, error) {
	res, err := o.runAs(ctx, a, stopSandboxesTimeout, "/usr/bin/env", "-u", "INVOCATION_ID",
		filepath.Join(o.env.Layout.BinDir, binGateway), "sandbox-daemon", "stop-sandboxes")
	var stopped []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "stopped sandbox "); ok && name != "" {
			stopped = append(stopped, name)
		}
	}
	if err != nil && res.ExitCode > 0 {
		err = fmt.Errorf("`%s sandbox-daemon stop-sandboxes` exited %d: %s", binGateway, res.ExitCode, commandReason(res))
	}
	return stopped, err
}

// commandReason is why a command run as the account failed: its last line
// on stderr or stdout. The exit status alone left "exit 1: " with an empty
// reason (GAP-0490).
func commandReason(res CommandResult) string {
	if reason := lastLine(res.Stderr); reason != "" {
		return reason
	}
	if reason := lastLine(res.Stdout); reason != "" {
		return reason
	}
	return "it printed no reason"
}

// lastLine is the last non-empty line of out, trimmed and bounded.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])
	if len(line) > 300 {
		line = line[:300] + "..."
	}
	return line
}

func (o *commandUserOps) Groups(ctx context.Context, a SandboxAccount) ([]string, error) {
	res, err := o.env.Runner.Run(ctx, "id", "-nG", a.Name)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(res.Stdout)), nil
}

// ---------------------------------------------------------------------------
// Settling accounts after a transaction.

// openshellChange records what the lifecycle did for the sandbox subsystem
// in the result, whether or not the run reports repairs.
func (l *lifecycle) openshellChange(format string, args ...any) {
	l.result.Changes = append(l.result.Changes, fmt.Sprintf(format, args...))
}

// pendingKinds orders the changes an account can wait for: a later kind
// includes the earlier ones.
var pendingKinds = map[string]int{"restart": 1, "launchd": 2, "switch": 3, "stop": 4}

// settleOpenShell runs after a transaction committed: it records the applied
// configuration and takes every account through what changed. An account that
// runs a sandbox keeps running it; its change waits.
func (l *lifecycle) settleOpenShell(ctx context.Context, op *openshellPlan) {
	env := l.env
	state := env.loadOpenShellState()
	prev := state.Applied
	cur := appliedOf(op)
	kind, reason := "", ""
	switch {
	case cur == nil || !cur.Enabled:
		if prev != nil && prev.Enabled {
			kind, reason = "stop", "sandboxes were turned off (openshell.enabled)"
		}
	case prev == nil || !prev.Enabled:
		// First time on: nothing runs yet. Accounts that are signed in start
		// the new socket the next time their manager reads the units.
		for _, a := range env.sandboxOps().LoggedIn(ctx) {
			if err := env.sandboxOps().Reload(ctx, a); err != nil {
				l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("could not make the user service manager of %s read the new sandbox units: %v; they are read at its next sign-in", a.Name, err))
			}
		}
	case prev.switchKey() != cur.switchKey():
		kind, reason = "switch", describeSwitch(prev, cur)
	case prev.DaemonInputs != cur.DaemonInputs:
		kind, reason = "restart", "the sandbox units, the gateway binary or the rendered OpenShell configuration changed"
	}
	if cur != nil && cur.Enabled {
		// Turned on again: a stop that was waiting no longer applies.
		for key, entry := range state.Pending {
			if entry.Kind == "stop" {
				delete(state.Pending, key)
			}
		}
	}
	if kind != "" {
		ops := env.sandboxOps()
		seen := map[int]bool{}
		for _, a := range append(ops.Accounts(ctx), ops.LoggedIn(ctx)...) {
			if seen[a.UID] {
				continue
			}
			seen[a.UID] = true
			key := strconv.Itoa(a.UID)
			entry, waiting := state.Pending[key]
			if kind == "switch" && waiting && entry.Kind == "switch" {
				l.supersedeSwitch(ctx, state, a, entry, prev, cur)
				continue
			}
			if waiting && pendingKinds[entry.Kind] >= pendingKinds[kind] && kind != "stop" {
				continue
			}
			state.Pending[key] = pending{User: a.Name, UID: a.UID, Home: a.Home, Kind: kind, Reason: reason,
				Since: env.Now().UTC().Format(time.RFC3339), From: prev}
		}
	}
	if (cur == nil || !cur.Enabled) && prev == nil && len(state.Pending) == 0 {
		// Sandboxes were never on: a host that does not use them keeps no
		// record of them.
		return
	}
	state.Applied = cur
	l.settlePending(ctx, state, cur)
	l.reconcileMacOSAgents(ctx, state)
	if err := env.saveOpenShellState(state); err != nil {
		l.result.AddWarning(codeState, "could not record the applied sandbox configuration: "+err.Error())
	}
}

// supersedeSwitch handles a switch for an account that still waits for an
// earlier one. The account runs the setup the earlier switch left (From),
// unless its daemon restarted since the switch was recorded (the launcher
// restarts an idle daemon that waits for a restart), which moved it to the
// setup applied then (prev). The new entry names that real setup as its
// from, so the line it prints is the direction the account actually goes;
// a switch back to the setup the account still runs is no switch at all
// (GAP-0455).
func (l *lifecycle) supersedeSwitch(ctx context.Context, state *openshellState, a SandboxAccount, entry pending, prev, cur *openshellApplied) {
	key := strconv.Itoa(a.UID)
	from := entry.From
	if from == nil || l.restartedSince(ctx, a, entry.Since) {
		from = prev
	}
	if from.switchKey() == cur.switchKey() {
		if from.DaemonInputs == cur.DaemonInputs {
			delete(state.Pending, key)
			return
		}
		entry.Kind, entry.Reason, entry.From = "restart", "the sandbox units, the gateway binary or the rendered OpenShell configuration changed", nil
		state.Pending[key] = entry
		return
	}
	entry.Reason, entry.From = describeSwitch(from, cur), from
	entry.User, entry.Home = a.Name, a.Home
	state.Pending[key] = entry
}

// restartedSince reports whether the account's daemon runs and started after
// since (an RFC 3339 time).
func (l *lifecycle) restartedSince(ctx context.Context, a SandboxAccount, since string) bool {
	at, err := time.Parse(time.RFC3339, since)
	if err != nil {
		return false
	}
	status, err := l.env.sandboxOps().Status(ctx, a)
	return err == nil && status.Active && status.StartedAt.After(at)
}

// retryOpenShell completes the changes accounts waited for, on a run that
// applied nothing else (ensure that found the deployment up to date,
// reconcile).
func (l *lifecycle) retryOpenShell(ctx context.Context) {
	state := l.env.loadOpenShellState()
	if len(state.Pending) == 0 && l.env.GOOS != "darwin" {
		return
	}
	before := len(l.result.Changes)
	l.settlePending(ctx, state, state.Applied)
	l.reconcileMacOSAgents(ctx, state)
	if err := l.env.saveOpenShellState(state); err != nil {
		l.result.AddWarning(codeState, "could not record the sandbox changes still waiting: "+err.Error())
	}
	if len(l.result.Changes) > before {
		l.result.Noop = false
		l.result.NoopReason = ""
	}
}

func describeSwitch(from, to *openshellApplied) string {
	var parts []string
	if from.Install != to.Install {
		parts = append(parts, fmt.Sprintf("install mode %s -> %s", from.Install, to.Install))
	}
	if from.Driver != to.Driver {
		parts = append(parts, fmt.Sprintf("driver %s -> %s", from.Driver, to.Driver))
	}
	if from.Version != to.Version {
		parts = append(parts, fmt.Sprintf("version %q -> %q", from.Version, to.Version))
	}
	if from.GatewayPort != to.GatewayPort {
		parts = append(parts, fmt.Sprintf("gateway port %d -> %d", from.GatewayPort, to.GatewayPort))
	}
	if from.Fallback != to.Fallback && from.Fallback != "" && to.Fallback != "" {
		// Only where the driver stays the MicroVM one: a driver change
		// already says why the fallback went or came (GAP-0463).
		parts = append(parts, fmt.Sprintf("driver_fallback %s -> %s", from.Fallback, to.Fallback))
	}
	if len(parts) == 0 {
		return "the sandbox setup changed"
	}
	return strings.Join(parts, ", ")
}

// fallbackOnlySwitch reports a switch that changes only the docker fallback:
// the account's OpenShell, driver and port stay, so no sandbox was made under
// another setup.
func fallbackOnlySwitch(from, to *openshellApplied) bool {
	if from == nil || to == nil || from.Fallback == to.Fallback {
		return false
	}
	f, t := *from, *to
	f.Fallback, t.Fallback = "", ""
	return f.switchKey() == t.switchKey()
}

// settlePending tries every waiting change: an account without a running
// sandbox gets it now, one with sandboxes keeps waiting.
func (l *lifecycle) settlePending(ctx context.Context, state *openshellState, cur *openshellApplied) {
	env := l.env
	ops := env.sandboxOps()
	for _, entry := range state.sortedPending() {
		key := strconv.Itoa(entry.UID)
		account := SandboxAccount{Name: entry.User, UID: entry.UID, Home: entry.Home, GID: -1}
		status, err := ops.Status(ctx, account)
		switch {
		case err != nil && entry.Kind != "launchd" && !env.hasHomeSandboxState(account):
			// No daemon ever ran here (it keeps its state in the home), so
			// nothing can be waiting: a pending entry no sandbox command of
			// the account could ever clear (GAP-0490).
			delete(state.Pending, key)
			continue
		case err != nil:
			entry.Sandboxes = -1
			entry.Reason = entry.reasonBase() + " (the lifecycle could not tell whether a sandbox of this account runs: " + err.Error() + ")"
			state.Pending[key] = entry
			continue
		case status.Active && status.Running > 0:
			entry.Sandboxes = status.Running
			state.Pending[key] = entry
			continue
		}
		if err := l.performAccountChange(ctx, ops, account, entry, status.Active, cur); err != nil {
			entry.Reason = entry.reasonBase() + " (" + err.Error() + ")"
			state.Pending[key] = entry
			l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("could not apply the %s change for %s: %v; the next run tries again", entry.Kind, entry.User, err))
			continue
		}
		delete(state.Pending, key)
	}
}

// reasonBase is the reason without the retry detail settlePending appends.
func (p pending) reasonBase() string {
	if i := strings.Index(p.Reason, " ("); i > 0 {
		return p.Reason[:i]
	}
	return p.Reason
}

// performAccountChange applies one waiting change to an account that runs no
// sandbox.
func (l *lifecycle) performAccountChange(ctx context.Context, ops SandboxUserOps, a SandboxAccount, entry pending, active bool, cur *openshellApplied) error {
	switch entry.Kind {
	case "launchd":
		jobs, err := l.env.loadedMacOSAgents(ctx, a)
		if err != nil {
			return err
		}
		for _, job := range jobs {
			if err := l.env.reloadMacOSAgent(ctx, job, job.state.Failure(false) != ""); err != nil {
				return err
			}
			l.openshellChange("reloaded %s for %s after its sandboxes stopped", job.label, a.Name)
		}
	case "restart":
		if !active {
			return nil // it starts on the new inputs
		}
		if err := ops.Stop(ctx, a, StopDaemon); err != nil {
			return err
		}
		l.openshellChange("restarted the sandbox daemon of %s (no sandbox of this account was running); %s", a.Name, entry.reasonBase())
	case "stop":
		if err := ops.Stop(ctx, a, StopDaemon|StopGateway|StopSocket); err != nil {
			return err
		}
		l.openshellChange("stopped the sandbox daemon and OpenShell gateway of %s: %s", a.Name, entry.reasonBase())
	case "switch":
		if !active && !l.env.hasHomeSandboxState(a) {
			// Nothing of the previous setup runs or is kept in this account
			// (it never used sandboxes): nothing to stop, replace or report.
			return nil
		}
		if err := ops.Stop(ctx, a, StopDaemon|StopGateway); err != nil {
			return err
		}
		from := entry.From
		if from == nil {
			from = &openshellApplied{}
		}
		if cur != nil && l.env.removesInstalledOpenShell(from, cur) {
			removed, kept, err := l.env.removeTarballInstall(a)
			if err != nil {
				return err
			}
			if len(removed) > 0 {
				l.openshellChange("removed the OpenShell that DefenseClaw installed for %s (%d files); %s", a.Name, len(removed), entry.reasonBase())
			}
			for _, path := range kept {
				l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("kept %s of %s: it changed after DefenseClaw installed it", path, a.Name))
			}
		}
		if cur != nil && fallbackOnlySwitch(from, cur) {
			l.openshellChange("restarted the sandbox daemon and OpenShell gateway of %s on the new fallback (%s)", a.Name, entry.reasonBase())
			break
		}
		l.openshellChange("switched the sandbox setup of %s (%s); %s", a.Name, entry.reasonBase(), sandboxSwitchLeftovers)
	}
	return nil
}

// sandboxSwitchLeftovers is what a switch does to the sandboxes made under
// the previous setup. They stay in `defenseclaw sandbox list`, but they
// cannot start, and OpenShell's gateway drops a sandbox its compute driver
// does not run a few minutes after the switch, with any work not brought
// back from it, even when the driver is switched back later (GAP-0663).
const sandboxSwitchLeftovers = "sandboxes made under the previous setup cannot start on the new one, and OpenShell drops them a few minutes after the switch, " +
	"with any work in them that was not brought back (`defenseclaw sandbox pull`): list them with `defenseclaw sandbox list`"

// removesInstalledOpenShell reports whether leaving from for to drops the
// OpenShell the setup mode installed in the account: setup is left, or its
// pinned version changes.
func (e *Env) removesInstalledOpenShell(from, to *openshellApplied) bool {
	return from.Install == "setup" && (to.Install != "setup" || from.Version != to.Version || !to.Enabled)
}

// ---------------------------------------------------------------------------
// Files in an account's home, as root, without following links.

// openHome opens the account's home directory, which must be owned by it.
func (e *Env) openHome(a SandboxAccount) (int, error) {
	fd, err := openOwnedDir(unix.AT_FDCWD, e.P(filepath.Clean(a.Home)), a.UID)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// walkDirs opens, below dirFD, each component of rel but the last as a folder
// the account owns, and returns the last folder's descriptor and the final
// name. fd is -1 when a folder on the way does not exist. It never creates
// one: the lifecycle runs as root, and a folder it made in an account's home
// would be root's (GAP-0244, GAP-0230).
func walkDirs(dirFD int, rel string, uid int) (fd int, name string, err error) {
	parts := strings.Split(filepath.ToSlash(filepath.Clean(rel)), "/")
	if rel == "" || filepath.IsAbs(rel) || parts[0] == ".." || parts[0] == "." {
		return -1, "", fmt.Errorf("%q is not a path below the home", rel)
	}
	cur, owned := dirFD, false
	closeCur := func() {
		if owned {
			_ = unix.Close(cur)
		}
	}
	for _, part := range parts[:len(parts)-1] {
		if part == ".." || part == "." || part == "" {
			closeCur()
			return -1, "", fmt.Errorf("%q is not a path below the home", rel)
		}
		next, err := openOwnedDir(cur, part, uid)
		closeCur()
		if err != nil || next < 0 {
			return -1, "", err
		}
		cur, owned = next, true
	}
	if !owned {
		// rel has one component: the caller uses the home itself.
		dup, derr := unix.Dup(dirFD)
		if derr != nil {
			return -1, "", derr
		}
		return dup, parts[0], nil
	}
	return cur, parts[len(parts)-1], nil
}

// removeBelowHome removes rel (a file, a link or a folder tree) below the
// account's home. A folder on the way that is a link or belongs to another
// account stops the removal with an error; a missing path is nothing to do.
func (e *Env) removeBelowHome(a SandboxAccount, rel string) (removed bool, err error) {
	home, err := e.openHome(a)
	if err != nil {
		return false, err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return false, err
	}
	defer unix.Close(parent)
	return removeTreeAt(parent, name, a.UID, 0)
}

const maxRemoveDepth = 64

// removeTreeAt removes name below dirFD. Directories are entered without
// following a link, only when the account owns them and on the same device;
// links are removed, never followed.
func removeTreeAt(dirFD int, name string, uid, depth int) (bool, error) {
	if depth > maxRemoveDepth {
		return false, fmt.Errorf("%s is nested too deeply", name)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(dirFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return false, err
		}
		return true, nil
	}
	var parent unix.Stat_t
	if err := unix.Fstat(dirFD, &parent); err != nil {
		return false, err
	}
	if int(st.Uid) != uid || st.Dev != parent.Dev {
		return false, fmt.Errorf("%s is not a folder of the account on its own filesystem; it is not removed", name)
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	// What was opened is what was checked: a folder swapped in between is not
	// entered.
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != st.Dev || opened.Ino != st.Ino || int(opened.Uid) != uid {
		_ = unix.Close(fd)
		return false, fmt.Errorf("%s changed while it was removed; it is not removed", name)
	}
	dir := os.NewFile(uintptr(fd), name)
	names, err := dir.Readdirnames(-1)
	if err != nil {
		_ = dir.Close()
		return false, err
	}
	var errs []error
	for _, child := range names {
		if _, err := removeTreeAt(fd, child, uid, depth+1); err != nil {
			errs = append(errs, err)
		}
	}
	_ = dir.Close()
	if len(errs) > 0 {
		return true, errors.Join(errs...)
	}
	if err := unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return true, err
	}
	return true, nil
}

// readBelowHome reads a regular file below the account's home, bounded;
// ok is false when it does not exist.
func (e *Env) readBelowHome(a SandboxAccount, rel string, limit int64) (data []byte, ok bool, err error) {
	home, err := e.openHome(a)
	if err != nil {
		return nil, false, err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return nil, false, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", rel)
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, false, fmt.Errorf("%s is larger than %d bytes", rel, limit)
	}
	return data, true, nil
}

// removeTarballInstall removes the OpenShell that the tarball install placed
// in the account's home: the files its manifest lists that are still what was
// installed. A file the account changed stays (kept).
func (e *Env) removeTarballInstall(a SandboxAccount) (removed, kept []string, err error) {
	manifestRel := filepath.ToSlash(filepath.Join(installStateRel, openshell.TarballManifestName))
	data, ok, err := e.readBelowHome(a, manifestRel, 1<<20)
	if err != nil || !ok {
		return nil, nil, err
	}
	var manifest openshell.InstalledRelease
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("the OpenShell install record of %s is unreadable: %w", a.Name, err)
	}
	listed := map[string]string{}
	for _, file := range manifest.Files {
		rel, relErr := filepath.Rel(filepath.Clean(a.Home), file.Path)
		if relErr == nil {
			listed[filepath.ToSlash(rel)] = file.SHA256
		}
	}
	for _, rel := range tarballRels {
		want, isListed := listed[rel]
		if !isListed {
			continue
		}
		got, present, derr := e.digestBelowHome(a, rel)
		switch {
		case derr != nil:
			return removed, kept, derr
		case !present:
			continue
		case got != want:
			kept = append(kept, filepath.Join(a.Home, rel))
			continue
		}
		if _, err := e.removeBelowHome(a, rel); err != nil {
			return removed, kept, err
		}
		removed = append(removed, filepath.Join(a.Home, rel))
	}
	if len(kept) == 0 {
		if _, err := e.removeBelowHome(a, manifestRel); err != nil {
			return removed, kept, err
		}
	}
	return removed, kept, nil
}

// digestBelowHome is the SHA-256 of a regular file below the home.
func (e *Env) digestBelowHome(a SandboxAccount, rel string) (digest string, present bool, err error) {
	home, err := e.openHome(a)
	if err != nil {
		return "", false, err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return "", false, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return "", false, nil
		}
		return "", false, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return "", true, fmt.Errorf("%s is not a regular file", rel)
	}
	// A file larger than any release binary was not installed by DefenseClaw.
	const limit = 1 << 30
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", true, err
	}
	if n > limit {
		return "too large", true, nil
	}
	return hex.EncodeToString(hash.Sum(nil)), true, nil
}

// ---------------------------------------------------------------------------
// Uninstall and purge.

// sandboxAccounts lists every account the sandbox subsystem may have left a
// daemon, an OpenShell gateway, sandboxes or files in: the accounts the
// sandbox stores and the enrollment record name, the signed-in ones, the ones
// a change waits for, and the ones the hook manifest enrolls. The uninstall
// calls it before it removes the per-user registrations, because removing
// them deletes the eligible-accounts record that names an account whose only
// trace is its sandbox state. It is empty when the subsystem was never on.
func (l *lifecycle) sandboxAccounts(ctx context.Context) []SandboxAccount {
	env := l.env
	state := env.loadOpenShellState()
	if state.Applied == nil && len(state.Pending) == 0 {
		return nil
	}
	ops := env.sandboxOps()
	seen := map[int]bool{}
	var accounts []SandboxAccount
	add := func(a SandboxAccount) {
		if !seen[a.UID] {
			seen[a.UID] = true
			accounts = append(accounts, a)
		}
	}
	for _, a := range ops.Accounts(ctx) {
		add(a)
	}
	for _, a := range ops.LoggedIn(ctx) {
		add(a)
	}
	for _, entry := range state.sortedPending() {
		add(SandboxAccount{Name: entry.User, UID: entry.UID, Home: entry.Home, GID: -1})
	}
	for _, a := range env.manifestSandboxAccounts() {
		add(a)
	}
	return accounts
}

// manifestSandboxAccounts are the accounts the hook manifest enrolls.
func (e *Env) manifestSandboxAccounts() []SandboxAccount {
	manifest, err := enterprisehooks.LoadStandaloneManifest(e.P(e.Layout.ManifestPath))
	if err != nil {
		return nil
	}
	var out []SandboxAccount
	for _, target := range manifest.Targets {
		if target.UID == nil {
			continue
		}
		a := SandboxAccount{Name: target.User, UID: *target.UID, GID: -1, Home: filepath.Clean(strings.TrimSpace(target.UserHome))}
		if target.GID != nil {
			a.GID = *target.GID
		}
		if e.usableSandboxAccount(a) {
			out = append(out, a)
		}
	}
	return out
}

// teardownOpenShell takes the sandbox subsystem out of every account in
// accounts (sandboxAccounts, read before the uninstall removed the records
// that name them) before the binaries and units go.
//
// Without purge every account keeps its sandboxes: their records, MicroVM
// disks, copy-mode work not pulled yet, providers and settings stay in its
// home for the next activation of the deployment, and only what runs stops
// (keepAccountSandboxes). It used to run `defenseclaw sandbox teardown`
// there too, which deleted the sandboxes and their unpulled work while the
// result said each account kept its sandbox state (GAP-0598). The gateway's
// registrations of the kept sandboxes stay too (keepSandboxStore): without
// them the next activation's gateway refused every kept sandbox.
//
// A purge runs `defenseclaw sandbox teardown` first, as the account, while
// its sandbox daemon and OpenShell gateway still answer, because it lists
// and deletes the sandboxes, providers and profiles through them; only then
// the account's units stop (stopping the daemon stops its sandboxes first),
// and what the subsystem left in the account's home goes too. It never
// deletes anything it did not create.
func (l *lifecycle) teardownOpenShell(ctx context.Context, accounts []SandboxAccount) {
	env, r := l.env, l.result
	state := env.loadOpenShellState()
	if state.Applied == nil && len(state.Pending) == 0 {
		// The sandbox subsystem was never on: no account has anything of it.
		return
	}
	applied := state.Applied
	ops := env.sandboxOps()
	purge := l.opts.Purge
	var kept []string
	for _, a := range accounts {
		if !env.hasHomeSandboxState(a) {
			// The subsystem never served this account (a signed-in
			// administrator or service account, a session of another lab
			// install, a home with only a root-owned folder an older release
			// left): nothing is torn down or deleted there. Only
			// DefenseClaw's own units, which the global enable link starts at
			// every sign-in, are stopped, quietly (GAP-0490).
			_ = ops.Stop(ctx, a, StopDaemon|StopGateway|StopSocket)
			continue
		}
		if !purge {
			l.keepAccountSandboxes(ctx, a)
			kept = append(kept, a.Name)
			continue
		}
		teardownErr := ops.Teardown(ctx, a)
		if teardownErr == nil {
			r.Changes = append(r.Changes, fmt.Sprintf("ran `defenseclaw sandbox teardown` as user %s while its sandbox daemon and OpenShell gateway still answered", a.Name))
		}
		if err := ops.Stop(ctx, a, StopDaemon|StopGateway|StopSocket); err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not stop the sandbox daemon of %s: %v; stop its user units by hand", a.Name, err))
		}
		l.purgeAccountSandboxImages(ctx, a)
		l.purgeAccountSandbox(a)
		if teardownErr != nil {
			// Teardown's next step assumes its local state still exists.
			// Purge removed those files independently, so describe the
			// resources that may remain instead of repeating that step.
			if env.GOOS == "linux" {
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("sandbox teardown did not finish for user %s; purge continued with local sandbox file removal; OpenShell gateway resources may remain and need manual cleanup; any Docker containers, volumes and images of its sandboxes that could not be removed are reported separately", a.Name))
			} else {
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("sandbox teardown did not finish for user %s; purge continued with local sandbox file removal; Docker images and OpenShell gateway resources may remain and need manual cleanup", a.Name))
			}
		}
	}
	switch {
	case purge:
	case len(kept) > 0:
		// The gateway's registrations of these sandboxes stay with them
		// (keepSandboxStore); the uninstall summary says so once they are
		// kept (keptSandboxStoreLine).
		l.sandboxesKept = kept
		r.Changes = append(r.Changes, fmt.Sprintf("stopped the sandbox subsystem; kept the sandboxes of %s in their homes with their records, disks and any work not pulled yet; "+
			"`%s --purge` of an active deployment deletes them",
			strings.Join(kept, ", "), env.lifecycleCommand(ActionUninstall)))
	case applied != nil && applied.Enabled:
		r.Changes = append(r.Changes, "stopped the sandbox subsystem; no account had sandboxes to keep")
	}
}

// keepAccountSandboxes stops what runs of the sandbox subsystem in an
// account whose sandboxes a non-purge uninstall keeps: its running
// sandboxes first, through its daemon, which syncs a MicroVM's disk before
// the stop so a copy's unpulled work survives it (openshell.Driver.
// StopFlushes; the macOS agent's bootout stops none), then its units, the
// daemon before the OpenShell gateway. Nothing in the account's home is
// deleted.
func (l *lifecycle) keepAccountSandboxes(ctx context.Context, a SandboxAccount) {
	r := l.result
	ops := l.env.sandboxOps()
	// A daemon that cannot say leaves it unknown whether a sandbox runs:
	// the sandboxes are stopped as if one did.
	if st, err := ops.Status(ctx, a); err != nil || st.Running > 0 {
		stopped, err := ops.StopSandboxes(ctx, a)
		if len(stopped) > 0 {
			r.Changes = append(r.Changes, fmt.Sprintf("stopped the running sandboxes of user %s (%s); they are kept, with their work", a.Name, strings.Join(stopped, ", ")))
		}
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not stop every running sandbox of %s through its sandbox daemon: %v; its units stop next, and a MicroVM sandbox "+
				"that was still running then may miss the files written in it since its disk was last synced", a.Name, err))
		}
	}
	err := ops.Stop(ctx, a, StopDaemon|StopSocket)
	if gwErr := ops.Stop(ctx, a, StopGateway); err == nil {
		err = gwErr
	}
	if err != nil {
		r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not stop the sandbox daemon of %s: %v; stop its user units by hand", a.Name, err))
	}
}

// purgeAccountSandbox removes what the sandbox subsystem left in an account:
// the daemon's state, MicroVM disks, CLI state and build logs, and the OpenShell
// that DefenseClaw installed and its state. An OpenShell the account or its
// administrator installed stays. Account teardown handles gateway resources;
// on Linux the root cleanup also removes the account's labelled Docker
// sandbox containers and volumes in both managed namespaces, then its images,
// before these files, including the image records, are removed.
func (l *lifecycle) purgeAccountSandbox(a SandboxAccount) {
	env, r := l.env, l.result
	removedAny := false
	remove := func(rel string) {
		removed, err := env.removeBelowHome(a, rel)
		switch {
		case err != nil:
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not remove %s of %s: %v; delete it by hand", rel, a.Name, err))
		case removed:
			removedAny = true
		}
	}
	removedFiles, kept, err := env.removeTarballInstall(a)
	switch {
	case err != nil:
		r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not remove the OpenShell DefenseClaw installed for %s: %v; delete ~/.local/bin/openshell* by hand", a.Name, err))
	case len(removedFiles) > 0:
		removedAny = true
		// The state of an OpenShell DefenseClaw installed and ran is its
		// own: TLS certificates, the gateway database, the runtime.
		remove(openshellStateRel)
		remove(openshellShareRel)
	}
	for _, path := range kept {
		r.AddWarning(codeSandboxUserState, fmt.Sprintf("kept %s of %s: it changed after DefenseClaw installed it", path, a.Name))
	}
	// Disks and images of the MicroVM driver are DefenseClaw's sandboxes'.
	remove(openshellVMStateRel)
	remove(env.daemonStateRel())
	remove(installStateRel)
	// What the managed `defenseclaw sandbox` keeps below ~/.defenseclaw (the
	// image records, each sandbox's CLI state; the teardown above writes the
	// image records again), unless the folder is the account's own
	// DefenseClaw install, whose sandbox data it would be (GAP-0490).
	if _, err := os.Lstat(env.P(filepath.Join(a.Home, ".defenseclaw", "config.yaml"))); errors.Is(err, fs.ErrNotExist) {
		remove(userSandboxDataRel)
		logs, err := env.sandboxImageLogRels(a)
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not list the sandbox image build logs of %s: %v; delete them by hand", a.Name, err))
		}
		for _, rel := range logs {
			remove(rel)
		}
		if _, err := env.removeEmptyBelowHome(a, ".defenseclaw/logs"); err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not remove the empty .defenseclaw/logs of %s: %v", a.Name, err))
		}
	}
	// The folders the install made for itself, once empty.
	for _, rel := range []string{".local/libexec/openshell", openshellStateRel, openshellShareRel, ".defenseclaw"} {
		if _, err := env.removeEmptyBelowHome(a, rel); err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not remove the empty %s of %s: %v", rel, a.Name, err))
		}
	}
	if removedAny {
		r.Changes = append(r.Changes, fmt.Sprintf("removed local sandbox files of user %s", a.Name))
	}
}

// sandboxImageLogRels lists the CLI's build logs below the account's home,
// without following links or entering directories another account owns.
func (e *Env) sandboxImageLogRels(a SandboxAccount) ([]string, error) {
	home, err := e.openHome(a)
	if err != nil || home < 0 {
		return nil, err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, ".defenseclaw/logs", a.UID)
	if err != nil || parent < 0 {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := openOwnedDir(parent, name, a.UID)
	if err != nil || fd < 0 {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var rels []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "sandbox-image-") && strings.HasSuffix(entry.Name(), ".log") {
			rels = append(rels, filepath.Join(".defenseclaw/logs", entry.Name()))
		}
	}
	return rels, nil
}

// removeOpenShellMachineState removes the lifecycle's own sandbox files that
// no deployment record lists, and their directory unless the package owns it
// (the package erase removes it then).
func (e *Env) removeOpenShellMachineState(channel string) {
	_ = removeFile(e.P(e.prerequisitesPath()))
	_ = removeFile(e.openshellStatePath())
	if !e.packageOwnsOpenShellDir(channel) {
		_ = removeDirIfEmpty(e.P(e.openshellDir()))
	}
}

// removeEmptyBelowHome removes the folder rel below the account's home when
// it is empty.
func (e *Env) removeEmptyBelowHome(a SandboxAccount, rel string) (bool, error) {
	home, err := e.openHome(a)
	if err != nil {
		return false, err
	}
	defer unix.Close(home)
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return false, err
	}
	defer unix.Close(parent)
	err = unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTEMPTY), errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTDIR):
		return false, nil
	}
	return false, err
}

// hasHomeSandboxState reports whether the managed sandbox subsystem served
// the account: it has a registration or decision record, or what only the
// managed sandbox daemon writes in a home (its state, the setup mode's
// OpenShell install record, MicroVM state) owned by the account. A folder
// the account does not own (an empty root-owned one an older release left)
// or a link is not its state, so a purge neither tears down nor deletes
// anything there (GAP-0490).
func (e *Env) hasHomeSandboxState(a SandboxAccount) bool {
	if e.sandboxRecorded(a) {
		return true
	}
	for _, rel := range []string{e.daemonStateRel(), installStateRel, openshellVMStateRel} {
		info, err := os.Lstat(e.P(filepath.Join(a.Home, rel)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) == a.UID {
			return true
		}
	}
	return false
}

// sandboxRecorded reports whether the managed gateway keeps a registration or
// decision record of the account: it ran a sandbox through the managed
// launcher.
func (e *Env) sandboxRecorded(a SandboxAccount) bool {
	for _, dir := range []string{"registrations", "decisions"} {
		if exists(e.P(filepath.Join(e.Layout.DataDir, "sandbox", dir, strconv.Itoa(a.UID)+".json"))) {
			return true
		}
	}
	return false
}
