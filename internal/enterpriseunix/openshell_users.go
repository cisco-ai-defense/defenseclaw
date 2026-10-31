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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
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
	// Live is the number that may hold compute a stop of the account's
	// OpenShell gateway would end unflushed or half started: the running
	// ones, those starting or stopping, and a MicroVM that completed or is
	// in OpenShell's error state, which OpenShell does not stop, until
	// OpenShell reports it stopped (sandboxapi.Status.Busy).
	// What stops that gateway on its own (busy) waits for them.
	Live int
	// PendingRestart is the daemon's own report that it waits for a restart.
	PendingRestart bool
	// StartedAt is when the daemon started (zero when it does not say).
	StartedAt time.Time
	// Legacy is a daemon whose status has no live count: one before
	// DefenseClaw 1.0.4, which a package upgrade left running. Its exit
	// stops the account's OpenShell gateway once no sandbox runs, with no
	// check for a MicroVM that completed or is in OpenShell's error state,
	// which that stop ends with no flush; a stop of it ends it first
	// (StopKill).
	Legacy bool
	// Unprotected are the account's live legacy guests, as a daemon of
	// DefenseClaw 1.0.4 or later reports them (sandboxapi.Status.Unprotected):
	// each runs unprotected until its user ends it.
	Unprotected []UnprotectedSandbox
}

// UnprotectedSandbox is one live legacy or contained guest of an account,
// or one that may be either whose gateway has not said: its name, the
// command its user runs to end it, why it is unprotected and what else its
// user does (sandboxapi.UnprotectedSandbox.Reason, Detail).
type UnprotectedSandbox struct {
	Name   string `json:"name"`
	Stop   string `json:"stop"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// daemonStop is scope for a stop of the sandbox daemon that st describes:
// with StopKill for a daemon before 1.0.4 (SandboxStatus.Legacy).
func daemonStop(st SandboxStatus, scope StopScope) StopScope {
	if st.Legacy {
		return scope | StopKill
	}
	return scope
}

// busy is how many of the account's sandboxes a stop of its gateway or
// daemon waits for: Live, never fewer than Running.
func (s SandboxStatus) busy() int {
	return max(s.Running, s.Live)
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
	// Drain runs `defenseclaw-gateway sandbox-daemon drain` as the account
	// and returns once it holds the account's OpenShell lifecycle lock,
	// which keeps the account's DefenseClaw from creating or starting a
	// sandbox, and found nothing a stop of the account's gateway would end
	// with no flush (openshell.CheckAccountGateways). The caller stops the
	// units that stop the gateway, then calls release, which lets the lock
	// go. An error (a sandbox OpenShell does not report stopped, a MicroVM
	// that runs as the account, a check that could not be made, a
	// DefenseClaw without the drain) means the gateway must not stop now.
	Drain(ctx context.Context, a SandboxAccount) (release func() error, err error)
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
	// and the launcher starts the daemon again on the next command (it
	// starts a stopped socket too).
	StopDaemon StopScope = 1 << iota
	// StopGateway stops the account's OpenShell gateway unit (setup mode).
	StopGateway
	// StopSocket stops the daemon's socket (Linux).
	StopSocket
	// StopKill first ends the daemon's main process with SIGKILL: the exit
	// of a daemon before DefenseClaw 1.0.4 (SandboxStatus.Legacy), which a
	// stop's SIGTERM runs, stops the account's OpenShell gateway under a
	// MicroVM that completed, with no flush. A killed daemon runs nothing on
	// its way out, and the unit's ExecStop, which then runs with no main
	// process, stops nothing. Alone it stops no unit: the service manager
	// starts the installed daemon again (systemd's Restart=, the launcher
	// on the next command).
	StopKill
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
	_, args := o.asAccount(a, argv...)
	if o.env.GOOS == "darwin" {
		return o.env.longRunner(timeout).Run(ctx, "sudo", args...)
	}
	return o.env.longRunner(timeout).Run(ctx, "runuser", args...)
}

// asAccount is the command that runs argv as the account: sudo (macOS) or
// runuser (Linux), with the account's home and, on Linux, its user manager.
func (o *commandUserOps) asAccount(a SandboxAccount, argv ...string) (string, []string) {
	uid := strconv.Itoa(a.UID)
	if o.env.GOOS == "darwin" {
		return "sudo", append([]string{"-n", "-u", a.Name, "-H", "/usr/bin/env", "HOME=" + a.Home}, argv...)
	}
	return "runuser", append([]string{"-u", a.Name, "--", "/usr/bin/env", "HOME=" + a.Home, "XDG_RUNTIME_DIR=/run/user/" + uid,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus"}, argv...)
}

// drainReadyWait bounds how long the lifecycle waits for an account's drain
// to hold its lock and check: the lock's own wait for the creates and
// starts in flight (2 minutes), and the check.
var drainReadyWait = 4 * time.Minute

// drainCommand makes the command a drain runs; a seam for tests.
var drainCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	return cmd
}

func (o *commandUserOps) Drain(ctx context.Context, a SandboxAccount) (func() error, error) {
	name, args := o.asAccount(a, filepath.Join(o.env.Layout.BinDir, binGateway), "sandbox-daemon", "drain")
	cmd := drainCommand(ctx, name, args...)
	// Its own process group, ended whole: a runuser or sudo killed alone
	// would leave the drain holding the account's lock and its pipes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out := &drainOutput{ready: make(chan struct{})}
	var stderr lockedBuffer
	cmd.Stdout, cmd.Stderr = out, &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("run the sandbox drain of %s: %w", a.Name, err)
	}
	t := time.NewTimer(drainReadyWait)
	defer t.Stop()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-out.ready:
		return func() error {
			_ = stdin.Close()
			if err := <-exited; err != nil {
				return fmt.Errorf("the sandbox drain of %s: %v: %s", a.Name, err, commandReason(CommandResult{Stdout: out.bytes(), Stderr: stderr.bytes()}))
			}
			return nil
		}, nil
	case err := <-exited:
		_ = stdin.Close()
		return nil, fmt.Errorf("the gateway of %s keeps running: %s (%v)", a.Name, commandReason(CommandResult{Stdout: out.bytes(), Stderr: stderr.bytes()}), err)
	case <-t.C:
	case <-ctx.Done():
	}
	_ = stdin.Close()
	_ = cmd.Cancel()
	<-exited
	return nil, fmt.Errorf("the gateway of %s keeps running: its sandbox drain did not answer within %s: %s", a.Name, drainReadyWait,
		commandReason(CommandResult{Stdout: out.bytes(), Stderr: stderr.bytes()}))
}

// drainOutput is a drain's standard output: ready closes once the line
// openshell.LifecycleDrained arrives.
type drainOutput struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	seen  bool
}

func (d *drainOutput) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, _ := d.buf.Write(p)
	if !d.seen {
		for _, line := range strings.Split(d.buf.String(), "\n") {
			if strings.TrimSpace(line) == openshell.LifecycleDrained {
				d.seen = true
				close(d.ready)
				break
			}
		}
	}
	return n, nil
}

func (d *drainOutput) bytes() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.buf.Bytes()...)
}

// lockedBuffer is a buffer written by one goroutine and read by another.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
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

// domain is the launchd domain of the account's sandbox agent
// (openshell.LaunchDomain): the one its job is loaded in, so a stop or a
// kill finds it, else the graphical session, else the background one.
func (o *commandUserOps) domain(ctx context.Context, a SandboxAccount) string {
	domain, _ := openshell.LaunchDomain(a.UID, labelSandbox, o.env.launchAgentLabel(labelSandbox), func(domain string) (string, error) {
		res, err := o.env.Runner.Run(ctx, "launchctl", "print", domain)
		return string(res.Stdout), err
	})
	return domain
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
		// `sandbox status` starts the daemon on demand and the daemon counts
		// what the gateway runs, so ask it. When neither service runs, durable
		// guest records still need checking before calling the account idle.
		if !o.unitRunning(ctx, a, userUnitGatewayService, labelOpenShellGateway) {
			return st, e.retainedComputeRefusal(a)
		}
	}
	// The managed binary, not the launcher path: a foreign file there (a
	// Python install, say) is its own row (checkLauncher), and its output
	// is no answer from the account's daemon (GAP-0016).
	res, err := o.runAs(ctx, a, userCommandTimeout, e.launcherTarget(), "sandbox", "status", "--output", "json")
	if err != nil {
		return st, fmt.Errorf("ask the sandbox daemon of %s: %w", a.Name, err)
	}
	var reply struct {
		Sandboxes int       `json:"sandboxes"`
		Running   int       `json:"running"`
		Live      *int      `json:"live"`
		StartedAt time.Time `json:"started_at"`
		Managed   *struct {
			PendingRestart bool `json:"pending_restart"`
		} `json:"managed"`
		Unprotected []UnprotectedSandbox `json:"unprotected"`
	}
	if err := json.Unmarshal(res.Stdout, &reply); err != nil {
		return st, fmt.Errorf("read the sandbox status of %s: %w", a.Name, err)
	}
	// The command started the daemon when the gateway ran without one.
	st.Active = true
	st.Running = reply.Running
	// A daemon before 1.0.4 does not say which sandboxes may hold compute:
	// every one it counts does (sandboxapi.Status.Busy).
	st.Live = max(reply.Sandboxes, reply.Running)
	st.Legacy = reply.Live == nil
	if reply.Live != nil {
		st.Live = *reply.Live
	}
	st.StartedAt = reply.StartedAt
	st.PendingRestart = reply.Managed != nil && reply.Managed.PendingRestart
	st.Unprotected = reply.Unprotected
	if st.busy() == 0 {
		// A daemon restarted on new inputs may no longer see a guest left by
		// the old gateway. Its zero count is not a disposition of that guest.
		if err := e.retainedComputeRefusal(a); err != nil {
			return st, err
		}
	}
	return st, nil
}

// retainedComputeRefusal checks the daemon's durable records when runtime
// status would let an account switch. A package upgrade can stop both old
// services while an OpenShell 0.1.3 MicroVM remains in Error: the new
// daemon's zero count cannot prove that its VM has stopped. Read only the
// account's own records through owned directory descriptors and refuse a
// record whose last observed OpenShell state may still hold compute.
func (e *Env) retainedComputeRefusal(a SandboxAccount) error {
	home, err := e.openHome(a)
	if err != nil || home < 0 {
		return err
	}
	defer unix.Close(home)
	rel := filepath.Join(e.daemonStateRel(), "sandboxes", "manager")
	parent, name, err := walkDirs(home, rel, a.UID)
	if err != nil || parent < 0 {
		return err
	}
	defer unix.Close(parent)
	fd, err := openOwnedDir(parent, name, a.UID)
	if err != nil || fd < 0 {
		return err
	}
	dir := os.NewFile(uintptr(fd), name)
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return fmt.Errorf("inspect retained sandboxes of %s: %w", a.Name, err)
	}
	for _, entry := range entries {
		sandboxName, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !openshell.ValidSandboxName(sandboxName) {
			continue
		}
		data, present, err := e.readBelowHome(a, filepath.Join(rel, entry.Name()), 8<<20)
		if err != nil {
			return fmt.Errorf("inspect retained sandbox %s of %s: %w; repair its account state, then retry", sandboxName, a.Name, err)
		}
		if !present {
			return fmt.Errorf("retained sandbox %s of %s changed while inspected; retry", sandboxName, a.Name)
		}
		var rec struct {
			Name           string `json:"name"`
			Driver         string `json:"driver"`
			Phase          string `json:"phase"`
			PhaseReason    string `json:"phase_reason"`
			SessionRelease string `json:"session_release"`
		}
		if err := json.Unmarshal(data, &rec); err != nil || rec.Name != sandboxName {
			return fmt.Errorf("retained sandbox %s of %s has an unreadable record; repair its account state, then retry", sandboxName, a.Name)
		}
		driver, known := openshell.LookupDriver(rec.Driver)
		if known && driver.StopFlushes {
			continue
		}
		phase := openshell.PhaseUnknown
		switch strings.ToLower(rec.Phase) {
		case "ready":
			phase = openshell.PhaseReady
		case "provisioning":
			phase = openshell.PhaseProvisioning
		case "starting":
			phase = openshell.PhaseStarting
		case "stopping":
			phase = openshell.PhaseStopping
		case "stopped":
			phase = openshell.PhaseStopped
		case "deleting":
			phase = openshell.PhaseDeleting
		case "completed":
			phase = openshell.PhaseCompleted
		case "error":
			phase = openshell.PhaseError
		}
		if !openshell.HoldsGateway(phase, rec.PhaseReason, false) {
			continue
		}
		detail := sandboxapi.DisplayText(rec.PhaseReason)
		if runes := []rune(detail); len(runes) > 160 {
			detail = string(runes[:160]) + "…"
		}
		if detail != "" {
			detail = ": " + detail
		}
		return fmt.Errorf("retained MicroVM %s of %s is %s%s and may still hold compute; %s; then rerun `%s`",
			sandboxName, a.Name, phase, detail, openshell.StopWayOn(sandboxName, phase, rec.PhaseReason, rec.SessionRelease), e.lifecycleCommand(ActionEnsure))
	}
	return nil
}

// unitRunning reports whether the account's user unit (systemd) or agent
// (launchd: a job of any label of base) is running.
func (o *commandUserOps) unitRunning(ctx context.Context, a SandboxAccount, unit, base string) bool {
	if o.env.GOOS == "darwin" {
		domain := o.domain(ctx, a)
		for _, label := range o.agentLabels(ctx, domain, base) {
			res, err := o.env.Runner.Run(ctx, "launchctl", "print", domain+"/"+label)
			if err == nil && strings.Contains(string(res.Stdout), "state = running") {
				return true
			}
		}
		return false
	}
	res, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "is-active", unit)
	return err == nil && strings.TrimSpace(string(res.Stdout)) == "active"
}

// agentLabels are the labels of base to act on in an account's domain: the
// installed one and each earlier one the domain still lists (GAP-0206).
func (o *commandUserOps) agentLabels(ctx context.Context, domain, base string) []string {
	res, _ := o.env.Runner.Run(ctx, "launchctl", "print", domain)
	return domainAgentLabels(res.Stdout, base, o.env.launchAgentLabel(base))
}

func (o *commandUserOps) Stop(ctx context.Context, a SandboxAccount, scope StopScope) error {
	e := o.env
	if scope&StopKill != 0 {
		if err := o.killDaemon(ctx, a); err != nil {
			return err
		}
	}
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
			for _, label := range o.agentLabels(ctx, domain, item.label) {
				res, err := e.Runner.Run(ctx, "launchctl", "bootout", domain+"/"+label)
				if err != nil && !bootoutNotLoaded(res, err) {
					errs = append(errs, err)
				}
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

// gatewayStopSyncer is a SandboxUserOps that can have the account sync its
// running MicroVMs before the macOS lifecycle boots its gateway agent out.
type gatewayStopSyncer interface {
	syncBeforeGatewayStop(ctx context.Context, a SandboxAccount)
}

// syncBeforeGatewayStop has the account sync the disk of every MicroVM its
// running OpenShell gateway lists ready before the macOS bootout of the
// gateway's LaunchAgent ends them (GAP-0380): the drain checked none ran,
// but a raw openshell client can start one before the bootout. It runs once
// the drain holds (drainAccount). It is the
// sync the Linux unit's second ExecStop runs (sandbox-daemon sync-sandboxes
// --managed, which notes one it could not sync for the account's feed);
// like that ExecStop's leading "-", a failed sync does not hold the stop.
func (o *commandUserOps) syncBeforeGatewayStop(ctx context.Context, a SandboxAccount) {
	if !o.unitRunning(ctx, a, userUnitGatewayService, labelOpenShellGateway) {
		return
	}
	_, _ = o.runAs(ctx, a, openshell.StopSyncTimeout+15*time.Second,
		filepath.Join(o.env.Layout.BinDir, binGateway), "sandbox-daemon", "sync-sandboxes", "--managed")
}

// daemonKillWait bounds how long a stop with StopKill waits for systemd to
// see the killed daemon go; daemonKillPoll paces the look. Variables for
// tests.
var (
	daemonKillWait = 15 * time.Second
	daemonKillPoll = 100 * time.Millisecond
)

// killDaemon ends the main process of the account's sandbox daemon with
// SIGKILL (StopKill). On Linux it waits until systemd saw that process go:
// the stop that follows then runs the unit's ExecStop with no main
// process, which stops nothing, where an ExecStop that still saw the
// killed process asked a socket no daemon answers. A daemon that does not
// run has nothing to end; one that cannot be ended is an error, and then
// nothing is stopped.
func (o *commandUserOps) killDaemon(ctx context.Context, a SandboxAccount) error {
	e := o.env
	if e.GOOS == "darwin" {
		domain := o.domain(ctx, a)
		var failed error
		for _, label := range o.agentLabels(ctx, domain, labelSandbox) {
			if res, err := e.Runner.Run(ctx, "launchctl", "kill", "SIGKILL", domain+"/"+label); err != nil && !bootoutNotLoaded(res, err) {
				failed = err
			}
		}
		if failed != nil && o.unitRunning(ctx, a, userUnitSandboxService, labelSandbox) {
			return fmt.Errorf("end the sandbox daemon of %s, which an earlier DefenseClaw started, before its stop: %w", a.Name, failed)
		}
		return nil
	}
	pid, err := o.daemonMainPID(ctx, a)
	if err != nil || pid == 0 {
		return err
	}
	if _, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "kill", "--kill-who=main", "--signal=SIGKILL", userUnitSandboxService); err != nil {
		if now, perr := o.daemonMainPID(ctx, a); perr != nil || now == pid {
			return fmt.Errorf("end the sandbox daemon of %s, which an earlier DefenseClaw started, before its stop: %w", a.Name, err)
		}
		return nil // it went by itself
	}
	deadline := time.Now().Add(daemonKillWait)
	for {
		now, err := o.daemonMainPID(ctx, a)
		if err != nil {
			return err
		}
		if now != pid {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the sandbox daemon of %s was sent SIGKILL, but systemd still names process %d after %s", a.Name, pid, daemonKillWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(daemonKillPoll):
		}
	}
}

// daemonMainPID is the main process systemd names for the account's sandbox
// daemon: 0 when none runs, also when the account's user manager does not
// run.
func (o *commandUserOps) daemonMainPID(ctx context.Context, a SandboxAccount) (int, error) {
	res, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "show", "--property=MainPID", "--value", userUnitSandboxService)
	if err != nil {
		if !o.unitRunning(ctx, a, userUnitSandboxService, labelSandbox) {
			return 0, nil
		}
		return 0, fmt.Errorf("read the main process of the sandbox daemon of %s: %w", a.Name, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil || pid < 0 {
		return 0, fmt.Errorf("read the main process of the sandbox daemon of %s: systemd said %q", a.Name, strings.TrimSpace(string(res.Stdout)))
	}
	return pid, nil
}

// bootoutNotLoaded reports a launchctl bootout that failed because the agent
// is not loaded: it is stopped already.
func bootoutNotLoaded(res CommandResult, err error) bool {
	return launchdNotLoaded(err) || strings.Contains(string(res.Stderr), "Could not find") || strings.Contains(string(res.Stderr), "No such process")
}

func (o *commandUserOps) Reload(ctx context.Context, a SandboxAccount) error {
	if o.env.GOOS != "linux" {
		return nil
	}
	_, err := o.runAs(ctx, a, userCommandTimeout, "/usr/bin/systemctl", "--user", "daemon-reload")
	return err
}

func (o *commandUserOps) Teardown(ctx context.Context, a SandboxAccount) error {
	res, err := o.runAs(ctx, a, teardownTimeout, o.env.launcherTarget(), "sandbox", "teardown", "--yes")
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
	state, kept := l.openShellStateForSettle()
	if kept {
		defer l.discardKeptOpenShellStateAfterSave(state, state.Applied != nil || len(state.Pending) != 0)
	}
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
		l.result.AddWarning(stateWriteCode(err, codeState), "could not record the applied sandbox configuration: "+err.Error())
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
		l.result.AddWarning(stateWriteCode(err, codeState), "could not record the sandbox changes still waiting: "+err.Error())
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
		if env.sandboxAccountRemoved(ctx, account) {
			// The account was removed from this computer: no user manager,
			// daemon or sandbox of it can run again, so nothing waits, and
			// the warning would never clear (its status and its drain both
			// fail on the missing account, GAP-0155). Its sandbox records
			// stay for the administrator's purge.
			delete(state.Pending, key)
			l.openshellChange("dropped the pending %s change of %s: the account no longer exists on this computer", entry.Kind, entry.User)
			continue
		}
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
			entry.Hold = err.Error()
			entry.Reason = entry.reasonBase() + " (the lifecycle could not tell whether a sandbox of this account runs: " + err.Error() + ")"
			state.Pending[key] = entry
			continue
		case status.Active && status.busy() > 0:
			entry.Hold = ""
			// Not only the running ones: a switch or stop takes the
			// account's OpenShell gateway down, under a MicroVM that
			// completed or is in OpenShell's error state (until OpenShell
			// reports it stopped: openshell.HoldsGateway) or a sandbox
			// still starting too.
			if status.Legacy {
				status = l.replaceLegacyDaemon(ctx, ops, account, status)
			}
			entry.Sandboxes = status.busy()
			state.Pending[key] = entry
			continue
		}
		if err := l.performAccountChange(ctx, ops, account, entry, status, cur); err != nil {
			entry.Hold = err.Error()
			entry.Reason = entry.reasonBase() + " (" + err.Error() + ")"
			state.Pending[key] = entry
			var held *drainHeld
			if errors.As(err, &held) {
				// Something started since the status check, or the drain
				// could not tell: the change waits, as for a running one.
				entry.Sandboxes = -1
				state.Pending[key] = entry
				l.result.AddWarning(codeSandboxPending, fmt.Sprintf("the %s change for %s waits: %v", entry.Kind, entry.User, held.err))
				continue
			}
			l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("could not apply the %s change for %s: %v; the next run tries again", entry.Kind, entry.User, err))
			continue
		}
		delete(state.Pending, key)
	}
}

// replaceLegacyDaemon puts the installed sandbox daemon in place of one
// that DefenseClaw before 1.0.4 started (SandboxStatus.Legacy, st) in the
// account a, whose sandboxes may hold compute, and returns the account's
// status after it. That daemon exits by itself once a package upgrade
// replaced its program or its settings changed (its pending restart), as
// soon as no sandbox of the account is ready, provisioning or starting, and
// its exit stops the account's OpenShell gateway: under a MicroVM that
// completed or is in OpenShell's error state, which it does not count, the
// VM ends with no flush (GAP-0868). The installed daemon counts those
// (sandboxapi.Status.Live) and keeps the gateway while they hold it. The
// old one is killed, so its exit runs nothing (StopKill alone: no unit is
// stopped, so neither the gateway nor any sandbox is), and the status
// starts the installed one. Its sandboxes' hooks fail closed in between.
func (l *lifecycle) replaceLegacyDaemon(ctx context.Context, ops SandboxUserOps, a SandboxAccount, st SandboxStatus) SandboxStatus {
	if err := ops.Stop(ctx, a, StopKill); err != nil {
		l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("could not end the sandbox daemon of %s that an earlier DefenseClaw started: once no sandbox of %s runs, "+
			"it stops the account's OpenShell gateway, also under a MicroVM that completed or is in OpenShell's error state, which loses what that VM has not written: %v; "+
			"the next run tries again", a.Name, a.Name, err))
		return st
	}
	next, err := ops.Status(ctx, a)
	switch {
	case err != nil:
		l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("ended the sandbox daemon of %s that an earlier DefenseClaw started, but could not ask the installed one: %v; "+
			"the account's next sandbox command starts it", a.Name, err))
		return st
	case next.Legacy:
		l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("the sandbox daemon of %s still runs the earlier DefenseClaw after it was ended; the next run tries again", a.Name))
		return next
	}
	l.openshellChange("replaced the sandbox daemon of %s, which an earlier DefenseClaw started, with this version's: its OpenShell gateway and its sandboxes keep running", a.Name)
	return next
}

// reasonBase is the reason without the retry detail settlePending appends.
func (p pending) reasonBase() string {
	if i := strings.Index(p.Reason, " ("); i > 0 {
		return p.Reason[:i]
	}
	return p.Reason
}

// drainHeld is a change that waits because the account's drain
// (SandboxUserOps.Drain) did not hold its gateway: err says why.
type drainHeld struct{ err error }

func (e *drainHeld) Error() string { return e.err.Error() }
func (e *drainHeld) Unwrap() error { return e.err }

// drainAccount holds the account's gateway (SandboxUserOps.Drain) for a stop
// of its units that stops its OpenShell gateway: the status check that let
// the change go came before it, and a sandbox started since would be
// stopped with the gateway, its MicroVM with no flush.
//
// It first stops the account's sandbox daemon and its socket, whatever
// DefenseClaw release the daemon runs. A daemon before 1.0.4 (one an
// upgrade left running) takes no lifecycle lock: through its socket it
// could start a sandbox after the drain's check, and the gateway's stop
// would end that one with no flush. A daemon that starts again (the
// socket or the launcher starts it on the next command) runs the
// installed DefenseClaw, which the drain's lock holds back, and the drain
// checks after the daemon is down, so it sees what the old daemon started
// before. That old daemon, which st (the status the change went on)
// describes, is killed, not stopped: its exit stops the gateway, under a
// MicroVM it started and that completed since the status (StopKill). The
// returned release lets the drain go, warning when it ended badly.
func (l *lifecycle) drainAccount(ctx context.Context, ops SandboxUserOps, a SandboxAccount, st SandboxStatus) (release func(), err error) {
	if err := ops.Stop(ctx, a, daemonStop(st, StopDaemon|StopSocket)); err != nil {
		return nil, fmt.Errorf("stop the sandbox daemon of %s before its gateway: %w", a.Name, err)
	}
	done, err := ops.Drain(ctx, a)
	if err != nil {
		return nil, &drainHeld{err: err}
	}
	// Every change that stops the gateway runs under this drain (a stop, a
	// switch, a LaunchAgent reload or label migration). launchd gives the
	// gateway agent no stop command, so on macOS the account syncs its
	// running MicroVMs here, before the bootout ends them (GAP-0380); on
	// Linux the gateway unit's second ExecStop does it.
	if s, ok := ops.(gatewayStopSyncer); ok && l.env.GOOS == "darwin" {
		s.syncBeforeGatewayStop(ctx, a)
	}
	return func() {
		if err := done(); err != nil {
			l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("the gateway of %s was stopped, but its drain ended badly: %v", a.Name, err))
		}
	}, nil
}

// performAccountChange applies one waiting change to an account that runs no
// sandbox. A change that stops the account's OpenShell gateway (a LaunchAgent
// reload, a stop, a switch) does so only under the account's drain
// (drainAccount), once its sandbox daemon is down. The stops under it name
// the daemon again: one the socket or the launcher started since runs the
// installed DefenseClaw, which the drain held back. st is the account's
// status the change went on.
func (l *lifecycle) performAccountChange(ctx context.Context, ops SandboxUserOps, a SandboxAccount, entry pending, st SandboxStatus, cur *openshellApplied) error {
	active := st.Active
	switch entry.Kind {
	case "launchd":
		jobs, err := l.env.loadedMacOSAgents(ctx, a)
		if err != nil {
			return err
		}
		if len(jobs) > 0 {
			release, err := l.drainAccount(ctx, ops, a, st)
			if err != nil {
				return err
			}
			defer release()
		}
		for _, job := range jobs {
			if job.old() {
				if err := l.env.migrateMacOSAgent(ctx, job, jobs); err != nil {
					return err
				}
				l.openshellChange("replaced %s of %s with %s, the label of this DefenseClaw's LaunchAgent, after its sandboxes stopped", job.domain+"/"+job.label, a.Name, job.current)
				continue
			}
			if err := l.env.reloadMacOSAgent(ctx, job, job.state.Failure(false) != ""); err != nil {
				return err
			}
			l.openshellChange("reloaded %s for %s after its sandboxes stopped", job.label, a.Name)
		}
	case "restart":
		if !active {
			return nil // it starts on the new inputs
		}
		// A daemon before 1.0.4 is killed: its exit would stop the
		// gateway, which this change keeps, under a MicroVM that completed.
		if err := ops.Stop(ctx, a, daemonStop(st, StopDaemon)); err != nil {
			return err
		}
		l.openshellChange("restarted the sandbox daemon of %s (no sandbox of this account was running); %s", a.Name, entry.reasonBase())
	case "stop":
		release, err := l.drainAccount(ctx, ops, a, st)
		if err != nil {
			return err
		}
		defer release()
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
		// Held until the previous setup is gone: a daemon the socket or the
		// launcher starts in between would run on it.
		release, err := l.drainAccount(ctx, ops, a, st)
		if err != nil {
			return err
		}
		defer release()
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

// errHomeNotAnswering is the openHome error of a status or verify run for a
// home that did not answer a bounded lookup: it is not opened in process.
var errHomeNotAnswering = errors.New("the home did not answer a lookup in time (a stalled home mount?), so it is not read")

// homeLookupAnswers looks a home up in a bounded stat(1) child. Tests
// replace it.
var homeLookupAnswers = enterprisestatus.PathAnswers

// homeAnswers reports whether a home may be looked up in this process. In
// status and verify the home's file system is asked first, in a bounded
// child, for a name that does not exist below the home: a lookup of a home
// on a stalled FUSE or NFS mount blocks a thread in the kernel, and status
// and verify never answered (GAP-1751). The home itself is no probe: its
// attributes can come from a cache while every lookup below it stalls. The
// answer is kept for the run; describeUnansweredHomes reports the homes
// that did not answer.
func (e *Env) homeAnswers(path string) bool {
	if !e.boundedHomeLookups {
		return true
	}
	path = filepath.Clean(path)
	e.homeLookups.Lock()
	defer e.homeLookups.Unlock()
	if answered, ok := e.homeLookups.answered[path]; ok {
		return answered
	}
	answered := homeLookupAnswers(filepath.Join(path, homeLookupProbeName()))
	if e.homeLookups.answered == nil {
		e.homeLookups.answered = map[string]bool{}
	}
	e.homeLookups.answered[path] = answered
	return answered
}

// unansweredHomes are the homes whose lookup did not answer in this run.
func (e *Env) unansweredHomes() []string {
	e.homeLookups.Lock()
	defer e.homeLookups.Unlock()
	var homes []string
	for home, answered := range e.homeLookups.answered {
		if !answered {
			homes = append(homes, home)
		}
	}
	sort.Strings(homes)
	return homes
}

// homeLookupProbeName is a name no home holds, new for each lookup, so no
// cached answer stands in for the file system's.
func homeLookupProbeName() string {
	return fmt.Sprintf(".defenseclaw-lookup-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// openHome opens the account's home directory, which must be owned by it.
func (e *Env) openHome(a SandboxAccount) (int, error) {
	path := e.P(filepath.Clean(a.Home))
	if !e.homeAnswers(path) {
		return -1, fmt.Errorf("account home %s: %w", path, errHomeNotAnswering)
	}
	fd, err := openOwnedDir(unix.AT_FDCWD, path, a.UID)
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
// trace is its sandbox state. The active setup decides whether the subsystem
// was on; after a failed uninstall of a recorded deployment, the kept setup
// does. It is empty when neither setup records an active subsystem.
func (l *lifecycle) sandboxAccounts(ctx context.Context) []SandboxAccount {
	env := l.env
	state := l.uninstallOpenShellState()
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
// deletes anything it did not create. The active setup, or the kept setup on
// a failed uninstall retry with a deployment record, decides whether it ran.
func (l *lifecycle) teardownOpenShell(ctx context.Context, accounts []SandboxAccount) {
	env, r := l.env, l.result
	state := l.uninstallOpenShellState()
	if state.Applied == nil && len(state.Pending) == 0 {
		// The sandbox subsystem was never on: no account has anything of
		// it. The macOS pkg still installs both LaunchAgents with it off
		// (planPackagedMacOSSandbox), and launchd loads them at every
		// sign-in, so they are unloaded all the same.
		l.bootOutMacOSAgents(ctx, nil)
		return
	}
	// A purge stops each account's units below, which on macOS boots its
	// agents out of one domain before the sweep runs. What is loaded is read
	// first, so the sweep names every agent the uninstall unloaded, also the
	// ones the account's own stop took out (GAP-0113).
	loaded := l.loadedMacOSAgents(ctx)
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
	l.bootOutMacOSAgents(ctx, loaded)
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

// macOSAgentJobs lists, in a fixed order, the domain/label of each of
// DefenseClaw's two LaunchAgents in the gui and the user launchd domain of
// every account that runs a process on the Mac.
func (l *lifecycle) macOSAgentJobs(ctx context.Context) ([]string, error) {
	res, err := l.env.Runner.Run(ctx, "ps", "-axo", "uid=")
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var uids []int
	for _, field := range strings.Fields(string(res.Stdout)) {
		uid, err := strconv.Atoi(field)
		// 501 is the first macOS user account; below it are the system's.
		if err != nil || uid < 501 || uid >= 4294967294 || seen[uid] {
			continue
		}
		seen[uid] = true
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	var jobs []string
	for _, uid := range uids {
		for _, domain := range []string{"gui/" + strconv.Itoa(uid), "user/" + strconv.Itoa(uid)} {
			// The installed label, the bare one of 1.0.0 to 1.0.3, and any
			// earlier one the domain still lists (GAP-0206).
			listing, _ := l.env.Runner.Run(ctx, "launchctl", "print", domain)
			for _, base := range openshell.LaunchAgentBases {
				labels := domainAgentLabels(listing.Stdout, base, l.env.launchAgentLabel(base))
				if !slices.Contains(labels, base) {
					labels = append(labels, base)
				}
				for _, label := range labels {
					jobs = append(jobs, domain+"/"+label)
				}
			}
		}
	}
	return jobs, nil
}

// loadedMacOSAgents reads which of DefenseClaw's LaunchAgents launchd has
// loaded in the signed-in accounts, before anything of the uninstall stops
// them. Only a job launchd prints counts as loaded; one it cannot say about
// does not, so the uninstall never claims to have unloaded it. A listing
// that fails is left to the sweep to report.
func (l *lifecycle) loadedMacOSAgents(ctx context.Context) map[string]bool {
	if l.env.GOOS != "darwin" {
		return nil
	}
	jobs, err := l.macOSAgentJobs(ctx)
	if err != nil {
		return nil
	}
	loaded := map[string]bool{}
	for _, job := range jobs {
		if _, err := l.env.Runner.Run(ctx, "launchctl", "print", job); err == nil {
			loaded[job] = true
		}
	}
	return loaded
}

// bootOutMacOSAgents boots DefenseClaw's two LaunchAgents out of the gui
// and the user launchd domain of every account that runs a process on the
// Mac, once the accounts' own teardown above is done and before the plists
// and the binary they name go. launchd loads both agents (they are in
// /Library/LaunchAgents) for every account that signs in, also one the
// deployment never served, and a job can stay loaded in either domain, while
// Stop boots out only one of them; a job left loaded named a deleted plist
// and binary until the account logged out (#1210). An agent that is not
// loaded is fine. The change line names every agent the uninstall unloaded:
// the ones booted out here and the ones in loadedBefore (read before the
// accounts' teardown) that an account's own stop already took out. What
// could not be unloaded is a warning: it goes at the account's next logout.
func (l *lifecycle) bootOutMacOSAgents(ctx context.Context, loadedBefore map[string]bool) {
	env, r := l.env, l.result
	if env.GOOS != "darwin" {
		return
	}
	jobs, err := l.macOSAgentJobs(ctx)
	if err != nil {
		r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not list the accounts that run processes to unload the DefenseClaw LaunchAgents (%v); a loaded one unloads at that account's next logout", err))
		return
	}
	var unloaded, failed []string
	for _, job := range jobs {
		res, err := env.Runner.Run(ctx, "launchctl", "bootout", job)
		message := string(res.Stdout) + " " + string(res.Stderr)
		switch {
		case err == nil:
			unloaded = append(unloaded, job)
		case launchdNotLoaded(err), strings.Contains(message, "Could not find"), strings.Contains(message, "No such process"),
			guiDomainUnsupported(res, message+" "+err.Error()):
			// Not loaded there (any more), or no GUI session.
			if loadedBefore[job] {
				unloaded = append(unloaded, job)
			}
		default:
			failed = append(failed, fmt.Sprintf("%s (%v)", job, err))
		}
	}
	if len(unloaded) > 0 {
		r.Changes = append(r.Changes, "unloaded the DefenseClaw sandbox LaunchAgents of the signed-in accounts ("+strings.Join(unloaded, ", ")+")")
	}
	if len(failed) > 0 {
		r.AddWarning(codeSandboxUserState, "could not unload "+strings.Join(failed, ", ")+"; each unloads at that account's next logout, or run `launchctl bootout <domain>/<label>` as root")
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
	if st, err := ops.Status(ctx, a); err != nil || st.busy() > 0 {
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

// removeOpenShellMachineState removes the lifecycle's sandbox files that no
// deployment record lists. When keepRecord is true it moves the applied
// setup record aside for the kept sandboxes, where only settleOpenShell reads
// it during activation; a retry of a failed uninstall keeps that valid moved
// record. The OpenShell directory goes unless the package owns it.
func (e *Env) removeOpenShellMachineState(channel string, keepRecord bool) (bool, error) {
	_ = removeFile(e.P(e.prerequisitesPath()))
	var kept bool
	var err error
	if keepRecord {
		if kept, err = e.keepOpenShellState(); err != nil {
			// Nothing stale stays behind: the record goes, as it did before
			// kept sandboxes carried it.
			_ = removeFile(e.openshellStatePath())
		}
	} else {
		_ = removeFile(e.openshellStatePath())
		if err = removeFile(e.openshellKeptStatePath()); err != nil {
			err = fmt.Errorf("could not remove the stale record of the sandbox setup %s: %w", e.openshellKeptStatePath(), err)
		}
	}
	if !e.packageOwnsOpenShellDir(channel) {
		_ = removeDirIfEmpty(e.P(e.openshellDir()))
	}
	return kept, err
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

// sandboxAccountRemoved reports whether the host's account database answers
// that a is gone: `getent passwd UID` exits 2 (not found) on Linux, and
// `dscl . -read /Users/NAME` finds no record on macOS. A lookup that fails
// any other way (a directory outage, for one) is no answer, so a change an
// account waits for is never dropped for a directory that did not answer.
func (e *Env) sandboxAccountRemoved(ctx context.Context, a SandboxAccount) bool {
	if a.UID <= 0 {
		return false
	}
	if e.GOOS == "darwin" {
		if !plainAccountName(a.Name) {
			return false
		}
		_, err := e.Runner.Run(ctx, "dscl", ".", "-read", "/Users/"+a.Name, "UniqueID")
		return err != nil && strings.Contains(err.Error(), "eDSRecordNotFound")
	}
	res, err := e.Runner.Run(ctx, "getent", "passwd", strconv.Itoa(a.UID))
	return err != nil && res.ExitCode == 2
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
