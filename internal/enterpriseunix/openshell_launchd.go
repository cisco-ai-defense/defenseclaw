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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func launchAgentDisabled(raw []byte, label string) bool {
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " => ")
		if !ok || strings.Trim(key, "\" ") != label {
			continue
		}
		return strings.HasPrefix(value, "disabled") || strings.HasPrefix(value, "true")
	}
	return false
}

func (e *Env) gatewayFileIdentity() (string, error) {
	path := e.P(filepath.Join(e.Layout.BinDir, binGateway))
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s has no inode identity", path)
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}

// refreshLaunchAgentPrograms gives the gateway file the LaunchAgents execute
// a new file with the same bytes (GAP-0049). macOS keeps the code signature
// it checked with a file, so a program file rewritten in place can be killed
// for code signing at every later start, and a bootout and bootstrap alone
// start that same file again. The lifecycle has already checked the gateway
// against the deployment record, and launchAgentProgram checks the package
// copy against the gateway.
func (e *Env) refreshLaunchAgentPrograms() error {
	program, err := e.launchAgentProgram()
	if err != nil {
		return err
	}
	paths := []string{filepath.Join(e.Layout.BinDir, binGateway)}
	if program != paths[0] {
		paths = append(paths, program)
	}
	for _, path := range paths {
		if err := e.refreshFile(e.P(path)); err != nil {
			return fmt.Errorf("give %s a new file: %w", path, err)
		}
	}
	return nil
}

type loadedLaunchAgent struct {
	domain string
	label  string
	// base is the label's base (labelSandbox or labelOpenShellGateway) and
	// current the installed label of that base; a job of another label is
	// one an earlier DefenseClaw loaded (GAP-0206).
	base, current string
	state         openshell.LaunchAgentState
}

// old reports a job of an earlier label, whose plist is gone.
func (j loadedLaunchAgent) old() bool { return j.label != j.current }

// loadedMacOSAgents inspects only the two DefenseClaw jobs in both account
// domains: the installed label of each and any earlier label of it the
// domain still lists. A job can remain loaded in either domain after the
// session changes.
func (e *Env) loadedMacOSAgents(ctx context.Context, a SandboxAccount) ([]loadedLaunchAgent, error) {
	var out []loadedLaunchAgent
	uid := strconv.Itoa(a.UID)
	for _, domain := range []string{"gui/" + uid, "user/" + uid} {
		listing, exists, err := e.macOSAgentDomain(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("inspect LaunchAgent domain %s of %s: %w", domain, a.Name, err)
		}
		if !exists {
			continue
		}
		disabled, err := e.Runner.Run(ctx, "launchctl", "print-disabled", domain)
		if err != nil {
			return nil, fmt.Errorf("check disabled LaunchAgents for %s in %s: %w", a.Name, domain, err)
		}
		for _, base := range openshell.LaunchAgentBases {
			current := e.launchAgentLabel(base)
			for _, label := range domainAgentLabels(listing, base, current) {
				if launchAgentDisabled(disabled.Stdout, label) {
					continue
				}
				res, err := e.Runner.Run(ctx, "launchctl", "print", domain+"/"+label)
				if err != nil {
					if launchdNotLoaded(err) || strings.Contains(string(res.Stderr), "Could not find service") || strings.Contains(string(res.Stderr), "No such process") {
						continue
					}
					return nil, fmt.Errorf("inspect LaunchAgent %s of %s in %s: %w", label, a.Name, domain, err)
				}
				state := openshell.ParseLaunchAgentState(res.Stdout)
				if state.State == "" {
					return nil, fmt.Errorf("inspect LaunchAgent %s of %s in %s: launchctl reported no service state", label, a.Name, domain)
				}
				out = append(out, loadedLaunchAgent{domain: domain, label: label, base: base, current: current, state: state})
			}
		}
	}
	return out, nil
}

func (e *Env) macOSAgentDomainExists(ctx context.Context, domain string) (bool, error) {
	_, exists, err := e.macOSAgentDomain(ctx, domain)
	return exists, err
}

// macOSAgentDomain returns launchctl's listing of a domain and whether the
// domain exists; loadedMacOSAgents reads earlier LaunchAgent labels from
// the listing (GAP-0206).
func (e *Env) macOSAgentDomain(ctx context.Context, domain string) ([]byte, bool, error) {
	res, err := e.Runner.Run(ctx, "launchctl", "print", domain)
	if err != nil {
		message := string(res.Stdout) + " " + string(res.Stderr) + " " + err.Error()
		if strings.Contains(message, "Could not find domain") || strings.Contains(message, "No such process") || launchdNotLoaded(err) {
			return nil, false, nil
		}
		if strings.HasPrefix(domain, "gui/") && guiDomainUnsupported(res, message) {
			// macOS can leave /dev/console owned by the last logged-out
			// user. This answer means that user has no live GUI domain,
			// regardless of the console's owner (GAP-0316 / GAP-0260).
			return nil, false, nil
		}
		return nil, false, err
	}
	if !strings.Contains(string(res.Stdout), domain+" = {") {
		return nil, false, nil
	}
	return res.Stdout, true, nil
}

// domainAgentLabels are the labels of base to look at in a domain: the
// installed one first, then each earlier one the domain's listing names.
func domainAgentLabels(listing []byte, base, current string) []string {
	labels := []string{current}
	for _, label := range openshell.LaunchAgentLabelsIn(listing, base) {
		if label != current {
			labels = append(labels, label)
		}
	}
	return labels
}

// guiDomainUnsupported matches launchd's answer for the gui domain of an
// account without a GUI session on macOS 15: exit 125 with "Domain does not
// support specified action" rather than "Could not find domain" (GAP-0639).
func guiDomainUnsupported(res CommandResult, message string) bool {
	return res.ExitCode == 125 && strings.Contains(message, "Domain does not support specified action")
}

// activeMacOSConsoleSession requires both a live GUI domain and the current
// console owner. Neither an inactive fast-user-switch domain nor a stale
// /dev/console owner alone establishes an active GUI console session.
// It is used only for reload advice, never for hook authorization.
func (e *Env) activeMacOSConsoleSession(ctx context.Context, uid int) (bool, error) {
	_, exists, err := e.macOSAgentDomain(ctx, "gui/"+strconv.Itoa(uid))
	if err != nil || !exists {
		return false, err
	}
	owner, _, err := e.OwnerOf(e.P("/dev/console"))
	return err == nil && owner == uid, err
}

// migrateMacOSAgent boots out a job of an earlier label and, unless the
// domain has loaded the installed label already, bootstraps that label in
// its place, idle: macOS killed the earlier label's start for code signing
// after an upgrade whatever was reloaded (GAP-0206).
func (e *Env) migrateMacOSAgent(ctx context.Context, job loadedLaunchAgent, loaded []loadedLaunchAgent) error {
	target := job.domain + "/" + job.label
	if res, err := e.Runner.Run(ctx, "launchctl", "bootout", target); err != nil && !bootoutNotLoaded(res, err) {
		return fmt.Errorf("boot out %s: %w", target, err)
	}
	for _, other := range loaded {
		if other.domain == job.domain && other.label == job.current {
			return nil
		}
	}
	return e.bootstrapMacOSAgent(ctx, loadedLaunchAgent{domain: job.domain, label: job.current, base: job.base, current: job.current}, false)
}

// reloadMacOSAgent uses the same bootout/bootstrap sequence that recovered the
// field failure. A failed job is kickstarted because neither plist has
// RunAtLoad; an idle job remains idle until its next sandbox command.
func (e *Env) reloadMacOSAgent(ctx context.Context, job loadedLaunchAgent, failed bool) error {
	target := job.domain + "/" + job.label
	// The account's drain boots the sandbox agent out first
	// (drainAccount): one that is not loaded any more is out already.
	if res, err := e.Runner.Run(ctx, "launchctl", "bootout", target); err != nil && !bootoutNotLoaded(res, err) {
		return fmt.Errorf("boot out %s: %w", target, err)
	}
	return e.bootstrapMacOSAgent(ctx, job, failed)
}

// bootstrapMacOSAgent loads the job's plist into its domain, starts a failed
// job and checks the result.
func (e *Env) bootstrapMacOSAgent(ctx context.Context, job loadedLaunchAgent, failed bool) error {
	target := job.domain + "/" + job.label
	plist := e.P(filepath.Join(openshell.LaunchAgentsDir, job.label+".plist"))
	if _, err := e.Runner.Run(ctx, "launchctl", "bootstrap", job.domain, plist); err != nil {
		return fmt.Errorf("bootstrap %s: %w", target, err)
	}
	if failed {
		if _, err := e.Runner.Run(ctx, "launchctl", "kickstart", target); err != nil {
			return fmt.Errorf("start %s after bootstrap: %w", target, err)
		}
	}
	// launchctl can acknowledge a start before the process becomes running.
	// A short bounded poll checks the result without delaying a healthy install.
	for attempt := 0; attempt < 5; attempt++ {
		res, err := e.Runner.Run(ctx, "launchctl", "print", target)
		if err != nil {
			return fmt.Errorf("check %s after bootstrap: %w", target, err)
		}
		state := openshell.ParseLaunchAgentState(res.Stdout)
		problem := state.Failure(failed && job.base == labelOpenShellGateway)
		if problem == "" && (!failed || state.State == "running" || job.base == labelSandbox && state.Runs > 0 && state.ExitCode == "0") {
			return nil
		}
		if attempt == 4 || !failed {
			return fmt.Errorf("%s after bootstrap: %s (state %q)", target, problem, state.State)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

// reconcileMacOSAgents runs after the deployment commits or an ensure no-op.
// The state holds the gateway inode seen at the last reload, so an old 1.0.1
// state (no identity) and every pkg replacement reload once, while a second
// ensure of the same inode leaves healthy jobs untouched. A job killed for
// code signing first gets a new gateway file, then the same reload.
func (l *lifecycle) reconcileMacOSAgents(ctx context.Context, state *openshellState) bool {
	e := l.env
	if e.GOOS != "darwin" || state.Applied == nil || !state.Applied.Enabled {
		return false
	}
	identity, err := e.gatewayFileIdentity()
	if err != nil {
		l.result.AddWarning(codeSandboxUserState, "could not inspect the LaunchAgent gateway binary: "+err.Error())
		return false
	}
	changed := identity != state.GatewayIdentity
	refreshed := false
	for _, a := range e.sandboxOps().Accounts(ctx) {
		if !e.usableSandboxAccount(a) {
			continue
		}
		jobs, err := e.loadedMacOSAgents(ctx, a)
		if err != nil {
			if changed {
				key := strconv.Itoa(a.UID)
				if old, waiting := state.Pending[key]; !waiting || old.Kind == "launchd" || old.Kind == "restart" {
					state.Pending[key] = pending{User: a.Name, UID: a.UID, Home: a.Home, Kind: "launchd", Reason: "the signed gateway binary changed (" + err.Error() + ")", Since: e.Now().UTC().Format(time.RFC3339), Sandboxes: -1}
				}
			}
			l.result.AddWarning(codeSandboxUserState, err.Error())
			continue
		}
		if len(jobs) == 0 {
			// No DefenseClaw job is loaded in either domain (a logged-out
			// account): launchd loads the current program at the next login,
			// so a reload recorded earlier has nothing left to do.
			key := strconv.Itoa(a.UID)
			if old, waiting := state.Pending[key]; waiting && old.Kind == "launchd" {
				delete(state.Pending, key)
			}
			continue
		}
		var status SandboxStatus
		var statusErr error
		statusChecked := false
		for _, job := range jobs {
			if changed || job.old() || job.base == labelOpenShellGateway && job.state.State != "running" {
				status, statusErr = e.sandboxOps().Status(ctx, a)
				statusChecked = true
				break
			}
		}
		var needed []loadedLaunchAgent
		for _, job := range jobs {
			if changed || job.old() || job.state.Failure(job.base == labelOpenShellGateway && status.Running > 0) != "" {
				needed = append(needed, job)
			}
		}
		if len(needed) == 0 {
			continue
		}
		if !statusChecked {
			status, statusErr = e.sandboxOps().Status(ctx, a)
		}
		key := strconv.Itoa(a.UID)
		if old, waiting := state.Pending[key]; waiting {
			if old.Kind == "switch" || old.Kind == "stop" {
				// Those changes already boot out the gateway when safe.
				continue
			}
			if old.Kind == "restart" {
				old.Kind = "launchd"
				old.Reason = "the signed gateway binary or a loaded LaunchAgent changed"
				state.Pending[key] = old
			}
		}
		if statusErr != nil || status.busy() > 0 {
			count := status.busy()
			if statusErr != nil {
				count = -1
			}
			state.Pending[key] = pending{User: a.Name, UID: a.UID, Home: a.Home, Kind: "launchd", Reason: "the signed gateway binary or a loaded LaunchAgent changed", Since: e.Now().UTC().Format(time.RFC3339), Sandboxes: count}
			l.result.AddWarning(codeSandboxPending, fmt.Sprintf("LaunchAgent reload for %s waits for its running sandboxes to stop", a.Name))
			continue
		}
		// A reload of a job that runs stops it, the gateway's with its
		// MicroVMs: under the account's drain only, which checks again what
		// the status above read.
		release, derr := l.drainAccount(ctx, e.sandboxOps(), a, status)
		if derr != nil {
			state.Pending[key] = pending{User: a.Name, UID: a.UID, Home: a.Home, Kind: "launchd", Reason: "the signed gateway binary or a loaded LaunchAgent changed (" + derr.Error() + ")",
				Since: e.Now().UTC().Format(time.RFC3339), Sandboxes: -1}
			l.result.AddWarning(codeSandboxPending, fmt.Sprintf("LaunchAgent reload for %s waits: %v", a.Name, derr))
			continue
		}
		var failed error
		for _, job := range needed {
			if job.old() {
				if err := e.migrateMacOSAgent(ctx, job, jobs); err != nil {
					failed = err
					break
				}
				l.openshellChange("replaced %s of %s with %s, the label of this DefenseClaw's LaunchAgent", job.domain+"/"+job.label, a.Name, job.current)
				continue
			}
			if job.state.CodeSigningKilled() && !refreshed {
				if err := e.refreshLaunchAgentPrograms(); err != nil {
					failed = err
					break
				}
				refreshed = true
				l.openshellChange("gave the LaunchAgent gateway a new file after macOS killed %s of %s for code signing", job.label, a.Name)
			}
			if err := e.reloadMacOSAgent(ctx, job, job.state.Failure(job.base == labelOpenShellGateway && status.Running > 0) != ""); err != nil {
				failed = err
				break
			}
			l.openshellChange("reloaded %s for %s after its program or job failed", job.label, a.Name)
		}
		release()
		if failed != nil {
			state.Pending[key] = pending{User: a.Name, UID: a.UID, Home: a.Home, Kind: "launchd", Reason: "the signed gateway binary or a loaded LaunchAgent changed (" + failed.Error() + ")", Since: e.Now().UTC().Format(time.RFC3339)}
			next := "repair retries it"
			if l.opts.Action == ActionRepair {
				next = "reinstall a signed DefenseClaw package, then run status and verify; if it still fails, collect launchctl and codesign diagnostics"
			}
			l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("could not reload the LaunchAgent of %s: %v; %s", a.Name, failed, next))
		} else {
			delete(state.Pending, key)
		}
	}
	if refreshed {
		// Record the new file, so the next ensure does not reload the
		// healthy jobs again.
		if current, err := e.gatewayFileIdentity(); err == nil {
			identity = current
		}
	}
	state.GatewayIdentity = identity
	return changed
}

// describeMacOSAgents is read-only for status and verify. An ensure from a
// package warns and records a failed reload for repair instead of failing the
// package receipt solely because one user's loaded job cannot be reloaded.
func (l *lifecycle) describeMacOSAgents(ctx context.Context) {
	if l.env.GOOS != "darwin" {
		return
	}
	for _, a := range l.env.sandboxOps().Accounts(ctx) {
		if !l.env.usableSandboxAccount(a) {
			continue
		}
		jobs, err := l.env.loadedMacOSAgents(ctx, a)
		if err != nil {
			if l.opts.Action == ActionEnsure && l.opts.FromPackage {
				l.result.AddWarning(codeSandboxUserState, err.Error())
			} else {
				l.result.AddError(codeSandboxUserState, err.Error())
				l.result.SecurityComplete = false
			}
			continue
		}
		var running int
		for _, job := range jobs {
			if job.base == labelOpenShellGateway && job.state.State != "running" {
				if status, err := l.env.sandboxOps().Status(ctx, a); err == nil {
					running = status.Running
				}
				break
			}
		}
		for _, job := range jobs {
			if job.old() {
				// The reconcile replaces it once the account's sandboxes
				// have stopped (a pending launchd reload says so).
				l.result.Services = append(l.result.Services, enterprisestatus.Service{Name: "sandbox " + a.Name + " " + job.domain + "/" + job.label, Kind: sandboxRowKind, State: "earlier label: " + job.state.State})
				l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("LaunchAgent %s of %s (uid %d) in %s is the label of an earlier DefenseClaw (%s); `%s` replaces it with %s once no sandbox of the account runs",
					job.label, a.Name, a.UID, job.domain, job.state.State, l.env.lifecycleCommand(ActionRepair), job.current))
				continue
			}
			if why := job.state.Failure(job.base == labelOpenShellGateway && running > 0); why != "" {
				next := "run `" + l.env.lifecycleCommand(ActionRepair) + "`"
				if job.state.CodeSigningKilled() {
					next += ": it gives the LaunchAgent gateway a new file and reloads the job"
				}
				if l.opts.Action == ActionRepair {
					next = "reinstall a signed DefenseClaw package, then run status and verify; if it still fails, collect launchctl and codesign diagnostics"
				}
				message := fmt.Sprintf("LaunchAgent %s of %s (uid %d) in %s failed: %s; %s", job.label, a.Name, a.UID, job.domain, why, next)
				l.result.Services = append(l.result.Services, enterprisestatus.Service{Name: "sandbox " + a.Name + " " + job.domain + "/" + job.label, Kind: sandboxRowKind, State: "failed: " + why})
				l.result.SecurityComplete = false
				if l.opts.Action == ActionEnsure && l.opts.FromPackage {
					l.result.AddWarning(codeSandboxUserState, message)
				} else {
					l.result.AddError(codeSandboxUserState, message)
				}
			} else if notice := job.state.Notice(); notice != "" {
				l.result.Services = append(l.result.Services, enterprisestatus.Service{Name: "sandbox " + a.Name + " " + job.domain + "/" + job.label, Kind: sandboxRowKind, State: "idle: " + notice})
				l.result.AddWarning(codeSandboxUserState, fmt.Sprintf("LaunchAgent %s of %s (uid %d) in %s is loaded and idle: %s", job.label, a.Name, a.UID, job.domain, notice))
			}
		}
	}
}
