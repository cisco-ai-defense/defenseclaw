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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// ledgerFreshness mirrors the gateway's guardian authorization window.
const ledgerFreshness = 5 * time.Minute

// codeUnitFailed names a DefenseClaw oneshot unit systemd reports failed.
const codeUnitFailed = "unit_failed"

// codeNotStarted names a deployment installed with --no-start.
const codeNotStarted = "not_started"

// readOnly handles status and verify.
func (l *lifecycle) readOnly(ctx context.Context) int {
	env, r := l.env, l.result
	// status waits for a run that holds the lock the same way, because the
	// run stops and starts the services (GAP-2246). It still reports the
	// recorded deployment below, so detection sees it installed.
	statusBusy := false
	busyMessage := ""
	if env.waitForApplyTrigger(ctx) {
		// The apply trigger is applying a changed config.yaml, secret or
		// policy file: until it commits, the files differ from the record and
		// the gateway may not read the new file yet. status and verify said
		// "modified after install ... run repair" for those seconds, and a
		// repair then fought the apply for the lock (GAP-0919).
		if l.opts.Action == ActionVerify {
			r.AddError(codeBusy, applyingConfigChange(ActionVerify))
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
		statusBusy, busyMessage = true, applyingConfigChange(ActionStatus)
	} else if l.opts.Action == ActionStatus && env.Geteuid() == 0 {
		lock, err := env.acquireLock(ctx)
		statusBusy = errors.Is(err, errLockBusy)
		lock.release()
	}
	if l.opts.Action == ActionVerify && env.packageTransactionInProgress() {
		// The package scripts are replacing the deployment: its own ensure
		// applies and verifies the new package. A check now compares the new
		// package with the deployment the old one applied, and its failure
		// left the daily verify unit failed after a healthy upgrade
		// (GAP-0585).
		r.AddError(codeBusy, "a DefenseClaw package install or upgrade is in progress, and its own lifecycle run applies and verifies the new package; this verify run skipped its checks")
		return enterprisestatus.BusyExitCode(env.GOOS)
	}
	if l.opts.Action == ActionVerify {
		// The daily verify can start while another run changes the
		// deployment: ensure restarts the timer, and a Persistent timer past
		// its daily time fires at once. verify waits for that run like any
		// lifecycle action, then releases the lock so it never holds up a
		// change; a run that outlasts the wait is busy, not a failed check.
		lock, err := env.acquireLock(ctx)
		if errors.Is(err, errLockBusy) {
			r.AddError(codeBusy, err.Error()+"; "+readOnlyBusyNextStep(env.LockTimeout, ActionVerify))
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
		lock.release()
	}
	record, err := env.loadDeployment()
	if err != nil {
		if errors.Is(err, os.ErrPermission) && env.Geteuid() != 0 {
			// A standard user cannot read the root-only deployment record;
			// the lstat error and installed=false read as a missing
			// deployment (GAP-1201).
			r.AddError(codeNotRoot, "run this command as root (sudo or the MDM agent); a standard user cannot read the deployment record")
			return 0
		}
		r.AddError(codeState, err.Error())
		return 0
	}
	pending, _ := env.loadPending()
	if pending != nil {
		r.TransactionPending = true
	}
	if statusBusy {
		if record != nil {
			r.Installed = true
			r.InstalledVersion = record.ProductVersion
		}
		if busyMessage == "" {
			busyMessage = errLockBusy.Error() + "; " + readOnlyBusyNextStep(env.LockTimeout, ActionStatus)
		}
		r.AddError(codeBusy, busyMessage)
		return enterprisestatus.BusyExitCode(env.GOOS)
	}
	if record == nil {
		r.Installed = false
		failure := env.lastPackageInstallFailure()
		if l.opts.Action == ActionVerify {
			message := "DefenseClaw enterprise is not installed"
			if failure != "" {
				message += "; the package's own install run failed (see the " + codePackageInstallFailed + " warning)"
			}
			r.AddError(codeNotInstalled, message)
		}
		env.warnPackageInstallFailed(r, failure)
		if leftovers := env.unmanagedLeftovers(env.Services, ChannelPayload); len(leftovers) > 0 {
			r.AddWarning(codeLeftovers, "DefenseClaw machine state exists without a committed deployment: "+strings.Join(leftovers, ", ")+"; "+env.leftoversNextStep(ctx, failure != ""))
		}
		return 0
	}
	r.Installed = true
	r.InstalledVersion = record.ProductVersion
	if failure := env.lastPackageInstallFailure(); failure != "" {
		// A package reinstall or upgrade the lifecycle refused (a full disk,
		// a config it rejected) printed Complete and left status and verify
		// green; only last-package-result.json said so (GAP-0469). The
		// result stays until a later run succeeds.
		r.AddWarning(codePackageInstallFailed, "the last package install, reinstall or upgrade did not apply: "+failure+
			"; the deployment keeps running as it was. Fix that, then apply the package with `"+env.lifecycleCommand(ActionEnsure)+" --from-package`")
	}
	strict := l.opts.Action == ActionVerify
	problems := l.verifyInstalled(ctx, record, strict)
	l.warnLowDiskSpace()
	dropInProblems, dropIns := l.unitDropIns(ctx, record)
	problems = append(problems, dropInProblems...)
	if len(dropIns) > 0 {
		r.AddWarning(codeUnitDropIn, "local drop-ins change DefenseClaw units: "+strings.Join(dropIns, ", ")+"; they keep the units' account, sandbox and config")
	}
	l.describe(ctx, record, true)
	l.warnSELinuxConfinedUsers()
	problems = append(problems, l.describeMachinePolicy(record)...)
	if machinePolicyIncomplete(r) {
		r.SecurityComplete = false
	}
	if strict {
		l.warnUnprivilegedUserNamespaces()
	}
	if strict {
		// An agent the guardian or the enumerator could not protect for one
		// account (an unverified hook contract, an agent it could not enroll)
		// stays a warning for that account: the rest of the host is
		// compliant, as on Windows.
		// Machine-policy gaps (a removed vendor policy) and a config that
		// enables no connector for the eligible users fail verify only;
		// status reports them as warnings with security_complete false.
		for _, warning := range r.Warnings {
			if warning.Code == codeMachinePolicyIncomplete || warning.Code == codeGuardianTargetFailed || warning.Code == codeConfigRejected ||
				warning.Code == codeNoConnectorsEnabled {
				problems = append(problems, warning.Message)
			}
		}
	}
	if pending != nil {
		// Mid-transaction files differ from the record because the run was
		// interrupted, not because someone edited them (GAP-0468).
		problems = append([]string{env.interruptedTransactionProblem(pending)}, withoutTransactionDrift(problems)...)
	}
	// A problem either action finds makes the deployment unhealthy, and
	// both exit 1 for it; status leaves out verify's stricter checks.
	reported := map[string]bool{}
	for _, problem := range problems {
		if !reported[problem] {
			reported[problem] = true
			r.AddError(codeVerify, problem)
		}
	}
	if len(problems) > 0 {
		// security_complete requires no errors; describe set it before
		// these were added, so a missing hook binary read complete
		// (GAP-1217).
		r.SecurityComplete = false
	}
	if record.NoStart {
		// Nothing runs, so no agent is protected; ensure reported it as a
		// warning, and status and verify read ok with every service
		// not_loaded (GAP-0542).
		r.AddError(codeNotStarted, "the deployment was installed with --no-start, so its services are not running and agents are not protected; run `"+
			env.lifecycleCommand(ActionRepair)+"` or `"+env.lifecycleCommand(ActionEnsure)+"` to start them")
	}
	if !record.NoStart && !r.Readiness.Gateway {
		// A gateway that is down because the installed binary refuses the
		// installed config is not helped by repair, which applies the same
		// config again: say why and what to fix.
		if refusal := l.configRefusal(ctx); refusal != "" {
			r.AddError(codeConfigRefused, env.configRefusedMessage(refusal))
		}
	}
	if strict && r.TransactionPending {
		r.AddError(codeVerify, "a lifecycle transaction is pending; "+l.recoverPendingFromVerify(ctx))
	}
	return 0
}

// applyTriggerRunning reports whether the apply trigger (the run the path
// unit or launchd job starts after config.yaml, a secret or a policy file
// changed) is running now.
func (e *Env) applyTriggerRunning(ctx context.Context) bool {
	name := unitApplyService
	if e.GOOS == "darwin" {
		name = labelApply
	}
	if e.SelfUnit == name {
		return false
	}
	status, err := e.Services.Status(ctx, Unit{Name: name})
	if err != nil {
		return false
	}
	if e.GOOS == "darwin" {
		return status.State == "running"
	}
	return strings.HasPrefix(status.State, "activating")
}

// waitForApplyTrigger waits up to LockTimeout for a running apply trigger to
// finish, the way status and verify wait for the lifecycle lock, and reports
// whether it is still running. A no-op apply launchd started a few seconds
// after an ensure --config made detect.sh --require-healthy print busy on a
// healthy host when verify did not wait for it.
func (e *Env) waitForApplyTrigger(ctx context.Context) bool {
	deadline := e.Now().Add(e.LockTimeout)
	for e.applyTriggerRunning(ctx) {
		if !e.Now().Before(deadline) {
			return true
		}
		select {
		case <-ctx.Done():
			return true
		case <-time.After(e.PollInterval):
		}
	}
	return false
}

// applyingConfigChange is the lifecycle_busy message of a status or verify
// that ran while the apply trigger applied a configuration change.
func applyingConfigChange(action string) string {
	return "a configuration change is being applied (the apply trigger runs ensure after config.yaml, a secret or a policy file changed), so " +
		action + " checked nothing but the installed version; this is not a failure and needs no repair: wait for it to finish (usually under a minute), then rerun " + action
}

// clearSupersededUnitFailures clears the failed state an earlier lifecycle
// run left on the apply or daily verify oneshot once this run has left the
// deployment healthy (committed, or found up to date). Left in place, every
// verify kept warning unit_failed after a refused package upgrade was
// recovered, or after a package upgrade interrupted the daily verify, until
// an administrator ran systemctl reset-failed (GAP-0423, GAP-0585).
func (l *lifecycle) clearSupersededUnitFailures(ctx context.Context) {
	env := l.env
	resetter, ok := env.Services.(failedResetter)
	if !ok {
		return
	}
	for _, unit := range env.Services.Units() {
		if unit.Name != unitApplyService && unit.Name != unitVerifyService {
			continue
		}
		if status, err := env.Services.Status(ctx, unit); err == nil && strings.HasPrefix(status.State, "failed") {
			if resetter.ResetFailed(ctx, unit) == nil {
				l.noteChange("cleared the failed state an earlier run left on %s", unit.Name)
			}
		}
	}
}

// interruptedTransactionProblem names a transaction a reset or a killed run
// left pending, and the commands that finish it.
func (e *Env) interruptedTransactionProblem(pending *Pending) string {
	action, phase, started := pending.Action, pending.Phase, pending.StartedAt
	if action == "" {
		action = "change"
	}
	if phase == "" {
		phase = "unknown"
	}
	if started == "" {
		started = "an unknown time"
	}
	return fmt.Sprintf("a lifecycle %s that started at %s was interrupted in its %s phase (a reset or a killed run), so files differ from the deployment record; "+
		"`%s` rolls it back to the last committed deployment, and to apply the config it was applying run `%s --config <file>` again",
		action, started, phase, e.lifecycleCommand("repair"), e.lifecycleCommand(ActionEnsure))
}

// withoutTransactionDrift drops the file and config drift an interrupted
// transaction explains.
func withoutTransactionDrift(problems []string) []string {
	kept := problems[:0:0]
	for _, problem := range problems {
		if strings.HasSuffix(problem, " was modified after install") || strings.Contains(problem, "changed since it was applied") {
			continue
		}
		kept = append(kept, problem)
	}
	return kept
}

// recoverPendingFromVerify starts the apply trigger for a transaction a
// killed run left pending (an MDM timeout or a power loss during quiesce).
// verify held the lifecycle lock a moment ago, so no run is applying it, and
// the services that run stopped stay stopped until a mutating run rolls it
// back; nothing started one on its own (GAP-0428). The apply trigger runs
// ensure, which recovers the transaction first. It returns the next step.
func (l *lifecycle) recoverPendingFromVerify(ctx context.Context) string {
	env := l.env
	if env.Geteuid() != 0 {
		return "the next mutating run recovers it"
	}
	var err error
	if env.GOOS == "darwin" {
		_, err = env.Runner.Run(ctx, "launchctl", "kickstart", "system/"+labelApply)
	} else {
		_, err = env.Runner.Run(ctx, "systemctl", "start", "--no-block", unitApplyService)
	}
	if err != nil {
		return "run `" + env.lifecycleCommand("repair") + "` to roll it back"
	}
	return "started the apply trigger, which rolls it back and starts the stopped services again"
}

// verifyInstalled compares the host with record. strict adds the checks
// that only make sense on a settled deployment (ledger freshness, sandbox
// properties). It returns human-readable problems.
func (l *lifecycle) verifyInstalled(ctx context.Context, record *Deployment, strict bool) []string {
	problems := l.verifyDeployment(ctx, record, strict, false)
	// Not part of the check after activation: a guardian or gateway writing
	// its state at that moment is not drift.
	account := Account{Name: record.ServiceUser, UID: record.ServiceUID, GID: record.ServiceGID}
	problems = append(problems, l.env.stateModeProblems(account)...)
	return append(problems, l.env.aclProblems(ctx, record)...)
}

// verifyDeployment is verifyInstalled; with inputsChanged the checks of
// config.yaml's bytes and mode and of the protected credentials are left out,
// because they changed during the transaction and a follow-up applies them.
func (l *lifecycle) verifyDeployment(ctx context.Context, record *Deployment, strict, inputsChanged bool) []string {
	env := l.env
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	account, ok, err := env.Accounts.Lookup(ctx, record.ServiceUser)
	switch {
	case err != nil:
		add("service account %s: %v", record.ServiceUser, err)
	case !ok:
		add("service account %s is missing, so the gateway cannot start; `%s` recreates it and restores the owners of its folders", record.ServiceUser, env.lifecycleCommand("repair"))
	case account.UID != record.ServiceUID || account.GID != record.ServiceGID:
		add("service account %s is %d:%d, deployment recorded %d:%d", record.ServiceUser, account.UID, account.GID, record.ServiceUID, record.ServiceGID)
	case account.LoginShell != "":
		add("%v", loginAccountError(account, env.lifecycleCommand("ensure"), env.GOOS))
	}

	packageDrift, packageDriftChecked := "", false
	hookDamage := env.inspectHookBinary(record)
	for _, path := range sortedKeys(record.Files) {
		if inputsChanged && path == env.Layout.ConfigPath {
			continue
		}
		if hookDamage != nil && path == env.installedHookPath() {
			add("%s", env.hookBinaryProblem(record, hookDamage))
			continue
		}
		got, err := sha256File(env.P(path))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && filepath.Dir(path) == env.Layout.BinDir {
				add("%s", env.missingBinaryProblem(record, path))
				continue
			}
			add("%s: %v", path, err)
			continue
		}
		if got != record.Files[path] {
			if record.Channel == ChannelPackage && filepath.Dir(path) == env.Layout.BinDir {
				if !packageDriftChecked {
					packageDrift, packageDriftChecked = l.packageVersionDrift(ctx, record), true
				}
				if packageDrift != "" {
					continue // one message below, not one per binary
				}
			}
			if record.Channel == ChannelPackage && filepath.Dir(path) == env.Layout.BinDir {
				add("%s was modified after install; %s", path, env.packageReinstallStep(record.ProductVersion))
				continue
			}
			add("%s was modified after install", path)
		}
	}
	if packageDrift != "" {
		add("%s", packageDrift)
	}
	skip := ""
	if hookDamage != nil {
		skip = env.installedHookPath() // named above
	}
	problems = append(problems, env.installedModeProblems(record, inputsChanged, skip)...)
	loadCredential := env.GOOS == "linux" && env.Services.Version(ctx) >= loadCredentialSystemd
	for _, dir := range env.managedDirs(Account{Name: record.ServiceUser, UID: record.ServiceUID, GID: record.ServiceGID}, loadCredential) {
		if dir.External {
			continue
		}
		_, _, mode, err := statOwnerMode(env.P(dir.Path))
		if err != nil {
			add("%s: %v", dir.Path, err)
			continue
		}
		uid, gid, err := env.OwnerOf(env.P(dir.Path))
		if err != nil {
			add("%s: %v", dir.Path, err)
			continue
		}
		if mode&os.ModeSymlink != 0 || !mode.IsDir() {
			add("%s is not a directory", dir.Path)
			continue
		}
		if mode.Perm() != dir.Mode || uid != dir.Owner.UID || gid != dir.Owner.GID {
			add("%s is %04o %d:%d, want %04o %d:%d", dir.Path, mode.Perm(), uid, gid, dir.Mode, dir.Owner.UID, dir.Owner.GID)
		}
	}
	if err := env.Trust(env.P(env.Layout.ConfigPath), TrustAdminFile); err != nil {
		add("config trust: %v", err)
	}
	// A pack file a standard user came to own (or that turned writable)
	// changes enforcement at the next restart with no trace (GAP-0552).
	for _, label := range config.RulePackCheckOrder(record.RulePacks) {
		dir := record.RulePacks[label]
		if err := env.Trust(env.P(dir), TrustRulePack); err != nil && !errors.Is(err, os.ErrNotExist) {
			add("%s %q is not administrator-controlled: %v; %s", label, dir, err, rulePackTrustAdvice)
		}
	}
	if raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err != nil {
		add("config: %v", err)
	} else if sha256Bytes(raw) != record.ConfigSHA256 && !inputsChanged {
		add("config.yaml changed since it was applied; run ensure")
	} else if env.GOOS == "darwin" && !inputsChanged {
		// Custom JSONL files are not in record.Files or the managed ACL walk.
		// Check the destinations of the applied config on every status/verify.
		compiled, err := config.ParseCompileObservabilityV8(env.Layout.ConfigPath, raw, config.ObservabilityV8CompileOptions{
			DefaultDataDir: env.Layout.DataDir, CredentialsDir: env.P(env.Layout.SecretsDir),
		})
		if err == nil && compiled != nil && compiled.Plan != nil {
			for _, destination := range compiled.Plan.Destinations() {
				if destination.Kind != config.ObservabilityV8DestinationJSONL || !destination.Enabled || destination.Generated {
					continue
				}
				if problem, err := env.jsonlACLProblem(ctx, filepath.Clean(destination.Transport.Path)); err != nil {
					add("inspect macOS ACL of observability destination %q: %v", destination.Name, err)
				} else if problem != "" {
					add("observability destination %q writes %s, which %s", destination.Name, filepath.Clean(destination.Transport.Path), problem)
				}
			}
		}
	}
	if err := env.Trust(env.P(env.Layout.DescriptorPath), TrustAdminFile); err != nil {
		add("runtime descriptor trust: %v", err)
	} else if data, err := readBounded(env.P(env.Layout.DescriptorPath), maxInputBytes); err != nil {
		add("runtime descriptor: %v", err)
	} else if _, err := managed.ParseRuntimeDescriptor(data); err != nil {
		add("runtime descriptor: %v", err)
	}
	if _, secretsSHA, err := env.listSecrets(); err != nil {
		add("secrets: %v", err)
	} else if secretsSHA != record.SecretsSHA256 && !inputsChanged {
		add("protected credentials changed since they were applied; run ensure")
	}
	if fragments, ok := env.Services.(fragmentReporter); ok {
		// An override elsewhere on the unit path (a unit an earlier manual
		// deployment left in /etc/systemd/system over a packaged unit, say)
		// replaces the definition this deployment installed.
		for _, unit := range env.Services.Units() {
			if unitMasked(ctx, env.Services, unit) {
				add("%s is masked, so it cannot start; `%s` unmasks it (or run `systemctl unmask %s`)", unit.Name, env.lifecycleCommand("repair"), unit.Name)
				continue
			}
			want := env.Services.DefinitionPath(unit, record.Channel)
			if got := fragments.FragmentPath(ctx, unit); got != "" && !sameUnitFile(env, got, want) {
				add("%s is loaded from %s instead of %s; remove the other unit file and run ensure", unit.Name, got, want)
			}
		}
	}
	if record.Channel == ChannelPackage && env.GOOS == "linux" {
		for _, unit := range env.Services.Units() {
			embedded, _ := systemdunits.ReadFile(unit.Name)
			if got, err := sha256File(env.P(env.Services.DefinitionPath(unit, ChannelPackage))); err != nil || got != sha256Bytes(embedded) {
				add("%s does not match this build; reinstall the package", env.Services.DefinitionPath(unit, ChannelPackage))
			}
		}
	}

	if !record.NoStart {
		for _, unit := range env.Services.Units() {
			if unit.Required && !env.Services.Active(ctx, unit) && !l.backFromRestart(ctx, unit) {
				add("%s is not active", unit.Name)
			}
		}
		// The launchd apply and daily verify jobs are not readiness checks
		// (a loaded job waits for its trigger), but launchd runs neither
		// once it is booted out: status and verify read ok while nothing
		// would apply the next config push (GAP-0956).
		for _, unit := range env.Services.Units() {
			if !unit.Required && unit.Activate && unit.Name != env.SelfUnit && !env.Services.Active(ctx, unit) {
				switch unit.Kind {
				case "path":
					add("%s is not loaded, so nothing applies the next change to config.yaml, a secret or a policy file; run `%s` to load it", unit.Name, env.lifecycleCommand(ActionRepair))
				case "timer":
					add("%s is not loaded, so the daily verify does not run; run `%s` to load it", unit.Name, env.lifecycleCommand(ActionRepair))
				}
			}
		}
		for _, unit := range env.Services.Units() {
			if unit.Kind != "gateway" {
				continue
			}
			_, err := l.gatewayHealth(ctx, unit, record.ServiceUID)
			var held *apiPortHeldError
			if err != nil && !errors.As(err, &held) && (env.GOOS == "darwin" || !l.apiSocketActive(ctx)) {
				// The gateway is down: another process may hold the API
				// port so that it cannot start (on Linux while the socket
				// unit is stopped). Name it.
				if problem := l.portHeldProblem(ctx, record.ServiceUID, false); problem != "" {
					add("%s", problem)
				}
			}
			if err != nil {
				add("%v", err)
			}
		}
	}

	if strict && !record.NoStart {
		if sd, ok := env.Services.(*systemdManager); ok {
			props := sd.Sandbox(ctx, unitGateway)
			want := map[string]string{"User": record.ServiceUser, "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateUsers": "no"}
			for key, value := range want {
				if got, present := props[key]; present && got != value {
					add("%s %s=%s, want %s", unitGateway, key, got, value)
				}
			}
			if caps, present := props["CapabilityBoundingSet"]; present && strings.TrimSpace(caps) != "" {
				add("%s keeps capabilities %q; want none", unitGateway, caps)
			}
		}
		// A running job an administrator disabled keeps working until the
		// next boot, where launchd does not start it (GAP-1802).
		for _, unit := range env.Services.Units() {
			if unit.Activate && unitDisabled(ctx, env.Services, unit) {
				add("%s is disabled and will not start after a reboot; run `%s`", unit.Name, env.lifecycleCommand("repair"))
			}
		}
		if problem := l.ledgerProblem(); problem != "" {
			add("%s", problem)
		}
	}
	return problems
}

// packageVersionDrift explains package-owned binaries that differ from the
// record when the package on disk is another version than the deployment
// applied: the package manager replaced the binaries and the package's own
// install run did not finish (it failed and rolled back, or an older package
// was refused). The lifecycle cannot put the previous package's binaries back,
// so the state is named instead of read as a modified file (GAP-0111). ""
// when the versions agree, which leaves a real modification to its own message.
func (l *lifecycle) packageVersionDrift(ctx context.Context, record *Deployment) string {
	env := l.env
	version, err := env.binaryVersion(ctx, filepath.Join(env.P(env.Layout.BinDir), binGateway))
	if err != nil || version == "" || version == record.ProductVersion {
		return ""
	}
	cause := ""
	if failure := env.lastPackageInstallFailure(); failure != "" {
		cause = " (" + failure + ")"
	}
	return fmt.Sprintf("the installed package is version %s but the deployment applied %s: the package's install run did not finish%s; "+
		"fix that and run `%s --from-package` to apply it (add --allow-downgrade when %s is the older package you meant to go back to)",
		version, record.ProductVersion, cause, env.lifecycleCommand(ActionEnsure), version)
}

// restartSettle bounds the wait for a unit its service manager is about to
// start again. The sensor helper exits on purpose when the guardian manifest
// changes (an account was enrolled or revoked), and systemd (RestartSec=5s)
// or launchd (ThrottleInterval 5) restarts it.
const restartSettle = 15 * time.Second

// backFromRestart reports whether a unit that is not active is in a planned
// restart and is active again within restartSettle. A unit that crashed is
// not waited for: a crash loop would come back for a moment each time and
// read as healthy.
func (l *lifecycle) backFromRestart(ctx context.Context, unit Unit) bool {
	env := l.env
	if restarts, ok := env.Services.(plannedRestartReporter); !ok || !restarts.PlannedRestart(ctx, unit) {
		return false
	}
	deadline := env.Now().Add(restartSettle)
	for {
		if env.Services.Active(ctx, unit) {
			return true
		}
		if !env.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(env.PollInterval):
		}
	}
}

// installedModeProblems reports recorded files whose mode or owner drifted,
// which the digest check cannot see: an installed binary another account
// could replace, a loosened config.yaml, or any recorded file that became
// group- or other-writable. Repair restores the modes of the files it
// writes; it refuses to adopt a replaceable binary, so that problem names
// the command that restores it.
func (e *Env) installedModeProblems(record *Deployment, skipConfig bool, skip string) []string {
	var problems []string
	for _, path := range sortedKeys(record.Files) {
		if (skipConfig && path == e.Layout.ConfigPath) || path == skip {
			continue
		}
		_, _, mode, err := statOwnerMode(e.P(path))
		if err != nil || mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			continue // the digest check names it
		}
		uid, gid, err := e.OwnerOf(e.P(path))
		if err != nil {
			continue
		}
		perm := mode.Perm()
		switch {
		case filepath.Dir(path) == e.Layout.BinDir:
			if perm&0o022 != 0 {
				problems = append(problems, fmt.Sprintf("%s is writable by group or other (%04o), so another account could replace it; restore it with `chmod 0755 %s` or reinstall the package", path, perm, path))
			} else if uid != 0 {
				problems = append(problems, fmt.Sprintf("%s is owned by uid %d, not root, so that account could replace it; restore it with `chown 0 %s` or reinstall the package", path, uid, path))
			}
		case path == e.Layout.ConfigPath:
			if perm != 0o640 || uid != 0 || gid != record.ServiceGID {
				problems = append(problems, fmt.Sprintf("%s is %04o %d:%d, want 0640 0:%d; run `%s` to restore it", path, perm, uid, gid, record.ServiceGID, e.lifecycleCommand("repair")))
			}
		case perm&0o022 != 0:
			problems = append(problems, fmt.Sprintf("%s is writable by group or other (%04o); run `%s` to restore it", path, perm, e.lifecycleCommand("repair")))
		}
	}
	return problems
}

// lifecycleCommand is the administrator command line for a lifecycle
// action on this host, with the absolute gateway path (sudo's secure_path
// does not include the install directory).
// LifecycleCommand is the full `defenseclaw-gateway enterprise <os> <action>`
// command line of this host, for next-step advice.
func (e *Env) LifecycleCommand(action string) string { return e.lifecycleCommand(action) }

func (e *Env) lifecycleCommand(action string) string {
	group := "linux"
	if e.GOOS == "darwin" {
		group = "macos"
	}
	return filepath.Join(e.Layout.BinDir, binGateway) + " enterprise " + group + " " + action
}

// hookBinaryProblem names a damaged hook binary, what it means for the
// agents and the command that puts it back (GAP-1217, GAP-0680).
func (e *Env) hookBinaryProblem(record *Deployment, damage *hookBinaryDamage) string {
	text := e.installedHookPath() + " is " + damage.String() + ", so "
	switch damage.state {
	case hookBinaryEmpty:
		text += "agents run their DefenseClaw hook as an empty script that allows every tool call"
	case hookBinaryNotRootOwned:
		text += "that account could replace the hook every agent runs"
	case hookBinaryHashMismatch, hookBinaryNotRegular:
		text += "agents run a hook DefenseClaw did not install"
	default:
		text += "no agent's DefenseClaw hook can start; Claude Code, Codex and the other agents treat that as a non-blocking error and run tool calls without DefenseClaw"
	}
	if e.sealedHookValid(record) {
		return text + ". The hook guardian starts its restore within seconds; to restore it now, run `" + e.lifecycleCommand(ActionRepair) + "`, which puts it back from the copy the lifecycle sealed"
	}
	if record.Channel == ChannelPackage {
		return text + "; " + e.packageReinstallStep(record.ProductVersion)
	}
	return text + "; run `" + e.lifecycleCommand(ActionRepair) + " --payload <staged payload directory>`"
}

// missingBinaryProblem names a recorded binary other than the hook that is
// gone and the command that puts it back.
func (e *Env) missingBinaryProblem(record *Deployment, path string) string {
	if record.Channel == ChannelPackage {
		return path + " is missing; " + e.packageReinstallStep(record.ProductVersion)
	}
	return path + " is missing; run `" + e.lifecycleCommand(ActionRepair) + " --payload <staged payload directory>`"
}

// codePackageInstallFailed names the failed ensure of the package's own
// postinstall when no deployment is committed (GAP-1744).
const codePackageInstallFailed = "package_install_failed"

// lastPackageResultFile is the result the deb/rpm and the macOS pkg
// postinstall keep of their own `ensure --from-package` run.
const lastPackageResultFile = "last-package-result.json"

// lastPackageLogFile is the standard error of the same run.
const lastPackageLogFile = "last-package-result.log"

// clearSupersededFailures removes what an earlier failed run left once a
// later run has committed a deployment: the gateway output kept by a failed
// activation, and the failed result of the package's own install run. Left in
// place, an upgrade whose activation was rolled back keeps reporting ok:false
// and the previous version to MDM detection and to administrators after
// ensure recovered the host, and a healthy host keeps the old failure details.
// The package's own run leaves its result alone: its shell holds the result
// file open and the run writes the document after the lifecycle returns.
func (l *lifecycle) clearSupersededFailures() {
	dir := l.env.P(l.env.Layout.LifecycleDir)
	_ = os.Remove(filepath.Join(dir, activationFailureFileName))
	if l.opts.Reason == "package" || l.env.lastPackageInstallFailure() == "" {
		return
	}
	for _, name := range []string{lastPackageResultFile, lastPackageLogFile} {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// lastPackageInstallFailure returns "code: message" of the first error of the
// package postinstall's failed install run, or "" when there is none. dnf
// printed only "run verify", and verify then said not_installed without the
// cause (a missing protected credential) that the result names (GAP-1744).
func (e *Env) lastPackageInstallFailure() string {
	raw, err := readBounded(e.P(filepath.Join(e.Layout.LifecycleDir, lastPackageResultFile)), maxInputBytes)
	if err != nil {
		return ""
	}
	var last struct {
		OK     bool                       `json:"ok"`
		Action string                     `json:"action"`
		Errors []enterprisestatus.Message `json:"errors"`
	}
	if json.Unmarshal(raw, &last) != nil || last.OK || len(last.Errors) == 0 {
		return ""
	}
	switch last.Action {
	case ActionEnsure, ActionInstall, ActionUpgrade:
	default:
		return ""
	}
	first := last.Errors[0]
	return strings.TrimSpace(first.Code + ": " + first.Message)
}

// warnPackageInstallFailed adds the package_install_failed warning that
// names why the package's own install run failed and how to finish the
// install. status, verify and an uninstall that found nothing to remove all
// give it, so their unmanaged_leftovers hint can defer to it (GAP-2410).
func (e *Env) warnPackageInstallFailed(r *enterprisestatus.Result, failure string) {
	if failure == "" {
		return
	}
	next := "fix that, then finish the install with `" + e.lifecycleCommand(ActionEnsure) + " --from-package`"
	if e.GOOS == "darwin" {
		// A failed pkg install records no receipt, and ensure does not
		// write one, so receipt-based MDM inventory keeps reporting the
		// Mac as not installed (GAP-2359).
		next = "fix that, then install the package again, which also records the pkg receipt that MDM inventory reads (`" +
			e.lifecycleCommand(ActionEnsure) + " --from-package` finishes the install but records no receipt)"
	}
	opening := "the package was installed, but its own install run did not complete, so no deployment is active: "
	if e.GOOS == "darwin" {
		// pkgutil keeps no receipt for a pkg whose postinstall failed.
		opening = "the package's files were copied, but its postinstall did not complete, so macOS recorded no pkg receipt and no deployment is active: "
	}
	r.AddWarning(codePackageInstallFailed, opening+failure+"; "+next)
}

// leftoversNextStep tells the administrator what to do about machine state
// no committed deployment owns, typically after a lifecycle uninstall that
// kept the package installed: remove the package, or activate it again.
// After the package's own install run failed, the package_install_failed
// warning already names the finish step (on macOS: install the pkg again,
// for its receipt), so the activate hint defers to it (GAP-2380).
func (e *Env) leftoversNextStep(ctx context.Context, packageInstallFailed bool) string {
	gateway := filepath.Join(e.Layout.BinDir, binGateway)
	reactivate := "`" + e.lifecycleCommand("ensure") + " --from-package --config <file>`"
	if packageInstallFailed {
		reactivate = "finish the install as the " + codePackageInstallFailed + " warning says"
	}
	if e.GOOS == "linux" {
		remove := ""
		if _, err := e.Runner.Run(ctx, "dpkg", "-S", gateway); err == nil {
			remove = "apt remove defenseclaw-enterprise"
			if !exists(e.P(e.Layout.ConfigDir)) {
				// After uninstall --purge, purge the package too: it also
				// forgets the package's configuration files.
				remove = "apt purge defenseclaw-enterprise"
			}
		} else if _, err := e.Runner.Run(ctx, "rpm", "-qf", "--quiet", gateway); err == nil {
			remove = "dnf remove defenseclaw-enterprise"
		}
		if remove != "" {
			if packageInstallFailed {
				return "the defenseclaw-enterprise package is still installed: remove it with `" + remove + "` (or the MDM uninstall.sh), or " + reactivate
			}
			return "the defenseclaw-enterprise package is still installed: remove it with `" + remove + "` (or the MDM uninstall.sh), or activate the deployment again with " + reactivate
		}
	}
	if packageInstallFailed {
		return "remove it with `" + e.lifecycleCommand("uninstall") + " --purge` (this also deletes the kept config and state), or " + reactivate
	}
	return "remove it with `" + e.lifecycleCommand("uninstall") + " --purge` (this also deletes the kept config and state), or activate the deployment again with " + reactivate + " (package) or `--payload <dir>` (payload archive)"
}

// apiSocketActive reports whether the Linux API socket unit is listening
// (PID 1 then holds the port; nobody else can bind it).
func (l *lifecycle) apiSocketActive(ctx context.Context) bool {
	for _, unit := range l.env.Services.Units() {
		if unit.Name == unitAPISocket {
			return l.env.Services.Active(ctx, unit)
		}
	}
	return true
}

// sameUnitFile reports whether systemd's fragment path names the expected
// unit file. Split-/usr builds search /lib/systemd/system before
// /usr/lib/systemd/system, and on a merged-/usr host both are one
// directory, so the same file can be reported under either name.
func sameUnitFile(env *Env, got, want string) bool {
	if got == want {
		return true
	}
	gotInfo, err := os.Stat(env.P(got))
	if err != nil {
		return false
	}
	wantInfo, err := os.Stat(env.P(want))
	return err == nil && os.SameFile(gotInfo, wantInfo)
}

// ledgerProblem checks that the guardian authorization ledger is fresh and
// that the guardian's root-only credential attestation belongs to it. The
// ledger carries earlier successes forward so a target stays eligible for
// repair; only the attestation says what the last reconcile did, so an old
// success in the ledger alone is never current readiness. A reconcile writes
// the ledger before the attestation, so a read between the two is retried.
func (l *lifecycle) ledgerProblem() string {
	env := l.env
	path := env.P(filepath.Join(env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	for attempt := 1; ; attempt++ {
		data, err := readBounded(path, 4<<20)
		if errors.Is(err, os.ErrNotExist) {
			return "the hook guardian has not published its authorization ledger yet"
		}
		if err != nil {
			return "guardian ledger: " + err.Error()
		}
		var ledger struct {
			UpdatedAt string `json:"updated_at"`
		}
		if json.Unmarshal(data, &ledger) == nil && ledger.UpdatedAt != "" {
			if err := managed.ValidateHookGuardianFreshness(ledger.UpdatedAt, env.Now()); err != nil {
				return "guardian ledger: " + err.Error()
			}
		}
		problem, torn := env.attestationProblem(data)
		if torn && attempt == 5 && problem == guardianManifestNotReconciled && l.manifestJustChanged() {
			// An apply, ensure or enumerator cycle has just rewritten
			// targets.yaml, and the guardian reconciles it within about a
			// minute while it keeps enforcing the targets it last reconciled.
			// Keep the wait guidance (GAP-0691), but report incomplete
			// coverage until the guardian attests the new roster.
			l.noteGuardianCatchingUp()
			return problem
		}
		if !torn || attempt == 5 {
			return problem
		}
		time.Sleep(env.PollInterval)
	}
}

// packageTransactionMarker is what the Linux package preinstall leaves while
// it holds the config-apply trigger for the transaction; the postinstall
// removes it after its ensure.
const packageTransactionMarker = "/run/defenseclaw-enterprise-apply-path.held"

// packageTransactionInProgress reports a package transaction that started
// less than half an hour ago (an older marker is from an interrupted one).
func (e *Env) packageTransactionInProgress() bool {
	if e.GOOS != "linux" {
		return false
	}
	info, err := os.Lstat(e.P(packageTransactionMarker))
	return err == nil && e.Now().Sub(info.ModTime()) < 30*time.Minute
}

// guardianCatchUpWindow is how long after targets.yaml changed a guardian
// that has not reconciled it yet is waited for rather than failed: it
// reconciles each minute.
const guardianCatchUpWindow = 3 * time.Minute

// codeGuardianReconcilePending warns that the guardian has not reconciled
// a targets.yaml that changed moments ago without declaring coverage complete.
const codeGuardianReconcilePending = "guardian_reconcile_pending"

// manifestJustChanged reports a targets.yaml written within
// guardianCatchUpWindow.
func (l *lifecycle) manifestJustChanged() bool {
	info, err := os.Stat(l.env.P(l.env.Layout.ManifestPath))
	if err != nil {
		return false
	}
	age := l.env.Now().Sub(info.ModTime())
	return age >= -time.Minute && age < guardianCatchUpWindow
}

// noteGuardianCatchingUp adds the guardian_reconcile_pending warning once.
func (l *lifecycle) noteGuardianCatchingUp() {
	for _, warning := range l.result.Warnings {
		if warning.Code == codeGuardianReconcilePending {
			return
		}
	}
	l.result.AddWarning(codeGuardianReconcilePending, "targets.yaml changed moments ago and the hook guardian has not reconciled it yet; "+
		"it does within about a minute and until then enforces the targets it last reconciled. No repair is needed: run verify again in a minute to confirm the new targets")
}

// describe fills the result's services, readiness and enrollment.
func (l *lifecycle) describe(ctx context.Context, record *Deployment, _ bool) {
	env, r := l.env, l.result
	r.Services = r.Services[:0]
	reportedPolicy, reloadError := "", ""
	for _, unit := range env.Services.Units() {
		status, _ := env.Services.Status(ctx, unit)
		r.Services = append(r.Services, status)
		if !unit.Required && strings.HasPrefix(status.State, "failed") {
			// A failed oneshot (the apply or daily verify run, the guardian
			// reconcile) is not a readiness check, but it must not sit under
			// a green headline either.
			r.AddWarning(codeUnitFailed, fmt.Sprintf("%s failed on its last run; see `journalctl -u %s`, and clear it with `systemctl reset-failed %s` once resolved", unit.Name, unit.Name, unit.Name))
		}
		active := env.Services.Active(ctx, unit)
		switch unit.Kind {
		case "gateway":
			if active {
				serviceUID := l.serviceUID
				if record != nil {
					serviceUID = record.ServiceUID
				}
				if body, err := l.gatewayHealth(ctx, unit, serviceUID); err == nil {
					r.Readiness.Gateway = true
					l.readGatewayPosture(body)
					reportedPolicy, reloadError = gatewayPolicyHealth(body)
				}
			}
		case "guardian":
			r.Readiness.Guardian = active && l.ledgerProblem() == ""
		case "enumerator":
			r.Readiness.Enumerator = active
		case "sensor_helper":
			r.Readiness.SensorHelper = active
		}
	}
	sort.SliceStable(r.Services, func(i, j int) bool { return r.Services[i].Name < r.Services[j].Name })
	if record != nil {
		r.InstalledVersion = record.ProductVersion
		if (r.Action == "status" || r.Action == "verify") && slices.Contains(record.MachinePolicyConnectors, "cursor") {
			r.AddWarning("cursor_agent_prompt_hook_unavailable", "Cursor Agent CLI 2026.10.01 does not send beforeSubmitPrompt; prompt text is not inspected. Check hook_decision rows for actual coverage")
		}
	}
	r.Enrollment = l.enrollmentCounts()
	l.describePolicy(ctx, reportedPolicy, reloadError)
	if problem := env.rejectedConfigProblem(); problem != "" {
		// Not a verifyInstalled problem: the installed files match the
		// record, and ensure must stay a no-op until config.yaml changes.
		r.AddWarning(codeConfigRejected, problem)
	}
	r.CoverageComplete = r.Readiness.Gateway && r.Readiness.Guardian && r.Readiness.Enumerator
	r.SecurityComplete = r.CoverageComplete && r.Readiness.SensorHelper && len(r.Errors) == 0 && !machinePolicyIncomplete(r)
	l.describeHookContracts(ctx)
	l.describeUnprotectedAgents()
	l.describeGuardianCleanups()
	l.describeDeletedEnrolledAccounts()
	l.describeDiscoveryHomeDirs()
	l.describeIdentityRecords()
	l.describeDestinations()
	if record != nil {
		l.describePerUserGateways(ctx)
		l.describeAgentSessionsBeforeActivation(ctx, record)
	}
	if exists(env.rotationIntentPath()) {
		r.AddWarning(codeRotationIncomplete, "a credential rotation did not finish; run rotate-credentials, or any other lifecycle action, to complete it or roll it back")
	}
	if r.Inspection.Local == "" {
		r.Inspection.Local = "unknown"
	}
	if r.Inspection.AIDefense == "" {
		r.Inspection.AIDefense = "unknown"
	}
	if strings.HasPrefix(r.Inspection.AIDefense, "unavailable") {
		// Not an error: the local policy engine keeps deciding. But the
		// cloud inspection the administrator enabled is not running.
		r.AddWarning(codeAIDefenseUnavailable, "Cisco AI Defense inspection is enabled but reports "+
			r.Inspection.AIDefense+"; the local policy engine keeps deciding. Check the "+
			"enterprise.inspection.ai_defense credential and network access")
	}
}

// codeAIDefenseUnavailable warns that enabled AI Defense inspection is
// failing (for example a rejected key).
const codeAIDefenseUnavailable = "ai_defense_unavailable"

// codeDirectoryLookups warns that the gateway cannot resolve some accounts in
// the directory (a domain controller or SSSD that does not answer).
const codeDirectoryLookups = "directory_lookups_failing"

const codeProfileAssignments = "profile_assignment_unmatched"
const codeOptionalDestination = "optional_destination_failing"

// codeJudgeFailing names an LLM judge whose recent calls all failed, or that
// could not start.
const codeJudgeFailing = enterprisestatus.CodeJudgeFailing

// readGatewayPosture copies the gateway's inspection posture from /health
// when the gateway publishes it, and warns when it reports directory lookups
// that fail: the accounts without cached facts then run under the default
// guardrail profile, and nothing else in status or verify showed it (GAP-0216).
func (l *lifecycle) readGatewayPosture(body []byte) {
	var health struct {
		ProfileAssignmentWarnings []string `json:"profile_assignment_warnings"`
		Telemetry                 struct {
			Details struct {
				OptionalState  string `json:"optional_destination_state"`
				FailureSummary string `json:"optional_destination_failure_summary"`
			} `json:"details"`
		} `json:"telemetry"`
		Inspection *struct {
			Local     string `json:"local"`
			AIDefense string `json:"ai_defense"`
		} `json:"inspection"`
		Directory *struct {
			Failing  int      `json:"failing"`
			Since    string   `json:"since"`
			Stale    int      `json:"stale"`
			Accounts []string `json:"accounts"`
		} `json:"directory"`
		ProfileWarnings []string `json:"profile_warnings"`
		Guardrail       *struct {
			Details enterprisestatus.JudgeHealth `json:"details"`
		} `json:"guardrail"`
	}
	if json.Unmarshal(body, &health) != nil {
		return
	}
	// A judge that stops answering silently downgrades detection to the
	// static rules; only /health and the journal said so (GAP-0626).
	if g := health.Guardrail; g != nil {
		if message, failing := g.Details.Warning(); failing {
			l.result.AddWarning(codeJudgeFailing, message)
		}
	}
	if health.Inspection != nil {
		l.result.Inspection.Local = health.Inspection.Local
		l.result.Inspection.AIDefense = health.Inspection.AIDefense
	}
	for _, warning := range health.ProfileAssignmentWarnings {
		l.result.AddWarning(codeProfileAssignments, warning)
	}
	if health.Telemetry.Details.OptionalState == "degraded" {
		l.result.AddWarning(codeOptionalDestination, "optional telemetry destination failing: "+health.Telemetry.Details.FailureSummary+
			"; inspect `defenseclaw-gateway status` or the gateway /health telemetry details")
	}
	if d := health.Directory; d != nil && d.Failing > 0 {
		which := ""
		if ids := directoryLookupAccounts(d.Accounts); ids != "" {
			which = " (" + ids + ")"
		}
		message := fmt.Sprintf("directory lookups are failing for %d account(s)%s since %s; accounts without cached facts get the "+
			"default guardrail profile (default_lookup_failed)", d.Failing, which, d.Since)
		if d.Stale > 0 {
			message += fmt.Sprintf(", and %d account(s) are served older facts that are dropped after an hour", d.Stale)
		}
		check := "Check SSSD or the domain controller"
		if l.env.GOOS == "darwin" {
			check = "Check the directory binding of this Mac (dsconfigad -show) or the domain controller; once it answers, " +
				"sudo dscacheutil -flushcache; sudo dsmemberutil flushcache makes Open Directory list the domain groups again " +
				"(it can keep answering without them for 15 minutes or more)"
		}
		l.result.AddWarning(codeDirectoryLookups, message+". "+check+"; `"+
			l.env.lifecycleCommand("profile-explain --user <account>")+"` shows the reason")
	}
	// profile_warnings repeats the group warnings profile_assignment_warnings
	// already lists; each is listed once (GAP-0928).
	health.ProfileWarnings = slices.DeleteFunc(health.ProfileWarnings, func(warning string) bool {
		return slices.Contains(health.ProfileAssignmentWarnings, warning)
	})
	for i, warning := range health.ProfileWarnings {
		if i == profileWarningsMax {
			l.result.AddWarning(codeProfileAssignment, fmt.Sprintf("%d more guardrail profile assignment warnings", len(health.ProfileWarnings)-i))
			break
		}
		if warning = strings.TrimSpace(warning); warning != "" && len(warning) <= 1024 {
			l.result.AddWarning(codeProfileAssignment, "guardrail profile "+warning)
		}
	}
}

// codeIdentityRecordsStale warns that the guardian identity records look
// older than the guardian keeps them by the wall clock (GAP-0921).
const codeIdentityRecordsStale = "identity_records_stale"

// identityRecordsFreshFor is how old any guardian identity record may
// look: the guardian rewrites them every 15 minutes, and within about a
// minute after a clock step.
const identityRecordsFreshFor = 30 * time.Minute

// describeIdentityRecords warns while the guardian identity records look
// stale or are dated in the future: the gateway then ignores those over an
// hour old, and the accounts a profile assignment selects by UPN get the
// default profile.
func (l *lifecycle) describeIdentityRecords() {
	env := l.env
	dir := enterprisehooks.IdentitySpoolDir(env.P(env.Layout.GuardianAuthDir))
	oldest, key, stale := enterprisehooks.IdentitySpoolStale(dir, env.Now(), identityRecordsFreshFor)
	if !stale {
		return
	}
	// The guardian removes the record of an account it no longer publishes
	// (GAP-1113), so a stale record is one it still publishes and could not
	// refresh: name the account and where the guardian says why.
	l.result.AddWarning(codeIdentityRecordsStale, fmt.Sprintf("the hook guardian's oldest identity record, of uid %s, was last written at %s by "+
		"this host's clock: the clock was stepped, the directory lookup for that account keeps failing, or the guardian is not "+
		"running; records over an hour old are ignored, and accounts a guardrail profile assignment selects by UPN then get "+
		"the default profile. The guardian rewrites them within about a minute of a clock step; if this persists, fix the "+
		"lookup failure its log names for that uid (%s), or restart the hook guardian if it is not running",
		key, oldest.UTC().Format(time.RFC3339), env.guardianLogHint()))
}

// guardianLogHint names where the hook guardian logs.
func (e *Env) guardianLogHint() string {
	if e.GOOS == "darwin" {
		return filepath.Join(e.Layout.LogDir, "hook-guardian.err.log")
	}
	return "journalctl -u " + unitGuardian
}

// codeProfileAssignment warns that a guardrail profile assignment selects
// nobody: a group the host does not know (renamed, deleted, or spelled
// another way after an SSSD naming switch), so its members get the default
// profile (GAP-0704).
const codeProfileAssignment = "profile_assignment_unmatched"

// profileWarningsMax bounds the assignment warnings status and verify list.
const profileWarningsMax = 20

// directoryLookupAccounts names the failing accounts the gateway reported by
// uid ("uid 1001, uid 1002"); anything that is not a plain uid is dropped.
func directoryLookupAccounts(ids []string) string {
	named := []string{}
	for _, id := range ids {
		if id == "" || len(id) > 10 || strings.Trim(id, "0123456789") != "" {
			continue
		}
		named = append(named, "uid "+id)
	}
	return strings.Join(named, ", ")
}

// enrollmentCounts summarizes the guardian authorization ledger; detailed
// per-target state belongs to `enterprise hooks status`.
func (l *lifecycle) enrollmentCounts() enterprisestatus.Enrollment {
	env := l.env
	var counts enterprisestatus.Enrollment
	data, err := readBounded(env.P(filepath.Join(env.Layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile)), 4<<20)
	if err != nil {
		return counts
	}
	var ledger struct {
		TargetCount  int `json:"target_count"`
		FailureCount int `json:"failure_count"`
		PendingCount int `json:"pending_count"`
	}
	if json.Unmarshal(data, &ledger) == nil {
		counts.Targets, counts.Failed, counts.Pending = ledger.TargetCount, ledger.FailureCount, ledger.PendingCount
	}
	return counts
}
