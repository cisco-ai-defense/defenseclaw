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
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// ledgerFreshness mirrors the gateway's guardian authorization window.
const ledgerFreshness = 5 * time.Minute

// codeUnitFailed names a DefenseClaw oneshot unit systemd reports failed.
const codeUnitFailed = "unit_failed"

// readOnly handles status and verify.
func (l *lifecycle) readOnly(ctx context.Context) int {
	env, r := l.env, l.result
	if l.opts.Action == ActionVerify {
		// The daily verify can start while another run changes the
		// deployment: ensure restarts the timer, and a Persistent timer past
		// its daily time fires at once. verify waits for that run like any
		// lifecycle action, then releases the lock so it never holds up a
		// change; a run that outlasts the wait is busy, not a failed check.
		lock, err := env.acquireLock(ctx)
		if errors.Is(err, errLockBusy) {
			r.AddError(codeBusy, err.Error()+"; "+verifyBusyNextStep)
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
	if pending, _ := env.loadPending(); pending != nil {
		r.TransactionPending = true
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
		if failure != "" {
			r.AddWarning(codePackageInstallFailed, "the package was installed, but its own install run did not complete, so no deployment is active: "+
				failure+"; fix that, then finish the install with `"+env.lifecycleCommand(ActionEnsure)+" --from-package`")
		}
		if leftovers := env.unmanagedLeftovers(env.Services, ChannelPayload); len(leftovers) > 0 {
			r.AddWarning(codeLeftovers, "DefenseClaw machine state exists without a committed deployment: "+strings.Join(leftovers, ", ")+"; "+env.leftoversNextStep(ctx))
		}
		return 0
	}
	r.Installed = true
	r.InstalledVersion = record.ProductVersion
	strict := l.opts.Action == ActionVerify
	problems := l.verifyInstalled(ctx, record, strict)
	l.describe(ctx, record, true)
	problems = append(problems, l.describeMachinePolicy(record)...)
	if strict {
		l.warnUnprivilegedUserNamespaces()
	}
	if strict {
		// An agent the guardian or the enumerator could not protect for one
		// account (an unverified hook contract, an agent it could not enroll)
		// stays a warning for that account: the rest of the host is
		// compliant, as on Windows.
		// Machine-policy gaps (a removed vendor policy) fail verify only;
		// status reports them as warnings with security_complete false.
		for _, warning := range r.Warnings {
			if warning.Code == codeMachinePolicyIncomplete || warning.Code == codeGuardianTargetFailed || warning.Code == codeConfigRejected {
				problems = append(problems, warning.Message)
			}
		}
	}
	// A problem either action finds makes the deployment unhealthy, and
	// both exit 1 for it; status leaves out verify's stricter checks.
	for _, problem := range problems {
		r.AddError(codeVerify, problem)
	}
	if strict && r.TransactionPending {
		r.AddError(codeVerify, "a lifecycle transaction is pending; the next mutating run recovers it")
	}
	return 0
}

// verifyInstalled compares the host with record. strict adds the checks
// that only make sense on a settled deployment (ledger freshness, sandbox
// properties). It returns human-readable problems.
func (l *lifecycle) verifyInstalled(ctx context.Context, record *Deployment, strict bool) []string {
	return l.verifyDeployment(ctx, record, strict, false)
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
		add("service account %s is missing", record.ServiceUser)
	case account.UID != record.ServiceUID || account.GID != record.ServiceGID:
		add("service account %s is %d:%d, deployment recorded %d:%d", record.ServiceUser, account.UID, account.GID, record.ServiceUID, record.ServiceGID)
	}

	for _, path := range sortedKeys(record.Files) {
		if inputsChanged && path == env.Layout.ConfigPath {
			continue
		}
		got, err := sha256File(env.P(path))
		if err != nil {
			add("%s: %v", path, err)
			continue
		}
		if got != record.Files[path] {
			add("%s was modified after install", path)
		}
	}
	problems = append(problems, env.installedModeProblems(record, inputsChanged)...)
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
	if raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err != nil {
		add("config: %v", err)
	} else if sha256Bytes(raw) != record.ConfigSHA256 && !inputsChanged {
		add("config.yaml changed since it was applied; run ensure")
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
func (e *Env) installedModeProblems(record *Deployment, skipConfig bool) []string {
	var problems []string
	for _, path := range sortedKeys(record.Files) {
		if skipConfig && path == e.Layout.ConfigPath {
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

// codePackageInstallFailed names the failed ensure of the package's own
// postinstall when no deployment is committed (GAP-1744).
const codePackageInstallFailed = "package_install_failed"

// lastPackageResultFile is the result the deb/rpm and the macOS pkg
// postinstall keep of their own `ensure --from-package` run.
const lastPackageResultFile = "last-package-result.json"

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

// leftoversNextStep tells the administrator what to do about machine state
// no committed deployment owns, typically after a lifecycle uninstall that
// kept the package installed: remove the package, or activate it again.
func (e *Env) leftoversNextStep(ctx context.Context) string {
	gateway := filepath.Join(e.Layout.BinDir, binGateway)
	reactivate := "`" + e.lifecycleCommand("ensure") + " --from-package --config <file>`"
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
			return "the defenseclaw-enterprise package is still installed: remove it with `" + remove + "` (or the MDM uninstall.sh), or activate the deployment again with " + reactivate
		}
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
		if !torn || attempt == 5 {
			return problem
		}
		time.Sleep(env.PollInterval)
	}
}

// describe fills the result's services, readiness and enrollment.
func (l *lifecycle) describe(ctx context.Context, record *Deployment, _ bool) {
	env, r := l.env, l.result
	r.Services = r.Services[:0]
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
					l.readInspection(body)
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
	}
	r.Enrollment = l.enrollmentCounts()
	if problem := env.rejectedConfigProblem(); problem != "" {
		// Not a verifyInstalled problem: the installed files match the
		// record, and ensure must stay a no-op until config.yaml changes.
		r.AddWarning(codeConfigRejected, problem)
	}
	r.CoverageComplete = r.Readiness.Gateway && r.Readiness.Guardian && r.Readiness.Enumerator
	r.SecurityComplete = r.CoverageComplete && r.Readiness.SensorHelper && len(r.Errors) == 0
	l.describeHookContracts(ctx)
	l.describeUnprotectedAgents()
	l.describeGuardianCleanups()
	if record != nil {
		l.describePerUserGateways(ctx)
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

// readInspection copies the gateway's inspection posture from /health when
// the gateway publishes it.
func (l *lifecycle) readInspection(body []byte) {
	var health struct {
		Inspection *struct {
			Local     string `json:"local"`
			AIDefense string `json:"ai_defense"`
		} `json:"inspection"`
	}
	if json.Unmarshal(body, &health) == nil && health.Inspection != nil {
		l.result.Inspection.Local = health.Inspection.Local
		l.result.Inspection.AIDefense = health.Inspection.AIDefense
	}
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
