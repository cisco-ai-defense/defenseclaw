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
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Actions.
const (
	ActionInstall   = "install"
	ActionUpgrade   = "upgrade"
	ActionRepair    = "repair"
	ActionEnsure    = "ensure"
	ActionReconcile = "reconcile"
	ActionStatus    = "status"
	ActionVerify    = "verify"
	ActionUninstall = "uninstall"
)

// Actions lists the lifecycle actions in documentation order.
var Actions = []string{ActionInstall, ActionUpgrade, ActionRepair, ActionEnsure, ActionReconcile, ActionRotateCredentials, ActionStatus, ActionVerify, ActionUninstall}

// Options are one lifecycle invocation's inputs.
type Options struct {
	Action string
	// PayloadDir holds the binaries to install (payload channel).
	PayloadDir string
	// FromPackage installs the binaries the deb/rpm/pkg already placed in
	// the layout's bin directory (package channel).
	FromPackage bool
	// ConfigFile replaces the managed config.
	ConfigFile string
	NoStart    bool
	// AdoptExisting backs up and takes over a pre-existing unmanaged
	// layout instead of refusing.
	AdoptExisting bool
	// AllowDowngrade permits installing a payload older than the recorded
	// deployment (a deliberate rollback). Without it downgrades are refused.
	AllowDowngrade bool
	// Purge makes uninstall also remove each enrolled account's per-user
	// DefenseClaw data and binaries.
	Purge bool
	// KeepState makes a (non-purge) uninstall keep the machine state: the
	// config, secrets, gateway and guardian state, logs and lifecycle
	// state, and the service account, so a reinstall resumes with them.
	// Without it uninstall removes all of it.
	KeepState bool
	// KeepServiceAccount makes uninstall keep the gateway service account,
	// which it removes otherwise.
	KeepServiceAccount bool
	// ProductVersion, when set, must equal the payload's version.
	ProductVersion string
	// Reason annotates an ensure run (e.g. "path", "secret", "package").
	Reason string
	// Mutate changes protected state (for example a credential) inside the
	// lifecycle lock, immediately before an ensure applies it, so the
	// change and its application are one transaction: the apply watcher
	// that the change wakes cannot interleave with it. A Mutate error fails
	// the run before anything is applied.
	Mutate func(ctx context.Context) error
}

// Error codes in the lifecycle result.
const (
	codeInvalidArguments    = "invalid_arguments"
	codeUnsupportedPlatform = "unsupported_platform"
	codeNotRoot             = "not_root"
	codeServiceManager      = "service_manager_unavailable"
	codeBusy                = "lifecycle_busy"
	codeChange              = "change_failed"
	codeProfileConflict     = "profile_conflict"
	codeUnmanagedLayout     = "unmanaged_layout_present"
	codeAlreadyInstalled    = "already_installed"
	codeDowngrade           = "downgrade_refused"
	codeNotInstalled        = "not_installed"
	codePayload             = "payload_invalid"
	codePackageOwned        = "package_owned_binaries"
	codeConfig              = "config_invalid"
	codeConfigRefused       = "config_refused"
	codeAccount             = "service_account"
	codeApply               = "apply_failed"
	codeActivate            = "activation_failed"
	codeRolledBack          = "rolled_back"
	codeRollbackFailed      = "rollback_failed"
	codeRecovered           = "recovered_interrupted_transaction"
	codeUninstall           = "uninstall_failed"
	codeReconcile           = "reconcile_failed"
	codeVerify              = "verify_failed"
	codeState               = "state_unreadable"
	codeLeftovers           = "unmanaged_leftovers"
	codeWSL                 = "wsl_distribution"
)

type lifecycle struct {
	env    *Env
	opts   Options
	result *enterprisestatus.Result
	// serviceUID is the gateway account of the running transaction.
	serviceUID int
	// planned are the inputs the last transaction of this run applied.
	planned *plannedInputs
	// reportChanges is set while a repair or ensure re-applies an installed
	// deployment: the result then lists what the transaction changed.
	reportChanges bool
	// perUserRemoved counts the per-user hook registrations an uninstall
	// removed, for its summary.
	perUserRemoved int
	// keptPerUser is what each enrolled account keeps after a default
	// uninstall; keptKnown is false when the accounts record was unreadable.
	keptPerUser []perUserKept
	keptKnown   bool
	// packageManaged is set when the deb/rpm owns the binaries, so the
	// uninstall leaves them to the package manager.
	packageManaged bool
	// serviceAccountKept is set when an uninstall could not delete the
	// service account (macOS can deny the directory-record delete).
	serviceAccountKept bool
	// gatewayKeptRunning is set when the gateway applied a config change
	// itself (hotConfigApply) and was not restarted.
	gatewayKeptRunning bool
}

// noteChange records one change a repair or ensure made to an installed
// deployment, so its result says what was repaired.
func (l *lifecycle) noteChange(format string, args ...any) {
	if l.reportChanges {
		l.result.Changes = append(l.result.Changes, fmt.Sprintf(format, args...))
	}
}

// plannedInputs are the administrator inputs one transaction planned from.
type plannedInputs struct {
	configSHA string
	// configFromInstalled is set when the config came from the installed
	// config.yaml rather than --config.
	configFromInstalled bool
	secretsSHA          string
}

// Run executes one lifecycle action and returns its result; the result's
// ExitCode is set.
func Run(ctx context.Context, env *Env, opts Options) *enterprisestatus.Result {
	env.fillDefaults()
	l := &lifecycle{
		env:    env,
		opts:   opts,
		result: enterprisestatus.New(opts.Action, managed.ProfileStandalone, env.GOOS, env.ProductVersion),
	}
	failure := l.run(ctx)
	// A run can describe the deployment more than once (after a follow-up
	// transaction, or a refused one), and each pass reports the same
	// standing warnings; the result names each problem once.
	l.result.Warnings = uniqueMessages(l.result.Warnings)
	l.result.Finish(env.GOOS, failure)
	return l.result
}

// uniqueMessages drops repeats of an identical code and message, keeping
// the first occurrence's position.
func uniqueMessages(messages []enterprisestatus.Message) []enterprisestatus.Message {
	seen := make(map[enterprisestatus.Message]bool, len(messages))
	out := messages[:0:0]
	for _, message := range messages {
		if seen[message] {
			continue
		}
		seen[message] = true
		out = append(out, message)
	}
	return out
}

// run returns the specific failure exit code (0 for the generic one).
func (l *lifecycle) run(ctx context.Context) int {
	env, r := l.env, l.result
	if !contains(Actions, l.opts.Action) {
		r.AddError(codeInvalidArguments, fmt.Sprintf("unknown action %q", l.opts.Action))
		return enterprisestatus.InvalidArgsExitCode(env.GOOS)
	}
	if code := l.validateOptions(); code != 0 {
		return code
	}
	if env.GOOS != "linux" && env.GOOS != "darwin" {
		r.AddError(codeUnsupportedPlatform, fmt.Sprintf("no standalone lifecycle for %s", env.GOOS))
		return 0
	}
	readOnly := l.opts.Action == ActionStatus || l.opts.Action == ActionVerify
	if env.Geteuid() != 0 && l.opts.Action != ActionStatus {
		r.AddError(codeNotRoot, "run this command as root (sudo or the MDM agent)")
		return 0
	}
	if err := env.Services.Check(ctx); err != nil {
		r.AddError(codeServiceManager, err.Error())
		return 0
	}
	if l.opts.Action != ActionInstall && l.opts.Action != ActionEnsure && env.insideWSL() {
		r.AddWarning(codeWSL, wslDeploymentWarning)
	}
	if readOnly {
		return l.readOnly(ctx)
	}

	if err := env.ensureDir(env.P(env.Layout.LifecycleDir), 0o700, rootOwner()); err != nil {
		r.AddError(codeState, err.Error())
		return 0
	}
	lock, err := env.acquireLock(ctx)
	if err != nil {
		if errors.Is(err, errLockBusy) {
			r.AddError(codeBusy, err.Error()+"; "+lockBusyNextStep(env.LockTimeout))
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
		r.AddError(codeState, err.Error())
		return 0
	}
	defer lock.release()
	if l.opts.Action == ActionUninstall {
		// An uninstall leaves no lifecycle directory holding only its lock
		// (a rerun, or the package preremove after an uninstall, found
		// nothing installed and would otherwise recreate it). A kept
		// deployment record or retained state keeps the directory.
		defer func() {
			dir := env.P(env.Layout.LifecycleDir)
			if entries, err := os.ReadDir(dir); err == nil && len(entries) == 1 && entries[0].Name() == lockFileName {
				_ = os.Remove(filepath.Join(dir, lockFileName))
				_ = os.Remove(dir)
			}
		}()
	}

	if !l.recoverInterrupted(ctx) && l.opts.Action != ActionUninstall {
		// The previous deployment's files are only in the kept snapshot;
		// changing anything now would lose them. Uninstall removes the
		// deployment either way, so it proceeds.
		return 0
	}
	record, err := env.loadDeployment()
	if err != nil {
		r.AddError(codeState, err.Error())
		return 0
	}
	if record != nil {
		r.Installed = true
		r.InstalledVersion = record.ProductVersion
		if l.opts.Action != ActionUninstall {
			l.recoverInterruptedRotation(ctx, record)
		}
	}
	if l.supersededApplyRun(record) {
		// A transaction leaves a queued apply run alone. When that
		// transaction upgraded the deployment, the queued run is still the
		// previous binary, whose rendering would undo part of the upgrade;
		// the transaction that upgraded read (or followed up on) the change
		// that started this run.
		r.Noop = true
		r.NoopReason = "superseded"
		r.AddWarning(codeSuperseded, fmt.Sprintf("this apply run's binary (%s) is older than the installed deployment (%s), which another run applied while this one waited; the installed binary applies later changes",
			env.ProductVersion, record.ProductVersion))
		l.describe(ctx, record, false)
		return 0
	}
	if l.opts.Mutate != nil {
		if l.opts.Action != ActionEnsure {
			r.AddError(codeInvalidArguments, "a protected-state change can only be applied by ensure")
			return enterprisestatus.InvalidArgsExitCode(env.GOOS)
		}
		resume := l.pauseApplyTrigger(ctx)
		err := l.opts.Mutate(ctx)
		resume()
		if err != nil {
			r.AddError(codeChange, err.Error())
			return 0
		}
		if record == nil && l.opts.PayloadDir == "" && !l.opts.FromPackage {
			// Staged before the first install (a credential the config
			// references): the install applies it.
			r.Noop = true
			r.NoopReason = "not_installed"
			r.AddWarning(codeNotInstalled, "DefenseClaw enterprise is not installed yet; the change is stored and the first install applies it")
			return 0
		}
	}

	switch l.opts.Action {
	case ActionInstall:
		if record != nil {
			r.AddError(codeAlreadyInstalled, "DefenseClaw enterprise is already installed; use upgrade, repair or ensure")
			return 0
		}
		return l.settleInputChanges(ctx, l.freshInstall(ctx))
	case ActionUpgrade:
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed; use install or ensure")
			return 0
		}
		if l.opts.PayloadDir == "" && !l.opts.FromPackage {
			r.AddError(codeInvalidArguments, "upgrade needs --payload or --from-package")
			return enterprisestatus.InvalidArgsExitCode(env.GOOS)
		}
		return l.settleInputChanges(ctx, l.apply(ctx, record))
	case ActionRepair:
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed; use install or ensure")
			return 0
		}
		return l.settleInputChanges(ctx, l.apply(ctx, record))
	case ActionEnsure:
		if record == nil {
			return l.settleInputChanges(ctx, l.freshInstall(ctx))
		}
		if env.insideWSL() {
			r.AddWarning(codeWSL, wslDeploymentWarning)
		}
		if noop, reason := l.ensureNoop(ctx, record); noop {
			r.Noop = true
			r.NoopReason = reason
			if !exists(env.committedConfigPath()) {
				// A deployment committed before the lifecycle kept the applied
				// config; the installed file is exactly that config.
				if raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err == nil && sha256Bytes(raw) == record.ConfigSHA256 {
					_ = env.saveCommittedConfig(raw)
				}
			}
			l.settleRejectedConfig()
			l.describe(ctx, record, false)
			// The host runs this package and is healthy, so what a failed
			// package run left (its result and the kept gateway output) is
			// stale, as after a run that commits a deployment; the run that
			// found it so used to keep it (GAP-0174).
			if l.opts.FromPackage && len(r.Errors) == 0 {
				l.clearSupersededFailures()
			}
			return 0
		}
		return l.settleInputChanges(ctx, l.apply(ctx, record))
	case ActionReconcile:

		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed")
			return 0
		}
		return l.reconcile(ctx, record)
	case ActionRotateCredentials:
		return l.rotateCredentials(ctx, record)
	case ActionUninstall:
		return l.uninstall(ctx, record)
	}
	return 0
}

// pauseApplyTrigger stops the Linux apply path unit while a protected-state
// change (enterprise secret set or remove) writes under this run's lock, and
// returns the function that starts it again. This run applies the change
// itself. Left watching, the path unit started the apply service on that
// write, and its redundant ensure held the lock for several seconds after
// this run returned, so a lifecycle command typed right after it failed
// lifecycle_busy (GAP-2261). The transaction stops the path unit anyway
// while it applies (quiesce) and starts it again when it activates.
func (l *lifecycle) pauseApplyTrigger(ctx context.Context) func() {
	env := l.env
	unit := Unit{Name: unitApplyPath, Kind: "path"}
	if env.GOOS != "linux" || !env.Services.Active(ctx, unit) || env.Services.Stop(ctx, unit) != nil {
		return func() {}
	}
	return func() { _ = env.Services.Start(context.WithoutCancel(ctx), unit) }
}

// codeSuperseded names an apply run that stood down for a newer binary.
const codeSuperseded = "lifecycle_superseded"

// supersededApplyRun reports an apply-trigger ensure (--reason path) whose
// binary is an older release than the recorded deployment.
func (l *lifecycle) supersededApplyRun(record *Deployment) bool {
	running := strings.TrimPrefix(l.env.ProductVersion, "v")
	if record == nil || l.opts.Action != ActionEnsure || l.opts.Reason != "path" || l.opts.AllowDowngrade ||
		running == "dev" || !versionPattern.MatchString(running) || compareProductVersions(running, record.ProductVersion) >= 0 {
		return false
	}
	// Stand down only while the newer binary the record describes is the
	// one installed. Older binaries on disk (for example a package
	// downgrade whose own ensure was refused) are this run's binary: it
	// reports the mismatch instead of silently skipping every change.
	installed := filepath.Join(l.env.Layout.BinDir, binGateway)
	digest, err := sha256File(l.env.P(installed))
	return err == nil && record.Files[installed] != "" && digest == record.Files[installed]
}

func (l *lifecycle) validateOptions() int {
	o, r := l.opts, l.result
	bad := func(message string) int {
		r.AddError(codeInvalidArguments, message)
		return enterprisestatus.InvalidArgsExitCode(l.env.GOOS)
	}
	if o.PayloadDir != "" && o.FromPackage {
		return bad("--payload and --from-package are mutually exclusive")
	}
	if (o.PayloadDir != "" || o.FromPackage || o.ConfigFile != "" || o.AdoptExisting || o.NoStart) &&
		!contains([]string{ActionInstall, ActionUpgrade, ActionRepair, ActionEnsure}, o.Action) {
		return bad(fmt.Sprintf("--payload, --from-package, --config, --adopt-existing and --no-start do not apply to %s", o.Action))
	}
	if o.Purge && o.Action != ActionUninstall {
		return bad("--purge applies only to uninstall")
	}
	if (o.KeepState || o.KeepServiceAccount) && o.Action != ActionUninstall {
		return bad("--keep-state and --keep-service-account apply only to uninstall")
	}
	if o.KeepState && o.Purge {
		return bad("--keep-state and --purge are mutually exclusive")
	}
	if o.ConfigFile != "" && !filepath.IsAbs(o.ConfigFile) {
		return bad("--config must be an absolute path")
	}
	return 0
}

// wslDeploymentWarning reports a deployment that already runs inside WSL.
const wslDeploymentWarning = "this Linux system is a WSL distribution: the Windows user can open it as root (wsl -u root) and Windows machine policy does not reach it, so DefenseClaw cannot enforce here; govern WSL from the Windows side (enterprise.machine_policy.windows_wsl) and uninstall this deployment"

// insideWSL reports whether this Linux system is a WSL distribution: the
// interop binfmt handler or /run/WSL is present, or the kernel release
// names Microsoft.
func (e *Env) insideWSL() bool {
	if e.GOOS != "linux" {
		return false
	}
	for _, marker := range []string{"/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late", "/run/WSL"} {
		if _, err := os.Stat(e.P(marker)); err == nil {
			return true
		}
	}
	release, err := os.ReadFile(e.P("/proc/sys/kernel/osrelease"))
	return err == nil && strings.Contains(strings.ToLower(string(release)), "microsoft")
}

func (l *lifecycle) freshInstall(ctx context.Context) int {
	env, r := l.env, l.result
	if env.insideWSL() {
		r.AddError(codeWSL, "refusing to install inside a WSL distribution: the Windows user can open it as root (wsl -u root) and Windows machine policy does not reach it, so it is not a boundary DefenseClaw can enforce; govern WSL from the Windows side with enterprise.machine_policy.windows_wsl")
		return 0
	}
	if present, where := env.secureClientPresent(); present {
		r.AddError(codeProfileConflict, fmt.Sprintf("a Cisco Secure Client DefenseClaw deployment is present (%s); the profiles are mutually exclusive — uninstall it first", where))
		return 0
	}
	channel := ChannelPayload
	if l.opts.FromPackage {
		channel = ChannelPackage
	}
	if l.opts.PayloadDir == "" && !l.opts.FromPackage {
		r.AddError(codeInvalidArguments, "install needs --payload <dir> or --from-package; to apply the installed package, run `"+
			env.lifecycleCommand(ActionEnsure)+" --from-package`")
		return enterprisestatus.InvalidArgsExitCode(env.GOOS)
	}
	var adopting *adoption
	if leftovers := env.unmanagedLeftovers(env.Services, channel); len(leftovers) > 0 {
		if !l.opts.AdoptExisting {
			r.AddError(codeUnmanagedLayout, "existing DefenseClaw machine state is not owned by a committed deployment ("+strings.Join(leftovers, ", ")+"); rerun with --adopt-existing to back it up and take it over")
			return 0
		}
		adopting = env.planAdoption(leftovers, channel)
	}
	return l.applyAdopting(ctx, nil, adopting)
}

// adoption is the takeover of a pre-existing unmanaged layout. It runs
// inside the install transaction: the plan is validated first, the unit
// files it removes are in the snapshot, and the units it stops and
// disables are restarted and re-enabled if the install rolls back.
type adoption struct {
	// leftovers are archived before anything changes.
	leftovers []string
	// units are stopped and disabled.
	units []string
	// removeFiles are unit files that would shadow or duplicate the new
	// deployment's units.
	removeFiles []string
}

// planAdoption decides what adopting leftovers changes. Config and state
// stay in place; a valid legacy config is reused when no --config is given.
func (e *Env) planAdoption(leftovers []string, channel string) *adoption {
	a := &adoption{leftovers: leftovers}
	if e.GOOS != "linux" {
		return a
	}
	a.units = append(a.units, legacyLinuxUnits...)
	for _, unit := range e.Services.Units() {
		a.units = append(a.units, unit.Name)
	}
	for _, name := range legacyLinuxUnits {
		if path := filepath.Join("/etc/systemd/system", name); exists(e.P(path)) {
			a.removeFiles = append(a.removeFiles, path)
		}
	}
	if channel == ChannelPackage {
		// systemd loads /etc/systemd/system before /usr/lib/systemd/system:
		// a unit an earlier manual deployment left there under a packaged
		// name would replace the package's definition.
		for _, unit := range e.Services.Units() {
			if path := e.Services.DefinitionPath(unit, ChannelPayload); exists(e.P(path)) {
				a.removeFiles = append(a.removeFiles, path)
			}
		}
	}
	return a
}

// archiveAdoption backs up the leftovers before the transaction changes
// anything.
func (l *lifecycle) archiveAdoption(a *adoption) error {
	env := l.env
	archive := filepath.Join(env.P(env.Layout.LifecycleDir), adoptedPrefix+env.Now().UTC().Format("20060102T150405.000000000Z")+".tar.gz")
	if err := env.archivePaths(archive, a.leftovers); err != nil {
		return fmt.Errorf("back up the existing layout: %w", err)
	}
	l.result.AddWarning("adopted_existing_layout", "backed up the existing layout to "+archive)
	return nil
}

// takeOver stops and disables the adopted units and removes the unit
// files that would shadow the new deployment.
func (l *lifecycle) takeOver(ctx context.Context, a *adoption) error {
	env := l.env
	if len(a.units) == 0 && len(a.removeFiles) == 0 {
		return nil
	}
	for _, name := range a.units {
		unit := Unit{Name: name}
		_ = env.Services.Stop(ctx, unit)
		_ = env.Services.Disable(ctx, unit)
	}
	for _, path := range a.removeFiles {
		if err := removeFile(env.P(path)); err != nil {
			return err
		}
	}
	return env.Services.Reload(ctx)
}

// archivePaths writes a gzip tar of the given canonical paths.
func (e *Env) archivePaths(archive string, paths []string) error {
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	walkErr := func() error {
		for _, canonical := range paths {
			root := e.P(canonical)
			err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, err := os.Lstat(path)
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() && !info.IsDir() {
					return nil
				}
				header, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(e.P("/"), path)
				header.Name = rel
				if err := tw.WriteHeader(header); err != nil {
					return err
				}
				if info.Mode().IsRegular() {
					in, err := os.Open(path)
					if err != nil {
						return err
					}
					_, copyErr := io.Copy(tw, in)
					_ = in.Close()
					return copyErr
				}
				return nil
			})
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	}()
	closeErr := errors.Join(tw.Close(), gz.Close(), file.Sync(), file.Close())
	if walkErr != nil {
		_ = os.Remove(archive)
		return walkErr
	}
	return closeErr
}

// plan is the complete desired state of one apply.
type plan struct {
	account Account
	channel string
	version string
	payload *payload
	config  *validatedConfig
	// configFromInstalled is set when config came from the installed file.
	configFromInstalled bool
	secrets             []string
	secretsSHA          string
	dirs                []desiredDir
	files               []desiredFile
	binaries            []desiredFile
	createdDirs         []string
	stale               []string
	systemd             int
	installedAt         string
	// intended are the machine-policy connectors the config asks for;
	// machinePolicy is the subset the descriptor records (all of intended
	// unless a previous transaction with the same config could not place
	// some of them).
	intended      []string
	machinePolicy []string
	render        renderInputs
	// packageUnits are the digests of the unit files the Linux package
	// placed (package channel), keyed by canonical path.
	packageUnits map[string]string
}

// buildPlan computes the desired state without mutating the host. account
// must already exist.
func (l *lifecycle) buildPlan(ctx context.Context, record *Deployment, account Account) (*plan, error) {
	env := l.env
	p := &plan{account: account, channel: ChannelPayload, systemd: env.Services.Version(ctx)}
	if record != nil {
		p.channel = record.Channel
		p.installedAt = record.InstalledAt
	}
	if l.opts.FromPackage {
		p.channel = ChannelPackage
	} else if l.opts.PayloadDir != "" {
		p.channel = ChannelPayload
	}
	if p.installedAt == "" {
		p.installedAt = env.Now().UTC().Format(time.RFC3339)
	}

	switch {
	case l.opts.PayloadDir != "":
		pay, err := env.loadPayload(ctx, l.opts.PayloadDir)
		if err != nil {
			return nil, &codedError{code: codePayload, err: err}
		}
		p.payload = pay
	case p.channel == ChannelPackage:
		pay, err := env.loadPayload(ctx, env.P(env.Layout.BinDir))
		if err != nil {
			return nil, &codedError{code: codePayload, err: env.installedPayloadError(err, ChannelPackage)}
		}
		p.payload = pay
	default:
		// Repair or ensure without a payload keeps the installed binaries,
		// which must still be exactly what the record says.
		for name, want := range recordBinaries(env, record) {
			got, err := sha256File(env.P(filepath.Join(env.Layout.BinDir, name)))
			if err != nil || got != want {
				return nil, &codedError{code: codePayload, err: fmt.Errorf("installed %s does not match the deployment record; repair with --payload", name)}
			}
		}
		pay, err := env.loadPayload(ctx, env.P(env.Layout.BinDir))
		if err != nil {
			return nil, &codedError{code: codePayload, err: env.installedPayloadError(err, p.channel)}
		}
		p.payload = pay
	}
	p.version = p.payload.Version
	if record != nil && !l.opts.AllowDowngrade && compareProductVersions(p.version, record.ProductVersion) < 0 {
		return nil, &codedError{code: codeDowngrade, err: fmt.Errorf("payload version %s is older than the installed %s; downgrades are refused (rerun with --allow-downgrade to roll back deliberately)", p.version, record.ProductVersion)}
	}
	if l.opts.ProductVersion != "" && strings.TrimPrefix(l.opts.ProductVersion, "v") != p.version {
		return nil, &codedError{code: codePayload, err: fmt.Errorf("payload version %s does not match --product-version %s", p.version, l.opts.ProductVersion)}
	}
	if p.channel == ChannelPayload && l.opts.PayloadDir != "" && env.GOOS == "linux" {
		if env.packageOwned(ctx, filepath.Join(env.Layout.BinDir, binGateway)) {
			return nil, &codedError{code: codePackageOwned, err: errors.New("the installed binaries belong to the defenseclaw-enterprise package; upgrade with the package manager")}
		}
	}

	raw, fromInstalled, err := l.configBytes()
	if err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	validated, err := env.validateConfigSource(raw, l.opts.ConfigFile)
	if err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	if err := env.checkRulePacksReadable(validated, account); err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	// A config_version 8 administrator config (a previous release's, or an
	// MDM file still in that format) is installed as the v9 migration
	// writes it; its v8 checks above keep their wording.
	migrated, err := env.migrateConfigV9(ctx, raw, validated)
	if err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	if migrated != nil {
		v9, err := env.validateConfigSource(migrated.Migrated, l.opts.ConfigFile)
		if err != nil {
			return nil, &codedError{code: codeConfig, err: fmt.Errorf("the config_version 9 migration of the config does not validate: %w", err)}
		}
		if err := env.checkRulePacksReadable(v9, account); err != nil {
			return nil, &codedError{code: codeConfig, err: err}
		}
		if fromInstalled && record != nil && record.ProductVersion == p.version &&
			config.MigratedSource(env.P(env.Layout.ConfigPath), migrated.Record.SourceSHA256) {
			// Configuration management put back the v8 file this host
			// already migrated. Rewriting it again would fight that tool on
			// every run, so its bytes stay, as for any in-place edit (the
			// gateway migrates a v8 file in memory), and only the v9 checks
			// apply. This is only for a run that keeps the version: after a
			// rollback the earlier release put the v8 file back and recorded
			// its own version, so the upgrade migrates it again and replaces
			// the stale migration record (GAP-0113).
			v9.Raw, v9.SHA = validated.Raw, validated.SHA
		} else {
			v9.Migration = &configMigration{
				Source: append([]byte(nil), raw...), Record: migrated.Record,
				EnvKey: migrated.EnvKey, EnvValue: migrated.EnvValue,
			}
			// The migrated bytes replace the installed v8 file.
			fromInstalled = false
		}
		validated = v9
	}
	if err := env.checkCandidateAssets(validated); err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	p.configFromInstalled = fromInstalled
	p.config = validated

	p.secrets, p.secretsSHA, err = env.listSecrets()
	if err != nil {
		return nil, &codedError{code: codeState, err: err}
	}
	loadCredential := env.GOOS == "linux" && p.systemd >= loadCredentialSystemd

	p.intended, err = env.MachinePolicy.Intended(validated.Loaded)
	if err != nil {
		return nil, &codedError{code: codeMachinePolicy, err: err}
	}
	p.machinePolicy = p.intended
	if record != nil && record.ConfigSHA256 == validated.SHA && record.MachinePolicyConnectors != nil {
		// Same config: keep what the last transaction could actually place,
		// so a connector whose vendor file refuses DefenseClaw's entry does
		// not make every ensure re-apply and restart the services.
		p.machinePolicy = intersectSorted(record.MachinePolicyConnectors, p.intended)
	}

	p.dirs = env.managedDirs(account, loadCredential)
	for _, connector := range validated.machinePolicyEnabled(env.GOOS) {
		for _, dir := range machinePolicyDirs(env.GOOS, connector) {
			p.dirs = append(p.dirs, desiredDir{Path: dir, Mode: 0o755, Owner: rootOwner(), External: true})
		}
	}
	if err := env.checkSharedParentsTraversable(p.dirs); err != nil {
		return nil, &codedError{code: codeApply, err: err}
	}

	p.render = renderInputs{
		Account: account, Channel: p.channel, Version: p.version, InstalledAt: p.installedAt,
		Config: validated, Secrets: p.secrets, LoadCredential: loadCredential,
		MachinePolicy: p.machinePolicy,
	}
	files, err := env.renderFiles(p.render)
	if err != nil {
		return nil, &codedError{code: codeApply, err: err}
	}
	p.files = files
	if p.channel == ChannelPackage && env.GOOS == "linux" {
		p.packageUnits = map[string]string{}
		for _, unit := range env.Services.Units() {
			path := env.Services.DefinitionPath(unit, ChannelPackage)
			if digest, err := sha256File(env.P(path)); err == nil {
				p.packageUnits[path] = digest
			}
		}
	}
	serviceGroup := fileOwner{UID: 0, GID: account.GID}
	p.files = append(p.files, desiredFile{Path: env.Layout.ConfigPath, Data: validated.Raw, SHA: validated.SHA, Mode: 0o640, Owner: serviceGroup, Kind: "config", KeepContent: fromInstalled})

	if p.channel == ChannelPayload {
		for _, name := range sortedKeys(p.payload.Digests) {
			p.binaries = append(p.binaries, desiredFile{
				Path: filepath.Join(env.Layout.BinDir, name), Src: filepath.Join(p.payload.Dir, name),
				SHA: p.payload.Digests[name], Mode: 0o755, Owner: rootOwner(), Kind: "binary",
			})
		}
	}

	// Files the previous deployment wrote that this one no longer does.
	if record != nil {
		want := map[string]bool{}
		for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
			want[file.Path] = true
		}
		for path := range record.Files {
			if !want[path] {
				if p.channel == ChannelPackage && (strings.HasPrefix(path, env.Layout.BinDir+"/") || strings.HasPrefix(path, packageUnitDir+"/")) {
					continue // the package owns the binaries and units now
				}
				p.stale = append(p.stale, path)
			}
		}
		sort.Strings(p.stale)
	}
	return p, nil
}

func recordBinaries(env *Env, record *Deployment) map[string]string {
	out := map[string]string{}
	if record == nil {
		return out
	}
	for path, digest := range record.Files {
		if filepath.Dir(path) == env.Layout.BinDir {
			out[filepath.Base(path)] = digest
		}
	}
	return out
}

// configBytes picks the config to install: --config, else the installed
// file, else the default. fromInstalled reports the installed file.
func (l *lifecycle) configBytes() (data []byte, fromInstalled bool, err error) {
	env := l.env
	if l.opts.ConfigFile != "" {
		if err := trustedInputFile(l.opts.ConfigFile, "--config"); err != nil {
			return nil, false, err
		}
		data, err = readBounded(l.opts.ConfigFile, maxInputBytes)
		return data, false, err
	}
	data, err = readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err == nil {
		return data, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConfig(env.Layout), false, nil
	}
	return nil, false, err
}

type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func errorCode(err error, fallback string) string {
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}
	return fallback
}

// apply runs the install/upgrade/repair transaction.
func (l *lifecycle) apply(ctx context.Context, record *Deployment) int {
	return l.applyAdopting(ctx, record, nil)
}

// applyAdopting is apply that first takes over an adopted layout.
func (l *lifecycle) applyAdopting(ctx context.Context, record *Deployment, adopting *adoption) int {
	env, r := l.env, l.result
	serviceName := env.Layout.ServiceUser
	account, err := env.Accounts.Ensure(ctx, serviceName)
	if err != nil {
		r.AddError(codeAccount, err.Error())
		return 0
	}
	committedConfig := l.inPlaceConfigEdit(record)
	p, err := l.buildPlan(ctx, record, account)
	if err != nil {
		code := errorCode(err, codeApply)
		r.AddError(code, err.Error())
		if committedConfig != nil && (code == codeConfig || code == codeMachinePolicy) {
			l.revertRejectedConfig(record, committedConfig, nil)
		}
		if record != nil {
			// Refused before any change: the running deployment is untouched,
			// so the result reports its services and readiness rather than
			// an empty list that reads as a host that is down.
			l.describe(ctx, record, false)
		}
		return 0
	}
	l.serviceUID = account.UID
	l.planned = &plannedInputs{configSHA: p.config.SHA, configFromInstalled: p.configFromInstalled, secretsSHA: p.secretsSHA}
	l.reportChanges = record != nil && (l.opts.Action == ActionRepair || l.opts.Action == ActionEnsure)
	changesBefore := len(r.Changes)

	units := env.Services.Units()
	previouslyActive := []string{}
	for _, unit := range units {
		if env.Services.Active(ctx, unit) {
			previouslyActive = append(previouslyActive, unit.Name)
		}
	}
	// What started at boot before the transaction is put back if it rolls
	// back: activation enables every managed unit, and a packaged unit file
	// stays on disk after a rollback, so a unit left enabled would start at
	// the next boot as an uncommitted deployment.
	_, enabledRecorded := env.Services.(enabledReporter)
	previouslyEnabled := []string{}
	for _, unit := range units {
		if unitEnabled(ctx, env.Services, unit) {
			previouslyEnabled = append(previouslyEnabled, unit.Name)
		}
	}
	if adopting != nil {
		// What the adopted layout was running and starting at boot is put
		// back if this install rolls back.
		for _, name := range adopting.units {
			if isManagedUnit(units, name) {
				continue // recorded above
			}
			unit := Unit{Name: name}
			if env.Services.Active(ctx, unit) {
				previouslyActive = append(previouslyActive, name)
			}
			if unitEnabled(ctx, env.Services, unit) {
				previouslyEnabled = append(previouslyEnabled, name)
			}
		}
		if err := l.archiveAdoption(adopting); err != nil {
			r.AddError(codeUnmanagedLayout, err.Error())
			return 0
		}
	}

	snapshotID := env.Now().UTC().Format("20060102T150405.000000000Z")
	snapPaths := []string{}
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		if file.KeepContent {
			// Never written; a rollback must not put older bytes back over
			// a change made during the transaction.
			continue
		}
		snapPaths = append(snapPaths, file.Path)
	}
	snapPaths = append(snapPaths, p.stale...)
	if adopting != nil {
		snapPaths = append(snapPaths, adopting.removeFiles...)
	}
	snapPaths = append(snapPaths, filepath.Join(env.Layout.LifecycleDir, deploymentFileName))
	// The migration evidence goes back with the config on a rollback. An
	// existing generation record does not: the counter never goes back, and
	// the rollback records the restored config as a new generation. One this
	// transaction creates goes away with the config it names.
	if generation := configwrite.GenerationPath(env.Layout.ConfigPath); !exists(env.P(generation)) {
		snapPaths = append(snapPaths, generation)
	}
	if p.config.Migration != nil {
		snapPaths = append(snapPaths, env.Layout.ConfigPath+config.ConfigV8BackupSuffix, config.MigrationRecordPath(env.Layout.ConfigPath))
		if p.config.Migration.EnvKey != "" {
			snapPaths = append(snapPaths, serviceDotEnvPath(env))
		}
	}
	dirPaths := []string{}
	for _, dir := range p.dirs {
		dirPaths = append(dirPaths, dir.Path)
	}
	snap, err := env.takeSnapshot(snapshotID, snapPaths, dirPaths)
	if err != nil {
		r.AddError(codeApply, err.Error())
		return 0
	}
	pending := &Pending{
		Action: l.opts.Action, StartedAt: env.Now().UTC().Format(time.RFC3339), SnapshotDir: snap.Dir, Phase: "quiesce",
		PreviouslyActive: previouslyActive, PreviouslyEnabled: previouslyEnabled, EnabledRecorded: enabledRecorded,
	}
	if err := env.savePending(pending); err != nil {
		env.discardSnapshot(snap)
		r.AddError(codeApply, err.Error())
		return 0
	}

	failAndRollback := func(code string, cause error) int {
		r.AddError(code, cause.Error())
		// The rollback undoes this transaction's changes.
		r.Changes = r.Changes[:changesBefore]
		if record == nil {
			// A failed first install leaves no DefenseClaw entries behind in
			// vendor machine policy; an upgrade or repair keeps the previous
			// deployment's entries, which name the same hook binary.
			if _, err := env.MachinePolicy.RemoveAll(); err != nil {
				r.AddWarning(codeMachinePolicy, "remove machine policy after the failed install: "+err.Error())
			}
		}
		var revertConfig func()
		var newerConfig []byte
		if committedConfig != nil {
			// The snapshot of an in-place edit holds the edited bytes; the
			// previous deployment's config is the last applied copy. It goes
			// back before the services restart.
			revertConfig = func() { newerConfig = l.revertRejectedConfig(record, committedConfig, p.config.Raw) }
		}
		restored, err := l.rollback(ctx, snap, pending, false, revertConfig)
		if newerConfig != nil {
			l.restoreNewerConfig(record, newerConfig)
		}
		if err != nil {
			message := err.Error()
			if refusal := l.configRefusal(ctx); refusal != "" {
				message += "; the restored deployment's gateway refuses the configuration the same way: " + refusal
			}
			r.AddError(codeRollbackFailed, message)
		} else {
			r.AddWarning(codeRolledBack, "restored the previous deployment")
		}
		if !restored {
			// The snapshot holds the only copy of the previous files (a full
			// disk is the usual cause). Keep it and the pending intent so the
			// next lifecycle run retries the restore.
			r.AddWarning(codeRollbackFailed, keptSnapshotAdvice)
			return 0
		}
		_ = env.clearPending()
		env.discardSnapshot(snap)
		if record != nil {
			// The previous deployment is back and running; report it.
			l.describe(ctx, record, false)
		}
		return 0
	}

	if adopting != nil {
		if err := l.takeOver(ctx, adopting); err != nil {
			return failAndRollback(codeUnmanagedLayout, err)
		}
	}
	keep := l.keepRunningDuringChange(p)
	hot := l.hotConfigApply(ctx, record, p, adopting)
	if gateway, ok := gatewayUnitOf(units); hot && ok {
		keep[gateway.Name] = true
	}
	l.quiesce(ctx, units, keep)
	pending.Phase = "apply"
	_ = env.savePending(pending)

	createdDirs, err := l.applyDirs(p)
	if err != nil {
		return failAndRollback(codeApply, err)
	}
	if err := env.settleSecretModes(ctx, account); err != nil {
		return failAndRollback(codeApply, err)
	}
	changed, err := l.applyFilesRecorded(ctx, p, account)
	if err != nil {
		return failAndRollback(codeApply, err)
	}
	if record != nil {
		// An edit made in place (the config-apply trigger) is never rewritten,
		// so applyFiles does not name it; the result still says it was applied.
		if p.configFromInstalled && p.config.SHA != record.ConfigSHA256 {
			l.noteChange("applied the edited %s", env.Layout.ConfigPath)
		}
		if p.secretsSHA != record.SecretsSHA256 {
			l.noteChange("applied the changed secrets")
		}
	}
	changesApplied := len(r.Changes) > changesBefore
	// Vendor machine policy goes in before the services start so the
	// gateway loads a descriptor that names exactly the connectors whose
	// hooks are in place.
	if err := l.publishMachinePolicy(p, changed); err != nil {
		return failAndRollback(errorCode(err, codeMachinePolicy), err)
	}
	restartSockets := socketsToRestart(env, units, record, p, changed)
	if err := env.initialManifest(account); err != nil {
		return failAndRollback(codeApply, err)
	}
	if l.opts.Action == ActionRepair {
		// The guardian and the enumerator are stopped: neither reads or
		// rewrites the manifest while deleted accounts leave it.
		l.revokeDeletedAccounts(ctx)
	}
	if env.GOOS == "linux" {
		if _, err := env.Runner.Run(ctx, "restorecon", "-R", env.P(env.Layout.InstallRoot), env.P(env.Layout.ConfigDir)); err != nil && !errors.Is(err, ErrCommandNotFound) {
			r.AddWarning("selinux_relabel", err.Error())
		}
	}
	if err := env.Services.Reload(ctx); err != nil {
		return failAndRollback(codeApply, err)
	}

	pending.Phase = "activate"
	_ = env.savePending(pending)
	activationStarted := env.Now()
	if !l.opts.NoStart {
		if err := l.activate(ctx, units, restartSockets, hot); err != nil {
			// A readiness failure on the API port already names the holder.
			if named := (*apiPortHeldError)(nil); !errors.As(err, &named) {
				if held := l.portHeldProblem(ctx, account.UID, false); held != "" {
					err = fmt.Errorf("%w; %s", err, held)
				}
			}
			if refusal := l.configRefusal(ctx); refusal != "" {
				err = fmt.Errorf("%w; %s", err, env.configRefusedMessage(refusal))
			}
			if excerpt := l.recordActivationFailure(ctx); excerpt != "" {
				err = fmt.Errorf("%w; gateway output (kept in %s): %s", err,
					filepath.Join(env.Layout.LifecycleDir, activationFailureFileName), excerpt)
			}
			return failAndRollback(codeActivate, err)
		}
		for _, unit := range units {
			if !unit.Activate || !env.Services.Active(ctx, unit) {
				continue
			}
			switch {
			case !contains(previouslyActive, unit.Name):
				l.noteChange("started %s, which was not running", unit.Name)
			case changesApplied && unit.Kind == "gateway" && !l.gatewayKeptRunning:
				l.noteChange("restarted %s to load the change", unit.Name)
			}
		}
	} else {
		for _, unit := range units {
			if unit.Activate {
				_ = env.Services.Disable(ctx, unit)
			}
		}
		r.AddWarning("not_started", "installed without starting the services (--no-start); run repair or ensure to activate")
	}

	newRecord := &Deployment{
		Profile: managed.ProfileStandalone, Platform: env.GOOS, ProductVersion: p.version, Channel: p.channel,
		InstalledAt: p.installedAt, UpdatedAt: env.Now().UTC().Format(time.RFC3339), NoStart: l.opts.NoStart,
		ServiceUser: account.Name, ServiceUID: account.UID, ServiceGID: account.GID,
		ConfigSHA256: p.config.SHA, SecretsSHA256: p.secretsSHA, Files: map[string]string{},
		MachinePolicyConnectors: append([]string{}, p.machinePolicy...),
		RulePacks:               copyStringMap(p.config.RulePacks),
	}
	if record != nil {
		newRecord.CreatedServiceAccount = record.CreatedServiceAccount
		newRecord.CreatedDirs = append(newRecord.CreatedDirs, record.CreatedDirs...)
	}
	newRecord.CreatedServiceAccount = newRecord.CreatedServiceAccount || account.Created
	newRecord.CreatedDirs = mergeUnique(newRecord.CreatedDirs, createdDirs)
	for _, file := range p.files {
		newRecord.Files[file.Path] = file.SHA
	}
	for _, file := range p.binaries {
		newRecord.Files[file.Path] = file.SHA
	}
	if p.channel == ChannelPackage {
		for name, digest := range p.payload.Digests {
			newRecord.Files[filepath.Join(env.Layout.BinDir, name)] = digest
		}
		// The applied package units, so the next upgrade restarts a socket
		// only when its definition actually changed.
		for path, digest := range p.packageUnits {
			newRecord.Files[path] = digest
		}
	}

	if !l.opts.NoStart && l.testFaultAfterServicesRequested() {
		return failAndRollback(codeLifecycleTestFault, errors.New("the lifecycle test fault asked this run to fail after its services started"))
	}
	if !l.opts.NoStart {
		// Inputs written during this transaction are applied by a follow-up
		// (settleInputChanges); they do not fail this one.
		if problems := l.verifyDeployment(ctx, newRecord, false, l.inputsChanged()); len(problems) > 0 {
			return failAndRollback(codeVerify, errors.New(strings.Join(problems, "; ")))
		}
	}
	if err := env.saveDeployment(newRecord); err != nil {
		return failAndRollback(codeApply, err)
	}
	_ = env.clearPending()
	// The deployment owns its state again; a kept-state record from an
	// earlier non-purge uninstall no longer applies.
	env.clearRetainedState()
	l.clearSupersededFailures()
	if err := env.saveCommittedConfig(p.config.Raw); err != nil {
		r.AddWarning(codeConfigReverted, "could not keep a copy of the applied config; a rejected in-place edit cannot be reverted: "+err.Error())
	}
	l.settleRejectedConfig()
	env.discardSnapshot(snap)
	r.Installed = true
	r.InstalledVersion = newRecord.ProductVersion
	if !l.opts.NoStart {
		// The result reports what the guardian found under the new state
		// (an agent the change left without hooks), not its previous report.
		if l.awaitGuardianReport(ctx, activationStarted) {
			l.noteRepairedTargets(activationStarted)
		}
	}
	l.describe(ctx, newRecord, false)
	// The change that leaves the eligible users without a connector says so
	// at once, as on Windows, not only at the next status (GAP-0266).
	l.warnNoConnectorsEnabled(p.config)
	return 0
}

// quiesce stops the services in reverse activation order. Sockets stay up
// so hooks queue during the change; they are restarted in activation only
// when their definition changed. The units in keep stay as they are.
func (l *lifecycle) quiesce(ctx context.Context, units []Unit, keep map[string]bool) {
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage > ordered[j].Stage })
	for _, unit := range ordered {
		if unit.Kind == "socket" || unit.Name == l.env.SelfUnit || keep[unit.Name] {
			continue
		}
		_ = l.env.Services.Stop(ctx, unit)
	}
}

// keepRunningDuringChange lists the config-apply entry points a transaction
// leaves alone. A run of the apply service (Linux) or job (macOS) that is
// waiting for the lifecycle lock was started by a change to config.yaml, a
// secret or a policy, often by this transaction's own writes; stopping it
// killed the waiting run, which left defenseclaw-enterprise-apply.service
// failed and dropped an administrator change made during the transaction.
// Left alone it runs ensure once this transaction releases the lock. The
// macOS job is also its own path watcher, so it is kept only while its
// definition stays the same (a changed plist must be reloaded).
func (l *lifecycle) keepRunningDuringChange(p *plan) map[string]bool {
	env := l.env
	keep := map[string]bool{}
	switch env.GOOS {
	case "linux":
		keep[unitApplyService] = true
	case "darwin":
		unit := Unit{Name: labelApply}
		path := env.Services.DefinitionPath(unit, p.channel)
		current, err := sha256File(env.P(path))
		if err != nil {
			return keep
		}
		for _, file := range p.files {
			if file.Path == path && file.SHA == current {
				keep[labelApply] = true
			}
		}
	}
	return keep
}

func (l *lifecycle) applyDirs(p *plan) ([]string, error) {
	env := l.env
	created := []string{}
	for _, dir := range p.dirs {
		path := env.P(dir.Path)
		if dir.External {
			if exists(path) {
				if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
					// /opt on some systems is a symlink (ostree); resolve by
					// refusing to write through it.
					return nil, fmt.Errorf("%s exists and is not a plain directory", dir.Path)
				}
				continue
			}
			created = append(created, dir.Path)
		}
		if err := env.ensureDir(path, dir.Mode, dir.Owner); err != nil {
			return nil, err
		}
	}
	for _, file := range p.files {
		if err := mkdirParents(env.P(filepath.Dir(file.Path))); err != nil {
			return nil, err
		}
	}
	return created, nil
}

// applyFilesRecorded is applyFiles under config.yaml.lock, the single
// writer's lock (actor lifecycle): it then records the installed config in
// config.generation.json when the config changed or the record does not
// match it, and keeps the v8 bytes and migration-v9.json when the run
// migrated a config_version 8 config.
func (l *lifecycle) applyFilesRecorded(ctx context.Context, p *plan, account Account) (map[string]bool, error) {
	env := l.env
	configPath := env.P(env.Layout.ConfigPath)
	var changed map[string]bool
	_, err := configwrite.Locked(ctx, configPath, configwrite.Options{
		Actor: configwrite.ActorLifecycle, Reason: "enterprise " + l.opts.Action,
	}, func() (bool, error) {
		var err error
		if changed, err = l.applyFiles(p); err != nil {
			return false, err
		}
		state, stateErr := configwrite.ReadGenerationState(configPath)
		return changed[env.Layout.ConfigPath] || stateErr != nil || state.ConfigSHA256 != p.config.SHA, nil
	})
	if err != nil {
		return nil, err
	}
	// The gateway service reads the generation record, as it reads config.yaml.
	serviceGroup := fileOwner{UID: 0, GID: account.GID}
	if err := env.fixMetadata(env.P(configwrite.GenerationPath(env.Layout.ConfigPath)), 0o640, serviceGroup); err != nil {
		return nil, err
	}
	if migration := p.config.Migration; migration != nil && changed[env.Layout.ConfigPath] {
		if err := env.writeFileAtomic(configPath+config.ConfigV8BackupSuffix, migration.Source, 0o600, rootOwner()); err != nil {
			return nil, err
		}
		record, err := json.MarshalIndent(migration.Record, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := env.writeFileAtomic(env.P(config.MigrationRecordPath(env.Layout.ConfigPath)), append(record, '\n'), 0o640, serviceGroup); err != nil {
			return nil, err
		}
		if migration.EnvKey != "" {
			if err := writeMigratedDotEnvKey(env, migration, account); err != nil {
				return nil, err
			}
		}
		l.noteChange("migrated %s to config_version 9 (%d values moved, %d conflicts; the v8 file is kept as %s%s, the --config a rollback to a config_version 8 release needs)",
			env.Layout.ConfigPath, len(migration.Record.Moved), len(migration.Record.Conflicts), env.Layout.ConfigPath, config.ConfigV8BackupSuffix)
		if migration.Record.ActionsRowsIgnored > 0 {
			l.result.AddWarning(config.LocalEnforcementEntriesIgnored, fmt.Sprintf(
				"%d local block/allow entries in audit.db are ignored; the administrator config is the policy", migration.Record.ActionsRowsIgnored))
		}
	}
	return changed, nil
}

// serviceDotEnvPath is the gateway service's .env, which it loads at start.
func serviceDotEnvPath(env *Env) string {
	return filepath.Join(env.Layout.DataDir, ".env")
}

// writeMigratedDotEnvKey adds the scanner key a v8 config held inline to the
// service .env (unless the variable is already defined there), so the
// analyzer the migrated config enables keeps its credential.
func writeMigratedDotEnvKey(env *Env, migration *configMigration, account Account) error {
	path := env.P(serviceDotEnvPath(env))
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, changed := config.DotEnvWithKey(existing, migration.EnvKey, migration.EnvValue)
	if !changed {
		return nil
	}
	return env.writeFileAtomic(path, updated, 0o600, fileOwner{UID: account.UID, GID: account.GID})
}

// applyFiles writes every binary and file whose bytes differ, fixes the
// metadata of the rest, removes stale files, and returns the canonical
// paths it wrote or removed.
func (l *lifecycle) applyFiles(p *plan) (map[string]bool, error) {
	env := l.env
	changed := map[string]bool{}
	for _, file := range append(append([]desiredFile{}, p.binaries...), p.files...) {
		current, _ := sha256File(env.P(file.Path))
		if current == file.SHA {
			if l.reportChanges && env.metadataDiffers(env.P(file.Path), file.Mode, file.Owner) {
				l.noteChange("restored the mode and owner of %s", file.Path)
			}
			if err := env.fixMetadata(env.P(file.Path), file.Mode, file.Owner); err != nil {
				return nil, err
			}
			continue
		}
		if file.KeepContent {
			// Changed since the plan read it: the newer bytes stay, and the
			// run applies them in a follow-up transaction. A regular file
			// still gets the managed mode and owner.
			if info, err := os.Lstat(env.P(file.Path)); err == nil && info.Mode().IsRegular() {
				if err := env.fixMetadata(env.P(file.Path), file.Mode, file.Owner); err != nil {
					return nil, err
				}
			}
			continue
		}
		var err error
		if file.Src != "" {
			err = env.copyFileAtomic(file.Src, env.P(file.Path), file.Mode, file.Owner)
		} else {
			err = env.writeFileAtomic(env.P(file.Path), file.Data, file.Mode, file.Owner)
		}
		if err != nil {
			return nil, err
		}
		changed[file.Path] = true
		l.noteChange("rewrote %s", file.Path)
	}
	for _, path := range p.stale {
		if err := removeFile(env.P(path)); err != nil {
			return nil, err
		}
		changed[path] = true
		l.noteChange("removed %s, which the deployment no longer uses", path)
		if ownedParent(filepath.Dir(path)) {
			_ = removeDirIfEmpty(env.P(filepath.Dir(path)))
		}
	}
	return changed, nil
}

// metadataDiffers reports whether path's permission bits or owner differ
// from the managed ones fixMetadata sets.
func (e *Env) metadataDiffers(path string, mode os.FileMode, owner fileOwner) bool {
	_, _, current, err := statOwnerMode(path)
	if err != nil {
		return false
	}
	uid, gid, err := e.OwnerOf(path)
	return err == nil && (current.Perm() != mode.Perm() || uid != owner.UID || gid != owner.GID)
}

func (e *Env) fixMetadata(path string, mode os.FileMode, owner fileOwner) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return e.Lchown(path, owner.UID, owner.GID)
}

// initialManifest seeds an empty guardian manifest so the guardian and the
// sensor helper start before the enumerator has published its first rows.
// An existing manifest (enumerator- or administrator-written) is kept.
func (e *Env) initialManifest(account Account) error {
	path := e.P(e.Layout.ManifestPath)
	if exists(path) {
		return nil
	}
	return e.writeFileAtomic(path, []byte("version: 1\ntargets: []\n"), 0o640, fileOwner{UID: 0, GID: account.GID})
}

// packageUnitDir is where the Linux package installs its units.
const packageUnitDir = "/usr/lib/systemd/system"

// socketsToRestart lists the listening sockets whose definition changed in
// this transaction. Every other socket keeps its listener: PID 1 holds it
// across the gateway restart, so queued hooks survive and no other local
// process can bind the port while the definition is replaced. A package
// upgrade that leaves a socket unit byte-identical does not restart it; a
// record written before the lifecycle tracked package units falls back to
// restarting on a version change.
func socketsToRestart(env *Env, units []Unit, record *Deployment, p *plan, changed map[string]bool) map[string]bool {
	restart := map[string]bool{}
	for _, unit := range units {
		if unit.Kind != "socket" {
			continue
		}
		path := env.Services.DefinitionPath(unit, p.channel)
		switch {
		case changed[path]:
			restart[unit.Name] = true
		case p.channel == ChannelPackage && record != nil:
			previous, tracked := record.Files[path]
			if tracked {
				restart[unit.Name] = previous != p.packageUnits[path]
			} else {
				restart[unit.Name] = record.ProductVersion != p.version
			}
		}
	}
	return restart
}

// activate enables and starts the units in stage order and waits for the
// gateway to report healthy. A running socket keeps its listener (queued
// hooks survive the change) unless its definition changed; a changed one is
// restarted in one service-manager job, so the port is unbound only for
// the moment the listener is replaced. With hot, a gateway that kept running
// is not started again: it is waited for until it has applied the config.
func (l *lifecycle) activate(ctx context.Context, units []Unit, restartSockets map[string]bool, hot bool) error {
	env := l.env
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage < ordered[j].Stage })
	for _, unit := range ordered {
		if !unit.Activate {
			continue
		}
		wasDisabled := unitDisabled(ctx, env.Services, unit)
		if err := env.Services.Enable(ctx, unit); err != nil {
			return fmt.Errorf("enable %s: %w", unit.Name, err)
		}
		if wasDisabled {
			l.noteChange("re-enabled %s, which was disabled and would not start after a reboot", unit.Name)
		}
		if unit.Name == env.SelfUnit {
			// Already running: this transaction executes inside it.
			continue
		}
		if unit.Kind == "path" && env.GOOS == "darwin" && env.Services.Active(ctx, unit) {
			// The apply job stayed loaded through the change (its definition
			// did not change); a kickstart would kill a queued run.
			continue
		}
		if unit.Kind == "socket" && env.Services.Active(ctx, unit) {
			if !restartSockets[unit.Name] {
				continue
			}
			if err := restartUnit(ctx, env.Services, unit); err != nil {
				return fmt.Errorf("restart %s: %w", unit.Name, err)
			}
			continue
		}
		if hot && unit.Kind == "gateway" && env.Services.Active(ctx, unit) {
			if err := l.settleHotGateway(ctx, unit); err != nil {
				return err
			}
			continue
		}
		if err := env.Services.Start(ctx, unit); err != nil {
			return fmt.Errorf("start %s: %w", unit.Name, err)
		}
		if unit.Kind == "gateway" {
			if err := l.waitGatewayReady(ctx, unit); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *lifecycle) waitGatewayReady(ctx context.Context, unit Unit) error {
	env := l.env
	deadline := env.Now().Add(env.ReadyTimeout)
	var lastErr error
	for {
		if env.Services.Active(ctx, unit) {
			_, err := l.gatewayHealth(ctx, unit, l.serviceUID)
			if err == nil {
				return nil
			}
			lastErr = err
		} else {
			lastErr = fmt.Errorf("%s is not active", unit.Name)
		}
		if !env.Now().Before(deadline) {
			return fmt.Errorf("gateway did not become ready within %s: %w", env.ReadyTimeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(env.PollInterval):
		}
	}
}

// keptSnapshotAdvice tells the administrator what a kept snapshot means.
const keptSnapshotAdvice = "the previous deployment could not be fully restored; its snapshot and the pending transaction are kept and the next lifecycle run retries the restore (free disk space first if the disk is full)"

// rollback puts the host back as the pending intent recorded it: the units
// the transaction enabled are disabled again, everything is stopped, the
// snapshot is restored and what was running and enabled before is started
// and enabled again. With restoreFirst the files are put back before any
// service is touched (linking and renaming are safe while the services
// run), and a restore that fails returns without stopping or starting
// anything. restored is false when any file could not be put back; the
// snapshot must then be kept for a retry.
func (l *lifecycle) rollback(ctx context.Context, snap *snapshot, intent *Pending, restoreFirst bool, beforeStart func()) (restored bool, err error) {
	env := l.env
	units := env.Services.Units()
	previouslyActive, previouslyEnabled := intent.PreviouslyActive, intent.PreviouslyEnabled
	var disableErrs []error
	if intent.EnabledRecorded {
		// Disabled while the unit files still exist (a failed payload install
		// removes its own). A packaged unit file stays in /usr/lib after the
		// rollback, so an enabled one would start an uncommitted gateway, or
		// sockets next to a restored legacy layout, at the next boot.
		for _, unit := range units {
			if !unit.Activate || unit.Name == env.SelfUnit || contains(previouslyEnabled, unit.Name) || !unitEnabled(ctx, env.Services, unit) {
				continue
			}
			if err := env.Services.Disable(ctx, unit); err != nil {
				disableErrs = append(disableErrs, fmt.Errorf("disable %s: %w", unit.Name, err))
			}
		}
	}
	if restoreFirst {
		if err := env.restoreFiles(snap); err != nil {
			return false, errors.Join(append(disableErrs, err)...)
		}
	}
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage > ordered[j].Stage })
	for _, unit := range ordered {
		// A socket that was listening before keeps listening, and the unit
		// running this transaction keeps running.
		if (unit.Kind == "socket" && contains(previouslyActive, unit.Name)) || unit.Name == env.SelfUnit {
			continue
		}
		if unit.Name == unitApplyService {
			// A queued apply run is waiting for the lock; it re-applies the
			// restored state (a no-op) or a change made meanwhile.
			continue
		}
		_ = env.Services.Stop(ctx, unit)
	}
	restoreErr := env.restore(snap)
	if beforeStart != nil {
		beforeStart()
	}
	if err := l.recordRestoredGeneration(ctx); err != nil {
		l.result.AddWarning(codeRolledBack, "could not record the restored config.yaml in "+configwrite.GenerationFileName+": "+err.Error())
	}
	reloadErr := env.Services.Reload(ctx)
	var startErrs []error
	for _, name := range previouslyEnabled {
		if err := env.Services.Enable(ctx, Unit{Name: name}); err != nil {
			startErrs = append(startErrs, err)
		}
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].Stage < units[j].Stage })
	for _, unit := range units {
		// A queued apply run was left running; starting the oneshot again
		// would wait for that run, which waits for this transaction's lock.
		if contains(previouslyActive, unit.Name) && unit.Name != env.SelfUnit && unit.Name != unitApplyService {
			if err := env.Services.Start(ctx, unit); err != nil {
				startErrs = append(startErrs, err)
			}
		}
	}
	// Units of an adopted layout that this deployment does not manage.
	for _, name := range previouslyActive {
		if !isManagedUnit(units, name) {
			if err := env.Services.Start(ctx, Unit{Name: name}); err != nil {
				startErrs = append(startErrs, err)
			}
		}
	}
	return restoreErr == nil, errors.Join(restoreErr, reloadErr, errors.Join(disableErrs...), errors.Join(startErrs...))
}

// recordRestoredGeneration records the config.yaml a rollback put back as a
// new config generation (actor lifecycle). The transaction may already have
// recorded, and the gateway reported, a generation for the config it
// installed; a monotonic counter keeps that number for that config only.
// Nothing is recorded when there is no config or no generation record, or
// when the record already names the restored bytes.
func (l *lifecycle) recordRestoredGeneration(ctx context.Context) error {
	env := l.env
	configPath := env.P(env.Layout.ConfigPath)
	statePath := env.P(configwrite.GenerationPath(env.Layout.ConfigPath))
	uid, gid, mode, err := statOwnerMode(statePath)
	if err != nil {
		return nil
	}
	if _, err := os.Stat(configPath); err != nil {
		return nil
	}
	_, err = configwrite.Locked(ctx, configPath, configwrite.Options{
		Actor: configwrite.ActorLifecycle, Reason: "enterprise " + l.opts.Action + " rollback",
	}, func() (bool, error) {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return false, err
		}
		state, stateErr := configwrite.ReadGenerationState(configPath)
		return stateErr != nil || state.ConfigSHA256 != configwrite.SHA256Hex(raw), nil
	})
	if err != nil {
		return err
	}
	return env.fixMetadata(statePath, mode.Perm(), fileOwner{UID: uid, GID: gid})
}

// recoverInterrupted rolls back a transaction a previous run left pending,
// or whose rollback could not restore every file. It returns false when
// the snapshot still could not be restored: the snapshot and the intent are
// kept, and the run must not change the host.
func (l *lifecycle) recoverInterrupted(ctx context.Context) bool {
	env, r := l.env, l.result
	pending, err := env.loadPending()
	if err != nil {
		r.AddWarning(codeRecovered, "discarded an unreadable pending transaction: "+err.Error())
		_ = env.clearPending()
		return true
	}
	if pending == nil {
		return true
	}
	snap, err := env.loadSnapshot(pending.SnapshotDir)
	if err == nil {
		err = env.checkBlobs(snap)
	}
	if err != nil {
		r.AddWarning(codeRecovered, fmt.Sprintf("an interrupted %s left no usable snapshot (%v); this run re-applies the desired state", pending.Action, err))
		_ = env.clearPending()
		if snap != nil {
			env.discardSnapshot(snap)
		}
		return true
	}
	// The files go back before any service is touched: a restore that
	// still fails (the disk is still full) then leaves the running services
	// alone instead of stopping and restarting the gateway on every apply
	// trigger, MDM ensure or package postinstall until it succeeds.
	restored, err := l.rollback(ctx, snap, pending, true, nil)
	switch {
	case !restored:
		r.AddError(codeRollbackFailed, fmt.Sprintf("could not roll back the interrupted %s started at %s: %v", pending.Action, pending.StartedAt, err))
		r.AddWarning(codeRollbackFailed, keptSnapshotAdvice)
		return false
	case err != nil:
		r.AddWarning(codeRecovered, fmt.Sprintf("rolled back an interrupted %s with errors: %v", pending.Action, err))
	default:
		r.AddWarning(codeRecovered, fmt.Sprintf("rolled back an interrupted %s started at %s", pending.Action, pending.StartedAt))
	}
	_ = env.clearPending()
	env.discardSnapshot(snap)
	return true
}

// ensureNoop reports whether the installed deployment already matches the
// desired state. It never mutates the host.
func (l *lifecycle) ensureNoop(ctx context.Context, record *Deployment) (bool, string) {
	env := l.env
	account, ok, err := env.Accounts.Lookup(ctx, env.Layout.ServiceUser)
	if err != nil || !ok || account.UID != record.ServiceUID || account.GID != record.ServiceGID {
		return false, ""
	}
	p, err := l.buildPlan(ctx, record, account)
	if err != nil {
		// apply reports the same error with rollback semantics.
		return false, ""
	}
	if p.version != record.ProductVersion || p.channel != record.Channel || p.config.SHA != record.ConfigSHA256 || p.secretsSHA != record.SecretsSHA256 || len(p.stale) > 0 {
		return false, ""
	}
	if l.opts.NoStart != record.NoStart {
		return false, ""
	}
	// The same config can resolve to another rule pack (an unset
	// rule_pack_dir follows <policy_dir>/guardrail/default once it exists).
	if !sameStringMap(p.config.RulePacks, record.RulePacks) {
		return false, ""
	}
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		if record.Files[file.Path] != file.SHA {
			return false, ""
		}
	}
	if problems := l.verifyInstalled(ctx, record, false); len(problems) > 0 {
		return false, ""
	}
	if l.machinePolicyDrift(p) {
		return false, ""
	}
	return true, "up_to_date"
}

func (l *lifecycle) reconcile(ctx context.Context, record *Deployment) int {
	env, r := l.env, l.result
	l.republishMachinePolicy(record)
	since := env.Now()
	var err error
	if env.GOOS == "linux" {
		err = env.Services.Start(ctx, Unit{Name: unitGuardianOneshot})
	} else {
		_, err = env.runGatewayCLI(ctx, "enterprise", "hooks", "reconcile", "--manifest", env.Layout.ManifestPath, "--json")
	}
	// `enterprise hooks reconcile` exits 1 when it could not protect a
	// target, after writing a report that names each one. describe reports
	// those targets for their accounts, so the reconcile fails for them in
	// the same words (not with the command line and its log output), and not
	// at all for a path an account broke in its own home or for the target
	// of an account that no longer exists, which verify does not fail on
	// either. The oneshot's failed state would only repeat the report.
	targets := err != nil && l.guardianTargetFailedSince(since)
	if targets && env.GOOS == "linux" {
		_, _ = env.Runner.Run(ctx, "systemctl", "reset-failed", unitGuardianOneshot)
	}
	if err != nil && !targets {
		r.AddError(codeReconcile, err.Error())
	}
	l.describe(ctx, record, false)
	if targets {
		named := false
		for _, warning := range r.Warnings {
			switch warning.Code {
			case codeHookContractUnverified, codeGuardianTargetFailed:
				r.AddError(codeReconcile, warning.Message)
				named = true
			case codeGuardianTargetUserPath, codeGuardianTargetAccountRemoved:
				named = true
			}
		}
		if !named {
			r.AddError(codeReconcile, err.Error())
		}
	}
	return 0
}

// uninstall stops and removes the deployment, with its machine state (the
// config, secrets, gateway and guardian state, logs and lifecycle state) and
// the service account. Each account keeps its own ~/.defenseclaw and
// per-user binaries unless purge is set. KeepState keeps the machine state
// for a reinstall to resume with.
func (l *lifecycle) uninstall(ctx context.Context, record *Deployment) int {
	env, r := l.env, l.result
	units := env.Services.Units()
	if record == nil && !l.opts.Purge {
		r.Noop = true
		r.NoopReason = "not_installed"
		// After a failed first package install, give the same finish step
		// as status and verify (GAP-2410).
		failure := env.lastPackageInstallFailure()
		env.warnPackageInstallFailed(r, failure)
		if leftovers := env.unmanagedLeftovers(env.Services, ChannelPayload); len(leftovers) > 0 {
			r.AddWarning(codeLeftovers, "no committed deployment, but DefenseClaw machine state exists ("+strings.Join(leftovers, ", ")+"); "+env.leftoversNextStep(ctx, failure != ""))
		}
		return 0
	}
	if !l.opts.Purge {
		// Read before the machine state, and the accounts record with it, go.
		l.keptPerUser, l.keptKnown = env.perUserLeftovers()
	}
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage > ordered[j].Stage })
	stopUnit := func(unit Unit) {
		_ = env.Services.Stop(ctx, unit)
		// On macOS launchctl disable writes an override into launchd's
		// database that no command can delete (GAP-1443). The definitions
		// are removed below; one that stays is disabled there.
		if unit.Activate && env.GOOS != "darwin" {
			_ = env.Services.Disable(ctx, unit)
		}
	}
	disableKeptDefinitions := func() {
		if env.GOOS != "darwin" {
			return
		}
		for _, unit := range units {
			if unit.Activate && exists(env.P(env.Services.DefinitionPath(unit, ChannelPayload))) {
				_ = env.Services.Disable(ctx, unit)
			}
		}
	}
	// The guardian repairs any DefenseClaw registration that goes missing
	// from a manifest target, the enumerator republishes the manifest, and
	// the apply and verify triggers start lifecycle runs. All of them stop
	// before any registration is removed; otherwise the guardian puts each
	// removed hook back within its debounce and the users are left with
	// registrations naming a binary this uninstall deletes. The gateway and
	// its sockets keep answering hooks until the registrations are gone.
	for _, unit := range ordered {
		if repairsRegistrations(unit) {
			stopUnit(unit)
		}
	}
	var errs []error
	// Per-user registrations go first, while the binaries they name still
	// exist: each user's worker removes only DefenseClaw's own entries (and,
	// on purge, that user's DefenseClaw state).
	//
	// Without a deployment record (after a default or --keep-state
	// uninstall) a purge still finds the enrolled accounts when the
	// enrollment record and the config it needs are there; otherwise it
	// names the accounts whose per-user files stay (GAP-2632).
	perUserLeft := false
	gatewayPresent := exists(filepath.Join(env.P(env.Layout.BinDir), binGateway))
	enrollmentKept := exists(env.P(env.Layout.ManifestPath)) && exists(env.P(env.Layout.ConfigPath))
	// Without a record, the package database says whether the deb/rpm owns
	// the binaries: a purge deleted those of an installed rpm (GAP-2632).
	l.packageManaged = env.GOOS == "linux" && (record != nil && record.Channel == ChannelPackage ||
		record == nil && gatewayPresent && env.packageOwned(ctx, filepath.Join(env.Layout.BinDir, binGateway)))
	if gatewayPresent && (record != nil || enrollmentKept) {
		perUserLeft = l.removePerUserRegistrations(ctx)
	} else if record == nil {
		l.warnUnpurgedPerUser(ctx)
	}
	// DefenseClaw's vendor machine policy entries go next, while the hook
	// binary they name still exists; administrator entries stay byte for
	// byte (enterprisepolicy restores the recorded preimage or edits only
	// DefenseClaw's own entries).
	if policy, err := env.MachinePolicy.RemoveAll(); err != nil {
		errs = append(errs, fmt.Errorf("remove machine policy: %w", err))
	} else {
		for _, state := range policy.States {
			if state.Changed {
				r.MachinePolicy[state.Connector] = state.ToStatus()
			}
		}
	}
	for _, unit := range ordered {
		if !repairsRegistrations(unit) {
			stopUnit(unit)
		}
	}
	if perUserLeft {
		disableKeptDefinitions()
		// Some users' agents still name the hook binary. Removing it now
		// would leave those registrations calling a program that no longer
		// exists, with nothing left to remove them: the binaries, the
		// deployment record and the state stay, so a rerun of this uninstall
		// removes the rest and ensure restores the deployment.
		if err := errors.Join(errs...); err != nil {
			r.AddError(codeUninstall, err.Error())
		}
		r.AddError(codeUninstall, "stopped before removing the DefenseClaw binaries, the deployment record and the state, because the per-user hook registrations listed above still name them; fix each one and rerun `"+l.uninstallCommand()+"`, or run ensure to restore the deployment")
		return 0
	}
	// On Linux the deb/rpm removes its own files. A macOS pkg has no
	// uninstaller, so the lifecycle removes the binaries and the receipt.
	packageManaged := l.packageManaged
	paths := []string{}
	if record != nil {
		for path := range record.Files {
			if packageManaged && (filepath.Dir(path) == env.Layout.BinDir || strings.HasPrefix(path, "/usr/lib/")) {
				continue
			}
			paths = append(paths, path)
		}
	} else {
		for _, unit := range units {
			paths = append(paths, env.Services.DefinitionPath(unit, ChannelPayload))
		}
		paths = append(paths, env.Layout.DescriptorPath)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if path == env.Layout.ConfigPath {
			continue // machine state: removed with its directory below
		}
		if err := removeFile(env.P(path)); err != nil {
			errs = append(errs, err)
		}
		if ownedParent(filepath.Dir(path)) {
			_ = removeDirIfEmpty(env.P(filepath.Dir(path)))
		}
	}
	if err := env.Services.Reload(ctx); err != nil {
		errs = append(errs, err)
	}
	if env.GOOS == "linux" {
		// A unit that failed before uninstall (the daily verify, say)
		// would otherwise stay listed as "not-found failed".
		names := make([]string, 0, len(units))
		for _, unit := range units {
			names = append(names, unit.Name)
		}
		_, _ = env.Runner.Run(ctx, "systemctl", append([]string{"reset-failed"}, names...)...)
		// A Persistent= timer leaves its last-trigger stamp behind.
		for _, name := range append(names, legacyLinuxUnits...) {
			if strings.HasSuffix(name, ".timer") {
				_ = removeFile(env.P(systemdTimerStampPath(name)))
			}
		}
	}
	if env.GOOS == "darwin" {
		// launchctl disable writes an override to launchd's database that
		// outlives the job, and launchctl cannot delete one. A label that an
		// older version or --no-start disabled goes back to launchd's
		// default, enabled, once its definition is gone (Enable writes
		// nothing for a label that is not disabled). A definition that is
		// still there is disabled, so a reboot does not start it.
		for _, unit := range units {
			if unit.Activate && !exists(env.P(env.Services.DefinitionPath(unit, ChannelPayload))) {
				_ = env.Services.Enable(ctx, unit)
			}
		}
		disableKeptDefinitions()
	}
	_ = os.RemoveAll(env.P(env.Layout.HookSocketDir))
	// Runtime leftovers of the stopped services: the sensor helper's socket
	// directory and the gateway's plugin cache (its TempDir is /tmp: the
	// service manager sets no TMPDIR).
	_ = os.RemoveAll(env.P(env.Layout.SensorSocketDir))
	if record != nil && record.ServiceUID > 0 {
		_ = os.RemoveAll(env.P(fmt.Sprintf("/tmp/defenseclaw-plugin-cache-%d", record.ServiceUID)))
	}
	// Vendor policies are product files: they leave with the deployment,
	// including the nested rule-pack directories.
	_ = os.RemoveAll(env.P(env.Layout.VendorPolicyDir))
	// The managed OpenCode plugin left with the recorded files above.
	_ = removeDirIfEmpty(env.P(openCodePluginDir(env.Layout)))
	_ = removeDirIfEmpty(env.P(filepath.Dir(env.Layout.VendorPolicyDir)))
	if env.GOOS == "darwin" {
		if record != nil && record.Channel == ChannelPackage {
			_, _ = env.Runner.Run(ctx, "pkgutil", "--forget", MacOSPackageID)
		}
	}
	if record != nil {
		// Deepest first: a parent is empty only once its children are gone
		// (/etc/claude-code after /etc/claude-code/managed-settings.d).
		dirs := append([]string(nil), record.CreatedDirs...)
		sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
		for _, dir := range dirs {
			_ = removeDirIfEmpty(env.P(dir))
		}
	}
	_ = env.clearPending()
	// An interrupted credential rotation ends here too: the services are
	// stopped, so its staged key would otherwise outlive the deployment and
	// be accepted again by a reinstall until a lifecycle run settled it.
	// The committed key stays with the retained state.
	if err := env.removeRotationKeys(); err != nil {
		errs = append(errs, err)
	} else if err := env.clearRotationIntent(); err != nil {
		errs = append(errs, err)
	}
	// No config is running once the deployment is gone; a reinstall that
	// keeps the retained config.yaml starts without an old rejection.
	_ = removeFile(env.rejectedConfigPath())
	_ = os.RemoveAll(filepath.Join(env.P(env.Layout.LifecycleDir), snapshotsDirName))
	env.removeSideStores("")

	// The machine state goes too (owner decision: the default uninstall
	// removes the services and the machine state; only each account's own
	// data stays). A purge removes it whatever failed above; the default
	// uninstall only once everything above succeeded, so a failed one keeps
	// the deployment record, the config and the state for a rerun, or for
	// an ensure that restores the deployment.
	removeState := l.opts.Purge || (!l.opts.KeepState && len(errs) == 0)
	if removeState {
		for _, dir := range []string{env.Layout.ConfigDir, env.Layout.DataDir, env.Layout.GuardianAuthDir, env.Layout.LogDir, env.Layout.LifecycleDir} {
			if err := os.RemoveAll(env.P(dir)); err != nil {
				errs = append(errs, err)
			}
		}
		if !packageManaged {
			if err := os.RemoveAll(env.P(env.Layout.InstallRoot)); err != nil {
				errs = append(errs, err)
			}
		}
		if env.GOOS == "darwin" {
			_ = removeDirIfEmpty(env.P("/opt/cisco"))
			_ = removeDirIfEmpty(env.P("/Library/Logs/Cisco"))
		}
		if !l.opts.KeepServiceAccount {
			// By now the services, the binaries (this CLI included) and the
			// deployment record are gone, so failing the uninstall here would
			// leave a command that cannot be rerun. The account is a leftover
			// to delete by hand.
			if err := env.Accounts.Remove(ctx, env.Layout.ServiceUser); err != nil {
				l.serviceAccountKept = true
				r.AddWarning(codeAccount, fmt.Sprintf("the service account %s was not removed: %v; everything else is removed. Delete the account by hand: %s",
					env.Layout.ServiceUser, err, serviceAccountDeleteCommand(env.GOOS, env.Layout.ServiceUser)))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		if !removeState && record != nil {
			// The deployment record stays until the removal is complete:
			// without it a rerun of uninstall is a no-op and a reinstall
			// (the package postinstall, an MDM ensure) refuses the kept state
			// as an unmanaged layout. With it, rerunning uninstall finishes
			// the removal and ensure restores the deployment.
			err = fmt.Errorf("%w; the deployment record is kept: fix the cause and rerun uninstall (or run ensure to restore the deployment)", err)
		}
		r.AddError(codeUninstall, err.Error())
		return 0
	}
	_ = removeFile(env.deploymentPath())
	_ = removeFile(env.policyStatePath())
	if l.opts.KeepState && record != nil {
		// Record what stays so a reinstall resumes with it instead of
		// refusing it as an unmanaged layout.
		if err := env.recordRetainedState(); err != nil {
			r.AddWarning(codeLeftovers, "could not record the retained gateway state; a reinstall may need --adopt-existing: "+err.Error())
		}
	}
	r.Installed = false
	r.Changes = append(r.Changes, l.uninstallSummary(record)...)
	return 0
}

// serviceAccountDeleteCommand is how an administrator deletes the service
// account by hand after an uninstall could not.
func serviceAccountDeleteCommand(goos, name string) string {
	if goos == "darwin" {
		return "`sudo dscl . -delete /Users/" + name + "` and `sudo dscl . -delete /Groups/" + name + "`"
	}
	return "`sudo userdel " + name + "`"
}

// uninstallSummary says what a completed uninstall removed and kept, like
// the change list of ensure and repair. A bare "uninstall: done" did not
// tell the administrator what happened to the machine state or to the
// users' own data (GAP-1227).
func (l *lifecycle) uninstallSummary(record *Deployment) []string {
	env, r := l.env, l.result
	layout := env.Layout
	removed := "stopped and removed the DefenseClaw services, binaries and deployment record"
	if l.packageManaged {
		removed = "stopped and removed the DefenseClaw services and deployment record (the package manager removes the package's files)"
	}
	lines := []string{removed}
	if l.perUserRemoved > 0 {
		lines = append(lines, fmt.Sprintf("removed %d DefenseClaw per-user hook registrations from the enrolled accounts", l.perUserRemoved))
	}
	if len(r.MachinePolicy) > 0 {
		lines = append(lines, "removed DefenseClaw's machine policy entries for "+strings.Join(sortedKeys(r.MachinePolicy), ", "))
	}
	state := fmt.Sprintf("the managed config and secrets (%s), the gateway and guardian state (%s, %s), the logs (%s)",
		layout.ConfigDir, layout.DataDir, layout.GuardianAuthDir, layout.LogDir)
	switch {
	case l.opts.KeepState:
		lines = append(lines, "kept for a reinstall: "+state+" and the service account "+layout.ServiceUser)
	case l.opts.KeepServiceAccount:
		lines = append(lines, "removed the machine state: "+state+" and the lifecycle state ("+layout.LifecycleDir+"); kept the service account "+layout.ServiceUser)
	case l.serviceAccountKept:
		lines = append(lines, "removed the machine state: "+state+" and the lifecycle state ("+layout.LifecycleDir+"); the service account "+layout.ServiceUser+" stays (see the warning)")
	default:
		lines = append(lines, "removed the machine state: "+state+", the lifecycle state ("+layout.LifecycleDir+") and the service account "+layout.ServiceUser)
	}
	if !l.opts.Purge {
		if kept := l.keptPerUserLine(record); kept != "" {
			lines = append(lines, kept)
		}
	}
	return lines
}

// removePerUserRegistrations runs `enterprise hooks remove-all` (with
// --purge on a purge) and reports what it could not do, one message per
// account and connector: an error for a registration that is still in
// place, a warning for an account whose home is unavailable or whose
// per-user state stayed, and for a check that names no registration. It
// returns whether any registration is left.
func (l *lifecycle) removePerUserRegistrations(ctx context.Context) bool {
	env, r := l.env, l.result
	args := []string{"enterprise", "hooks", "remove-all", "--manifest", env.Layout.ManifestPath, "--json"}
	if l.opts.Purge {
		args = append(args, "--purge")
	}
	out, err := env.runGatewayCLI(ctx, args...)
	if err != nil && l.opts.Purge && !json.Valid(out.Stdout) {
		// An installed binary from before remove-all took --purge: remove
		// the registrations, which is what the binaries are kept for.
		out, err = env.runGatewayCLI(ctx, args[:len(args)-1]...)
	}
	var report struct {
		Pending     []string `json:"pending"`
		Failed      []string `json:"failed"`
		StateFailed []string `json:"state_failed"`
		Purged      []string `json:"purged"`
		Removed     int      `json:"removed"`
		// PurgedDetail is absent from an installed binary that predates it.
		PurgedDetail map[string]purgedUserDetail `json:"purged_detail"`
	}
	if jsonErr := json.Unmarshal(out.Stdout, &report); jsonErr != nil && err == nil {
		return false
	}
	l.perUserRemoved = report.Removed
	rerun := "`" + l.uninstallCommand() + "`"
	left := false
	for _, entry := range report.Failed {
		label, reason, _ := strings.Cut(entry, ": ")
		user, connector, ok := strings.Cut(label, "/")
		if !ok {
			// A check that names no registration (an unreadable eligible
			// accounts file, say) does not hold up the uninstall.
			r.AddWarning(codePerUserHooks, "some per-user hook registrations were not checked: "+entry)
			continue
		}
		r.AddError(codePerUserHooks, fmt.Sprintf("DefenseClaw's %s hooks for user %s were not removed: %s; fix the cause (or remove DefenseClaw's entries from that account's %s config) and rerun %s", connector, user, reason, connector, rerun))
		left = true
	}
	if err != nil && len(report.Failed) == 0 {
		r.AddError(codePerUserHooks, "the per-user hook registrations could not be removed: "+err.Error()+"; fix the cause and rerun "+rerun)
		left = true
	}
	for _, entry := range report.Pending {
		user, connector, _ := strings.Cut(entry, "/")
		r.AddWarning(codePerUserHooks, fmt.Sprintf("DefenseClaw's %s hooks for user %s were not removed because that account's home is not available; once it is, remove DefenseClaw's entries from that account's %s config", connector, user, connector))
	}
	for _, entry := range report.StateFailed {
		user, reason, _ := strings.Cut(entry, ": ")
		r.AddWarning(codePerUserState, fmt.Sprintf("the DefenseClaw per-user data and binaries of user %s were not removed: %s; fix the cause and rerun %s", user, reason, rerun))
	}
	// A purge deletes data an account created before the install; name each
	// account, instead of a bare "done".
	for _, user := range report.Purged {
		var detail *purgedUserDetail
		if found, ok := report.PurgedDetail[user]; ok {
			detail = &found
		}
		r.Changes = append(r.Changes, purgedUserChange(user, detail))
	}
	return left
}

// purgedUserDetail is what the purge found and removed for one account.
type purgedUserDetail struct {
	Data     bool `json:"data"`
	Binaries bool `json:"binaries"`
	Gateway  bool `json:"gateway"`
	UVCache  bool `json:"uv_cache"`
}

// purgedUserChange names what the purge removed for user: only what it
// found, so an account that never had a per-user install is not said to
// have lost per-user binaries and a gateway (GAP-1444). Without detail (an
// installed binary from before it) it names everything the purge covers.
func purgedUserChange(user string, detail *purgedUserDetail) string {
	const data = "all DefenseClaw per-user data of user %s (~/.defenseclaw, including its hook scripts and the foreign-hooks-backup folder)"
	if detail == nil {
		return fmt.Sprintf("removed "+data+" and its per-user binaries and launcher links in ~/.local/bin, after stopping its per-user gateway", user)
	}
	var text string
	switch {
	case detail.Data && detail.Binaries:
		text = fmt.Sprintf("removed "+data+" and its per-user binaries and launcher links in ~/.local/bin", user)
	case detail.Data:
		text = fmt.Sprintf("removed "+data, user)
	case detail.Binaries:
		text = fmt.Sprintf("removed the DefenseClaw per-user binaries and launcher links of user %s in ~/.local/bin", user)
	case detail.UVCache:
		text = fmt.Sprintf("removed DefenseClaw's entries in the uv cache (~/.cache/uv) of user %s", user)
	default:
		text = fmt.Sprintf("found no DefenseClaw per-user data or binaries of user %s to remove", user)
	}
	// Earlier per-user installers left a DefenseClaw wheel in the account's
	// uv cache per install; the purge removes those too (GAP-1947).
	if detail.UVCache && (detail.Data || detail.Binaries) {
		text += ", and DefenseClaw's entries in its uv cache (~/.cache/uv)"
	}
	if detail.Gateway {
		text += ", after stopping its per-user gateway"
	}
	return text
}

// uninstallCommand is this run's uninstall command line, for a rerun.
func (l *lifecycle) uninstallCommand() string {
	command := l.env.lifecycleCommand(ActionUninstall)
	if l.opts.Purge {
		command += " --purge"
	}
	if l.opts.KeepState {
		command += " --keep-state"
	}
	if l.opts.KeepServiceAccount {
		command += " --keep-service-account"
	}
	return command
}

func mergeUnique(values ...[]string) []string {
	set := map[string]bool{}
	for _, list := range values {
		for _, value := range list {
			set[value] = true
		}
	}
	return sortedKeys(set)
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// sameStringMap compares two maps, treating nil and empty as equal.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}
