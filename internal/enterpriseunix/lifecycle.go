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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
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
	// Without it uninstall removes that state except the gateway's sandbox
	// registrations, their key and the sandbox setup record while an account
	// keeps sandboxes. Purge removes those too.
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
	// MutateUndo puts back what Mutate changed when the run then refuses
	// the config before it changes anything (Result.ConfigRefused): a
	// refused secret set left the new credential on disk while the result
	// said the refused config changed nothing (GAP-1734).
	MutateUndo func(ctx context.Context) error
	// Bundle is a signed policy bundle (.dcbundle file or directory, an
	// absolute path) that an ensure stages, verifies, applies, confirms and
	// makes current (bundleapply.go).
	Bundle string
	// BundleInbox makes an ensure apply the highest version in the bundle
	// inbox (<etc>/bundles/inbox) and remove the processed files.
	BundleInbox bool
	// DeliveryID is the opaque `bundle apply --delivery-id` the bundle
	// receipt records ("" for none; enterprisestatus.CheckDeliveryID).
	DeliveryID string
	// Interrupted is closed when the command got SIGTERM or an interrupt.
	// A transaction then finishes the step it is in and rolls back at the
	// next safe point (before it stops the services, before it writes the
	// files, before it starts the services), and the run returns its result
	// for the command to print. The signal used to kill the run mid-step,
	// with no result, and a later run recovered it (I-1317). nil for none.
	Interrupted <-chan struct{}
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
	// codeInterrupted: a stop signal made the transaction roll back.
	codeInterrupted       = "interrupted"
	codeRollbackFailed    = "rollback_failed"
	codeRecovered         = "recovered_interrupted_transaction"
	codeUninstall         = "uninstall_failed"
	codeUninstallPrecheck = "uninstall_precheck_refused"
	// codeUninstallIncomplete: the uninstall stopped before removing the
	// binaries, because per-user hook registrations or vendor machine policy
	// still name them, and started the services again. The package removal
	// (preremove.sh) matches this code exactly and keeps the package files
	// (GAP-1519).
	codeUninstallIncomplete = "uninstall_incomplete"
	codeReconcile           = "reconcile_failed"
	codeVerify              = "verify_failed"
	codeState               = "state_unreadable"
	codeLeftovers           = "unmanaged_leftovers"
	codeWSL                 = "wsl_distribution"
	// codeConfigMetadataRestored: an unchanged config.yaml got its managed
	// mode and owner back without a transaction (GAP-0941).
	codeConfigMetadataRestored = "config_metadata_restored"
)

// maxMetadataRechecks bounds how often one ensure restores the config.yaml
// owner again and re-checks for a no-op after an install of the same bytes
// replaced it during the check.
const maxMetadataRechecks = 3

type lifecycle struct {
	env    *Env
	opts   Options
	result *enterprisestatus.Result
	// gatewayAuditFailure is the active mandatory event-history write failure
	// in the gateway's latest /health answer, used when describe computes
	// security_complete after reading that answer.
	gatewayAuditFailure bool
	// replacedHooksFenced is set once the run fenced the replaced
	// release's shell hooks (fenceReplacedHooks).
	replacedHooksFenced bool
	// keepThroughRollback names the units a rollback leaves running: the
	// gateway and the sensor helper of an interrupted hot transaction
	// (recoverInterrupted, GAP-0238).
	keepThroughRollback map[string]bool
	// serviceUID is the gateway account of the running transaction.
	serviceUID int
	// planned are the inputs the last transaction of this run applied.
	planned *plannedInputs
	// reportChanges is set while a repair or ensure re-applies an installed
	// deployment: the result then lists what the transaction changed.
	reportChanges bool
	// helperModeRestart is set when ensure applies because the running
	// sensor helper reported another Tetragon mode than the config renders
	// (helperModeDrift); the transaction's restart of the helper is the
	// change it reports.
	helperModeRestart bool
	// perUserStateKept names the accounts whose per-user state the purge
	// left in place (remove-all's state_failed: a pending cleanup still
	// needs it, or its home was not available). Their session-facts cache
	// stays with that state (GAP-0582).
	perUserStateKept map[string]bool
	// perUserRemoved counts the per-user hook registrations an uninstall
	// removed, for its summary.
	perUserRemoved int
	// floorCheckerKept: the uninstall kept the floor checker
	// (keepFloorChecker), for its summary.
	floorCheckerKept bool
	// keptPerUser is what each enrolled account keeps after a default
	// uninstall; keptKnown is false when the accounts record was unreadable.
	keptPerUser []perUserKept
	keptKnown   bool
	// enrolledHomes are the (rooted, clean) homes of the enrolled accounts
	// the record named before the uninstall removed it.
	enrolledHomes map[string]bool
	// packageManaged is set when the deb/rpm owns the binaries, so the
	// uninstall leaves them to the package manager.
	packageManaged bool
	// kernelRemoved are the Tetragon policies an uninstall removed, for its
	// summary.
	kernelRemoved []string
	// serviceAccountKept is set when an uninstall could not delete the
	// service account (macOS can deny the directory-record delete).
	serviceAccountKept bool
	// gatewayKeptRunning is set when the gateway applied a config change
	// itself (hotConfigApply) and was not restarted.
	gatewayKeptRunning bool
	// confirmCommitted is set while a committed change outside bundle mode
	// describes the gateway: a generation the gateway rejected or does not
	// run then fails the run with its cause, as verify does (GAP-0943).
	confirmCommitted bool
	// policyAssetsEdited is set when ensure found a policy asset the config
	// names edited in place (policyAssetsChanged): the apply then records the
	// next config_generation although config.yaml stayed the same.
	policyAssetsEdited bool
	// policyAssetRefusal is why the installed gateway binary refuses the
	// policy of an up-to-date deployment (configRefusal), found by
	// policyAssetsChanged: a policy asset the config names was edited in
	// place into one that does not load. ensure applies nothing and reports
	// it (GAP-0229).
	policyAssetRefusal string
	// noopPolicy is the policy ensureNoop computed for an up-to-date
	// deployment, which the result's policy block reuses once
	// (computePolicy) instead of building the generation again.
	noopPolicy *computedPolicy
	// failedInstallLeftovers is set when an uninstall removes what a failed
	// first package install left, with no deployment committed.
	failedInstallLeftovers bool
	// policiesKept is set when a Linux uninstall kept the administrator
	// policies in Layout.PolicyDir (GAP-0960).
	policiesKept bool
	// sandboxesKept names the accounts whose sandboxes a non-purge
	// uninstall kept; sandboxStoreKept is set once it kept the gateway's
	// registrations of them with it (GAP-0598).
	sandboxesKept       []string
	sandboxStoreKept    bool
	openshellRecordKept bool
	// configWrittenDuringRun holds a config.yaml another writer put in place
	// while a transaction of this run planned its own (applyFiles kept it).
	// A rollback restores the earlier file, so the newer one is put back
	// after it and applied once the run ends.
	configWrittenDuringRun []byte
	// rollbackConfigSHA is the config.yaml a rollback left in place for the
	// restored deployment's restart (the snapshot, or the reverted last
	// applied config), or "" when the restore failed. A config.yaml with
	// other bytes after the restart was written by another writer since and
	// is never overwritten (restoreNewerConfig, GAP-1379).
	rollbackConfigSHA string
	// rollbackConfigFile is the file of that config.yaml: a writer that
	// puts the same bytes back after the restart replaces it, which the
	// digest alone cannot tell (GAP-1411).
	rollbackConfigFile os.FileInfo
	// configACLWritable is set when a transaction found a macOS ACL entry
	// that let another account write config.yaml after the plan checked it,
	// or could not read the ACLs: bytes that changed since are not applied,
	// also when removing the entry failed (GAP-1501, GAP-1535).
	configACLWritable bool
	// generationBefore is config.generation.json as the running transaction
	// found it; generationExposed is set once the gateway can have read the
	// transaction's config (it applies a config change itself, or the services
	// start). A rollback before that puts the record back as it was: no
	// gateway reported the generation the failed run recorded, so the counter
	// has nothing to protect and a run that changed nothing left the
	// generation moved (GAP-0381). After it the counter only moves forward.
	generationBefore  *generationRecord
	generationExposed bool
	// interruptedConfigSHA is the hex SHA-256 of the config.yaml an
	// interrupted transaction left, which this run's recovery rolled back:
	// the config of a bundle whose run was killed before it committed. Settle
	// reports that bundle interrupted, never superseded (GAP-1574).
	interruptedConfigSHA string
	// machinePolicyPublished is set once a transaction of this run wrote
	// vendor machine policy for its config, which a rollback then undoes.
	machinePolicyPublished bool
	// machinePolicyErr is the error of the last vendor machine policy
	// publish: a file DefenseClaw could not write its hooks into.
	machinePolicyErr error
	// osPlan is the sandbox subsystem of the plan this run built last.
	osPlan *openshellPlan
	// bundle is the signed policy bundle this run applies (nil for none).
	bundle *bundleRun
	// currentBundleGeneration attributes a plain ensure or repeat that
	// applies the current confirmed bundle's config.
	currentBundleGeneration *configwrite.Options
	// confirmedLate are the manifest SHA-256s of the bundles this run's
	// settle confirmed late (bundle_confirmed_after_interrupt).
	confirmedLate map[string]bool
	// reinstallAfterSettle, when set, installs the last good bundle again
	// before settle records a disproved receipt. The re-settle at the end
	// of a run sets it: no later step of that run would put it back.
	reinstallAfterSettle func(context.Context, *Deployment) (enforcing string, ok bool)
	// inboxProcessed are the bundle inbox files this run removes at its end.
	inboxProcessed []string
	// inboxSuperseded are the lower inbox versions this run did not apply,
	// and inboxTopVersion the version it applied instead.
	inboxSuperseded []supersededInbox
	inboxTopVersion uint64
}

// noteChange records one change a repair or ensure made to an installed
// deployment, so its result says what was repaired.
// interrupted reports whether the command got a stop signal
// (Options.Interrupted).
func (l *lifecycle) interrupted() bool {
	select {
	case <-l.opts.Interrupted:
		return true
	default:
		return false
	}
}

// untilInterrupted is ctx, also cancelled when the command gets a stop
// signal (Options.Interrupted). Call stop once it is no longer needed.
func (l *lifecycle) untilInterrupted(ctx context.Context) (_ context.Context, stop func()) {
	if l.opts.Interrupted == nil {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-l.opts.Interrupted:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// interruptedError is the cause of a transaction rolled back for a stop
// signal before step.
func interruptedError(step string) error {
	return fmt.Errorf("the run got a stop signal (SIGTERM or an interrupt) and rolled back before it %s; run it again", step)
}

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
	// appliedConfigSHA is the config of the deployment this transaction
	// started from, which a rollback restores ("" on a first install).
	appliedConfigSHA string
	// revertedConfig is config.yaml as revertRejectedConfig left it when it
	// put the last applied config back in place of this transaction's
	// rejected edit, or nil. A config.yaml written after it holds a fresh
	// push, also one of the rejected bytes (GAP-1412).
	revertedConfig os.FileInfo
}

// Run executes one lifecycle action and returns its result; the result's
// ExitCode is set.
func Run(ctx context.Context, env *Env, opts Options) *enterprisestatus.Result {
	env.fillDefaults()
	env.agentDigest = "" // set by this run's plan, if it plans
	if env.Yield != nil {
		env.Yield()
	}
	l := &lifecycle{
		env:    env,
		opts:   opts,
		result: enterprisestatus.New(opts.Action, managed.ProfileStandalone, env.GOOS, env.ProductVersion),
	}
	env.dirFlagsCleared = func(path, flags string) {
		if opts.Action == ActionEnsure || opts.Action == ActionRepair {
			l.result.Changes = append(l.result.Changes, fmt.Sprintf("cleared the macOS %s flag of %s, which stopped DefenseClaw from managing the folder", flags, path))
		}
	}
	failure := l.run(ctx)
	env.dirFlagsCleared = nil
	// A no-op ensure and a committed change report the same observed host
	// limits as status and verify. They do not change these kernel settings.
	if l.result.Installed && opts.Action != ActionStatus && opts.Action != ActionVerify && opts.Action != ActionUninstall {
		l.warnOpenPolicyViews()
	}
	// A run can describe the deployment more than once (after a follow-up
	// transaction, or a refused one), and each pass reports the same
	// standing warnings; the result names each problem once.
	l.result.Warnings = uniqueMessages(l.result.Warnings)
	l.result.Finish(env.GOOS, failure)
	return l.result
}

// What a repair that succeeded adds to its changes, so --json says what the
// text output says (GAP-0020, GAP-0061).
const (
	// RepairNothingChanged is the change a repair of a healthy deployment
	// lists.
	RepairNothingChanged = "nothing to repair"
	// RepairRestartedServices is listed by every repair that started the
	// services (GAP-2030).
	RepairRestartedServices = "restarted the DefenseClaw services to re-apply the deployment; `ensure` leaves a healthy deployment running"
)

// summarizeRepair ends the changes of a repair that succeeded: a healthy
// deployment had nothing to repair, and repair re-applies the deployment,
// so it stops and starts every service even then. With --no-start
// (not_started) it started none.
func (l *lifecycle) summarizeRepair() {
	r := l.result
	if len(r.Errors) > 0 {
		return
	}
	if len(r.Changes) == 0 {
		r.Changes = append(r.Changes, RepairNothingChanged)
	}
	if !hasMessageCode(r.Warnings, codeNotStarted) {
		r.Changes = append(r.Changes, RepairRestartedServices)
	}
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
func (l *lifecycle) run(ctx context.Context) (failure int) {
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
	// Before the lock, which another run can hold for the readiness timeout.
	env.closePrivateDirs(ctx)

	// The lock stays at one inode while anything is in the lifecycle
	// directory; only an uninstall that leaves it empty removes it (see
	// removeLockWithLastState), and acquireLock lets no waiter run on the
	// removed file.
	if err := env.ensureDir(env.P(env.Layout.LifecycleDir), 0o700, rootOwner()); err != nil {
		r.AddError(codeState, err.Error())
		l.reportNoSpace(err)
		return 0
	}
	// A stop signal ends the wait for the lock: the run that waited could
	// otherwise take it later and remove or change the deployment after
	// the command was told to stop.
	lockCtx, stopLockWait := l.untilInterrupted(ctx)
	lock, err := env.acquireLock(lockCtx)
	stopLockWait()
	if err != nil && l.interrupted() {
		r.AddError(codeInterrupted, "the run got a stop signal (SIGTERM or an interrupt) while it waited for the lifecycle lock; nothing was changed")
		return 0
	}
	if err != nil {
		if errors.Is(err, errLockBusy) {
			r.AddError(codeBusy, err.Error()+"; "+lockBusyNextStep(env.LockTimeout))
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
		if errors.Is(err, errLockRemoved) {
			if l.opts.Action == ActionUninstall {
				// Only an uninstall that left the lifecycle directory empty
				// removes the lock: the run this one waited for removed the
				// deployment, so there is nothing left to remove. A busy exit
				// here aborted the rpm or deb removal whose preremove waited
				// for a concurrent MDM purge, after the purge had removed
				// everything (GAP-0112).
				r.Noop, r.NoopReason = true, "not_installed"
				message := "DefenseClaw enterprise was uninstalled by the lifecycle run this uninstall waited for; nothing was left to remove"
				if l.opts.Purge {
					message += " (each account keeps its per-user DefenseClaw files if that run was not a purge)"
				}
				r.AddWarning(codeNotInstalled, message)
				return 0
			}
			r.AddError(codeBusy, err.Error()+"; rerun the command if it is still needed")
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
		r.AddError(codeState, err.Error())
		l.reportNoSpace(err)
		return 0
	}
	defer lock.release()
	if l.interrupted() {
		r.AddError(codeInterrupted, "the run got a stop signal (SIGTERM or an interrupt) before it started; nothing was changed")
		return 0
	}
	// Managed hooks answer closed while this run can stop or restart the
	// gateway (GAP-1074). Removed before the lock is released.
	releaseMarker, err := env.holdLifecycleMarker()
	if err != nil {
		r.AddError(codeState, err.Error()+"; nothing was changed")
		l.reportNoSpace(err)
		return 0
	}
	defer releaseMarker()
	if l.opts.FromPackage && l.opts.Reason != "package" {
		// Recorded before the lock goes, so a package run that waits for it
		// writes its own result after this one.
		defer func() { l.recordPackageResult(failure) }()
	}
	if l.opts.Action == ActionInstall || l.opts.Action == ActionUpgrade ||
		l.opts.Action == ActionEnsure || l.opts.Action == ActionRepair {
		defer func() {
			if len(r.Errors) != 0 || !r.Installed || r.InstalledVersion != env.ProductVersion {
				return
			}
			current, err := env.loadDeployment()
			if err == nil && current != nil && current.ProductVersion == env.ProductVersion {
				l.invalidateLegacyHookSessions(ctx)
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
	// A superseded apply run is an older binary than the deployment: the
	// policy digest it computes is not the one the installed gateway
	// reports, so it proves nothing about a pending receipt. It settles no
	// receipt and reinstalls no bundle; the installed binary does that.
	superseded := l.supersededApplyRun(record)
	settlePending := false
	if l.opts.Action != ActionUninstall && !superseded {
		settlePending = l.settleBundles(ctx, record)
	}
	if record != nil {
		r.Installed = true
		r.InstalledVersion = record.ProductVersion
		if l.opts.Action != ActionUninstall {
			l.recoverInterruptedRotation(ctx, record)
		}
	}
	if settlePending && slices.Contains([]string{ActionInstall, ActionUpgrade, ActionRepair, ActionEnsure}, l.opts.Action) {
		// A repair or upgrade can make the gateway available or move it to
		// this build's digest. Recheck after the action, while still holding
		// the lifecycle lock, so its result reports the settled receipt. A
		// receipt the new gateway disproves gets the last good bundle back
		// in this run.
		defer func() {
			if l.opts.Bundle != "" || len(r.Errors) != 0 {
				return
			}
			latest, err := env.loadDeployment()
			if err != nil {
				r.AddWarning(codeBundleStateUnreadable, "could not recheck the pending policy bundle: "+err.Error())
				return
			}
			l.reinstallAfterSettle = l.reinstallLastGoodBundle
			stillPending := l.settleBundles(ctx, latest)
			l.reinstallAfterSettle = nil
			l.describeBundle()
			if !stillPending {
				r.Warnings = slices.DeleteFunc(r.Warnings, func(w enterprisestatus.Message) bool {
					return w.Code == enterprisebundle.WarnBundlePending
				})
			}
		}()
	}
	if superseded {
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
		return l.requireProtectedTargetsOnChange(0)
	}
	if l.applyRunAfterRolledBackUpgrade(record) {
		r.Noop = true
		r.NoopReason = "upgrade_rolled_back"
		r.AddWarning(codeUpgradeRolledBack, fmt.Sprintf("the upgrade to %s failed and was rolled back to %s, and config.yaml and the protected credentials are still the ones %s applied, so this apply run does not retry the upgrade; install the package again, or run `%s --from-package`",
			env.ProductVersion, record.ProductVersion, record.ProductVersion, env.lifecycleCommand(ActionEnsure)))
		l.describe(ctx, record, false)
		return l.requireProtectedTargetsOnChange(0)
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
			// A bundle refusal (secret set to a value the signed bundle does
			// not bind) keeps its code.
			code := codeChange
			if bundleCode := enterprisebundle.CodeOf(err); bundleCode != "" {
				code = string(bundleCode)
			}
			r.AddError(code, err.Error())
			return 0
		}
		if undo := l.opts.MutateUndo; undo != nil {
			defer func() {
				if !r.ConfigRefused {
					return
				}
				resume := l.pauseApplyTrigger(ctx)
				defer resume()
				if err := undo(ctx); err != nil {
					r.AddError(codeChange, "the config was refused, and the change made before the check could not be put back: "+err.Error())
				}
			}()
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

	if code, done := l.prepareBundleMode(ctx, record, settlePending); done {
		return l.requireProtectedTargetsOnChange(code)
	}

	switch l.opts.Action {
	case ActionInstall:
		if record != nil {
			r.AddError(codeAlreadyInstalled, "DefenseClaw enterprise is already installed; use upgrade, repair or ensure")
			return 0
		}
		return l.requireProtectedTargets(l.settleInputChanges(ctx, l.freshInstall(ctx)))
	case ActionUpgrade:
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed; use install or ensure")
			return 0
		}
		if l.opts.PayloadDir == "" && !l.opts.FromPackage {
			r.AddError(codeInvalidArguments, "upgrade needs --payload or --from-package")
			return enterprisestatus.InvalidArgsExitCode(env.GOOS)
		}
		return l.requireProtectedTargets(l.settleInputChanges(ctx, l.apply(ctx, record)))
	case ActionRepair:
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed; use install or ensure")
			return 0
		}
		// The installed binaries are the payload of a repair without one: a
		// missing hook binary refused it with payload_invalid (GAP-1217).
		l.restoreTamperedHookBinary(ctx, record)
		code := l.settleInputChanges(ctx, l.apply(ctx, record))
		l.summarizeRepair()
		return l.requireProtectedTargets(code)
	case ActionEnsure:
		if record == nil {
			return l.requireProtectedTargets(l.settleInputChanges(ctx, l.freshInstall(ctx)))
		}
		if l.opts.Bundle != "" {
			return l.requireProtectedTargets(l.applyBundle(ctx, record))
		}
		return l.requireProtectedTargets(l.ensureInstalled(ctx, record, l.apply))
	case ActionReconcile:
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed")
			return 0
		}
		l.restoreTamperedHookBinary(ctx, record)
		l.retryOpenShell(ctx)
		return l.reconcile(ctx, record)
	case ActionRotateCredentials:
		return l.rotateCredentials(ctx, record)
	case ActionUninstall:
		code := l.uninstall(ctx, record)
		l.removeLockWithLastState(record)
		return code
	}
	return 0
}

// ensureInstalled is ensure on an installed deployment: put back what was
// tampered with, return when nothing differs from the inputs, else run apply
// (the transaction) and the follow-ups for inputs that changed meanwhile.
func (l *lifecycle) ensureInstalled(ctx context.Context, record *Deployment, apply func(context.Context, *Deployment) int) int {
	env, r := l.env, l.result
	if env.insideWSL() {
		r.AddWarning(codeWSL, wslDeploymentWarning)
	}
	restored := l.restoreTamperedHookBinary(ctx, record)
	l.restoreUnchangedConfigMetadata(ctx, record)
	restored = l.restoreTamperedMachinePolicy(record) || restored
	if problems, _ := l.unitDropIns(ctx, record); len(problems) > 0 {
		r.AddError(codeVerify, strings.Join(problems, "; "))
		l.describe(ctx, record, false)
		return 0
	}
	noop, reason := l.ensureNoop(ctx, record)
	// Configuration management that installs the same config.yaml
	// again while this run checks (two installs seconds apart) replaced
	// the owner the restore above put back, and the run restarted the
	// gateway for that owner alone (GAP-1030). Restore and check again
	// while the installed bytes are still the applied config.
	for retry := 0; !noop && retry < maxMetadataRechecks && l.restoreUnchangedConfigMetadata(ctx, record); retry++ {
		noop, reason = l.ensureNoop(ctx, record)
	}
	if noop {
		// A run that put a tampered file back changed the host.
		r.Noop = !restored
		if !restored {
			r.NoopReason = reason
		}
		if refusal := l.policyAssetRefusal; refusal != "" {
			r.AddError(codeConfigRefused, env.policyAssetRefusedMessage(refusal))
		}
		if err := env.sealHookBinary(record); err != nil {
			r.AddWarning(codeHookBinaryNotRestored, "could not keep a copy of the hook binary to restore it from: "+err.Error())
		}
		if !exists(env.committedConfigPath()) {
			// A deployment committed before the lifecycle kept the applied
			// config; the installed file is exactly that config.
			if raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err == nil && sha256Bytes(raw) == record.ConfigSHA256 {
				_ = env.saveCommittedConfig(raw)
			}
		}
		l.settleRejectedConfig()
		if len(r.Errors) == 0 {
			env.clearApplyRetries()
		}
		l.clearSupersededUnitFailures(ctx)
		l.retryOpenShell(ctx)
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
	return l.settleInputChanges(ctx, apply(ctx, record))
}

// removeLifecycleStateKeepingLock clears transaction state without replacing
// the lock inode, which this run still holds. Waiters can have the file open
// before this run acquired it. The deployment record stays too: the
// uninstall removes it last, once everything else is gone. Removed here, an
// uninstall that then failed to remove another state folder left no record,
// so its rerun was a not_installed no-op and the leftovers needed
// --adopt-existing (GAP-1440).
func (e *Env) removeLifecycleStateKeepingLock(keep ...string) error {
	dir := e.P(e.Layout.LifecycleDir)
	skip := map[string]bool{lockFileName: true, deploymentFileName: true}
	for _, name := range keep {
		skip[name] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if skip[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// removeLockWithLastState removes the lifecycle lock, and the lifecycle
// directory with it, when an uninstall left nothing else there. A purge
// left the root-only lock and its directory behind on every host
// (GAP-0112, GAP-0101), and the package removal's own uninstall run, a no-op
// after the MDM purge, created them again. This run still holds the lock:
// a run that waits for it wakes on the removed file, and acquireLock stops
// it instead of creating the directory again. On macOS the lifecycle
// directory is in the install root, which goes once it is empty, and then
// the parents the deployment created and left empty.
func (l *lifecycle) removeLockWithLastState(record *Deployment) {
	env := l.env
	dir := env.P(env.Layout.LifecycleDir)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != lockFileName || !entries[0].Type().IsRegular() {
		return
	}
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		return
	}
	if err := os.Remove(dir); err != nil {
		return
	}
	if filepath.Dir(env.Layout.LifecycleDir) != env.Layout.InstallRoot {
		return
	}
	_ = removeDirIfEmpty(env.P(env.Layout.InstallRoot))
	if record != nil {
		dirs := append([]string(nil), record.CreatedDirs...)
		sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
		for _, created := range dirs {
			_ = removeDirIfEmpty(env.P(created))
		}
	}
	if env.GOOS == "darwin" {
		_ = removeDirIfEmpty(env.P("/opt/cisco"))
	}
}

// removeInstallRootKeepingLock preserves the lock when macOS stores its
// lifecycle directory inside the install root, and each folder in keep
// that is a direct child of the install root (the macOS data folder with
// the kept sandbox registrations, GAP-0598).
func (e *Env) removeInstallRootKeepingLock(keep ...string) error {
	skip := map[string]bool{}
	for _, dir := range append([]string{e.Layout.LifecycleDir}, keep...) {
		if filepath.Dir(dir) == e.Layout.InstallRoot {
			skip[filepath.Base(dir)] = true
		}
	}
	if len(skip) == 0 {
		return os.RemoveAll(e.P(e.Layout.InstallRoot))
	}
	root := e.P(e.Layout.InstallRoot)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if skip[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
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
	if l.opts.Action != ActionEnsure || l.opts.Reason != "path" || l.opts.AllowDowngrade || !l.olderThanDeployment(record) {
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

// olderThanDeployment reports a release binary older than the recorded
// deployment. A development build is never older.
func (l *lifecycle) olderThanDeployment(record *Deployment) bool {
	running := strings.TrimPrefix(l.env.ProductVersion, "v")
	return record != nil && running != "dev" && versionPattern.MatchString(running) &&
		compareProductVersions(running, record.ProductVersion) < 0
}

// A package upgrade whose ensure fails rolls back to the previous
// deployment, but the package manager has already installed the new
// binaries. An apply-trigger run that ran after that rollback (the macOS
// apply job was running again as soon as the rollback finished) is the new
// binary against the restored record, so its ensure retried the upgrade
// that had just failed: a whole transaction under the lifecycle lock, and
// the next lifecycle command failed lifecycle_busy. Only the package, or an
// ensure --from-package, retries a failed package upgrade, as on Linux,
// where the preinstall holds the apply trigger for the transaction. The
// rollback leaves rolledBackUpgradeName in the lifecycle directory, and an
// apply-trigger run stands down while the deployment is the restored one
// and its inputs are still the ones that deployment applied. A changed
// config.yaml or credential is a new push, which the apply run applies (and
// that upgrades the deployment); a committed transaction removes the file.
const (
	rolledBackUpgradeName = "rolled-back-upgrade.json"
	codeUpgradeRolledBack = "upgrade_rolled_back"
)

// rolledBackUpgrade names the failed package upgrade and the deployment the
// rollback restored.
type rolledBackUpgrade struct {
	ProductVersion   string `json:"product_version"`
	InstalledVersion string `json:"installed_version"`
}

func (e *Env) rolledBackUpgradePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), rolledBackUpgradeName)
}

// recordRolledBackUpgrade records that a failed package upgrade to version
// was rolled back to record. A run of the apply trigger itself records
// nothing: its own retries (scheduleApplyRetry) keep running.
func (l *lifecycle) recordRolledBackUpgrade(record *Deployment, version string) {
	env := l.env
	if record == nil || !l.opts.FromPackage || env.SelfUnit != "" ||
		strings.TrimPrefix(version, "v") == strings.TrimPrefix(record.ProductVersion, "v") {
		return
	}
	data, err := json.Marshal(rolledBackUpgrade{ProductVersion: version, InstalledVersion: record.ProductVersion})
	if err == nil {
		err = env.writeFileAtomic(env.rolledBackUpgradePath(), append(data, '\n'), 0o600, rootOwner())
	}
	if err != nil {
		l.result.AddWarning(codeRolledBack, "could not record the rolled-back upgrade, so the apply trigger may retry it: "+err.Error())
	}
}

// applyRunAfterRolledBackUpgrade reports an apply-trigger ensure (--reason
// path) of the binary whose package upgrade rolled back to record, with
// config.yaml and the protected credentials still as record applied them.
func (l *lifecycle) applyRunAfterRolledBackUpgrade(record *Deployment) bool {
	env := l.env
	if record == nil || l.opts.Action != ActionEnsure || l.opts.Reason != "path" || l.opts.AllowDowngrade {
		return false
	}
	raw, err := readBounded(env.rolledBackUpgradePath(), maxInputBytes)
	if err != nil {
		return false
	}
	var failed rolledBackUpgrade
	if json.Unmarshal(raw, &failed) != nil ||
		strings.TrimPrefix(failed.ProductVersion, "v") != strings.TrimPrefix(env.ProductVersion, "v") ||
		failed.InstalledVersion != record.ProductVersion {
		return false
	}
	configSHA, err := sha256File(env.P(env.Layout.ConfigPath))
	if err != nil || configSHA != record.ConfigSHA256 {
		return false
	}
	_, secretsSHA, err := env.listSecrets()
	return err == nil && secretsSHA == record.SecretsSHA256
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
	if o.Bundle != "" || o.BundleInbox {
		switch {
		case o.Action != ActionEnsure:
			return bad("a policy bundle is applied by ensure")
		case o.Bundle != "" && o.BundleInbox:
			return bad("--bundle and --inbox are mutually exclusive")
		case o.Bundle != "" && !filepath.IsAbs(o.Bundle):
			return bad("--bundle must be an absolute path")
		case o.ConfigFile != "" || o.PayloadDir != "" || o.FromPackage || o.NoStart || o.AdoptExisting || o.Mutate != nil:
			return bad("a policy bundle carries the config: --config, --payload, --from-package, --no-start and --adopt-existing do not apply")
		}
	}
	if o.DeliveryID != "" {
		if o.Bundle == "" && !o.BundleInbox {
			return bad("--delivery-id applies only to a policy bundle apply")
		}
		if err := enterprisestatus.CheckDeliveryID(o.DeliveryID); err != nil {
			return bad(err.Error())
		}
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
	// configWritable says how an account other than root could write the
	// installed config.yaml when it could (installedConfigWritable); the
	// transaction then replaces the file before it changes anything.
	configWritable string
	secrets        []string
	secretsSHA     string
	dirs           []desiredDir
	files          []desiredFile
	binaries       []desiredFile
	stale          []string
	systemd        int
	installedAt    string
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
	// installedConfigSHA is the installed config.yaml's digest when the plan
	// read its inputs ("" when there was none). A different one when the
	// transaction writes the planned config means another writer replaced
	// the file during the run.
	installedConfigSHA string
	// openshell is the sandbox subsystem: its rendered files, user units and
	// links (openshell.go).
	openshell *openshellPlan
}

// buildPlan computes the desired state without mutating the host. account
// must already exist.
func (l *lifecycle) buildPlan(ctx context.Context, record *Deployment, account Account) (*plan, error) {
	env := l.env
	l.osPlan = nil
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
		if err := l.replacedPackageBinary(record, pay); err != nil {
			return nil, &codedError{code: codePayload, err: err}
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
	compilerPath := compilerInstallPath(env.Layout)
	p.version = p.payload.Version
	if record != nil && !l.opts.AllowDowngrade && compareProductVersions(p.version, record.ProductVersion) < 0 {
		return nil, &codedError{code: codeDowngrade, err: fmt.Errorf("payload version %s is older than the installed %s; downgrades are refused (rerun with --allow-downgrade to roll back deliberately)", p.version, record.ProductVersion)}
	}
	// Every candidate must meet an authenticated floor. A newly verified
	// signed replacement supplies its own floor even when the previously
	// confirmed bundle is damaged; other runs use the confirmed bundle.
	if l.bundle != nil {
		if err := bundleProductFloorRefusal(p.version, l.bundle.verifiedProductFloor); err != nil {
			return nil, err
		}
	} else if err := env.BundleProductFloorRefusal(p.version); err != nil {
		return nil, err
	}
	if l.opts.ProductVersion != "" && strings.TrimPrefix(l.opts.ProductVersion, "v") != p.version {
		return nil, &codedError{code: codePayload, err: fmt.Errorf("payload version %s does not match --product-version %s", p.version, l.opts.ProductVersion)}
	}
	if p.channel == ChannelPayload && l.opts.PayloadDir != "" && env.GOOS == "linux" {
		if env.packageOwned(ctx, filepath.Join(env.Layout.BinDir, binGateway)) {
			return nil, &codedError{code: codePackageOwned, err: errors.New("the installed binaries belong to the defenseclaw-enterprise package; upgrade with the package manager")}
		}
	}

	p.installedConfigSHA, _ = sha256File(env.P(env.Layout.ConfigPath))
	raw, fromInstalled, err := l.configBytes()
	if err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	writable, err := env.installedConfigWritable(ctx)
	if err != nil {
		return nil, &codedError{code: codeConfig, err: fmt.Errorf("check whether the installed config is writable by another account: %w", err)}
	}
	if writable != "" && fromInstalled && (record == nil || sha256Bytes(raw) != record.ConfigSHA256) {
		return nil, &codedError{code: codeConfig, err: fmt.Errorf("%s changed while %s, so an account other than root could have written the change; it is not applied. Push the administrator config again, or run `%s --config <file>`",
			env.Layout.ConfigPath, writable, env.lifecycleCommand(ActionEnsure))}
	}
	validated, err := env.validateConfigSource(raw, l.opts.ConfigFile)
	if err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	if err := refuseUnknownGuardrailConnectors(validated.Loaded, l.opts.ConfigFile, env.Layout.ConfigPath); err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	if record == nil {
		// The service group exists only now: packs staged before the first
		// install get it (GAP-0501).
		note, err := env.settleStagedSandboxPacks(validated.Loaded, account)
		if err != nil {
			return nil, &codedError{code: codeApply, err: err}
		}
		if note != "" {
			l.result.Changes = append(l.result.Changes, note)
		}
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
		l.warnConfigV8(migrated.Record)
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
	if fromInstalled {
		// An open the 1.0.0-1.0.2 migration wrote is not the administrator's
		// (managed hooks honour an explicit open since 1.0.3).
		repaired, err := env.repairMigratedCursorFailMode(validated)
		if err != nil {
			return nil, &codedError{code: codeConfig, err: err}
		}
		if repaired != nil {
			validated, fromInstalled = repaired, false
		}
	}
	if validated.Loaded.Fleet.Enabled {
		var compiler, marker, base string
		switch {
		case p.channel == ChannelPackage:
			// The package carries an inert source file. Materialize the active
			// compiler only when the validated config enables Fleet.
			base = env.P(env.Layout.InstallRoot)
			marker = compilerPackageDir
			compiler = env.P(packageCompilerSourcePath(env.Layout))
		case l.opts.PayloadDir != "":
			base = p.payload.Dir
			marker = compilerArchiveDir
			compiler = filepath.Join(base, marker, "tools", compilerFileName)
		default:
			// A Fleet-off payload install discards its archive. Enabling Fleet
			// later requires --payload; a Fleet-on repair can use its admitted
			// installed copy.
			base = env.P(env.Layout.InstallRoot)
			marker = filepath.Join("lib", "defenseclaw")
			compiler = env.P(compilerPath)
		}
		digest, err := loadCompilerFile(base, marker, compiler)
		if err != nil {
			return nil, &codedError{code: codePayload, err: err}
		}
		if digest != "" && compiler == env.P(compilerPath) {
			if err := env.checkInstalledCompiler(compilerPath); err != nil {
				return nil, &codedError{code: codePayload, err: err}
			}
		}
		p.payload.CompilerSource, p.payload.CompilerSHA = compiler, digest
		if p.payload.CompilerSHA == "" {
			return nil, &codedError{code: codePayload, err: fmt.Errorf("fleet.enabled is set but the managed payload has no %s; provide a release payload or package with the Fleet compiler", compilerFileName)}
		}
		if record != nil && record.Files[compilerPath] != "" && record.Files[compilerPath] != digest &&
			l.opts.Reason != "package" && p.payload.Version == record.ProductVersion {
			return nil, &codedError{code: codePayload, err: fmt.Errorf("installed %s does not match the deployment record; restore it from the same release", compilerPath)}
		}
		if record != nil && record.Files[compilerPath] != "" &&
			(p.channel == ChannelPackage || l.opts.PayloadDir == "") &&
			l.opts.Reason != "package" && p.payload.Version == record.ProductVersion {
			activeSHA, err := sha256File(env.P(compilerPath))
			if err != nil || activeSHA != record.Files[compilerPath] {
				return nil, &codedError{code: codePayload, err: fmt.Errorf("installed %s does not match the deployment record; restore it from the same release", compilerPath)}
			}
		}
		switch env.GOOS {
		case "darwin":
			if err := env.checkMacFleetPython(); err != nil {
				return nil, &codedError{code: codeConfig, err: err}
			}
		case "linux":
			if err := env.checkLinuxFleetPython(); err != nil {
				return nil, &codedError{code: codeConfig, err: err}
			}
		}
	}
	if err := env.checkCandidateAssets(validated); err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	if err := env.checkRequiredSandboxPacks(validated.Loaded); err != nil {
		return nil, &codedError{code: codeConfig, err: err}
	}
	p.configFromInstalled = fromInstalled
	p.configWritable = writable
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
	if p.payload.CompilerSHA != "" {
		p.dirs = append(p.dirs,
			desiredDir{Path: filepath.Join(env.Layout.InstallRoot, "lib"), Mode: 0o755, Owner: rootOwner()},
			desiredDir{Path: filepath.Dir(compilerPath), Mode: 0o755, Owner: rootOwner()})
	}
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

	if p.payload.CompilerSHA != "" {
		p.files = append(p.files, desiredFile{
			Path: compilerPath, Src: p.payload.CompilerSource, SHA: p.payload.CompilerSHA,
			Mode: 0o644, Owner: rootOwner(), Kind: "compiler",
		})
	}
	if p.channel == ChannelPayload {
		for _, name := range sortedKeys(p.payload.Digests) {
			p.binaries = append(p.binaries, desiredFile{
				Path: filepath.Join(env.Layout.BinDir, name), Src: filepath.Join(p.payload.Dir, name),
				SHA: p.payload.Digests[name], Mode: 0o755, Owner: rootOwner(), Kind: "binary",
			})
		}
	}

	if err := l.planOpenShell(p); err != nil {
		return nil, &codedError{code: codeOpenShell, err: err}
	}

	// The override a package-kept uninstall wrote over the package's
	// tmpfiles.d entries goes with the next install.
	if p.channel == ChannelPackage && env.GOOS == "linux" {
		if data, err := readBounded(env.P(packageTmpfilesOverride), 4096); err == nil && strings.HasPrefix(string(data), packageTmpfilesOverrideMarker) {
			p.stale = append(p.stale, packageTmpfilesOverride)
		}
	}
	// Files the previous deployment wrote that this one no longer does.
	want := map[string]bool{}
	for _, file := range append(append([]desiredFile{}, p.files...), p.binaries...) {
		want[file.Path] = true
	}
	if record != nil {
		for path := range record.Files {
			if !want[path] {
				if p.channel == ChannelPackage && env.packageOwns(path) {
					continue // the package owns the binaries, units and OpenCode plugin now
				}
				p.stale = append(p.stale, path)
			}
		}
	}
	if env.GOOS == "darwin" {
		// The LaunchAgents of an earlier label, also the ones a package put
		// there that no record names.
		for _, path := range env.strayLaunchAgents(want) {
			if !slices.Contains(p.stale, path) {
				p.stale = append(p.stale, path)
			}
		}
	}
	sort.Strings(p.stale)
	return p, nil
}

// replacedPackageBinary refuses installed package binaries that differ from
// the deployment record while the package version is still the recorded one.
// Only the package's own install run (--reason package) puts new binaries of
// the same version in place; any other difference is a file replaced after
// install. Recording it made verify green on a binary the package never
// shipped: repair, ensure --from-package and the apply trigger re-recorded a
// hook replaced by /usr/bin/true, and agents ran without enforcement
// (GAP-0522).
func (l *lifecycle) replacedPackageBinary(record *Deployment, pay *payload) error {
	if record == nil || l.opts.Reason == "package" || pay.Version != record.ProductVersion {
		return nil
	}
	recorded := recordBinaries(l.env, record)
	if len(recorded) == 0 {
		return nil
	}
	for _, name := range append(append([]string{}, requiredBinaries...), optionalBinaries...) {
		if recorded[name] != pay.Digests[name] {
			return fmt.Errorf("installed %s does not match the deployment record although the package is still version %s, so it was replaced after install; %s",
				name, pay.Version, l.env.packageReinstallStep(pay.Version))
		}
	}
	return nil
}

// packageReinstallStep is how an administrator puts back the binaries of
// the package version.
func (e *Env) packageReinstallStep(version string) string {
	if e.GOOS == "darwin" {
		return fmt.Sprintf("reinstall the package (sudo installer -pkg defenseclaw-enterprise-%s-darwin-arm64.pkg -target /) to restore it, or rerun with --payload <directory with the %s binaries>", version, version)
	}
	return fmt.Sprintf("reinstall the defenseclaw-enterprise %s package with your package manager to restore it, or rerun with --payload <directory with the %s binaries>", version, version)
}

// codeConfigV8 warns that the config a run read is still config_version 8.
const codeConfigV8 = "config_version_8"

// warnConfigV8 tells the administrator, on every run that reads a
// config_version 8 file, that the file should be replaced and which values
// the migration resolved differently. An MDM that keeps delivering the v8
// file saw green results while two values were dropped, the first run
// listing the migration only among its changes (GAP-0540).
func (l *lifecycle) warnConfigV8(record config.MigrationRecord) {
	source := l.opts.ConfigFile
	if source == "" {
		source = l.env.Layout.ConfigPath
	}
	message := fmt.Sprintf("the config this run read (%s) is config_version 8; DefenseClaw applies its config_version 9 migration. Deliver a config_version 9 file instead, for example the migrated %s",
		source, l.env.Layout.ConfigPath)
	var conflicts []string
	for _, conflict := range record.Conflicts {
		conflicts = append(conflicts, fmt.Sprintf("%s kept %s, dropped %s (%s)", conflict.To, conflict.Kept, conflict.Lost, conflict.Reason))
	}
	if len(conflicts) > 0 {
		message += fmt.Sprintf("; %d value(s) conflicted and the migration resolved them: %s", len(conflicts), strings.Join(conflicts, "; "))
	}
	if len(record.UnenforcedRegoData) > 0 {
		message += "; Rego rules no longer enforced: " + strings.Join(record.UnenforcedRegoData, "; ")
	}
	l.result.AddWarning(codeConfigV8, message)
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

// installedConfigWritable says how an account other than root could write
// the installed config.yaml: its mode, owner, a write ACL, or a folder that
// account can write (it could put another file in its place). An edited
// config is refused before repair removes those permissions (GAP-0524,
// GAP-1139, GAP-1141).
func (e *Env) installedConfigWritable(ctx context.Context) (string, error) {
	var aclTargets []aclTarget
	for _, canonical := range []string{e.Layout.ConfigPath, filepath.Dir(e.Layout.ConfigPath)} {
		path := e.P(canonical)
		_, _, mode, err := statOwnerMode(path)
		if err != nil {
			continue // configBytes reads or defaults the file; the transaction reports one that went away
		}
		uid, _, err := e.OwnerOf(path)
		if err != nil {
			continue
		}
		folder := canonical != e.Layout.ConfigPath
		if mode.Perm()&0o022 != 0 && (!folder || mode&os.ModeSticky == 0) || (uid != 0 && uid != os.Geteuid()) {
			return fmt.Sprintf("%s was %04o and owned by uid %d", canonical, mode.Perm(), uid), nil
		}
		if e.GOOS == "darwin" && (!folder || mode&os.ModeSticky == 0) {
			aclTargets = append(aclTargets, aclTarget{path: path})
		}
	}
	if len(aclTargets) > 0 {
		findings, err := e.aclFindings(ctx, aclTargets)
		if err != nil {
			return "", err
		}
		for _, finding := range findings {
			if finding.write {
				return fmt.Sprintf("%s has a macOS ACL entry that lets another account write it", finding.path), nil
			}
		}
	}
	return "", nil
}

// replaceWritableConfig puts a new file in place of an installed config.yaml
// another account could write (p.configWritable), before the transaction
// changes anything. Re-owning the file in place blessed what that account
// wrote after this run read it, and a descriptor it opened while it could
// write kept writing the live file: a standard user rewrote config.yaml a
// moment after the mode was loosened, the run re-owned the file, and its
// follow-up transaction applied the edit (GAP-0524). The new file holds the
// applied config, so a later write through such a descriptor goes nowhere.
// When config.yaml no longer holds the bytes this run read from it, that edit
// is refused: the applied config is returned for the caller to revert to.
// The other account loses write access to the folder and the file (its mode
// and, on macOS, its ACL entries) before config.yaml is read and replaced.
// Replaced while a folder ACL entry still let a standard user write there,
// another file that user put in its place before the transaction removed
// the entry was kept and applied by the follow-up transaction (GAP-1441).
func (l *lifecycle) replaceWritableConfig(ctx context.Context, record *Deployment, p *plan) ([]byte, error) {
	env := l.env
	// A folder another account can write lets it put another file there.
	if err := env.ensureDir(env.P(env.Layout.ConfigDir), 0o755, rootOwner()); err != nil {
		return nil, &codedError{code: codeApply, err: err}
	}
	path := env.P(env.Layout.ConfigPath)
	var trusted []byte
	if record != nil {
		committed, err := readBounded(env.committedConfigPath(), maxInputBytes)
		if err == nil && sha256Bytes(committed) == record.ConfigSHA256 {
			trusted = committed
		}
	}
	if err := l.removeConfigACLs(ctx); err != nil {
		// A --config run has no in-place edit to revert. Give the caller
		// verified applied bytes so it still replaces the ACL-written file.
		if record != nil {
			if trusted == nil {
				current, readErr := readBounded(path, maxInputBytes)
				if readErr == nil && sha256Bytes(current) == record.ConfigSHA256 {
					trusted = current
				}
			}
			if trusted != nil {
				return trusted, &codedError{code: codeConfig, err: err}
			}
		}
		return nil, &codedError{code: codeApply, err: err}
	}
	if record == nil {
		// No applied config to put there (an installed one was refused). A
		// --config install writes its own bytes over whatever another
		// account put there before it lost access.
		p.installedConfigSHA, _ = sha256File(path)
		return nil, nil
	}
	current, readErr := readBounded(path, maxInputBytes)
	if trusted == nil && readErr == nil && sha256Bytes(current) == record.ConfigSHA256 {
		trusted = current
	}
	if p.configFromInstalled && readErr == nil && sha256Bytes(current) != record.ConfigSHA256 {
		return trusted, &codedError{code: codeConfig, err: fmt.Errorf("%s was written while this run applied it and %s, so an account other than root could have written the change; it is not applied. Push the administrator config again, or run `%s --config <file>`",
			env.Layout.ConfigPath, p.configWritable, env.lifecycleCommand(ActionEnsure))}
	}
	if trusted == nil {
		p.installedConfigSHA, _ = sha256File(path)
		return nil, nil
	}
	// A refused edit stays current (status and verify report it) when the
	// new file replaces the reverted one.
	kept, keptErr := os.Stat(env.rejectedConfigPath())
	keep := keptErr == nil && !env.rejectionSuperseded(kept)
	if err := env.writeFileAtomic(path, trusted, 0o640, fileOwner{UID: 0, GID: p.account.GID}); err != nil {
		return nil, &codedError{code: codeApply, err: err}
	}
	// The file this run wrote is not one another writer put there during the
	// run (applyFiles, GAP-0745), so a --config run still writes its own.
	p.installedConfigSHA = sha256Bytes(trusted)
	if replaced, err := os.Stat(path); keep && err == nil {
		_ = os.Chtimes(env.rejectedConfigPath(), replaced.ModTime(), replaced.ModTime())
	}
	l.noteChange("replaced %s with a new file holding the applied config: %s, so another account could write it", env.Layout.ConfigPath, p.configWritable)
	return nil, nil
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
	if !l.opts.NoStart {
		// Checked before anything changes: the API socket cannot listen
		// while another process holds the port.
		if held := l.apiPortPreflight(ctx, record); held != "" {
			r.AddError(codeAPIPortHeld, held)
			if record != nil {
				l.describe(ctx, record, false)
			}
			return 0
		}
	}
	serviceName := env.Layout.ServiceUser
	account, err := env.Accounts.Ensure(ctx, serviceName)
	if err != nil {
		r.AddError(codeAccount, err.Error())
		return 0
	}
	committedConfig := l.inPlaceConfigEdit(record)
	p, err := l.buildPlan(ctx, record, account)
	if err == nil && p.configWritable != "" {
		var applied []byte
		if applied, err = l.replaceWritableConfig(ctx, record, p); applied != nil {
			committedConfig = applied
		}
	}
	if err != nil {
		code := errorCode(err, codeApply)
		// A plan that failed before commit must never supply prerequisite
		// settings to describe; the prior applied record remains in force.
		l.osPlan = nil
		if committedConfig == nil && code == codeConfig {
			// An edit written after the check above, while this run planned
			// (a standard user writing a config.yaml whose mode was just
			// loosened, GAP-0524), is reverted the same way.
			committedConfig = l.inPlaceConfigEdit(record)
		}
		r.AddError(code, err.Error())
		l.reportNoSpace(err)
		if record == nil && account.Created {
			// Refused before any change: the service account this run
			// created goes too (GAP-0542).
			_ = env.Accounts.Remove(ctx, serviceName)
		}
		if committedConfig != nil && (code == codeConfig || code == codeMachinePolicy) {
			l.revertRejectedConfig(record, committedConfig, nil, err.Error())
		}
		if record != nil {
			// Refused before any change: the running deployment is untouched,
			// so the result reports its services and readiness rather than
			// an empty list that reads as a host that is down.
			if code == codeConfig || code == codeMachinePolicy {
				// The refused file is not the config that runs: what describe
				// finds belongs to the running deployment, and says so
				// (GAP-0564).
				l.describeRunning(ctx, record)
			} else {
				l.describe(ctx, record, false)
			}
		}
		return 0
	}
	l.serviceUID = account.UID
	l.planned = &plannedInputs{configSHA: p.config.SHA, configFromInstalled: p.configFromInstalled, secretsSHA: p.secretsSHA}
	if record != nil {
		l.planned.appliedConfigSHA = record.ConfigSHA256
	}
	l.reportChanges = record != nil && (l.opts.Action == ActionRepair || l.opts.Action == ActionEnsure)
	changesBefore := len(r.Changes)
	if account.Created {
		// Configuration management removed the account (GAP-0515).
		l.noteChange("created the service account %s (uid %d), which was missing", account.Name, account.UID)
	}

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
	// existing generation record does not: the counter never goes back once
	// the gateway can have read it, and the rollback records the restored
	// config as a new generation (recordRestoredGeneration). One this
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
	if p.config.FailModeRepair != nil {
		snapPaths = append(snapPaths, config.MigrationRecordPath(env.Layout.ConfigPath))
	}
	dirPaths := []string{}
	for _, dir := range p.dirs {
		dirPaths = append(dirPaths, dir.Path)
	}
	snap, err := env.takeSnapshot(snapshotID, snapPaths, dirPaths)
	if err == nil {
		// The launcher and the enable link are symlinks: a rollback puts back
		// what they were.
		err = env.snapshotLinks(snap, p.openshellLinkPaths())
	}
	if err != nil {
		if snap != nil {
			env.discardSnapshot(snap)
		}
		r.AddError(codeApply, err.Error())
		l.reportDiskFull(err)
		return 0
	}
	// Decided before the intent is written, so a run killed at any phase of
	// a hot change is rolled back without a gateway restart (GAP-0238).
	hot := l.hotConfigApply(ctx, record, p, adopting)
	pending := &Pending{
		Action: l.opts.Action, StartedAt: env.Now().UTC().Format(time.RFC3339), SnapshotDir: snap.Dir, Phase: "quiesce",
		PreviouslyActive: previouslyActive, PreviouslyEnabled: previouslyEnabled, EnabledRecorded: enabledRecorded,
		Hot: hot,
	}
	if err := env.savePending(pending); err != nil {
		env.discardSnapshot(snap)
		r.AddError(codeApply, err.Error())
		l.reportDiskFull(err)
		return 0
	}

	l.rememberGeneration()
	failAndRollback := func(code string, cause error) int {
		r.AddError(code, cause.Error())
		// Before the rollback, which can free space: what was full when the
		// step failed (GAP-0662).
		l.reportDiskFull(cause)
		// The previous deployment's sandbox settings are back, not the plan's.
		l.osPlan = nil
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
		keepNewerConfig := func() {
			// A --config run: a config.yaml another writer put in place after
			// this transaction wrote its own (a push during activation) would
			// be lost to the snapshot restore, so it is kept and put back
			// after the restart like one applyFiles kept.
			// Not one another account could write (GAP-1501), also through
			// a macOS ACL entry this transaction removed (GAP-1518).
			current, problem, err := env.readConfigChecked(env.P(env.Layout.ConfigPath))
			if err == nil && problem == "" && !l.configACLWritable && sha256Bytes(current) != p.config.SHA && sha256Bytes(current) != p.installedConfigSHA {
				l.configWrittenDuringRun = current
			}
		}
		if committedConfig != nil {
			keepNewerConfig = nil
			// The snapshot of an in-place edit holds the edited bytes; the
			// previous deployment's config is the last applied copy. It goes
			// back before the services restart.
			revertConfig = func() { newerConfig = l.revertRejectedConfig(record, committedConfig, p.config.Raw, cause.Error()) }
		}
		restoreLiveBeforeStart := func(_ bool) {
			if revertConfig != nil {
				revertConfig()
			}
		}
		restored, err := l.rollback(ctx, snap, pending, false, keepNewerConfig, restoreLiveBeforeStart)
		if newerConfig != nil {
			l.restoreNewerConfig(record.ServiceGID, newerConfig)
		}
		if restored && record != nil && l.machinePolicyPublished {
			l.restoreMachinePolicy(record)
		}
		// Also after a failed first install: the snapshot removed the
		// config.yaml it wrote, and a push made during activation is the
		// administrator's file (p0 GAP-1410).
		if restored && newerConfig == nil && l.configWrittenDuringRun != nil {
			l.restoreNewerConfig(account.GID, l.configWrittenDuringRun)
		} else {
			l.configWrittenDuringRun = nil
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
		l.recordRolledBackUpgrade(record, p.version)
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
	if l.interrupted() {
		return failAndRollback(codeInterrupted, interruptedError("stopped the services"))
	}
	keep := l.keepRunningDuringChange(p)
	// The gateway that keeps running reloads config.yaml as soon as it is written.
	l.generationExposed = hot
	if gateway, ok := gatewayUnitOf(units); hot && ok {
		keep[gateway.Name] = true
		keepSensorHelperRunning(keep, units)
	}
	l.quiesce(ctx, units, keep)
	if l.interrupted() {
		return failAndRollback(codeInterrupted, interruptedError("wrote the new files"))
	}
	pending.Phase = "apply"
	_ = env.savePending(pending)

	createdDirs, err := l.applyDirs(p)
	if err != nil {
		return failAndRollback(codeApply, err)
	}
	if err := env.settleSecretModes(ctx, account); err != nil {
		return failAndRollback(codeApply, err)
	}
	if err := l.settleStateModes(account); err != nil {
		return failAndRollback(codeApply, err)
	}
	if err := l.removeACLs(ctx, aclFiles(env, p, record), aclConnectors(p, record)); err != nil {
		return failAndRollback(codeApply, err)
	}
	l.clearStaleHookSocket(account)
	changed, err := l.applyFilesRecorded(ctx, p, account)
	if err != nil {
		return failAndRollback(errorCode(err, codeApply), err)
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
	if err := env.initialManifest(); err != nil {
		return failAndRollback(codeApply, err)
	}
	if l.opts.Action == ActionRepair {
		// The guardian and the enumerator are stopped: neither reads or
		// rewrites the manifest while deleted accounts leave it.
		l.revokeDeletedAccounts(ctx)
	}
	if env.GOOS == "linux" {
		// The module labels the hook socket and the gateway binary;
		// restorecon then relabels the files already in place (GAP-0772).
		// A listening socket keeps the label systemd created it with, the
		// domain the gateway ran in then: the hook socket is replaced so
		// confined users reach the gateway's new domain (GAP-1143).
		if l.ensureSELinuxModule(ctx) {
			restartSockets[unitHookSocket] = true
		}
		if _, err := env.Runner.Run(ctx, "restorecon", "-R", env.P(env.Layout.InstallRoot), env.P(env.Layout.ConfigDir), env.P(env.Layout.HookSocketDir)); err != nil && !errors.Is(err, ErrCommandNotFound) {
			r.AddWarning("selinux_relabel", err.Error())
		}
	}
	if err := l.applyOpenShellLinks(p); err != nil {
		return failAndRollback(codeApply, err)
	}
	if err := env.Services.Reload(ctx); err != nil {
		return failAndRollback(codeApply, err)
	}

	if l.interrupted() {
		return failAndRollback(codeInterrupted, interruptedError("started the services"))
	}
	pending.Phase = "activate"
	_ = env.savePending(pending)
	l.generationExposed = true
	activationStarted := env.Now()
	if !l.opts.NoStart {
		if err := l.activate(ctx, units, restartSockets, hot, p); err != nil {
			// A readiness failure on the API port already names the holder.
			if named := (*apiPortHeldError)(nil); !errors.As(err, &named) {
				if held := l.portHeldProblem(ctx, account.UID, false); held != "" {
					err = fmt.Errorf("%w; %s", err, held)
				}
			}
			if gatewayFailure(err) {
				if refusal := l.configRefusal(ctx); refusal != "" {
					err = fmt.Errorf("%w; %s", err, env.configRefusedMessage(refusal))
				}
				if excerpt := l.recordActivationFailure(ctx); excerpt != "" {
					err = fmt.Errorf("%w; gateway output (kept in %s): %s", err,
						filepath.Join(env.Layout.LifecycleDir, activationFailureFileName), excerpt)
				}
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
		l.noteTetragonRestart(ctx, p, changed)
	} else {
		for _, unit := range units {
			if unit.Activate {
				_ = env.Services.Disable(ctx, unit)
			}
		}
		r.AddWarning(codeNotStarted, "installed without starting the services (--no-start); run repair or ensure to activate")
	}

	activatedAt := ""
	if record != nil {
		activatedAt = record.ActivatedAt
	}
	// The activation is the start of the services, not the plan: a first
	// install that fell back to InstalledAt (taken when the run planned)
	// missed the agent sessions started while it published the hooks and
	// started the services (GAP-1367). A record written by an older version
	// without the field keeps the InstalledAt fallback: it was activated
	// when it was installed.
	if !l.opts.NoStart && (record == nil || record.NoStart) {
		activatedAt = env.Now().UTC().Format(time.RFC3339Nano)
	}
	newRecord := &Deployment{
		Profile: managed.ProfileStandalone, Platform: env.GOOS, ProductVersion: p.version, Channel: p.channel,
		InstalledAt: p.installedAt, ActivatedAt: activatedAt, UpdatedAt: env.Now().UTC().Format(time.RFC3339), NoStart: l.opts.NoStart,
		ServiceUser: account.Name, ServiceUID: account.UID, ServiceGID: account.GID,
		ConfigSHA256: p.config.SHA, SecretsSHA256: p.secretsSHA, Files: map[string]string{},
		MachinePolicyConnectors: append([]string{}, p.machinePolicy...),
		ConnectorActivatedAt:    connectorActivations(record, p.machinePolicy, !l.opts.NoStart, env.Now().UTC().Format(time.RFC3339Nano)),
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

	if !l.opts.NoStart && l.testFaultRequested(testFaultAfterServices) {
		return failAndRollback(codeLifecycleTestFault, errors.New("the lifecycle test fault asked this run to fail after its services started"))
	}
	if !l.opts.NoStart {
		// Inputs written during this transaction are applied by a follow-up
		// (settleInputChanges); they do not fail this one.
		if problems := l.verifyDeployment(ctx, newRecord, false, l.inputsChanged()); len(problems) > 0 {
			return failAndRollback(codeVerify, errors.New(strings.Join(problems, "; ")))
		}
	}
	if l.bundle != nil {
		// The gateway must report the policy of the bundle before the
		// deployment commits; otherwise the snapshot (the last good config
		// and its untouched version directory) goes back.
		if err := l.confirmBundleInTransaction(ctx, p.config.SHA); err != nil {
			return failAndRollback(string(bundleConfirmationCode(err)), err)
		}
	}
	if err := env.saveDeployment(newRecord); err != nil {
		return failAndRollback(codeApply, err)
	}
	if l.bundle != nil {
		// The commit point of the bundle: the gateway reported its policy
		// above. A step below that fails does not undo it (finishBundle).
		l.bundle.committed = true
	}
	_ = env.clearPending()
	_ = removeFile(env.rolledBackUpgradePath())
	if err := env.sealHookBinary(newRecord); err != nil {
		r.AddWarning(codeHookBinaryNotRestored, "could not keep a copy of the hook binary to restore it from: "+err.Error())
	}
	// The deployment owns its state again; a kept-state record from an
	// earlier non-purge uninstall no longer applies.
	env.clearRetainedState()
	l.clearSupersededFailures()
	l.clearSupersededUnitFailures(ctx)
	if err := env.saveCommittedConfig(p.config.Raw); err != nil {
		r.AddWarning(codeConfigReverted, "could not keep a copy of the applied config; a rejected in-place edit cannot be reverted: "+err.Error())
	}
	l.settleRejectedConfig()
	env.discardSnapshot(snap)
	r.Installed = true
	r.InstalledVersion = newRecord.ProductVersion
	// Accounts follow the committed deployment: a daemon without a running
	// sandbox restarts on it now, one with sandboxes waits (openshell_users.go).
	l.settleOpenShell(ctx, p.openshell)
	if !l.opts.NoStart {
		// The result reports what the guardian found under the new state
		// (an agent the change left without hooks), not its previous report.
		if l.awaitGuardianReport(ctx, activationStarted) {
			l.noteRepairedTargets(activationStarted)
		}
	}
	// The change succeeds only when the gateway runs it. A config.yaml
	// replaced during the run is confirmed by its follow-up transaction, and
	// a signed bundle by its own confirmation (confirmBundleInTransaction).
	l.confirmCommitted = !l.opts.NoStart && !l.inputsChanged() && l.bundle == nil && !env.bundleMode()
	l.describe(ctx, newRecord, false)
	l.confirmCommitted = false
	if !l.opts.NoStart && l.testFaultRequested(testFaultAfterCommit) {
		r.AddError(codeLifecycleTestFault, "the lifecycle test fault asked this run to fail after its deployment committed")
	}
	// The change that leaves the eligible users without a connector says so
	// at once, as on Windows, not only at the next status (GAP-0266).
	l.warnNoConnectorsEnabled(p.config)
	l.warnUnenforcedAssetPolicy(p.config)
	if l.opts.Action == ActionRepair && l.machinePolicyErr != nil {
		// repair exists to put the deployment back; a vendor file it could not
		// put the hooks into (an administrator line that does not parse) is
		// not repaired, and the next verify fails on it again (GAP-0531).
		r.AddError(codeMachinePolicyIncomplete, "repair could not put DefenseClaw hooks back in vendor machine policy: "+
			l.machinePolicyErr.Error()+"; the rest of the deployment is repaired")
	}
	if l.opts.Action == ActionEnsure && l.machinePolicyErr != nil {
		// Ensure can apply other deployment changes while a combined or
		// unreadable vendor entry remains. A successful exit would claim the
		// requested coverage even though the descriptor excludes it.
		r.AddError(codeMachinePolicyIncomplete, "ensure could not put DefenseClaw hooks in vendor machine policy: "+
			l.machinePolicyErr.Error()+"; other deployment changes may have been applied")
	}
	return 0
}

// quiesce stops the services in reverse activation order. Sockets stay up
// so hooks queue during the change; they are restarted in activation only
// when their definition changed. The units in keep stay as they are. The
// verify timer stays too: its run waits for the lifecycle lock, and it is
// what notices (and recovers) a transaction a killed run left pending, which
// otherwise left verify unloaded with the services stopped (GAP-0428).
func (l *lifecycle) quiesce(ctx context.Context, units []Unit, keep map[string]bool) {
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage > ordered[j].Stage })
	for _, unit := range ordered {
		if unit.Kind == "socket" || unit.Kind == "timer" || unit.Name == l.env.SelfUnit || keep[unit.Name] {
			continue
		}
		if unit.Kind == "gateway" {
			// The guardian and the enumerator are stopped (a later stage),
			// so nothing renders the hooks again meanwhile (GAP-1123).
			l.fenceReplacedHooks(ctx)
		}
		_ = l.env.Services.Stop(ctx, unit)
	}
}

// keepSensorHelperRunning keeps the sensor helper up through a config
// change the gateway applies in place. Nothing the helper reads changes in
// one (its unit, binary and arguments stay, and it watches the homes
// manifest itself), but stopping it ended the gateway's kernel event stream
// while the gateway kept running, and Plane C stayed down until the gateway
// was restarted (GAP-1418).
func keepSensorHelperRunning(keep map[string]bool, units []Unit) {
	for _, unit := range units {
		if unit.Kind == "sensor_helper" {
			keep[unit.Name] = true
		}
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
		// A daily verify run waiting for the lock: stopping it killed it
		// (status=15/TERM) and left the unit failed after a healthy package
		// upgrade (GAP-0585). Left alone it verifies the changed deployment.
		keep[unitVerifyService] = true
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
		if l.reportChanges && env.metadataDiffers(path, dir.Mode, dir.Owner) {
			l.noteChange("restored the mode and owner of %s", dir.Path)
		}
		if err := env.ensureDir(path, dir.Mode, dir.Owner); err != nil {
			return nil, err
		}
	}
	for _, file := range p.files {
		if err := mkdirParents(env.P(filepath.Dir(file.Path))); err != nil {
			return nil, err
		}
		if file.Kind == "host-security" {
			if err := env.Trust(env.P(filepath.Dir(file.Path)), TrustAdminDir); err != nil {
				return nil, fmt.Errorf("%s is not administrator-controlled: %w", filepath.Dir(file.Path), err)
			}
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
	writeOptions := l.configWriteOptions()
	var changed map[string]bool
	_, err := configwrite.Locked(ctx, configPath, writeOptions, func() (bool, error) {
		var err error
		if changed, err = l.applyFiles(p); err != nil {
			return false, err
		}
		state, stateErr := configwrite.ReadGenerationState(configPath)
		// Equal bytes still need a generation naming the current signed
		// bundle. This also repairs records left by older lifecycle builds.
		bundleUnrecorded := writeOptions.Bundle.ID != "" &&
			(state.BundleID != writeOptions.Bundle.ID || state.BundleVersion != writeOptions.Bundle.Version ||
				state.SignerKeyID != writeOptions.Bundle.SignerKeyID || state.Actor != writeOptions.Actor)
		return changed[env.Layout.ConfigPath] || stateErr != nil || state.ConfigSHA256 != p.config.SHA || bundleUnrecorded || l.policyAssetsEdited, nil
	})
	if err != nil {
		return nil, err
	}
	if l.policyAssetsEdited {
		l.noteChange("recorded a policy asset the config names, changed in place, as the next config generation")
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
	if repair := p.config.FailModeRepair; repair != nil && changed[env.Layout.ConfigPath] {
		record, err := json.MarshalIndent(repair, "", "  ")
		if err != nil {
			return nil, err
		}
		if err := env.writeFileAtomic(env.P(config.MigrationRecordPath(env.Layout.ConfigPath)), append(record, '\n'), 0o640, serviceGroup); err != nil {
			return nil, err
		}
		for _, move := range repair.Repaired {
			l.noteChange("%s", config.MigratedCursorFailModeRepairNote(move))
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
		// config.yaml is checked again as it is applied: the plan checked
		// who could write it, but a push can loosen its mode before this
		// point, and restoring the managed owner and mode of bytes another
		// account wrote since made the follow-up transaction trust them as
		// administrator policy (GAP-1501).
		var checked []byte
		untrusted := ""
		if file.Kind == "config" {
			data, problem, err := env.readConfigChecked(env.P(file.Path))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			current, checked, untrusted = "", data, problem
			if data != nil {
				current = sha256Bytes(data)
			}
			if untrusted == "" && l.configACLWritable {
				untrusted = "a macOS ACL entry let another account write it"
			}
		}
		if current == file.SHA && untrusted != "" {
			// The planned bytes: a new file holds them, so a descriptor the
			// other account opened writes nowhere.
			if err := env.writeFileAtomic(env.P(file.Path), checked, file.Mode, file.Owner); err != nil {
				return nil, err
			}
			l.noteChange("replaced %s with a new file holding the applied config: %s, so another account could write it", file.Path, untrusted)
			continue
		}
		if current == file.SHA {
			if l.reportChanges && env.metadataDiffers(env.P(file.Path), file.Mode, file.Owner) {
				l.noteChange("restored the mode and owner of %s", file.Path)
			}
			if err := env.fixMetadata(env.P(file.Path), file.Mode, file.Owner); err != nil {
				return nil, err
			}
			continue
		}
		// A config.yaml written in place while this run held the lock (a
		// --config run, say) is newer than the bytes this run planned, so it
		// stays and a follow-up transaction applies it (input_changed). The
		// run overwrote it with its own file and nothing warned (GAP-0745).
		written := file.Kind == "config" && !file.KeepContent && current != p.installedConfigSHA
		if (file.KeepContent || written) && untrusted != "" {
			return nil, &codedError{code: codeConfig, err: fmt.Errorf("%s was written while this run applied it and %s, so an account other than root could have written the change; it is not applied. Push the administrator config again, or run `%s --config <file>`",
				file.Path, untrusted, env.lifecycleCommand(ActionEnsure))}
		}
		if written {
			l.configWrittenDuringRun = checked
		}
		if file.KeepContent || written {
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
	if err := e.Lchown(path, owner.UID, owner.GID); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// initialManifest seeds an empty guardian manifest so the guardian and the
// sensor helper start before the enumerator has published its first rows.
// An existing manifest (enumerator- or administrator-written) is kept.
func (e *Env) initialManifest() error {
	path := e.P(e.Layout.ManifestPath)
	if exists(path) {
		return nil
	}
	return e.writeFileAtomic(path, []byte("version: 1\ntargets: []\n"), 0o640, rootOwner())
}

// packageUnitDir is where the Linux package installs its units.
const packageUnitDir = "/usr/lib/systemd/system"

// packageUserUnitDir is where the Linux package installs the user units of
// the sandbox daemon (the three the rpm and deb carry). A package install
// records their digests in the deployment but never writes them, so a later
// run that does not plan them (nothing lists a package unit as a file) must
// not take them for files the deployment dropped and unlink them: verify then
// failed on the missing units and rolled every later run back (GAP-0176,
// GAP-0177).
const packageUserUnitDir = "/usr/lib/systemd/user"

// packageOwns reports whether the package manager owns path on a package
// install: the binaries, the system and user units, and the OpenCode plugin.
// The lifecycle records them and never removes them. The macOS agents are
// not here: the lifecycle writes those itself on every channel.
func (e *Env) packageOwns(path string) bool {
	return strings.HasPrefix(path, e.Layout.BinDir+"/") || strings.HasPrefix(path, packageUnitDir+"/") ||
		(e.GOOS == "linux" && strings.HasPrefix(path, packageUserUnitDir+"/")) ||
		path == enterprisepolicy.OpenCodeManagedPluginPath(e.Layout)
}

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
func (l *lifecycle) activate(ctx context.Context, units []Unit, restartSockets map[string]bool, hot bool, p *plan) error {
	env := l.env
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage < ordered[j].Stage })
	for _, unit := range ordered {
		// systemd refuses to enable or start a masked unit; the error said
		// neither "masked" nor how to undo it (GAP-0475).
		if unitMasked(ctx, env.Services, unit) {
			if err := env.Services.(maskReporter).Unmask(ctx, unit); err != nil {
				return &unitActivationError{unit: unit, err: fmt.Errorf("unmask %s: %w", unit.Name, err)}
			}
			l.noteChange("unmasked %s, which was masked and could not start", unit.Name)
		}
	}
	for _, unit := range ordered {
		if !unit.Activate {
			continue
		}
		wasDisabled := unitDisabled(ctx, env.Services, unit)
		if err := env.Services.Enable(ctx, unit); err != nil {
			return &unitActivationError{unit: unit, err: fmt.Errorf("enable %s: %w", unit.Name, err)}
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
		if hot && unit.Kind == "sensor_helper" && env.Services.Active(ctx, unit) {
			// Kept running through the config change; starting it again
			// would restart a launchd job (kickstart -k).
			continue
		}
		if hot && unit.Kind == "gateway" && env.Services.Active(ctx, unit) {
			if err := l.settleHotGateway(ctx, unit); err != nil {
				return err
			}
			continue
		}
		if env.GOOS == "linux" && unit.Kind == "sensor_helper" {
			previous, _ := env.sensorState()
			// A stop during an RPM handoff can leave the old helper active.
			// systemctl start then succeeds without applying the new drop-in.
			if env.Services.Active(ctx, unit) {
				if err := restartUnit(ctx, env.Services, unit); err != nil {
					return &unitActivationError{unit: unit, err: fmt.Errorf("restart %s: %w", unit.Name, err)}
				}
			} else if err := env.Services.Start(ctx, unit); err != nil {
				return &unitActivationError{unit: unit, err: fmt.Errorf("start %s: %w", unit.Name, err)}
			}
			if previous.Intent.Mode != "" && string(previous.Intent.Mode) != p.config.Tetragon.helperMode() {
				if err := l.waitHelperMode(ctx, unit, p.config.Tetragon.helperMode(), previous); err != nil {
					return &unitActivationError{unit: unit, err: err}
				}
				l.helperModeRestart = true
			}
			continue
		}
		if err := env.Services.Start(ctx, unit); err != nil {
			return &unitActivationError{unit: unit, err: fmt.Errorf("start %s: %w", unit.Name, err)}
		}
		if unit.Kind == "gateway" {
			if err := l.waitGatewayReady(ctx, unit); err != nil {
				return err
			}
		}
	}
	return nil
}

// unitActivationError is an activation failure of a unit that is not the
// gateway: the gateway's output does not say why it failed.
type unitActivationError struct {
	unit Unit
	err  error
}

func (e *unitActivationError) Error() string { return e.err.Error() }
func (e *unitActivationError) Unwrap() error { return e.err }

// gatewayFailure reports whether an activation error may come from the
// gateway, so that its output and a config refusal explain it.
func gatewayFailure(err error) bool {
	var unitErr *unitActivationError
	return !errors.As(err, &unitErr) || unitErr.unit.Kind == "gateway" || unitErr.unit.Kind == "socket"
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
// other service is touched (linking and renaming are safe while the
// services run), and a restore that fails returns without stopping or
// starting anything else. Only a sensor helper that recorded Tetragon
// policies stops first, so its policies are retired with the binary that
// loaded them and never under it; it starts again when the restore fails.
// beforeRestore runs once the services are stopped, just before the
// snapshot is put back. beforeStart runs afterwards and learns whether all
// files were restored. restored is false when any file could not be put
// back; the snapshot must then be kept for a retry.
func (l *lifecycle) rollback(ctx context.Context, snap *snapshot, intent *Pending, restoreFirst bool, beforeRestore func(), beforeStart func(bool)) (restored bool, err error) {
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
	// The Tetragon policies the transaction's helper loaded go with that
	// helper, before the snapshot puts the previous one back (once), and
	// never while it runs: a running helper reads their disappearance as an
	// operator's deletion and does not load them again until the intent
	// changes.
	retired := false
	retire := func() {
		if !retired {
			retired = true
			l.retireRolledBackKernelPolicies(ctx)
		}
	}
	if restoreFirst {
		// Only the helper stops before the files go back. When they cannot,
		// it starts again and manages its own policies as before.
		helper, stopped, safe := l.stopHelperHoldingKernelPolicies(ctx)
		if safe {
			retire()
		}
		if err := env.restoreFiles(snap); err != nil {
			if stopped {
				if startErr := env.Services.Start(ctx, helper); startErr != nil {
					err = errors.Join(err, startErr)
				}
			}
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
		if l.keepThroughRollback[unit.Name] {
			// It reloads the restored config.yaml itself.
			continue
		}
		_ = env.Services.Stop(ctx, unit)
	}
	// The helper is stopped now; the restored helper loads its own policies
	// again if it manages any.
	retire()
	if beforeRestore != nil {
		beforeRestore()
	}
	restoreErr := env.restore(snap)
	if beforeStart != nil {
		beforeStart(restoreErr == nil)
	}
	l.rollbackConfigSHA, l.rollbackConfigFile = "", nil
	if restoreErr == nil {
		l.rollbackConfigFile, _ = os.Stat(env.P(env.Layout.ConfigPath))
		l.rollbackConfigSHA, _ = sha256File(env.P(env.Layout.ConfigPath))
	}
	generationErr := l.recordRestoredGeneration(ctx)
	if generationErr != nil {
		l.result.AddWarning(codeRolledBack, "could not record the restored config.yaml in "+configwrite.GenerationFileName+": "+generationErr.Error())
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
			if l.keepThroughRollback[unit.Name] && env.Services.Active(ctx, unit) {
				// Kept running; launchd would restart a loaded job.
				continue
			}
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
	// launchd's bootstrap returns before the job listens (systemd waits for
	// the gateway's READY=1): wait for the restored gateway, so the result
	// reports the deployment that is back and not one still starting. One
	// that does not answer is reported not ready.
	if gateway, ok := gatewayUnitOf(units); ok && contains(previouslyActive, gateway.Name) && env.Services.Active(ctx, gateway) {
		_ = l.waitGatewayReady(ctx, gateway)
	}
	if restoreFirst {
		restoreErr = errors.Join(restoreErr, generationErr)
	}
	return restoreErr == nil, errors.Join(restoreErr, reloadErr, errors.Join(disableErrs...), errors.Join(startErrs...))
}

// generationRecord is config.generation.json before a transaction, with the
// config digest it names.
type generationRecord struct {
	raw   []byte
	sha   string
	state configwrite.GenerationState
}

// rememberGeneration keeps the generation record as the transaction found it.
func (l *lifecycle) rememberGeneration() {
	env := l.env
	l.generationBefore, l.generationExposed = nil, false
	configPath := env.P(env.Layout.ConfigPath)
	raw, err := readBounded(env.P(configwrite.GenerationPath(env.Layout.ConfigPath)), maxInputBytes)
	if err != nil {
		return
	}
	if state, err := configwrite.ReadGenerationState(configPath); err == nil {
		l.generationBefore = &generationRecord{raw: raw, sha: state.ConfigSHA256, state: state}
	}
}

// recordRestoredGeneration records the config.yaml a rollback put back as a
// new config generation (actor lifecycle). The transaction may already have
// recorded, and the gateway reported, a generation for the config it
// installed; a monotonic counter keeps that number for that config only.
// Nothing is recorded when there is no config or no generation record, or
// when the record already names the restored bytes. A run that failed before
// the gateway could read its config (generationExposed) puts the record back
// as the run found it instead, so the counter does not move.
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
	// A rollback to the config of the bundle the run found (the last good
	// bundle) is recorded as that bundle again, so /health and
	// config.change.applied name the bundle that enforces.
	opt := configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "enterprise " + l.opts.Action + " rollback"}
	if l.bundle != nil {
		opt.LocalActor = configwrite.CurrentOSActor()
	}
	var restoredPending *enterprisebundle.Receipt
	if before := l.generationBefore; before != nil {
		if raw, err := os.ReadFile(configPath); err == nil {
			opt = configwrite.RestoreOptions(before.state, configwrite.SHA256Hex(raw), opt)
		}
	} else if env.bundleMode() {
		// A killed process took generationBefore with it. Recover the actor
		// and bundle identity from the confirmed receipt, after checking that
		// the restored bytes really are that bundle's rendered config. A
		// higher delivery killed over a bundle an earlier run committed and
		// the gateway has not confirmed is rolled back to that bundle's
		// bytes: they are recorded as that bundle, and its receipt moves to
		// the new generation, so the gateway can still confirm it
		// (GAP-1803, GAP-2097).
		store := env.bundleStore()
		raw, ref, err := env.currentBundleConfig(store)
		if err != nil {
			return fmt.Errorf("read the confirmed bundle for rollback: %w", err)
		}
		restored, readErr := os.ReadFile(configPath)
		if readErr == nil && (ref == nil || !bytes.Equal(restored, raw)) {
			restoredPending = env.committedPendingBundle(store, ref, restored)
		}
		switch {
		case restoredPending != nil:
			pendingOpt, ok := enterprisebundle.GenerationOptions(restoredPending)
			if !ok {
				return fmt.Errorf("pending bundle %s version %d has no principal", displayID(restoredPending), restoredPending.Version)
			}
			pendingOpt.GenerationFloor = restoredPending.ConfigGeneration
			opt = pendingOpt
		case ref == nil:
			// No bundle was confirmed yet: the lifecycle records the bytes.
		case readErr != nil || !bytes.Equal(restored, raw):
			return fmt.Errorf("restored config does not match confirmed bundle %s version %d: %v", ref.BundleID, ref.Version, readErr)
		default:
			opt, err = currentBundleGenerationOptions(store, ref)
			if err != nil {
				return fmt.Errorf("read confirmed bundle attribution: %w", err)
			}
		}
	}
	if l.bundle != nil {
		if attempted := l.configWriteOptions(); attempted.Bundle != (configwrite.BundleRef{}) {
			opt.TransactionActor = attempted.Actor
			opt.TransactionBundle = attempted.Bundle
			opt.TransactionSummary = l.bundle.receipt.ChangeSummary
			opt.Lifecycle = true
		}
	}
	_, err = configwrite.Locked(ctx, configPath, opt, func() (bool, error) {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			return false, err
		}
		sha := configwrite.SHA256Hex(raw)
		if before := l.generationBefore; before != nil && !l.generationExposed && before.sha == sha {
			// Nothing read the generation this run recorded: the record the
			// run found already names the restored bytes, so it goes back as it was.
			return false, env.writeFileAtomic(statePath, before.raw, mode.Perm(), fileOwner{UID: uid, GID: gid})
		}
		state, stateErr := configwrite.ReadGenerationState(configPath)
		return stateErr != nil || state.ConfigSHA256 != sha ||
			(opt.Bundle.ID != "" && (state.BundleID != opt.Bundle.ID || state.BundleVersion != opt.Bundle.Version)), nil
	})
	if err != nil {
		return err
	}
	if err := env.fixMetadata(statePath, mode.Perm(), fileOwner{UID: uid, GID: gid}); err != nil {
		return err
	}
	if before := l.generationBefore; before != nil {
		l.rebindRestoredPendingBundle(before.state)
	}
	if restoredPending != nil {
		l.rebindRecoveredPendingBundle(restoredPending)
	}
	return nil
}

// rebindRecoveredPendingBundle moves the receipt of the committed,
// unconfirmed bundle a recovery put back (committedPendingBundle) to the
// generation recordRestoredGeneration recorded for its bytes and signed
// attribution, so the gateway's report of that generation confirms it.
func (l *lifecycle) rebindRecoveredPendingBundle(rc *enterprisebundle.Receipt) {
	state, err := configwrite.ReadGenerationState(l.env.P(l.env.Layout.ConfigPath))
	if err != nil || state.Generation <= rc.ConfigGeneration || state.ConfigSHA256 != rc.ConfigSHA256 ||
		state.BundleID != rc.BundleID || state.BundleVersion != rc.Version ||
		state.SignerKeyID != rc.SignerKeyID || state.Actor != rc.Principal {
		return
	}
	l.rebindPendingReceipt(rc, state.Generation)
}

// rebindRestoredPendingBundle keeps provable the unconfirmed bundle whose
// committed config a rollback put back. The counter only moves forward, so
// the rollback records those bytes, with that bundle's signed attribution,
// under a new generation; the receipt still named the old one, and every
// later ensure kept the bundle pending until it was delivered again
// (GAP-1186). Only the receipt whose committed generation is the one the
// run found, for the same bytes and attribution, moves to the new number.
func (l *lifecycle) rebindRestoredPendingBundle(before configwrite.GenerationState) {
	env := l.env
	if before.BundleID == "" || before.Generation == 0 || !env.bundleMode() {
		return
	}
	state, err := configwrite.ReadGenerationState(env.P(env.Layout.ConfigPath))
	if err != nil || state.Generation <= before.Generation || state.ConfigSHA256 != before.ConfigSHA256 ||
		state.BundleID != before.BundleID || state.BundleVersion != before.BundleVersion ||
		state.SignerKeyID != before.SignerKeyID || state.Actor != before.Actor {
		return
	}
	store := env.bundleStore()
	receipts, err := store.Unsettled()
	if err != nil {
		return
	}
	for _, rc := range receipts {
		if rc.State != enterprisebundle.StateApplied || rc.ConfigGeneration != before.Generation ||
			rc.ConfigSHA256 != state.ConfigSHA256 || rc.BundleID != state.BundleID || rc.Version != state.BundleVersion ||
			rc.SignerKeyID != state.SignerKeyID || rc.Principal != state.Actor {
			continue
		}
		l.rebindPendingReceipt(rc, state.Generation)
	}
}

// rebindPendingReceipt moves an applied receipt to the config generation
// that records its bytes again.
func (l *lifecycle) rebindPendingReceipt(rc *enterprisebundle.Receipt, generation uint64) {
	if err := l.env.bundleStore().RebindGeneration(rc, generation); err != nil {
		l.result.AddWarning(stateWriteCode(err, codeBundleStateUnreadable), fmt.Sprintf(
			"policy bundle %s version %d is installed again, but its receipt could not record the restored config generation; deliver it again to confirm it: %v%s",
			displayID(rc), rc.Version, err, stateWriteAction(err)))
	}
}

// recoverInterrupted rolls back a transaction a previous run left pending,
// or whose rollback could not restore every file. It returns false when
// the snapshot still could not be restored: the snapshot and the intent are
// kept, and the run must not change the host.
func (l *lifecycle) recoverInterrupted(ctx context.Context) bool {
	env, r := l.env, l.result
	pending, err := env.loadPending()
	if err != nil {
		if env.bundleMode() {
			r.AddError(codeRollbackFailed, "cannot read the interrupted bundle transaction, so the confirmed running policy cannot be restored: "+err.Error())
			return false
		}
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
		if env.bundleMode() {
			r.AddError(codeRollbackFailed, fmt.Sprintf("cannot restore the interrupted bundle transaction from its snapshot: %v", err))
			r.AddWarning(codeRollbackFailed, keptSnapshotAdvice)
			return false
		}
		r.AddWarning(codeRecovered, fmt.Sprintf("an interrupted %s left no usable snapshot (%v); this run re-applies the desired state", pending.Action, err))
		_ = env.clearPending()
		if snap != nil {
			env.discardSnapshot(snap)
		}
		return true
	}
	// An interrupted hot change goes back the way it came: the gateway and
	// the sensor helper keep running and the gateway reloads the restored
	// config.yaml, so the retry applies the change hot again with the same
	// gateway (GAP-0238, #1279 L3). A gateway that is not running is started
	// as before.
	l.keepThroughRollback = nil
	if pending.Hot {
		l.keepThroughRollback = hotRollbackKeep(ctx, env)
		defer func() { l.keepThroughRollback = nil }()
	}
	// The files go back before any other service is touched: a restore
	// that still fails (the disk is still full) then leaves the running
	// services alone instead of stopping and restarting the gateway on every
	// apply trigger, MDM ensure or package postinstall until it succeeds.
	left, _ := sha256File(env.P(env.Layout.ConfigPath))
	restored, err := l.rollback(ctx, snap, pending, true, nil, nil)
	if restored {
		l.interruptedConfigSHA = left
	}
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
	if err := l.confirmRecoveredBundle(ctx); err != nil {
		r.AddError(codeRollbackFailed, "interrupted bundle rollback did not restore the confirmed running policy: "+err.Error())
		r.AddWarning(codeRollbackFailed, keptSnapshotAdvice)
		return false
	}
	_ = env.clearPending()
	env.discardSnapshot(snap)
	return true
}

// hotRollbackKeep names the running gateway and sensor helper, which an
// interrupted hot transaction left running and its rollback leaves running.
func hotRollbackKeep(ctx context.Context, env *Env) map[string]bool {
	keep := map[string]bool{}
	for _, unit := range env.Services.Units() {
		if (unit.Kind == "gateway" || unit.Kind == "sensor_helper") && env.Services.Active(ctx, unit) {
			keep[unit.Name] = true
		}
	}
	return keep
}

// restoreUnchangedConfigMetadata puts back the managed mode and owner of an
// installed config.yaml whose bytes are the applied config, so the run stays
// a no-op. Configuration management that installs the same file again
// (install -o root -g root -m 0640) changed only its group: the run restored
// it and restarted the gateway to load a change that was none, on every run
// (GAP-0941). A --config run brings its own bytes and is left alone. It
// reports whether it restored them.
func (l *lifecycle) restoreUnchangedConfigMetadata(ctx context.Context, record *Deployment) bool {
	env := l.env
	if l.opts.ConfigFile != "" || record == nil {
		return false
	}
	// A config.yaml another account could write is replaced by the
	// transaction instead (replaceWritableConfig). Fixing its mode here, in
	// place, made it look trusted to the plan, so a write through a
	// descriptor that account opened while it could write was applied by
	// the follow-up transaction (GAP-0524).
	if writable, err := env.installedConfigWritable(ctx); err != nil || writable != "" {
		return false
	}
	path := env.P(env.Layout.ConfigPath)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return false
	}
	raw, err := readBounded(path, maxInputBytes)
	if err != nil || sha256Bytes(raw) != record.ConfigSHA256 {
		return false
	}
	account, ok, err := env.Accounts.Lookup(ctx, env.Layout.ServiceUser)
	if err != nil || !ok || account.GID != record.ServiceGID {
		return false
	}
	owner := fileOwner{UID: 0, GID: account.GID}
	if !env.metadataDiffers(path, 0o640, owner) || env.fixMetadata(path, 0o640, owner) != nil {
		return false
	}
	if !hasMessageCode(l.result.Warnings, codeConfigMetadataRestored) {
		l.result.AddWarning(codeConfigMetadataRestored, fmt.Sprintf(
			"restored the mode and owner of %s (0640, root and the service group); its content is the applied config, so nothing else changed",
			env.Layout.ConfigPath))
	}
	return true
}

// ensureNoop reports whether the installed deployment already matches the
// desired state. It never mutates the host.
func (l *lifecycle) ensureNoop(ctx context.Context, record *Deployment) (bool, string) {
	env := l.env
	l.noopPolicy, l.policyAssetsEdited, l.policyAssetRefusal = nil, false, ""
	account, ok, err := env.Accounts.Lookup(ctx, env.Layout.ServiceUser)
	if err != nil || !ok || account.UID != record.ServiceUID || account.GID != record.ServiceGID {
		return false, ""
	}
	p, err := l.buildPlan(ctx, record, account)
	if err != nil || p.configWritable != "" {
		// apply reports the same error with rollback semantics, or replaces
		// a config.yaml another account could write.
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
	if !record.NoStart {
		// A unit an administrator disabled may still run (the hook socket
		// starts the gateway again), so verifyInstalled passes; activation
		// re-enables it (GAP-0530).
		for _, unit := range env.Services.Units() {
			if unit.Activate && unitDisabled(ctx, env.Services, unit) {
				return false, ""
			}
		}
	}
	if l.machinePolicyDrift(p) {
		return false, ""
	}
	if !l.policyViewPinsCurrent(p.machinePolicy) {
		return false, ""
	}
	if l.helperModeDrift(ctx, p) {
		l.helperModeRestart = true
		return false, ""
	}
	if l.policyAssetsChanged(ctx, record, account) {
		return false, ""
	}
	if l.policyAssetRefusal != "" {
		return true, "policy_refused"
	}
	return true, "up_to_date"
}

// policyAssetsChanged reports whether the installed config computes to an
// effective policy the running gateway does not report while config.yaml
// and every file the lifecycle installs are as applied: a policy asset the
// config names was edited in place (a sandbox pack under the policies
// directory, whose folder the gateway does not watch). ensure then applies
// again, which records the change as the next config_generation and loads it
// into the gateway, instead of reporting a noop with applied false
// (GAP-0133). A gateway that is down or not serving, that publishes no
// digest (Secure Client), or that rejected its last reload, and a policy that
// does not build, are not changes a run can apply; status and verify keep
// reporting them, and ensure fails with the reason a policy does not build
// (policyAssetRefusal).
func (l *lifecycle) policyAssetsChanged(ctx context.Context, record *Deployment, account Account) bool {
	if record.NoStart {
		return false
	}
	env := l.env
	gateway, ok := gatewayUnitOf(env.Services.Units())
	if !ok || !env.Services.Active(ctx, gateway) {
		return false
	}
	body, err := l.gatewayHealth(ctx, gateway, account.UID)
	if err != nil {
		return false
	}
	reported, reloadError := gatewayPolicyHealth(body)
	if reported == "" || reloadError != "" {
		return false
	}
	digest, generation, err := l.computePolicy(ctx)
	if err != nil {
		// A policy that does not build is no change ensure applies: the
		// running gateway keeps the policy it loaded, and the run fails
		// with the reason instead of restarting into a policy that does not
		// load (GAP-0229).
		l.policyAssetRefusal = l.configRefusal(ctx)
		return false
	}
	if digest == reported {
		l.noopPolicy = &computedPolicy{digest: digest, generation: generation}
		return false
	}
	l.policyAssetsEdited = true
	return true
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
// the service account. Without purge each account keeps its ~/.defenseclaw,
// per-user binaries and sandboxes; the gateway's sandbox registrations and
// key stay for those sandboxes, and Linux keeps administrator policies.
// KeepState keeps the other machine state for a reinstall to resume with.
func (l *lifecycle) uninstall(ctx context.Context, record *Deployment) int {
	env, r := l.env, l.result
	// An uninstall resolves no service account (only install, ensure and
	// repair do), so a refused uninstall that started the services again
	// waited for a gateway served by uid 0 and timed out after 90 s, while
	// the restored gateway runs as the deployment's account (GAP-0184).
	if record != nil {
		l.serviceUID = record.ServiceUID
	}
	units := env.Services.Units()
	if record == nil && !l.opts.Purge {
		failure := env.lastPackageInstallFailure()
		// A first deb or rpm install that failed and rolled back left the
		// package machine state (the config, the state and log folders, the
		// lifecycle result and the service account the package created):
		// the package removal runs this uninstall, which found no deployment
		// and kept all of it (GAP-0421). It is removed as the state of a
		// committed deployment is. State a --keep-state uninstall kept stays.
		// A failed first macOS pkg install records no receipt, so its
		// binaries, the rejected config.yaml and the lifecycle result are
		// leftovers too, which the MDM uninstall script left in place
		// (GAP-0567).
		l.failedInstallLeftovers = failure != "" && !l.opts.KeepState && len(env.loadRetainedState()) == 0
		if !l.failedInstallLeftovers {
			r.Noop = true
			r.NoopReason = "not_installed"
			// After a failed first package install, give the same finish
			// step as status and verify (GAP-2410).
			env.warnPackageInstallFailed(r, failure)
			if leftovers := env.unmanagedLeftovers(env.Services, ChannelPayload); len(leftovers) > 0 {
				r.AddWarning(codeLeftovers, "no committed deployment, but DefenseClaw machine state exists ("+strings.Join(leftovers, ", ")+"); "+env.leftoversNextStep(ctx, failure != ""))
			}
			return 0
		}
	}
	// Read before the machine state, and the accounts record with it, go.
	// A Unix purge also needs this snapshot to report enrolled OSS data that
	// the per-user worker leaves untouched (GAP-0727).
	l.keptPerUser, l.enrolledHomes, l.keptKnown = env.perUserLeftovers()
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage > ordered[j].Stage })
	// stopUnits stops a group of units and returns the ones still running.
	// systemd stops the group in one request, so a socket cannot start the
	// service again while the rest of the group stops, and the group is
	// stopped again while one is still running (GAP-0112).
	stopUnits := func(group []Unit) []string {
		stopper, together := env.Services.(groupStopper)
		var running []string
		for attempt := 0; attempt < 3; attempt++ {
			if together {
				_ = stopper.StopTogether(ctx, group)
			} else {
				for _, unit := range group {
					_ = env.Services.Stop(ctx, unit)
				}
			}
			running = running[:0]
			for _, unit := range group {
				if env.Services.Active(ctx, unit) {
					running = append(running, unit.Name)
				}
			}
			if len(running) == 0 || !together {
				break
			}
		}
		// On macOS launchctl disable writes an override into launchd's
		// database that no command can delete (GAP-1443). The definitions
		// are removed below; one that stays is disabled there.
		for _, unit := range group {
			if unit.Activate && env.GOOS != "darwin" {
				_ = env.Services.Disable(ctx, unit)
			}
		}
		return running
	}
	stopGroup := func(registrations bool) []string {
		var group []Unit
		for _, unit := range ordered {
			if repairsRegistrations(unit) == registrations {
				group = append(group, unit)
			}
		}
		return stopUnits(group)
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
	gatewayPresent := exists(filepath.Join(env.P(env.Layout.BinDir), binGateway))
	// Rollback of a first package install may remove config.yaml after
	// enrollment, while leaving the manifest and hook registrations. The
	// remove-all command has a cleanup-only config-free path for this case.
	removePerUser := gatewayPresent && (record != nil || exists(env.P(env.Layout.ManifestPath)))
	if removePerUser && l.refuseUnresolvedPerUserRows(ctx) {
		return 0
	}
	// The guardian repairs any DefenseClaw registration that goes missing
	// from a manifest target, the enumerator republishes the manifest, and
	// the apply and verify triggers start lifecycle runs. All of them stop
	// before any registration is removed; otherwise the guardian puts each
	// removed hook back within its debounce and the users are left with
	// registrations naming a binary this uninstall deletes. The gateway and
	// its sockets keep answering hooks until the registrations are gone.
	// What ran and started at boot is recorded first: an uninstall that
	// stops short of removing the deployment puts it back (GAP-1500).
	wasActive, wasEnabled := map[string]bool{}, map[string]bool{}
	for _, unit := range units {
		wasActive[unit.Name] = unitStarted(ctx, env.Services, unit)
		wasEnabled[unit.Name] = unitEnabled(ctx, env.Services, unit)
	}
	stillRunning := stopGroup(true)
	// The accounts of the sandbox subsystem are read before the per-user
	// removal below deletes the records that name some of them.
	sandboxAccounts := l.sandboxAccounts(ctx)
	var errs []error
	// DefenseClaw's vendor machine policy entries go first, while the hook
	// binary they name still exists; administrator entries stay byte for
	// byte (enterprisepolicy restores the recorded preimage or edits only
	// DefenseClaw's own entries).
	policyLeft := false
	var policyRemoved []string
	if policy, err := env.MachinePolicy.RemoveAll(); err != nil {
		errs = append(errs, fmt.Errorf("remove machine policy: %w", err))
		policyLeft = true
	} else {
		for _, state := range policy.States {
			if state.Changed {
				r.MachinePolicy[state.Connector] = state.ToStatus()
				policyRemoved = append(policyRemoved, state.Connector)
			}
		}
	}
	// A machine-policy failure leaves every user's hooks and state intact:
	// removing or purging them first would leave the retained deployment
	// unguarded until its guardian repaired the registrations (GAP-0393).
	// Per-user registrations go next, while the binaries they name still
	// exist: each user's worker removes only DefenseClaw's own entries (and,
	// on purge, that user's DefenseClaw state).
	//
	// Without a deployment record (after a default or --keep-state
	// uninstall) a purge still finds the enrolled accounts when the
	// enrollment record and the config it needs are there; otherwise it
	// names the accounts whose per-user files stay (GAP-2632).
	perUserLeft := false
	// Without a record, the package database says whether the deb/rpm owns
	// the binaries: a purge deleted those of an installed rpm (GAP-2632).
	l.packageManaged = env.GOOS == "linux" && (record != nil && record.Channel == ChannelPackage ||
		record == nil && gatewayPresent && env.packageOwned(ctx, filepath.Join(env.Layout.BinDir, binGateway)))
	if removePerUser && !policyLeft {
		var cacheAccounts []sessionFactsAccount
		if l.opts.Purge {
			cacheAccounts = env.sessionFactsAccounts()
		}
		perUserLeft = l.removePerUserRegistrations(ctx)
		l.purgeSessionFactsCaches(cacheAccounts)
	} else if record == nil && l.opts.Purge && !policyLeft {
		l.warnUnpurgedPerUser(ctx)
	}
	if l.opts.Purge {
		l.reportRetainedEnrolledUserData()
		if removePerUser && !policyLeft {
			l.reportUnenrolledUserData(ctx)
		}
	}
	// The sandbox subsystem goes before the binaries it runs: a non-purge
	// uninstall stops and keeps each account's sandboxes, then its daemon
	// and OpenShell gateway. A purge tears down the sandboxes as the account
	// and removes what the subsystem left in its home.
	if !policyLeft {
		l.teardownOpenShell(ctx, sandboxAccounts)
		stillRunning = append(stillRunning, stopGroup(false)...)
	}
	if len(stillRunning) > 0 {
		errs = append(errs, fmt.Errorf("could not stop %s; stop them with %s and rerun `%s`",
			strings.Join(stillRunning, ", "), env.stopCommands(stillRunning), l.uninstallCommand()))
	}
	// The sensor helper is stopped. The Tetragon policies it loaded outlive
	// it and would keep enforcing with frozen anchors: remove them with the
	// binary that loaded them, before any binary or state goes.
	if !policyLeft {
		l.kernelRemoved = l.retireKernelPolicies(ctx)
	}
	if perUserLeft || policyLeft {
		if len(l.kernelRemoved) > 0 {
			r.Changes = append(r.Changes, kernelPolicyChange(l.kernelRemoved))
		}
		// Some users' agents, or vendor machine policy that could not be
		// withdrawn (GAP-1321), still name the hook binary. Removing it now
		// would leave those registrations calling a program that no longer
		// exists, so the agents run without enforcement and nothing is left
		// to remove them: the binaries, the deployment record and the state
		// stay, so a rerun of this uninstall removes the rest. The services
		// the uninstall stopped start again as they were: left stopped, the
		// gateway gave the retained hooks no decisions until an
		// administrator ran ensure (GAP-1500).
		if err := errors.Join(errs...); err != nil {
			r.AddError(codeUninstall, err.Error())
		}
		if record != nil {
			// The deployment stays, so its vendor machine policy goes back
			// before its services start: the entries of every connector the
			// removal could withdraw were gone (Codex beside an immutable
			// Claude Code file), and those agents ran without DefenseClaw
			// while the kept deployment read as installed (r102 GAP-0473).
			// What cannot be written back is named in a warning.
			l.restoreMachinePolicy(record)
			for _, connector := range policyRemoved {
				delete(r.MachinePolicy, connector)
			}
		}
		if failed := l.restoreUninstallServices(ctx, units, wasActive, wasEnabled); len(failed) > 0 {
			r.AddError(codeUninstall, "could not start the services this uninstall stopped again ("+strings.Join(failed, "; ")+"); run `"+env.lifecycleCommand(ActionEnsure)+"` to restore the deployment")
		}
		var holders []string
		if perUserLeft {
			holders = append(holders, "the per-user hook registrations listed above")
		}
		if policyLeft {
			holders = append(holders, "the vendor machine policy entries that could not be removed (a read-only or immutable policy file, for example)")
		}
		// Its own code: the package removal must keep the binaries these
		// registrations call, which an uninstall_failed result does not ask
		// for (GAP-1519).
		r.AddError(codeUninstallIncomplete, "stopped before removing the DefenseClaw binaries, the deployment record and the state, because "+strings.Join(holders, " and ")+" still name them; fix the cause and rerun `"+l.uninstallCommand()+"`, or run ensure to restore the deployment")
		return 0
	}
	// A device that takes signed bundles keeps a copy of the gateway for the
	// release floor check of the 1.0.4 and later package scripts: once the
	// binaries are gone (a --keep-state uninstall, or one that fails after
	// removing them) the installed gateway cannot answer, and a 1.0.4 or
	// later package below the confirmed bundle's floor would write its files
	// before its postinstall ensure refused it. A package older than 1.0.4
	// has no floor check, with or without the copy. The machine state removal
	// below takes the copy with the rest of the lifecycle state.
	if !l.opts.Purge {
		kept, err := env.keepFloorChecker(record)
		if err != nil {
			r.AddWarning(codeFloorCheckerNotKept, "could not keep the gateway that checks the release floor of the confirmed policy bundle ("+err.Error()+"); "+floorCheckerNotKeptLimit)
		}
		l.floorCheckerKept = kept
	}
	// On Linux the deb/rpm removes its own files (the binaries, units and
	// the managed OpenCode plugin). A macOS pkg has no uninstaller, so the
	// lifecycle removes the binaries and the receipt.
	packageManaged := l.packageManaged
	paths := []string{}
	if record != nil {
		for path := range record.Files {
			if packageManaged && (filepath.Dir(path) == env.Layout.BinDir || strings.HasPrefix(path, "/usr/lib/") ||
				path == compilerInstallPath(env.Layout) ||
				path == enterprisepolicy.OpenCodeManagedPluginPath(env.Layout)) {
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
	l.removeOpenShellFiles(record)
	if record == nil && env.GOOS == "linux" {
		for _, unit := range units {
			// The drop-in folders a rolled-back install left empty.
			_ = removeDirIfEmpty(env.P(filepath.Join("/etc/systemd/system", unit.Name+".d")))
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
	l.removeSELinuxModule(ctx)
	// Runtime leftovers of the stopped services: the sensor helper's socket
	// directory and the gateway's plugin cache (its TempDir is /tmp: the
	// service manager sets no TMPDIR).
	_ = os.RemoveAll(env.P(env.Layout.SensorSocketDir))
	if record != nil && record.ServiceUID > 0 {
		_ = os.RemoveAll(env.P(fmt.Sprintf("/tmp/defenseclaw-plugin-cache-%d", record.ServiceUID)))
	}
	// Vendor policies are product files: they leave with the deployment,
	// including the nested rule-pack directories. On a package host a plain
	// uninstall removes the vendor files and the folders left without a
	// file, and keeps only a file an administrator put there, for the
	// package removal (postremove.sh) to delete. An empty guardrail/default
	// left behind made the re-enable with a default-pack config, `ensure
	// --from-package --config`, refuse the pack as inventory_empty
	// (GAP-1582); without the folder ensure writes the vendor files again.
	if l.opts.Purge || !packageManaged {
		_ = os.RemoveAll(env.P(env.Layout.VendorPolicyDir))
	} else {
		if vendor, err := policyassets.Files(); err == nil {
			// Also without a deployment record, which lists them.
			for _, policy := range vendor {
				_ = removeFile(env.P(filepath.Join(env.Layout.VendorPolicyDir, filepath.FromSlash(policy.Path))))
			}
		}
		_ = pruneEmptyDirs(env.P(env.Layout.VendorPolicyDir))
	}
	// The managed OpenCode plugin left with the recorded files above, or
	// leaves with the deb or rpm that ships it.
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
	env.removeRejectedConfig()
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
		// The MDM wrapper's rotation journal goes with the credentials it
		// can put back: --keep-state and a failed uninstall keep both, so
		// a reinstall or ensure can still settle the rotation (GAP-1801).
		l.removeKitRotationJournal()
		for _, dir := range []string{env.Layout.ConfigDir, env.Layout.DataDir, env.Layout.GuardianAuthDir, env.Layout.LogDir} {
			var err error
			if dir == env.Layout.ConfigDir && !l.opts.Purge && env.GOOS == "linux" {
				// The administrator policies (custom rule packs, Rego) are
				// inputs the administrator wrote, not machine state: the
				// config that names them turns the deployment on again
				// (GAP-0960). A purge removes them.
				l.policiesKept, err = removeAllExcept(env.P(dir), env.P(env.Layout.PolicyDir))
			} else if dir == env.Layout.DataDir && l.keepSandboxStore() {
				// The sandboxes the accounts keep need the gateway's
				// registrations of them and their key at the next
				// activation (GAP-0598). A purge removes them.
				l.sandboxStoreKept, err = removeDataDirKeepingSandboxStore(env.P(dir))
			} else {
				err = os.RemoveAll(env.P(dir))
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		// The sensor helper's Tetragon state (burn-in, pause, the record of
		// loaded policies), unless it still names policies that may be
		// loaded: a helper installed later retires them from that record.
		if err := env.removeSensorState(); err != nil {
			errs = append(errs, err)
		}
		var keepLifecycle []string
		if l.openshellRecordKept {
			keepLifecycle = append(keepLifecycle, openshellKeptStateFile)
		}
		if err := env.removeLifecycleStateKeepingLock(keepLifecycle...); err != nil {
			errs = append(errs, err)
		}
		if !packageManaged {
			var keep []string
			if l.sandboxStoreKept {
				keep = append(keep, env.Layout.DataDir)
			}
			if err := env.removeInstallRootKeepingLock(keep...); err != nil {
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
					env.Layout.ServiceUser, err, serviceAccountDeleteCommand(env.GOOS, env.Layout.ServiceUser, err)))
			} else if packageManaged {
				// The package stays installed, and its tmpfiles.d entries
				// name the removed account: every boot logged ten
				// resolution errors and recreated empty root-owned state
				// folders (GAP-0516). An override of the same name turns
				// them off until the next install removes it.
				override := env.P(packageTmpfilesOverride)
				err := mkdirParents(filepath.Dir(override))
				if err == nil {
					err = env.writeFileAtomic(override, []byte(packageTmpfilesOverrideText), 0o644, rootOwner())
				}
				if err != nil {
					r.AddWarning(codeAccount, fmt.Sprintf("could not turn off the package's tmpfiles.d entries for the removed account: %v; the next boot logs that it cannot resolve %s", err, env.Layout.ServiceUser))
				}
			}
		}
		if l.sandboxStoreKept && !l.opts.KeepServiceAccount && !l.serviceAccountKept {
			// The account that owned the kept registrations is gone.
			if err := env.handSandboxStoreToRoot(); err != nil {
				r.AddWarning(codeLeftovers, fmt.Sprintf("could not hand the kept sandbox registrations in %s to root: %v; before the next ensure run `chown -R root:root %s`",
					env.Layout.DataDir, err, env.Layout.DataDir))
			}
		}
		if l.policiesKept && !l.opts.KeepServiceAccount && !l.serviceAccountKept {
			// The kept policies folder was root:<service group> 0750, and that
			// group is gone: a group created later with its id would read
			// it, and the account a reinstall creates could not reach the
			// packs below it, so the re-enable refused them. It goes back to
			// root, traversable, as an administrator stages it.
			kept := env.P(env.Layout.PolicyDir)
			err := fmt.Errorf("%s is not a directory", env.Layout.PolicyDir)
			if info, statErr := os.Lstat(kept); statErr != nil {
				err = statErr
			} else if info.IsDir() { // never through a symlink
				err = errors.Join(env.Lchown(kept, 0, 0), os.Chmod(kept, 0o751))
			}
			if err != nil {
				r.AddWarning(codeLeftovers, fmt.Sprintf("could not hand %s back to root: %v; before the next ensure run `chown root:root %s` and `chmod 0751 %s`",
					env.Layout.PolicyDir, err, env.Layout.PolicyDir, env.Layout.PolicyDir))
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
	if (l.opts.KeepState || l.sandboxStoreKept) && record != nil {
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
// On macOS it names Full Disk Access only when removeErr says that was the
// cause (errNoFullDiskAccess); any other refusal gets just the commands.
func serviceAccountDeleteCommand(goos, name string, removeErr error) string {
	if goos == "darwin" {
		commands := "`sudo dscl . -delete /Users/" + name + "` and `sudo dscl . -delete /Groups/" + name + "`"
		if errors.Is(removeErr, errNoFullDiskAccess) {
			commands += ", from a Terminal or an MDM script that has Full Disk Access (System Settings > Privacy & Security > Full Disk Access, or a PPPC profile); an ssh session without it is refused the same way"
		}
		return commands
	}
	return "`sudo userdel " + name + "`"
}

// restoreUninstallServices puts back the units an uninstall stopped, as
// they were before it (wasActive, wasEnabled), in activation order, the way
// a rollback does, and waits for the gateway. It returns what it could not
// restore.
func (l *lifecycle) restoreUninstallServices(ctx context.Context, units []Unit, wasActive, wasEnabled map[string]bool) []string {
	env := l.env
	ordered := append([]Unit{}, units...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Stage < ordered[j].Stage })
	var failed []string
	for _, unit := range ordered {
		if wasEnabled[unit.Name] {
			if err := env.Services.Enable(ctx, unit); err != nil {
				failed = append(failed, fmt.Sprintf("enable %s: %v", unit.Name, err))
			}
		}
		// The run itself, and a queued apply run that waits for this one.
		if !wasActive[unit.Name] || unit.Name == env.SelfUnit || unit.Name == unitApplyService {
			continue
		}
		if err := env.Services.Start(ctx, unit); err != nil {
			failed = append(failed, fmt.Sprintf("start %s: %v", unit.Name, err))
			continue
		}
		if unit.Kind == "gateway" {
			if err := l.waitGatewayReady(ctx, unit); err != nil {
				failed = append(failed, err.Error())
			}
		}
	}
	return failed
}

// uninstallSummary says what a completed uninstall removed and kept, like
// the change list of ensure and repair. A bare "uninstall: done" did not
// tell the administrator what happened to the machine state or to the
// users' own data (GAP-1227).
func (l *lifecycle) uninstallSummary(record *Deployment) []string {
	env, r := l.env, l.result
	layout := env.Layout
	removed := "stopped and removed the DefenseClaw services, binaries and deployment record"
	if l.failedInstallLeftovers {
		removed = "no deployment was committed (the package install failed); removed what that install left"
	} else if l.packageManaged {
		removed = "stopped and removed the DefenseClaw services and deployment record (the package manager removes the package's files)"
	}
	lines := []string{removed}
	if len(l.kernelRemoved) > 0 {
		lines = append(lines, kernelPolicyChange(l.kernelRemoved))
	}
	if l.perUserRemoved > 0 {
		lines = append(lines, fmt.Sprintf("removed %d DefenseClaw per-user hook registrations from the enrolled accounts", l.perUserRemoved))
	}
	if len(r.MachinePolicy) > 0 {
		lines = append(lines, "removed DefenseClaw's machine policy entries for "+strings.Join(sortedKeys(r.MachinePolicy), ", "))
	}
	state := fmt.Sprintf("the managed config and secrets (%s), the gateway and guardian state (%s, %s), the logs (%s)",
		layout.ConfigDir, layout.DataDir, layout.GuardianAuthDir, layout.LogDir)
	if l.sandboxStoreKept {
		state = fmt.Sprintf("the managed config and secrets (%s), the gateway and guardian state (%s except its sandbox registrations and their key, which stay, %s), the logs (%s)",
			layout.ConfigDir, layout.DataDir, layout.GuardianAuthDir, layout.LogDir)
	}
	lifecycleState := "the lifecycle state (" + layout.LifecycleDir + ")"
	if l.openshellRecordKept {
		lifecycleState = "the lifecycle state (" + layout.LifecycleDir + " except the record of the sandbox setup the kept sandboxes were made under, " +
			filepath.Join(layout.LifecycleDir, openshellKeptStateFile) + ")"
	}
	switch {
	case l.opts.KeepState:
		lines = append(lines, "kept for a reinstall: "+state+" and the service account "+layout.ServiceUser)
		if l.floorCheckerKept {
			lines = append(lines, "kept a root-only copy of the gateway in "+filepath.Join(layout.LifecycleDir, floorCheckerDir)+": the scripts of a 1.0.4 or later package run its release floor check of the confirmed policy bundle before a reinstall replaces any file; "+olderPackageFloorLimit)
		}
		if l.openshellRecordKept {
			lines = append(lines, "kept the record of the sandbox setup the kept sandboxes were made under in "+layout.LifecycleDir)
		}
	case l.opts.KeepServiceAccount:
		lines = append(lines, "removed the machine state: "+state+" and "+lifecycleState+"; kept the service account "+layout.ServiceUser)
	case l.serviceAccountKept:
		lines = append(lines, "removed the machine state: "+state+" and "+lifecycleState+"; the service account "+layout.ServiceUser+" stays (see the warning)")
	default:
		lines = append(lines, "removed the machine state: "+state+", "+lifecycleState+" and the service account "+layout.ServiceUser)
	}
	if l.policiesKept {
		// A package host keeps its binaries, so ensure --from-package turns
		// the deployment on again; a payload uninstall removed them, so the
		// re-enable is a payload install with the same config.
		reenable := "`" + env.lifecycleCommand(ActionEnsure) + " --from-package --config <file>` with the same config turns the deployment on again"
		if !l.packageManaged {
			reenable = "installing the payload again with the same config, `<payload>/" + binGateway + " enterprise linux ensure --payload <payload> --config <file>`, turns the deployment on again"
		}
		lines = append(lines, "kept the administrator policies in "+layout.PolicyDir+" (custom rule packs and Rego), so "+reenable+"; --purge removes them")
	}
	if kept := l.keptSandboxStoreLine(); kept != "" {
		lines = append(lines, kept)
	}
	if !l.opts.Purge {
		if kept := l.keptPerUserLine(record); kept != "" {
			lines = append(lines, kept)
		}
	}
	return lines
}

// removeAllExcept removes dir, or, when keep is a direct child of dir that
// is a directory, not a symlink to one, with a file somewhere below it,
// everything in dir but keep. The folders below keep that hold no file go,
// as does a keep with none (the empty folder the install created, or
// folders staged for a rule pack that never got one): left behind, an empty
// pack folder makes a later re-enable refuse it (GAP-1582). It reports
// whether keep stayed.
func removeAllExcept(dir, keep string) (bool, error) {
	if info, err := os.Lstat(keep); filepath.Dir(keep) != dir || err != nil || !info.IsDir() || !pruneEmptyDirs(keep) {
		return false, os.RemoveAll(dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	var errs []error
	for _, entry := range entries {
		if path := filepath.Join(dir, entry.Name()); path != keep {
			errs = append(errs, os.RemoveAll(path))
		}
	}
	return true, errors.Join(errs...)
}

// pruneEmptyDirs removes, deepest first, every directory in the tree at
// root, root included, that holds no file. A file, a symlink or an entry it
// cannot read keeps its directory and the directories above it. It reports
// whether root is still there.
func pruneEmptyDirs(root string) bool {
	info, err := os.Lstat(root)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	if !info.IsDir() {
		return true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return true
	}
	held := false
	for _, entry := range entries {
		if !entry.IsDir() || pruneEmptyDirs(filepath.Join(root, entry.Name())) {
			held = true
		}
	}
	return held || os.Remove(root) != nil
}

// recordPackageResult keeps the result of an `ensure --from-package` run
// outside the package's own install script (an administrator finishing the
// install or applying a rollback, the MDM wrapper) in
// last-package-result.json, which the install script writes for its own
// run. After a refused package apply the file kept ok: false for the newer
// build while the deployment was healthy again (GAP-1116).
func (l *lifecycle) recordPackageResult(failure int) {
	env := l.env
	result := *l.result
	result.Warnings = uniqueMessages(result.Warnings)
	result.Finish(env.GOOS, failure)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(env.P(env.Layout.LifecycleDir), lastPackageResultFile)
	if err := env.writeFileAtomic(path, append(data, '\n'), 0o600, rootOwner()); err != nil {
		l.result.AddWarning(stateWriteCode(err, codeState), "could not record this run in "+filepath.Join(env.Layout.LifecycleDir, lastPackageResultFile)+": "+err.Error())
	}
}

// refuseUnresolvedPerUserRows asks `enterprise hooks remove-all --check`,
// before any service stops or policy goes, whether every manifest row and
// every pending guardian cleanup can be removed. A failed command or incomplete report also refuses the uninstall:
// manifest parse and trust errors have no per-row failures to report.
func (l *lifecycle) refuseUnresolvedPerUserRows(ctx context.Context) bool {
	env, r := l.env, l.result
	out, commandErr := env.runGatewayCLI(ctx, "enterprise", "hooks", "remove-all", "--manifest", env.Layout.ManifestPath, "--json", "--check")
	var report struct {
		OK      bool     `json:"ok"`
		Pending []string `json:"pending"`
		Failed  []string `json:"failed"`
	}
	parseErr := json.Unmarshal(out.Stdout, &report)
	refused := false
	if parseErr == nil {
		for _, entry := range report.Failed {
			user, connector, reason, ok := cutPerUserEntry(entry)
			if !ok {
				continue
			}
			// The check also names the guardian's pending cleanups of
			// accounts the manifest no longer names (GAP-2377).
			r.AddError(codePerUserHooks, fmt.Sprintf("the %s hooks of user %s cannot be removed: %s; fix or remove that row in %s (for a pending guardian cleanup of an account the manifest no longer names, fix that account's home to an existing directory it owns, or remove the account) and rerun `%s`",
				connector, user, reason, env.Layout.ManifestPath, l.uninstallCommand()))
			refused = true
		}
		// A live account whose home is not available (an unmounted
		// volume) stops the removal below after it has already removed
		// what protects the other users (their hooks and Claude Code
		// blockers) and stopped the services (GAP-2358). It refuses here,
		// before anything changes. A pending entry with a reason (a home
		// that is gone, a removed account) still only warns.
		for _, entry := range report.Pending {
			user, connector, reason, ok := cutPerUserEntry(entry)
			if !ok || reason != "" {
				continue
			}
			r.AddError(codePerUserHooks, homeNotAvailableMessage(connector, user, "`"+l.uninstallCommand()+"`"))
			refused = true
		}
	}
	if commandErr == nil && parseErr == nil && report.OK && !refused {
		return false
	}
	if !refused {
		reason := "the hook-removal precheck did not succeed"
		if commandErr != nil {
			reason = commandErr.Error()
		} else if parseErr != nil {
			reason = "the hook-removal precheck returned an invalid report: " + parseErr.Error()
		}
		r.AddError(codePerUserHooks, "cannot check per-user hook removal: "+reason)
	}
	r.AddError(codeUninstallPrecheck, "nothing was changed: every service is still running and the machine policy is in place; fix the hook-removal precheck and rerun `"+l.uninstallCommand()+"`")
	return true
}

// homeNotAvailableMessage is the error for a live account whose home is not
// available, so DefenseClaw's connector registrations in it may remain and
// call the hook binary; rerun is the quoted uninstall command.
func homeNotAvailableMessage(connector, user, rerun string) string {
	return fmt.Sprintf("DefenseClaw's %s hooks for user %s were not removed because that account's home is not available, so a DefenseClaw registration may remain in it and call the hook binary; make that home available (mount its volume, or move its folder back to the recorded home if it was moved aside) and rerun %s; if that home folder was deleted, recreate it as a folder the account owns and rerun %s", connector, user, rerun, rerun)
}

// cutPerUserEntry splits a remove-all entry "user/connector: reason". The
// user part may be a home path, so the connector follows the last slash.
func cutPerUserEntry(entry string) (user, connector, reason string, ok bool) {
	label, reason, _ := strings.Cut(entry, ": ")
	i := strings.LastIndex(label, "/")
	if i < 0 {
		return "", "", reason, false
	}
	return label[:i], label[i+1:], reason, true
}

// removePerUserRegistrations runs `enterprise hooks remove-all` (with
// --purge on a purge) and reports what it could not do, one message per
// account and connector: an error for a registration that is still in
// place or in a home that is not available (GAP-0443), a warning for an
// account that was removed (with the reason remove-all gives) or whose
// per-user state stayed, and an error for a check that names no
// registration. It
// returns whether any registration is left.
func (l *lifecycle) removePerUserRegistrations(ctx context.Context) bool {
	env, r := l.env, l.result
	args := []string{"enterprise", "hooks", "remove-all", "--manifest", env.Layout.ManifestPath, "--json"}
	if l.opts.Purge {
		args = append(args, "--purge")
	}
	out, err := env.runGatewayCLILong(ctx, removeAllTimeout, args...)
	var report struct {
		OK           bool                        `json:"ok"`
		Pending      []string                    `json:"pending"`
		Failed       []string                    `json:"failed"`
		StateFailed  []string                    `json:"state_failed"`
		Purged       []string                    `json:"purged"`
		Removed      int                         `json:"removed"`
		PurgedDetail map[string]purgedUserDetail `json:"purged_detail"`
		// ClaudeHookUnblocked: the accounts whose Claude Code blocker the
		// uninstall removed (GAP-1828).
		ClaudeHookUnblocked []string `json:"claude_hook_unblocked"`
	}
	if jsonErr := json.Unmarshal(out.Stdout, &report); jsonErr != nil {
		r.AddError(codePerUserHooks, "the per-user hook removal returned an invalid report; keep the deployment and rerun `"+l.uninstallCommand()+"`")
		return true
	}
	if !report.OK && len(report.Failed) == 0 && err == nil {
		r.AddError(codePerUserHooks, "the per-user hook removal did not confirm success; keep the deployment and rerun `"+l.uninstallCommand()+"`")
		return true
	}
	l.perUserRemoved = report.Removed
	rerun := "`" + l.uninstallCommand() + "`"
	left := false
	for _, entry := range report.Failed {
		user, connector, reason, ok := cutPerUserEntry(entry)
		if !ok {
			// A check that names no registration (an unreadable eligible
			// accounts file, say) says registrations may be left, which
			// call the binaries: they stay, as for a named one. The precheck
			// refuses such a report before anything changes; one here was
			// only a warning, and the binaries went (GAP-1140).
			r.AddError(codePerUserHooks, "some per-user hook registrations were not checked: "+entry+"; fix the cause and rerun "+rerun)
			left = true
			continue
		}
		r.AddError(codePerUserHooks, fmt.Sprintf("DefenseClaw's %s hooks for user %s were not removed: %s; fix the cause; for a pending guardian cleanup, fix the account's home to an existing directory it owns, without symlinks or group/other write, or remove the account; then rerun %s", connector, user, reason, rerun))
		left = true
	}
	if err != nil && len(report.Failed) == 0 {
		r.AddError(codePerUserHooks, "the per-user hook registrations could not be removed: "+err.Error()+"; fix the cause and rerun "+rerun)
		left = true
	}
	for _, entry := range report.Pending {
		user, connector, reason, _ := cutPerUserEntry(entry)
		if reason != "" {
			// A removed account: its reason names the home and the remedy.
			r.AddWarning(codePerUserHooks, fmt.Sprintf("DefenseClaw's %s hooks for user %s were not removed: %s", connector, user, reason))
			continue
		}
		// The home of a live account is not available (an unmounted
		// volume, a home that did not answer): its registrations may still
		// be there and call the hook binary when it returns. They are kept
		// as registrations: the binaries, the deployment record and the
		// services stay, and a rerun once the home is back removes them
		// (GAP-0443; lead decision 2026-10-26 18:57).
		r.AddError(codePerUserHooks, homeNotAvailableMessage(connector, user, rerun))
		left = true
	}
	for _, entry := range report.StateFailed {
		user, reason, _ := strings.Cut(entry, ": ")
		if l.perUserStateKept == nil {
			l.perUserStateKept = map[string]bool{}
		}
		l.perUserStateKept[user] = true
		r.AddWarning(codePerUserState, fmt.Sprintf("the DefenseClaw per-user data and binaries of user %s were not removed: %s; fix the cause and rerun %s", user, reason, rerun))
	}
	// A purge deletes data an account created before the install; name each
	// account, instead of a bare "done".
	for _, user := range report.Purged {
		r.Changes = append(r.Changes, purgedUserChange(user, report.PurgedDetail[user]))
	}
	// The enrollment had replaced the account's own Claude Code hook script
	// with a blocker; the uninstall removed it, and the account's own hook
	// does not guard Claude Code until its owner sets it up again.
	for _, user := range report.ClaudeHookUnblocked {
		r.Changes = append(r.Changes, fmt.Sprintf("removed the Claude Code blocker the enrollment had written over the own DefenseClaw hook script of user %s (~/.defenseclaw/hooks/claude-code-hook.sh); that account's own Claude Code hook now reports a missing script and does not guard Claude Code until `defenseclaw setup claude-code` runs as that user", user))
	}
	return left
}

// purgedUserDetail is what the purge found and removed for one account.
type purgedUserDetail struct {
	Data     bool `json:"data"`
	Kept     bool `json:"kept"`
	Binaries bool `json:"binaries"`
	Gateway  bool `json:"gateway"`
	UVCache  bool `json:"uv_cache"`
	// RemovedConnectorBackups names the folders the OpenHands/OmniGent
	// backups were moved to instead of being deleted (GAP-2015).
	RemovedConnectorBackups string `json:"removed_connector_backups"`
}

// purgedUserChange names what the purge removed for user: only what it
// found, so an account that never had a per-user install is not said to
// have lost per-user binaries and a gateway (GAP-1444), and where the data
// of the account's own per-user install went (#1299).
func purgedUserChange(user string, detail purgedUserDetail) string {
	const data = "all DefenseClaw per-user data of user %s (~/.defenseclaw, including its hook scripts and the foreign-hooks-backup folder)"
	var text string
	if detail.Kept {
		// A machine uninstall never deletes or moves an account's own
		// data (GAP-0727, owner 2026-10-23).
		return fmt.Sprintf("kept the DefenseClaw per-user data of user %s (~/.defenseclaw) as it is: it holds the account's own DefenseClaw install from before the managed deployment (config, secrets, audit history, policies), which a machine uninstall never deletes or moves; its owner can remove it", user)
	}
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
	if detail.RemovedConnectorBackups != "" {
		text += "; the copies DefenseClaw saved of its OpenHands/OmniGent files were kept in " + detail.RemovedConnectorBackups + " (copy back what you need, then delete them)"
	}
	return text
}

// uninstallCommand is this run's uninstall command line, for a rerun.
// stopCommands is what an administrator runs to stop the named units by
// hand: one systemctl stop for all of them, or on macOS one launchctl
// bootout per launchd job.
func (e *Env) stopCommands(units []string) string {
	if e.GOOS != "darwin" {
		return "`systemctl stop " + strings.Join(units, " ") + "`"
	}
	commands := make([]string, 0, len(units))
	for _, unit := range units {
		commands = append(commands, "`launchctl bootout system/"+unit+"`")
	}
	return strings.Join(commands, ", ")
}

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
