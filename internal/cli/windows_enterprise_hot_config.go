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

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	gwconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A config-only ensure used to run the whole upgrade transaction: it stops
// every service, replaces the payload, validates and starts them again,
// which took about 130 seconds, during which the gateway was down and every
// agent failed closed (GAP-0135). A change the running gateway applies as a
// generation swap (P0 spec section 4) needs none of that. The gateway
// follows config.yaml, so the lifecycle replaces the file under the writer
// lock, with its access control kept, and waits until /health reports the
// policy the installed config computes to. Any doubt (a key the gateway
// reads once at start, a config_version 8 file, a busy lifecycle lock, a
// config that does not validate, a gateway that does not adopt the change,
// a verify that fails) puts the previous config back. A signed bundle does
// not fall through to the all-service upgrade transaction after a failed
// config apply.

// windowsEnterpriseHotConfigMaxBytes bounds the config read for the check.
const windowsEnterpriseHotConfigMaxBytes = 4 << 20

// Seams for tests. The timeout bounds how long the running gateway gets to
// report the policy the new config computes to.
var (
	windowsEnterpriseHotConfigTimeout        = 30 * time.Second
	windowsEnterpriseHotConfigRestartTimeout = 2 * time.Minute
	windowsEnterpriseHotConfigLayout         = windowsManagedStandaloneLayout
	windowsEnterpriseHotConfigLock           = acquireWindowsEnterpriseLifecycleLock
	windowsEnterpriseHotConfigValidate       = validateWindowsServiceConfig
	windowsEnterpriseHotConfigPoll           = 2 * time.Second
	windowsEnterpriseHotConfigWrite          = func(ctx context.Context, path string, raw []byte, opt configwrite.Options) error {
		_, err := configwrite.ReplaceDocument(ctx, path, raw, opt)
		return err
	}
	// The upgrade transaction admits --config only from a source that only
	// SYSTEM, Administrators and TrustedInstaller can write
	// (Assert-DefenseClawTrustedSource), as Setup CONFIG= does
	// (ValidateTrustedFilePath). The hot path checks the same, so whether a
	// standard user's edit is installed does not depend on which keys it
	// changed (GAP-0312).
	windowsEnterpriseHotConfigSourceCheck  = managed.ValidateTrustedConfigPath
	windowsEnterpriseHotConfigRestart      = restartWindowsStandaloneGateway
	windowsEnterpriseHotConfigRecover      = startWindowsStandaloneGatewayIfStopped
	windowsEnterpriseHotBundleReload       = reloadWindowsStandaloneBundlePolicy
	windowsEnterpriseHotConfigCloseHooks   = enterprisehooks.CloseWindowsStandaloneHooksForUnprovenUndo
	windowsEnterpriseHotConfigHooksHeld    = enterprisehooks.WindowsStandaloneHooksHeldClosed
	windowsEnterpriseHotConfigReleaseHooks = enterprisehooks.ReleaseWindowsStandaloneHookClosure
	// windowsEnterpriseHotConfigFailClosed stops the gateway after an undo
	// that could not be proven, once its hooks are durably closed.
	windowsEnterpriseHotConfigFailClosed = stopWindowsStandaloneGatewayFailClosed
	// windowsEnterpriseHotConfigApproveSource makes the config this ensure
	// applied the approved config source Repair restores (GAP-0779).
	windowsEnterpriseHotConfigApproveSource = approveWindowsStandaloneConfigSource
)

// approveWindowsStandaloneConfigSource records the installed config.yaml as
// the approved config source of the layout, in the protected install state
// folder (refreshManagedApprovedConfigSource).
func approveWindowsStandaloneConfigSource(layout managed.StandaloneLayout) error {
	installed, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return fmt.Errorf("read the installed config: %w", err)
	}
	return refreshManagedApprovedConfigSource(layout.LifecycleDir, layout.ConfigPath, installed)
}

// windowsEnterpriseHealApprovedSource is the check at the end of a lifecycle
// run that an approved config source an earlier build left stale does not
// outlive it (GAP-0779); tests replace it.
var windowsEnterpriseHealApprovedSource = healWindowsStandaloneApprovedConfigSource

// healWindowsStandaloneApprovedConfigSource puts the config a finished
// lifecycle run accepted into the approved config source when the deployment
// records one that differs: a binary-only upgrade, a repeat of the installed
// CONFIG= or a repair publishes none, so an older approved copy would
// otherwise survive and a Repair after a hand edit would restore it. It
// publishes only bytes config.generation.json binds to a lifecycle write, and
// the caller runs it last, after every proof of the run, so a run that fails
// later never changed the source. A signed-bundle deployment is left alone
// (Repair refuses it, and Setup approved copy is not proof of the bundle
// bytes). A source that is stale and cannot be refreshed fails the run: it
// must not report success while Repair could restore an older config.
func healWindowsStandaloneApprovedConfigSource(result *enterprisestatus.Result) {
	if !windowsEnterpriseIsElevated() {
		return
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil || layout.LifecycleDir == "" {
		return
	}
	// Only a deployment that records an approved config source has one to
	// heal; check before taking the lock so a host without one is untouched.
	if _, err := os.Stat(filepath.Join(layout.LifecycleDir, managedDeploymentRecordFile)); err != nil {
		return
	}
	if windowsStandaloneBundleStoreHoldsVersions(layout) {
		return
	}
	changed, err := healManagedApprovedConfigSourceBound(layout.LifecycleDir, layout.ConfigPath, func() (func(), error) {
		// layout.LifecycleDir is the install state folder (deployment.json and
		// the approved copy); the lock is in the lifecycle root (GAP-0854).
		lockPath, err := windowsStandaloneLifecycleLockPath()
		if err != nil {
			return nil, err
		}
		release, err := windowsEnterpriseHotConfigLock(lockPath)
		if windowsLifecycleLockBusy(err) {
			return nil, errManagedApprovedSourceBusy
		}
		return release, err
	})
	switch {
	case errors.Is(err, errManagedApprovedSourceBusy):
		result.AddError("lifecycle_busy", "another DefenseClaw lifecycle run holds lifecycle.lock, so the approved config source, which differs from the installed config, was not refreshed and "+
			windowsEnterpriseSetupCommand("/repair", "JSON=1")+" after a hand edit could restore an older config; the run can be retried."+windowsEnterpriseSetupSourceNote)
	case err != nil:
		result.AddError("approved_config_source_stale", "the approved config source differs from the installed config and could not be refreshed ("+
			windowsEnterpriseBoundedDiagnostic(err.Error())+"); "+windowsEnterpriseSetupCommand("/repair", "JSON=1")+" after a hand edit could restore an older config. Next step: run "+
			windowsEnterpriseSetupCommand("/ensure", "CONFIG=<approved absolute config path>", "JSON=1")+" from an elevated PowerShell prompt."+windowsEnterpriseSetupSourceNote)
	case changed:
		result.Changes = append(result.Changes, "refreshed the approved config source to the installed config, which an earlier release had left at an older config")
	}
}

// windowsStandaloneLifecycleLockPath is the lifecycle.lock every standalone
// lifecycle run holds. It lives in the lifecycle root (roots.LifecycleDir,
// ProgramData\Cisco\DefenseClaw-Lifecycle), not in the install state folder
// (layout.LifecycleDir, ProgramData\Cisco\DefenseClaw\install) that holds
// deployment.json and the approved config copy. The approved source check
// built the lock path from the second folder, where no lock file exists, so
// the proof of an up-to-date copy was never written after a Repair, a restart
// ensure or a no-op ensure and the next Repair over a hand edit was refused
// (GAP-0854).
func windowsStandaloneLifecycleLockPath() (string, error) {
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		return "", fmt.Errorf("resolve the lifecycle lock folder: %w", err)
	}
	return filepath.Join(roots.LifecycleDir, "lifecycle.lock"), nil
}

// refuseWindowsEnterpriseRepairOverUnprovenApprovedSource stops a Repair that
// would put the approved config source over a hand-edited config.yaml when
// nothing proves that source is the config the last lifecycle run applied. The
// installer restores it before any Go code runs again, and a release that
// applied configs in place left the copy at an older config with a matching
// digest, so the check has to come first (GAP-0779). It acts only on a
// standalone repair of an installed deployment that supplies no config of its
// own, has stored no signed bundle (the installer refuses those and names the
// CLI repair) and has no recovery pending; everything else is left to the
// installer. The first ensure, upgrade, install or repair of this release
// writes the proof, so the refusal names an ensure.
func refuseWindowsEnterpriseRepairOverUnprovenApprovedSource(action string, opts *windowsEnterpriseLifecycleOptions) error {
	if action != "repair" || !windowsEnterpriseStandalone(opts) || strings.TrimSpace(opts.configPath) != "" ||
		strings.TrimSpace(opts.stateRoot) != "" || opts.bundle != nil {
		return nil
	}
	deployment, err := windowsEnterpriseTargetDeployment(opts)
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || windowsEnterpriseStandaloneRecoveryPending(opts) {
		return nil
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil || layout.LifecycleDir == "" || windowsStandaloneBundleStoreHoldsVersions(layout) {
		return nil
	}
	if err := unprovenApprovedConfigSourceForHandEdit(layout.LifecycleDir, layout.ConfigPath); err != nil {
		return windowsEnterpriseInvalidArguments("%s; the earlier approved config may be older than the one now installed. Next step: run %s "+
			"from an elevated PowerShell prompt with the approved config (nothing was changed)%s",
			err.Error(), windowsEnterpriseSetupCommand("/ensure", "CONFIG=<approved absolute config path>", "JSON=1"), windowsEnterpriseSetupSourceNote)
	}
	return nil
}

// windowsStandaloneBundleStoreHoldsVersions is whether the deployment ever
// stored a signed policy bundle (a non-empty etc\bundles folder, as the
// installer checks). An unreadable folder counts as holding versions.
func windowsStandaloneBundleStoreHoldsVersions(layout managed.StandaloneLayout) bool {
	entries, err := os.ReadDir(filepath.Join(layout.ConfigDir, "bundles"))
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	return len(entries) > 0
}

// Seams for the approved-source rewrite (GAP-0590). Tests replace them.
var (
	// windowsEnterpriseInstalledLeafDrift is the standalone verdict on a
	// managed content file when only the file itself, not a folder above it,
	// has an untrusted owner or writer.
	windowsEnterpriseInstalledLeafDrift = managed.StandaloneFileLeafDrift
	// windowsEnterpriseManifestSourceCheck admits MANIFEST= only from a file
	// that only SYSTEM, Administrators and TrustedInstaller can write, as the
	// transaction does (Assert-DefenseClawTrustedSource).
	windowsEnterpriseManifestSourceCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "supplied hook guardian manifest")
	}
	windowsEnterpriseApprovedManifestStager = stageWindowsEnterpriseEnsureManifest
)

// reloadWindowsStandaloneBundlePolicy asks the installed gateway to load the
// config now. A Windows directory notification can be lost during an atomic
// config replacement; the bundle must not depend on that notification for
// activation. The adoption check below remains the authority if this request
// fails or races with the file watcher.
func reloadWindowsStandaloneBundlePolicy(ctx context.Context, layout managed.StandaloneLayout) error {
	installedCLI, err := windowsEnterpriseInstalledAdminCLI()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, installedCLI, "policy", "reload")
	command.Env = windowsEnterpriseEnvironmentWith(os.Environ(), windowsEnterpriseServicePins(layout))
	out, err := command.CombinedOutput()
	if err != nil {
		if detail := strings.TrimSpace(string(out)); detail != "" {
			return fmt.Errorf("policy reload: %w: %s", err, windowsEnterpriseBoundedDiagnostic(detail))
		}
		return fmt.Errorf("policy reload: %w", err)
	}
	return nil
}

// windowsEnterpriseServicePins are the environment pins the gateway service
// starts with. Any process that loads the managed config as the service
// does must carry all five: without them an administrator or SYSTEM is
// refused by the managed-host guard, and without the service account the
// protected credentials the config references are not trusted.
func windowsEnterpriseServicePins(layout managed.StandaloneLayout) map[string]string {
	return map[string]string{
		managed.ConfigPathEnv:            layout.ConfigPath,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: layout.ServiceUser,
		"DEFENSECLAW_HOME":               layout.DataDir,
	}
}

// windowsEnterpriseEnvironmentWith returns base with the pins set,
// replacing any entry of the same name (Windows names are case-insensitive).
func windowsEnterpriseEnvironmentWith(base []string, pins map[string]string) []string {
	environment := make([]string, 0, len(base)+len(pins))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		replaced := false
		for pin := range pins {
			if strings.EqualFold(name, pin) {
				replaced = true
				break
			}
		}
		if !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range pins {
		environment = append(environment, name+"="+value)
	}
	return environment
}

// windowsEnterpriseHotConfigCandidate reports whether this ensure is the
// production deployment's config-only change: a healthy, idle deployment, a
// supplied config, and nothing else asked for.
func windowsEnterpriseHotConfigCandidate(opts *windowsEnterpriseLifecycleOptions, status *windowsEnterpriseInstallerReport) bool {
	return windowsEnterpriseIsElevated() &&
		opts.coworkPackagePath == "" && opts.coworkSignaturePath == "" &&
		windowsEnterpriseVerifyAcceptable(status) &&
		strings.TrimSpace(opts.configPath) != "" &&
		strings.TrimSpace(opts.manifestPath) == "" && strings.TrimSpace(opts.mode) == "" && strings.TrimSpace(opts.connector) == "" &&
		!opts.noStart && strings.TrimSpace(opts.installRoot) == "" && strings.TrimSpace(opts.stateRoot) == "" &&
		strings.TrimSpace(opts.gatewayServiceName) == "" && strings.TrimSpace(opts.guardianServiceName) == ""
}

// windowsEnterpriseInstallOptionsChanged is the hot-path refusal of a run
// that also changes the install options. A bundle has no transaction
// fallback, and a retry of the same delivery is refused the same way, so it
// has its own code that exits 1603, not 1618.
const windowsEnterpriseInstallOptionsChanged = "the run also changes the install options (manifest, mode, connector, roots or service names)"

// windowsEnterpriseHotConfigUnavailable names the candidate condition a
// bundle delivery failed: the hot path needs an elevated, healthy, idle
// deployment.
func windowsEnterpriseHotConfigUnavailable(status *windowsEnterpriseInstallerReport) string {
	switch {
	case !windowsEnterpriseIsElevated():
		return "the lifecycle is not elevated"
	case status == nil:
		return "the installed deployment status could not be read"
	case !windowsEnterpriseVerifyAcceptable(status):
		return "the installed deployment did not verify healthy and idle: " + windowsEnterpriseVerifyFailureDetail(status, "")
	}
	return windowsEnterpriseInstallOptionsChanged
}

// windowsBundleTakeOverPendingCommit installs a signed bundle whose rendered
// config is byte-identical to the installed config a lower delivery
// committed and the gateway has not confirmed (a version bump that changes no
// setting, delivered during a gateway outage). The hot path needs a healthy
// deployment because it changes what the gateway enforces; this changes
// nothing the gateway reads but the generation record, so it runs without
// one: the run records its own generation for the same bytes under the
// lifecycle lock, its receipt stays applied until the gateway reports it,
// and the lower receipt then settles superseded (GAP-1187). It reports
// whether the run was that case and the record was written; otherwise the
// caller refuses as before.
func windowsBundleTakeOverPendingCommit(ctx context.Context, opts *windowsEnterpriseLifecycleOptions, result *enterprisestatus.Result) bool {
	run := opts.bundle
	if run == nil || run.prepared == nil || run.prepared.Receipt == nil || run.prepared.AlreadyApplied || run.driver == nil || !windowsEnterpriseIsElevated() {
		return false
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return false
	}
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		return false
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return false
	}
	defer release()
	installed, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return false
	}
	owner, err := run.driver.PendingCommitTakenOver(run.prepared.Receipt, installed)
	if err != nil || owner == nil {
		return false
	}
	writeOptions, _, err := windowsHotConfigWriteOptions(opts, configwrite.SHA256Hex(installed))
	if err != nil {
		return false
	}
	restoreEnvironment := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer restoreEnvironment()
	if err := windowsEnterpriseHotConfigWrite(ctx, layout.ConfigPath, installed, writeOptions); err != nil {
		return false
	}
	result.Readiness.Gateway = false
	result.SecurityComplete = false
	result.Policy = nil
	result.Changes = append(result.Changes, fmt.Sprintf(
		"recorded policy bundle %s version %d for the installed config, which version %d had committed with the same settings and the gateway had not confirmed; no setting changed, and gateway adoption is unconfirmed",
		run.prepared.Receipt.BundleID, run.prepared.Receipt.Version, owner.Version))
	return true
}

// windowsEnterpriseHotConfigApply applies the supplied config to the running
// gateway and fills result from a verify of the host. For a signed bundle,
// start-only keys restart only the gateway. An ordinary CONFIG= change whose
// start-only keys are all guardian-rendered machine policy
// (windowsEnterpriseGuardianRestartPaths) restarts only the hook guardian and
// then the gateway (GAP-0044); any other start-only key uses the upgrade
// transaction. It returns false after attempting to restore the old config on
// failure, with the start-only keys the transaction then applies.
func windowsEnterpriseHotConfigApply(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	status *windowsEnterpriseInstallerReport,
	result *enterprisestatus.Result,
) (appliedHot bool, transactionKeys []string) {
	// A signed bundle has no transaction fallback: the caller fails it with
	// bundle_apply_failed. Each refusal of a bundle says why, so a failed
	// first apply names its cause and a held lock is retried (GAP-0104).
	bundleChange := opts.bundle != nil && windowsBundleConfigChange(opts.bundle.prepared)
	payloadlessRollback := windowsBundleRollbackWithoutPayload(opts)
	opts.codexTargetTransaction = false
	opts.hotConfigRestoreFailed = false
	failBundle := func(code, message string) {
		switch {
		case bundleChange:
			result.AddError(code, message)
		case payloadlessRollback:
			// The rollback has no transaction fallback either: its result
			// (in the lifecycle log) names why the last good config is not back.
			result.AddError(code, "bundle rollback: "+message)
		}
	}
	unavailable := func(reason string) (bool, []string) {
		failBundle("bundle_hot_apply_unavailable", "the policy bundle could not be applied to the running deployment: "+windowsEnterpriseBoundedDiagnostic(reason))
		return false, nil
	}
	if !windowsEnterpriseHotConfigCandidate(opts, status) {
		reason := windowsEnterpriseHotConfigUnavailable(status)
		if reason == windowsEnterpriseInstallOptionsChanged {
			failBundle("bundle_install_options_changed", "the policy bundle could not be applied to the running deployment: "+reason+"; deliver the bundle without the install option change")
			return false, nil
		}
		if bundleChange && windowsBundleTakeOverPendingCommit(ctx, opts, result) {
			return true, nil
		}
		return unavailable(reason)
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return unavailable("cannot resolve the standalone layout: " + err.Error())
	}
	// An untrusted source goes to the transaction, which refuses it and
	// says why.
	if err := windowsEnterpriseHotConfigSourceCheck(opts.configPath); err != nil {
		return unavailable("the staged config failed its source check: " + err.Error())
	}
	next, err := readWindowsEnterpriseBoundedFile(opts.configPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return unavailable("cannot read the staged config: " + err.Error())
	}
	if config.NeedsMigrationV9(next) {
		return unavailable("the staged config needs a config_version migration")
	}
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		return unavailable("cannot resolve the trusted enterprise roots: " + err.Error())
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			failBundle("lifecycle_busy", "another DefenseClaw lifecycle run holds lifecycle.lock; the policy bundle was not applied and the run can be retried")
			return false, nil
		}
		return unavailable("cannot open lifecycle.lock: " + err.Error())
	}
	defer release()

	// Status and the installed bytes may have changed while this call waited
	// for lifecycle.lock. Snapshot only after acquiring it; rollback must
	// restore the configuration this attempt actually replaced (GAP-0492,
	// GAP-0493).
	previous, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return unavailable("cannot read the installed config: " + err.Error())
	}
	if config.NeedsMigrationV9(previous) {
		return unavailable("the installed config needs a config_version migration")
	}
	previousFleet, previousFleetErr := config.FleetEnabledFromSource(layout.ConfigPath, previous)
	nextFleet, nextFleetErr := config.FleetEnabledFromSource(opts.configPath, next)
	if err := errors.Join(previousFleetErr, nextFleetErr); err != nil {
		return unavailable("cannot read the Fleet setting of the staged or installed config: " + err.Error())
	}
	if previousFleet != nextFleet {
		// Fleet enablement changes the installed compiler as well as the
		// gateway config. A signed bundle has no compiler payload, and even
		// restarting the gateway cannot perform that lifecycle transaction.
		// Setup falls through to its full Upgrade; a bundle fails before any
		// config write so the administrator can apply it through Setup.
		if bundleChange {
			result.AddError("fleet_setup_required", "Fleet enablement changes require signed standalone Setup to install or remove the compiler; installed config and services were not changed")
		}
		return false, nil
	}
	changed, err := configwrite.ChangedPaths(previous, next)
	if err != nil {
		return unavailable("cannot compare the staged and installed configs: " + err.Error())
	}
	if bytes.Equal(previous, next) && !bundleChange {
		return unavailable("the staged config is byte-identical to the installed config")
	}
	// Turning Codex protection on or off is the lifecycle transaction's:
	// it owns Codex's machine policy. Nothing is written here, so the
	// guardian never writes the Codex requirements for a deployment record
	// that does not attest them (GAP-0033).
	if windowsConfigCodexTargetChanged(previous, next) {
		opts.codexTargetTransaction = true
		return false, nil
	}
	// A file that changes no setting (line endings, comments, formatting)
	// is installed the same way: the gateway reloads it to the same policy
	// (GAP-0601). Who is enrolled and which connectors are is applied too:
	// the gateway reads neither at start on Windows, and the targets are
	// refreshed below (GAP-0716).
	restart, err := configwrite.ManagedConfigRestartRequired(previous, next, configwrite.ManagedDefaultsFor(layout))
	if err != nil {
		return unavailable("cannot classify the config change: " + err.Error())
	}
	startOnly, refreshTargets := windowsBundleStartOnlyPaths(restart)
	startOnly = append(startOnly, configwrite.PrimaryConnectorChange(previous, next)...)
	// A bundle rollback by the installed CLI has no payload for the upgrade
	// transaction: it restarts only the gateway, as the bundle it undoes did.
	gatewayOnlyRestart := bundleChange || payloadlessRollback
	// A plain config change whose start-only keys the hook guardian renders
	// at machine scope restarts the guardian, then the gateway, instead of
	// every service in the upgrade transaction (GAP-0044).
	guardianRestart := !gatewayOnlyRestart && windowsEnterpriseGuardianRestartPaths(startOnly)
	if len(startOnly) > 0 && !gatewayOnlyRestart && !guardianRestart {
		return false, startOnly
	}
	if guardianRestart {
		// A restart that does not complete leaves the keys to the upgrade
		// transaction, which names them.
		defer func() {
			if !appliedHot && transactionKeys == nil {
				transactionKeys = startOnly
			}
		}()
	}

	restoreEnvironment := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer restoreEnvironment()

	generationPath := configwrite.GenerationPath(layout.ConfigPath)
	_, generationErr := os.Stat(generationPath)
	state, stateErr := configwrite.ReadGenerationState(layout.ConfigPath)
	recordedBefore := stateErr == nil && strings.EqualFold(state.ConfigSHA256, configwrite.SHA256Hex(previous))
	connectorChangeStartedAt := time.Now().UTC()
	// A bundle config is adopted only once the gateway names the bundle the
	// record names, including a repeated delivery of the confirmed bundle,
	// which has no receipt.
	writeOptions, adoptedBundle, err := windowsHotConfigWriteOptions(opts, configwrite.SHA256Hex(previous))
	if err != nil {
		failBundle("bundle_state_invalid", "cannot prove the signed config principal: "+windowsEnterpriseBoundedDiagnostic(err.Error()))
		return false, nil
	}
	// Adoption and undo both depend on the installed CLI's policy report.
	// Check that it can run and report the policy currently enforced before
	// changing config.yaml. A confirmed bundle replay repairs config drift,
	// so its installed digest can differ from the live one; its signed bundle
	// identity and post-write adoption are still proved below. Other changes
	// require the installed and live policies to agree before publication.
	proof, err := windowsEnterprisePolicyDigest(ctx)
	if err != nil {
		return unavailable("the installed CLI cannot prove the running gateway's policy: " + err.Error())
	}
	var priorPolicy policyDigestReport
	confirmedReplay := bundleChange && opts.bundle.prepared != nil && opts.bundle.prepared.AlreadyApplied
	if json.Unmarshal(proof, &priorPolicy) != nil || priorPolicy.Digest == "" ||
		priorPolicy.GatewayReportedDigest == "" ||
		(priorPolicy.Digest != priorPolicy.GatewayReportedDigest && !confirmedReplay) {
		return unavailable("the installed CLI did not prove that the gateway enforces the installed config")
	}
	kept := keepWindowsEnterpriseEditedConfig(layout, previous)
	// Undoing puts the config back. A config the record named is recorded
	// again as a new generation: the counter never goes back, because the
	// gateway may already have reported the number the attempt took. A hand
	// edit stays unrecorded, and a record the attempt created goes away.
	// Targets this attempt published for the new config are published again
	// for the restored one, so a user the new config dropped is enrolled
	// again (GAP-1494). A gateway this attempt restarted is restarted on the
	// restored config, and so is one whose restart failed, since what it
	// runs now is not known. Every other gateway is asked to reload. Every
	// undo then proves the gateway reports the restored config's policy: a
	// gateway can load the new config without the adoption check proving
	// it (the file watcher follows config.yaml, a bundle sends a reload
	// request first, and the check also fails on the generation or the
	// bundle identity), so a failed adoption check says nothing about which
	// policy is live (review loop round 4). A restore that cannot be proven
	// (the bytes, the targets or the gateway's policy) stops the gateway,
	// so no hook is decided by a policy no one verified, reports what is
	// really installed, and stops the run: the upgrade transaction would
	// otherwise snapshot the config this attempt left behind as its
	// preimage (GAP-1178, review loop round 3).
	targetsRefreshed := false
	// The targets published before this attempt refreshed them: an undo
	// whose enumerator cannot publish the restored config's targets puts
	// exactly these back (GAP-0847).
	var publishedBefore windowsHotConfigPublishedTargets
	gatewayRestartAttempted := false
	// The guardian rendered the candidate's machine policy once this is set:
	// an undo restarts it on the restored config and proves that too.
	guardianRestartAttempted := false
	gatewayOnNewConfig := func() bool {
		return gatewayRestartAttempted || (opts.bundle != nil && opts.bundle.gatewayRestarted)
	}
	undo := func() {
		restoreCtx := context.WithoutCancel(ctx)
		var restoreErr error
		// A candidate that opened a hook fail mode the previous config had
		// closed may already have open sidecars: the guardian renders them on
		// its pass, not when config.yaml goes back. Every standalone hook is
		// held closed until the affected targets verify with the restored
		// mode; without that proof the closure stays (review loop 2).
		holdFailModes := windowsHotConfigHookFailModeChanges(previous, next)
		holdErr, heldHere, holding := error(nil), false, false
		if published, err := windowsEnterpriseHotConfigPublishedTargets(layout); err != nil || len(holdFailModes.affected(published, true)) > 0 {
			holding = true
			if held, err := windowsEnterpriseHotConfigHooksHeld(); err != nil {
				holdErr = err
			} else if !held {
				if err := windowsEnterpriseHotConfigCloseHooks(layout); err != nil {
					holdErr = err
				} else {
					heldHere = true
				}
			}
		}
		observed, readErr := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
		switch {
		case readErr != nil:
			restoreErr = readErr
		case !bytes.Equal(observed, previous) && !bytes.Equal(observed, next):
			restoreErr = errors.New("the installed config no longer matches this attempt's previous or candidate bytes")
		case recordedBefore:
			// The record named previous: a bundle config goes back as that
			// bundle, so /health names the bundle that enforces again.
			restoreErr = windowsEnterpriseHotConfigWrite(restoreCtx, layout.ConfigPath, previous, configwrite.RestoreOptions(state, configwrite.SHA256Hex(previous), configwrite.Options{
				Actor: configwrite.ActorLifecycle, LocalActor: configwrite.CurrentOSActor(),
				Reason: "enterprise windows ensure (config change not applied)", ExpectSHA256: configwrite.SHA256Hex(observed),
			}))
		default:
			restoreErr = writeFileKeepingDACL(layout.ConfigPath, previous, layout.ConfigPath)
		}
		if restoreErr == nil {
			restored, readErr := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
			switch {
			case readErr != nil:
				restoreErr = readErr
			case !bytes.Equal(restored, previous):
				restoreErr = errors.New("the installed config does not hold the previous bytes after the restore")
			}
		}
		var targetsErr, gatewayErr, guardianErr error
		targetsRepublished := false
		// The previously enrolled targets the candidate's targets no longer
		// enroll: the guardian may already have removed their hooks, and
		// republishing targets.yaml does not prove the hooks are back.
		var lost []enterprisehooks.ManifestTarget
		if restoreErr == nil {
			if generationErr != nil {
				_ = os.Remove(generationPath)
			}
			if targetsRefreshed {
				if publishedBefore.dropped != nil {
					lost = publishedBefore.dropped()
				}
				if targetsErr = windowsEnterpriseHotConfigRefreshTargets(restoreCtx, layout); targetsErr == nil {
					targetsRepublished = true
				} else if publishedBefore.restore != nil {
					// A user the candidate dropped has no hook, so closing
					// hooks cannot protect them: the targets published before
					// this attempt go back as they were, and the guardian
					// registers their hooks again (GAP-0847).
					if putBackErr := publishedBefore.restore(); putBackErr == nil {
						result.AddWarning("targets_restored_from_record", "the hook enumerator could not publish the enrolled targets for the restored config ("+
							windowsEnterpriseBoundedDiagnostic(targetsErr.Error())+"); the targets published before this attempt were put back as they were")
						targetsErr, targetsRepublished = nil, true
					} else {
						targetsErr = fmt.Errorf("%w; putting back the targets published before this attempt failed too: %v", targetsErr, putBackErr)
					}
				}
				if targetsErr == nil && len(lost) > 0 {
					// A published targets.yaml is not a hook: the undo is
					// restored only once every previously enrolled target the
					// candidate dropped has its verified hook again, or waits
					// for its own Windows session (GAP-0905).
					if err := windowsEnterpriseHotConfigTargetHooksProven(restoreCtx, layout, lost, windowsEnterpriseHotConfigRestartTimeout); err != nil {
						targetsErr = fmt.Errorf("the previous targets were published again, but the hooks of the previously enrolled targets were not proven back: %w", err)
					}
				}
			}
			// A guardian this attempt restarted rendered the candidate's
			// machine policy: it reconciles the restored config, and its
			// targets are proven, before the gateway goes back (GAP-0044).
			if targetsErr == nil && guardianRestartAttempted {
				if err := windowsEnterpriseHotConfigGuardianReconcile(restoreCtx, layout, true); err != nil {
					guardianErr = fmt.Errorf("the hook guardian did not prove the enrolled targets on the restored config: %w", err)
				}
			}
			// The gateway goes back to the restored config: a restart for one
			// this attempt restarted or tried to restart, so it does not keep
			// the start-only settings of the config that was undone (a stopped
			// one is started), otherwise a reload request, since the file
			// watcher is best effort. Either way the proof follows.
			wait := windowsEnterpriseHotConfigTimeout
			if gatewayOnNewConfig() {
				wait = windowsEnterpriseHotConfigRestartTimeout
				restarted, err := windowsEnterpriseHotConfigRestart()
				if err != nil || !restarted {
					restarted, _ = windowsEnterpriseHotConfigRecover()
				}
				if restarted && opts.bundle != nil {
					opts.bundle.gatewayRestarted = true
				}
			} else {
				_ = windowsEnterpriseHotBundleReload(restoreCtx, layout)
			}
			if targetsErr == nil {
				proven, cliUnavailable := windowsEnterpriseHotConfigEnforcesInstalled(restoreCtx, wait)
				if !proven && cliUnavailable {
					// The CLI was available before publication but can vanish
					// while undo runs. The service's authenticated /health still
					// reports its live policy. If it has not taken the old
					// config, restart that service on the restored bytes and prove
					// the old policy there. A missing CLI alone is not an outage.
					proven = windowsEnterpriseHotConfigPriorPolicyLive(restoreCtx, layout, priorPolicy)
					if !proven {
						restarted, restartErr := windowsEnterpriseHotConfigRestart()
						if restartErr != nil || !restarted {
							restarted, _ = windowsEnterpriseHotConfigRecover()
						}
						if restarted && opts.bundle != nil {
							opts.bundle.gatewayRestarted = true
						}
						proven = windowsEnterpriseHotConfigWaitForPriorPolicy(restoreCtx, layout, priorPolicy, windowsEnterpriseHotConfigRestartTimeout)
					}
				}
				if !proven {
					gatewayErr = errors.New("the gateway did not report the restored config's policy before the deadline")
				}
			}
		}
		if restoreErr == nil && targetsErr == nil && gatewayErr == nil && guardianErr == nil {
			if !holding {
				return
			}
			renderErr := holdErr
			if renderErr == nil {
				published, err := windowsEnterpriseHotConfigPublishedTargets(layout)
				if err == nil {
					if reopened := holdFailModes.affected(published, true); len(reopened) > 0 {
						err = windowsEnterpriseHotConfigTargetHooksProven(restoreCtx, layout, reopened, windowsEnterpriseHotConfigRenderTimeout)
					}
				}
				renderErr = err
			}
			if renderErr == nil {
				if heldHere {
					if err := windowsEnterpriseHotConfigReleaseHooks(layout); err != nil {
						result.AddWarning("hook_closure_kept", "the previous hook fail mode is back for every enrolled target, but the hook closure could not be released ("+
							windowsEnterpriseBoundedDiagnostic(err.Error())+"); rerun ensure to release it")
					}
				}
				return
			}
			closure := "every standalone hook stays forced closed until ensure or repair proves the installed config again"
			if holdErr != nil {
				closure = "the hooks could not be held closed (" + windowsEnterpriseBoundedDiagnostic(holdErr.Error()) + ")"
			}
			if !bundleChange && !payloadlessRollback {
				// A plain config change goes on to the upgrade transaction,
				// which installs it and restarts the guardian, so an error
				// here said "the previous config is back" over a 1603 while
				// the transaction had installed the change (GAP-0933). The
				// transaction's own result decides; the closure is released
				// once the run ends clean and the gateway proves the
				// installed config (GAP-1599).
				result.AddWarning("hook_fail_mode_restore_unproven", "the change could not be applied in the running gateway and the hook guardian did not prove the previous hook fail mode for every enrolled target ("+
					windowsEnterpriseBoundedDiagnostic(renderErr.Error())+"); "+closure+"; the upgrade transaction applies the change")
				return
			}
			result.AddError("hook_fail_mode_restore_unproven", "the previous config is back and the gateway enforces it, but the hook guardian did not put the previous hook fail mode back for every enrolled target: "+
				windowsEnterpriseBoundedDiagnostic(renderErr.Error())+"; "+closure+". Next step: from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("verify"))
			return
		}
		opts.hotConfigRestoreFailed = true
		installed := windowsEnterpriseHotConfigUndoState(layout.ConfigPath, previous, next, targetsRefreshed, targetsRepublished)
		// The previous config is back and the gateway enforces it; what could
		// not be proven is the guardian's own publication, because a program
		// holds one of its state files open. That is not a verdict on any
		// policy, so the gateway keeps running and no hook is closed over it:
		// the error names the holder and the repair to run once it lets go
		// (GAP-0967). The accounts whose hooks the roster change took away wait
		// for the repair like an account that is signed out.
		if restoreErr == nil && gatewayErr == nil && (targetsErr != nil || guardianErr != nil) {
			if hold := windowsEnterpriseGuardianStateHeldNow(layout); hold != nil {
				cause := targetsErr
				if cause == nil {
					cause = guardianErr
				}
				unprotected := ""
				if len(lost) > 0 {
					unprotected = "; these previously enrolled targets have no DefenseClaw hook until the repair: " + windowsEnterpriseBoundedDiagnostic(strings.Join(windowsHotConfigTargetLabels(lost), ", "))
				}
				result.AddError("guardian_state_held", "the previous config is back and the gateway enforces it, but "+hold.describe()+": "+
					windowsEnterpriseBoundedDiagnostic(cause.Error())+"; "+installed+unprotected+"; the services were left running and no hook was closed. Next step: close that program, then from an elevated PowerShell prompt run "+
					windowsEnterpriseAdminCommand("repair"))
				return
			}
		}
		gateway := "the gateway service was stopped after every standalone hook was durably forced closed; rerun ensure after repair to prove the live policy and release that closure"
		if err := windowsEnterpriseHotConfigCloseHooks(layout); err != nil {
			gateway = "the gateway service was left running because its hooks could not be durably forced closed (" +
				windowsEnterpriseBoundedDiagnostic(err.Error()) + "); it may still enforce an unproven config"
		} else if err := windowsEnterpriseHotConfigFailClosed(); err != nil {
			gateway = "the hooks remain forced closed, but the gateway service could not be stopped (" +
				windowsEnterpriseBoundedDiagnostic(err.Error()) + "); it may still enforce an unproven config"
		}
		switch {
		case restoreErr != nil:
			result.AddError("config_restore_failed", "the config change was not applied and the previous config could not be put back at "+
				layout.ConfigPath+": "+windowsEnterpriseBoundedDiagnostic(restoreErr.Error())+"; "+installed+"; "+gateway+
				". Next step: from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("verify")+"; repair with the last good config before starting the gateway again")
		case targetsErr != nil:
			unprotected := ""
			if len(lost) > 0 {
				// Closing hooks does not reach these: name them.
				unprotected = "; these previously enrolled targets have no DefenseClaw hook now: " + windowsEnterpriseBoundedDiagnostic(strings.Join(windowsHotConfigTargetLabels(lost), ", "))
			}
			result.AddError("targets_restore_failed", "the previous config is back, but the enrolled targets could not be published for it again: "+
				windowsEnterpriseBoundedDiagnostic(targetsErr.Error())+"; "+installed+unprotected+"; "+gateway+". Next step: from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("repair")+
				" to enroll them again, then "+windowsEnterpriseAdminCommand("verify")+" before starting the gateway again")
		case guardianErr != nil:
			result.AddError("config_restore_failed", "the previous config is back at "+layout.ConfigPath+", but "+
				windowsEnterpriseBoundedDiagnostic(guardianErr.Error())+"; "+installed+"; "+gateway+
				". Next step: from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("verify")+"; repair before starting the gateway again")
		default:
			result.AddError("config_restore_failed", "the previous config is back at "+layout.ConfigPath+", but "+gatewayErr.Error()+
				"; "+installed+"; "+gateway+". Next step: from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("verify")+"; repair before starting the gateway again")
		}
	}
	if err := windowsEnterpriseHotConfigWrite(ctx, layout.ConfigPath, next, writeOptions); err != nil {
		if !configwrite.PublicationOccurred(err) {
			// Locks, reads, validation, permission checks and the final CAS
			// all fail before publication. Only the new candidate's rename
			// crosses the boundary at which the gateway might load it.
			message := "the bundle config could not be installed before publication: " + windowsEnterpriseBoundedDiagnostic(err.Error())
			if errors.Is(err, configwrite.ErrConflict) {
				message = "the installed config changed before the bundle write; retry with a fresh policy bundle: " + windowsEnterpriseBoundedDiagnostic(err.Error())
			}
			failBundle("bundle_config_write_failed", message)
			return false, nil
		}
		// A failed generation write or directory sync may follow publication.
		// Even if the writer restored old bytes, the watcher may have loaded
		// the candidate. Prove the previous policy is live before fallback.
		undo()
		failBundle("bundle_config_write_failed", "the bundle config could not be installed: "+windowsEnterpriseBoundedDiagnostic(err.Error()))
		return false, nil
	}
	if _, err := windowsEnterpriseHotConfigValidate(layout.ConfigPath, layout.DataDir, layout.ServiceUser, false); err != nil {
		undo()
		failBundle("bundle_config_validation_failed", "the installed bundle config failed post-write validation")
		return false, nil
	}
	if gatewayOnlyRestart && len(startOnly) == 0 {
		// The watcher also observes the atomic write, but its notification is
		// best effort on Windows. A reload request makes a policy-only bundle,
		// and the payload-less rollback of one, deterministic; a failed
		// request cannot bypass adoption confirmation.
		if err := windowsEnterpriseHotBundleReload(ctx, layout); err != nil {
			result.AddWarning("bundle_reload_request_failed", "the direct gateway reload request failed; waiting for the gateway's file watcher and checking its reported policy: "+windowsEnterpriseBoundedDiagnostic(err.Error()))
		}
	}
	if guardianRestart {
		// The guardian reads config.yaml before each reconcile; its restart
		// starts one now, which writes the managed_hooks_only lock into the
		// Claude Code drop-in at machine scope (GAP-0064) before any row. The
		// gateway restarts only once every published target is proven with
		// the new config, as the transaction starts the guardian first.
		guardianRestartAttempted = true
		if err := windowsEnterpriseHotConfigGuardianReconcile(ctx, layout, false); err != nil {
			noteWindowsEnterpriseEnsure(cmd, opts, "[ensure] the hook guardian did not prove the enrolled targets on the new config ("+
				windowsEnterpriseBoundedDiagnostic(err.Error())+"); the previous config goes back and the upgrade transaction applies the change")
			undo()
			return false, nil
		}
	}
	if len(startOnly) > 0 {
		// The undo restarts (or starts) the gateway on the restored config
		// after a failed restart too, and proves it; an undo it cannot prove
		// leaves the gateway stopped on purpose.
		gatewayRestartAttempted = true
		restarted, restartErr := windowsEnterpriseHotConfigRestart()
		if restarted && opts.bundle != nil {
			opts.bundle.gatewayRestarted = true
		}
		if restartErr != nil || !restarted {
			undo()
			message := "the gateway did not restart on the bundle config"
			if restartErr != nil {
				message += ": " + windowsEnterpriseBoundedDiagnostic(restartErr.Error())
			}
			failBundle("bundle_gateway_restart_failed", message)
			return false, startOnly
		}
	}
	adoptionWait := windowsEnterpriseHotConfigTimeout
	if gatewayOnNewConfig() {
		adoptionWait = windowsEnterpriseHotConfigRestartTimeout
	}
	if !windowsEnterpriseHotConfigAdopted(ctx, adoptionWait, adoptedBundle) {
		// A new delivery cannot be left applied when the gateway never
		// reported its policy. A repeat repairs the already confirmed signed
		// config without a new receipt; if the gateway is down, keep those
		// signed bytes and require a retry after it returns.
		if bundleChange && opts.bundle.prepared.AlreadyApplied && windowsBundlePolicy(ctx).Unavailable() {
			if refreshTargets {
				// As below: the targets it replaces are recorded first, so
				// an undo can enroll a dropped user again (GAP-0847).
				record, err := windowsEnterpriseHotConfigTargetsRecord(layout)
				if err != nil {
					undo()
					failBundle("bundle_targets_refresh_failed", "the bundle's enrolled targets were not refreshed: the published targets could not be recorded first ("+
						windowsEnterpriseBoundedDiagnostic(err.Error())+")")
					return false, nil
				}
				publishedBefore = record
				targetsRefreshed = true
				if err := windowsEnterpriseHotConfigRefreshTargets(ctx, layout); err != nil {
					undo()
					failBundle("bundle_targets_refresh_failed", "the bundle's enrolled targets could not be refreshed")
					return false, nil
				}
			}
			result.Readiness.Gateway = false
			result.SecurityComplete = false
			result.Policy = nil
			result.Changes = append(result.Changes, "restored the current signed bundle config; gateway adoption is unconfirmed")
			result.AddError(string(enterprisebundle.CodeNotConfirmed),
				"the repeated signed bundle config is installed, but the gateway is unavailable; retry the same bundle once the gateway runs")
			return true, nil
		}
		undo()
		failBundle("bundle_policy_not_adopted", "the gateway did not report the bundle policy, generation and identity before the apply deadline")
		return false, nil
	}
	// The enumerator publishes the targets the new config enrolls, as the
	// upgrade transaction does; the guardian reconciles them with the config
	// it reloads (enterpriseHookStandaloneConfigRefresh).
	if refreshTargets {
		// The refresh can drop a user's hook; it runs only once the targets
		// it replaces are recorded, so an undo can enroll that user again
		// (GAP-0847). A record that cannot be read leaves the targets as they
		// are and the change to the upgrade transaction.
		record, err := windowsEnterpriseHotConfigTargetsRecord(layout)
		if err != nil {
			undo()
			failBundle("bundle_targets_refresh_failed", "the bundle's enrolled targets were not refreshed: the published targets could not be recorded first ("+
				windowsEnterpriseBoundedDiagnostic(err.Error())+")")
			return false, nil
		}
		publishedBefore = record
		targetsRefreshed = true
		if err := windowsEnterpriseHotConfigRefreshTargets(ctx, layout); err != nil {
			undo()
			failBundle("bundle_targets_refresh_failed", "the bundle's enrolled targets could not be refreshed")
			return false, nil
		}
	}
	// The hook guardian renders a connector's hook fail mode into every
	// enrolled target's runtime sidecars when it reloads config.yaml, on its
	// next pass (about a minute). A verify before that pass read the previous
	// mode and put the previous config back, so a signed bundle could never
	// take an explicit open back to closed (GAP-1418). Wait, bounded, until
	// the published targets verify with the installed config.
	// Only targets whose effective mode the change moves are waited for: an
	// explicit closed on a default-closed config renders nothing new (review
	// loop 2).
	if failModes := windowsHotConfigHookFailModeChanges(previous, next); failModes.any() {
		targets, err := windowsEnterpriseHotConfigPublishedTargets(layout)
		targets = failModes.affected(targets, false)
		if err == nil && len(targets) > 0 {
			err = windowsEnterpriseHotConfigTargetHooksProven(ctx, layout, targets, windowsEnterpriseHotConfigRenderTimeout)
		}
		if err != nil {
			undo()
			failBundle("bundle_post_verify_failed", "the hook guardian did not put the changed hook fail mode in place for every enrolled target: "+
				windowsEnterpriseBoundedDiagnostic(err.Error()))
			return false, nil
		}
	}
	verifyReport, verifyRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script,
		windowsEnterprisePowerShellArgs("verify", windowsEnterpriseEnsureProbeOptions(opts)))
	if err != nil || !windowsEnterpriseVerifyAcceptable(verifyReport) {
		undo()
		message := "the standalone post-apply verification did not pass"
		if err != nil {
			message += ": " + windowsEnterpriseBoundedDiagnostic(err.Error())
		} else {
			message += ": " + windowsEnterpriseVerifyFailureDetail(verifyReport, "")
		}
		failBundle("bundle_post_verify_failed", message)
		return false, nil
	}
	if !bundleChange && !payloadlessRollback {
		// The approved source is what Repair puts back over a hand edit, so
		// the config this ensure applied has to become it: otherwise a
		// repair restores the config of an earlier ensure. The config stays
		// applied only with its approved source; any failure puts the
		// previous config back and leaves the change to the upgrade
		// transaction, which publishes both (GAP-0779).
		if err := windowsEnterpriseHotConfigApproveSource(layout); err != nil {
			noteWindowsEnterpriseEnsure(cmd, opts, "[ensure] the applied config could not be recorded as the approved config source ("+
				windowsEnterpriseBoundedDiagnostic(err.Error())+"); the previous config goes back and the upgrade transaction applies the change")
			undo()
			return false, nil
		}
	}
	accepted := *verifyReport
	accepted.OK = true
	applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
	if refreshTargets {
		warnWindowsEnterpriseHotAgentSessions(result, previous, next, connectorChangeStartedAt)
	}
	switch {
	case guardianRestart:
		result.Changes = append(result.Changes, "applied the config change after restarting the hook guardian and the gateway; the other services kept running")
	case len(startOnly) > 0:
		result.Changes = append(result.Changes, "applied the config change after restarting the gateway")
	default:
		result.Changes = append(result.Changes, "applied the config change in the running gateway; it was not restarted")
	}
	if kept != "" {
		result.AddWarning("config_reverted", "config.yaml had been changed outside the lifecycle; ensure put the managed config back and kept the edited file at "+kept)
	}
	applyWindowsEnterprisePolicy(ctx, result)
	// Status and verify listed the profile assignment warnings (a group SID
	// that resolves to nothing, a malformed one); ensure, which applied the
	// assignments, said nothing (GAP-0409).
	if result.Readiness.Gateway {
		if body, err := enterprisestatus.SettledGatewayHealth(ctx, windowsStandaloneGatewayHealth, 500*time.Millisecond, 8); err == nil {
			appendStandaloneGatewayWarnings(result, body, windowsStandaloneGatewayStatus())
		}
	}
	applied := strings.Join(changed, ", ")
	switch {
	case len(changed) == 0:
		applied = "no setting changed (line endings, comments or formatting only)"
	case refreshTargets:
		result.Changes = append(result.Changes, "refreshed the enrolled targets; the hook guardian registers and removes hooks for them without a restart")
	}
	if guardianRestart {
		result.AddWarning(windowsEnterpriseGuardianRestartWarning(status.InstalledVersion, startOnly))
	} else if len(startOnly) > 0 {
		result.AddWarning("ensure_bundle_applied", "ensure applied the policy bundle after restarting the gateway: "+applied)
	} else if bundleChange {
		result.AddWarning("ensure_bundle_applied", "ensure applied the policy bundle in the running gateway: "+applied)
	} else {
		result.AddWarning("ensure_config_applied", "ensure applied drift:config in the running gateway, without stopping any service: "+applied)
	}
	return true, nil
}

// windowsEnterpriseHotConfigGuardianReconcile restarts the hook guardian on
// the installed config.yaml through the service manager and waits, bounded by
// the restart timeout, until the installed gateway's readiness proves every
// published target verified or pending with complete protected authorization
// (windowsEnterpriseHotConfigTargetHooksProven). Readiness verifies each
// target against the config it loads, so it passes once the guardian has
// rendered that config's machine policy. The apply needs a running guardian
// and never starts a stopped one. The undo (restore) puts the guardian back
// as it was: one whose restart failed after its stop is started again, and
// the proof then decides. A seam for tests.
var windowsEnterpriseHotConfigGuardianReconcile = func(ctx context.Context, layout managed.StandaloneLayout, restore bool) error {
	restarted, err := restartWindowsStandaloneGuardian(restore)
	switch {
	case err != nil:
		return fmt.Errorf("restart the hook guardian: %w", err)
	case !restarted && !restore:
		return errors.New("the hook guardian service is not running")
	}
	targets, err := windowsEnterpriseHotConfigPublishedTargets(layout)
	if err != nil {
		return fmt.Errorf("read the published targets: %w", err)
	}
	return windowsEnterpriseHotConfigTargetHooksProven(ctx, layout, targets, windowsEnterpriseHotConfigRestartTimeout)
}

// restartWindowsStandaloneGuardian stops the running hook guardian service
// and starts it again, as the gateway restart does; false when it was not
// running. With startStopped a guardian that is stopped after that, or
// whose restart failed, is started.
func restartWindowsStandaloneGuardian(startStopped bool) (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(windowsStandaloneGuardianService)
	if err != nil {
		return false, err
	}
	defer service.Close()
	control := scmGatewayService{service}
	restarted, err := restartWindowsGatewayServiceBeforeStop(control, windowsStandaloneGuardianService, 60*time.Second, 250*time.Millisecond, nil)
	if startStopped && (err != nil || !restarted) {
		return startWindowsGatewayServiceIfStopped(control, windowsStandaloneGuardianService, 60*time.Second, 250*time.Millisecond)
	}
	return restarted, err
}

// noteWindowsEnterpriseEnsure records a line for the lifecycle log of a JSON
// run, whose stderr must stay quiet (GAP-1069), and prints it otherwise.
func noteWindowsEnterpriseEnsure(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, line string) {
	if !opts.jsonOutput {
		fmt.Fprintln(cmd.ErrOrStderr(), line)
		return
	}
	if len(opts.diagnostics) < windowsEnterpriseEnsureDiagnosticsLimit {
		opts.diagnostics = append(opts.diagnostics, line)
	}
}

// windowsEnterpriseHotConfigRenderTimeout bounds the wait for the hook
// guardian's next pass (its interval is one minute) to render a changed hook
// fail mode into the enrolled targets (GAP-1418).
var windowsEnterpriseHotConfigRenderTimeout = 3 * time.Minute

// windowsEnterpriseHotConfigPublishedTargets returns the enabled targets of
// the published targets.yaml; none when it does not exist. A seam for tests.
var windowsEnterpriseHotConfigPublishedTargets = func(layout managed.StandaloneLayout) ([]enterprisehooks.ManifestTarget, error) {
	manifest, err := enterprisehooks.LoadManifest(layout.ManifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var targets []enterprisehooks.ManifestTarget
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			targets = append(targets, target)
		}
	}
	return targets, nil
}

// windowsHotConfigFailModeChange compares the hook fail modes two configs
// give each connector on a managed standalone Windows host (unset is closed).
// all marks a change it cannot attribute (an unparseable config, a profile or
// another unrecognized hook_fail_mode key, application protection switched),
// which affects every connector.
type windowsHotConfigFailModeChange struct {
	all           bool
	before, after map[string]string
	// beforeCfg and afterCfg are the two configs as the gateway loads them,
	// when both load: the rendered mode of each connector then comes from
	// the real resolution chain, so an entry added or removed without its
	// own hook_fail_mode (an application_protection.connectors or a manual
	// guardrail.connectors entry) that switches the chain is seen (GAP-1498).
	beforeCfg, afterCfg *config.Config
}

func windowsHotConfigHookFailModeChanges(previous, next []byte) windowsHotConfigFailModeChange {
	before, beforeOK := windowsHotConfigHookFailModes(previous)
	after, afterOK := windowsHotConfigHookFailModes(next)
	change := windowsHotConfigFailModeChange{before: before, after: after}
	// Decoded as plain settings: the resolver reads only the fail mode,
	// connector and application protection keys, and the full loader also
	// checks paths that only hold at the installed location.
	beforeCfg, afterCfg := &config.Config{}, &config.Config{}
	if yaml.Unmarshal(previous, beforeCfg) == nil && yaml.Unmarshal(next, afterCfg) == nil {
		change.beforeCfg, change.afterCfg = beforeCfg, afterCfg
	}
	if !beforeOK || !afterOK || windowsHotConfigAppProtectionEnabled(previous) != windowsHotConfigAppProtectionEnabled(next) {
		change.all = true
		return change
	}
	for _, modes := range []map[string]string{before, after} {
		for path := range modes {
			if windowsHotConfigCanonicalFailMode(before[path]) == windowsHotConfigCanonicalFailMode(after[path]) {
				continue
			}
			if _, ok := windowsHotConfigFailModePathConnector(path); !ok {
				change.all = true
				return change
			}
		}
	}
	return change
}

// any reports whether some connector's mode may change: one named by a
// hook_fail_mode key, or one with no value of its own.
func (c windowsHotConfigFailModeChange) any() bool {
	if c.all {
		return true
	}
	names := map[string]bool{"\x00": true}
	for _, modes := range []map[string]string{c.before, c.after} {
		for path := range modes {
			if name, _ := windowsHotConfigFailModePathConnector(path); name != "" {
				names[name] = true
			}
		}
	}
	for _, cfg := range []*config.Config{c.beforeCfg, c.afterCfg} {
		if cfg == nil {
			continue
		}
		for name := range cfg.Guardrail.Connectors {
			names[name] = true
		}
		for name := range cfg.ApplicationProtection.Connectors {
			names[name] = true
		}
		for _, name := range cfg.ActiveConnectors() {
			names[name] = true
		}
	}
	for name := range names {
		if c.moves(name, false) {
			return true
		}
	}
	return false
}

// affected returns the targets whose connector's mode the change moves;
// reopened keeps only those it moves from closed to open.
func (c windowsHotConfigFailModeChange) affected(targets []enterprisehooks.ManifestTarget, reopened bool) []enterprisehooks.ManifestTarget {
	var out []enterprisehooks.ManifestTarget
	for _, target := range targets {
		if c.all || c.moves(target.Connector, reopened) {
			out = append(out, target)
		}
	}
	return out
}

// moves resolves connector before and after, under each way application
// protection can apply (not at all, by its connector entry, by its own
// guardrail), as Config.configuredHookFailModeForConnector does.
func (c windowsHotConfigFailModeChange) moves(connector string, reopened bool) bool {
	if c.all {
		return true
	}
	if c.beforeCfg != nil && c.afterCfg != nil && connector != "\x00" {
		before := enterprisehooks.ManagedHookFailMode(c.beforeCfg, connector)
		after := enterprisehooks.ManagedHookFailMode(c.afterCfg, connector)
		if before != after && (!reopened || after == "open") {
			return true
		}
	}
	for overlay := 0; overlay < 3; overlay++ {
		before := windowsHotConfigResolveFailMode(c.before, connector, overlay)
		after := windowsHotConfigResolveFailMode(c.after, connector, overlay)
		if before != after && (!reopened || after == "open") {
			return true
		}
	}
	return false
}

func windowsHotConfigResolveFailMode(modes map[string]string, connector string, overlay int) string {
	want := windowsHotConfigConnectorKey(connector)
	lookup := func(kind string) string {
		for path, mode := range modes {
			if name, ok := windowsHotConfigFailModePathConnector(path); ok && windowsHotConfigFailModePathKind(path) == kind &&
				(name == "" || windowsHotConfigConnectorKey(name) == want) {
				if canonical := windowsHotConfigCanonicalFailMode(mode); canonical != "" {
					return canonical
				}
			}
		}
		return ""
	}
	var chain []string
	switch overlay {
	case 1:
		chain = append(chain, "app-connector")
	case 2:
		chain = append(chain, "app-global")
	}
	chain = append(chain, "connector", "global")
	for _, kind := range chain {
		if mode := lookup(kind); mode != "" {
			return mode
		}
	}
	return "closed"
}

// windowsHotConfigFailModePathConnector names the connector of a recognized
// hook_fail_mode path ("" for a global one); ok is false for any other path.
func windowsHotConfigFailModePathConnector(path string) (string, bool) {
	path = strings.TrimPrefix(path, "[0]") // the document node
	switch {
	case path == ".guardrail.hook_fail_mode", path == ".application_protection.guardrail.hook_fail_mode":
		return "", true
	case strings.HasPrefix(path, ".guardrail.connectors.") && strings.HasSuffix(path, ".hook_fail_mode"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, ".guardrail.connectors."), ".hook_fail_mode")
		return name, name != "" && !strings.Contains(name, ".")
	case strings.HasPrefix(path, ".application_protection.connectors.") && strings.HasSuffix(path, ".guardrail.hook_fail_mode"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, ".application_protection.connectors."), ".guardrail.hook_fail_mode")
		return name, name != "" && !strings.Contains(name, ".")
	}
	return "", false
}

func windowsHotConfigFailModePathKind(path string) string {
	path = strings.TrimPrefix(path, "[0]") // the document node
	switch {
	case path == ".guardrail.hook_fail_mode":
		return "global"
	case path == ".application_protection.guardrail.hook_fail_mode":
		return "app-global"
	case strings.HasPrefix(path, ".guardrail.connectors."):
		return "connector"
	}
	return "app-connector"
}

func windowsHotConfigConnectorKey(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(name)))
}

// windowsHotConfigCanonicalFailMode is explicitHookFailMode: "" unset, "open"
// for open in any case, "closed" for every other value.
func windowsHotConfigCanonicalFailMode(mode string) string {
	switch mode = strings.ToLower(strings.TrimSpace(mode)); mode {
	case "":
		return ""
	case "open":
		return "open"
	}
	return "closed"
}

// windowsHotConfigAppProtectionEnabled reads application_protection.enabled.
func windowsHotConfigAppProtectionEnabled(raw []byte) bool {
	var doc struct {
		ApplicationProtection struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"application_protection"`
	}
	_ = yaml.Unmarshal(raw, &doc)
	return doc.ApplicationProtection.Enabled
}

// windowsHotConfigHookFailModes maps the YAML path of every hook_fail_mode
// key in raw to its value, trimmed and lowercased.
func windowsHotConfigHookFailModes(raw []byte) (map[string]string, bool) {
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, false
	}
	modes := map[string]string{}
	var walk func(node *yaml.Node, path string)
	walk = func(node *yaml.Node, path string) {
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for i, child := range node.Content {
				walk(child, path+"["+strconv.Itoa(i)+"]")
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := strings.ToLower(strings.TrimSpace(node.Content[i].Value))
				value := node.Content[i+1]
				if key == "hook_fail_mode" && value.Kind == yaml.ScalarNode {
					modes[path+"."+key] = strings.ToLower(strings.TrimSpace(value.Value))
					continue
				}
				walk(value, path+"."+key)
			}
		case yaml.AliasNode:
			if node.Alias != nil {
				walk(node.Alias, path)
			}
		}
	}
	walk(&document, "")
	return modes, true
}

// windowsEnterpriseHotConfigRefreshTargets runs one enumerator cycle with
// the installed CLI under the service pins, as the upgrade transaction does
// (Invoke-DefenseClawEnumeratorRefresh). A seam for tests.
var windowsEnterpriseHotConfigRefreshTargets = func(ctx context.Context, layout managed.StandaloneLayout) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	installedCLI, err := windowsEnterpriseInstalledAdminCLI()
	if err != nil {
		return fmt.Errorf("resolve installed CLI for enumerator refresh: %w", err)
	}
	command := exec.CommandContext(ctx, installedCLI,
		"enterprise", "windows", "enumerate", "--manifest", layout.ManifestPath, "--once")
	command.Env = windowsEnterpriseEnvironmentWith(os.Environ(), windowsEnterpriseServicePins(layout))
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("refresh the enrolled targets: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// windowsHotConfigPublishedTargets is the hook guardian's targets.yaml as it
// was published before a hot apply refreshed it: restore puts exactly those
// targets back, and dropped returns each of them the targets published now
// no longer enroll (GAP-0847).
type windowsHotConfigPublishedTargets struct {
	restore func() error
	dropped func() []enterprisehooks.ManifestTarget
}

// windowsEnterpriseHotConfigTargetsRecord records the published targets
// before the apply refreshes them. With none published no user has a hook
// to lose, and there is nothing to put back. A seam for tests.
var windowsEnterpriseHotConfigTargetsRecord = func(layout managed.StandaloneLayout) (windowsHotConfigPublishedTargets, error) {
	// The roster recorded here is written back under a trusted access list
	// if the refresh fails, so a roster another account owns or can write is
	// refused and not recorded (GAP-1048).
	if drift := managed.StandaloneFileLeafDrift(layout.ManifestPath, "hook guardian manifest"); drift != nil {
		return windowsHotConfigPublishedTargets{}, managed.RefuseStandaloneContentDrift(drift)
	}
	before, err := enterprisehooks.LoadManifest(layout.ManifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return windowsHotConfigPublishedTargets{restore: func() error { return nil }, dropped: func() []enterprisehooks.ManifestTarget { return nil }}, nil
	}
	if err != nil {
		return windowsHotConfigPublishedTargets{}, err
	}
	return windowsHotConfigPublishedTargets{
		restore: func() error {
			// Setup's own process lacks the standalone scope the writer's
			// refusal of a drifted manifest depends on (GAP-1048).
			defer pinWindowsStandaloneTrustScope()()
			_, err := enterprisehooks.WriteTargetsManifestAtomic(layout.ManifestPath, before)
			return err
		},
		dropped: func() []enterprisehooks.ManifestTarget {
			now, err := enterprisehooks.LoadManifest(layout.ManifestPath)
			if err != nil {
				now = enterprisehooks.Manifest{}
			}
			return windowsHotConfigDroppedTargets(before, now)
		},
	}, nil
}

// windowsHotConfigDroppedTargets returns each enabled target of before that
// now does not enroll.
func windowsHotConfigDroppedTargets(before, now enterprisehooks.Manifest) []enterprisehooks.ManifestTarget {
	key := func(target enterprisehooks.ManifestTarget) string {
		return strings.ToUpper(strings.TrimSpace(target.SID)) + "\x00" + strings.ToLower(strings.TrimSpace(target.Connector))
	}
	enrolled := make(map[string]bool, len(now.Targets))
	for _, target := range now.Targets {
		if target.IsEnabled() {
			enrolled[key(target)] = true
		}
	}
	var dropped []enterprisehooks.ManifestTarget
	for _, target := range before.Targets {
		if !target.IsEnabled() || enrolled[key(target)] {
			continue
		}
		dropped = append(dropped, target)
	}
	return dropped
}

// windowsHotConfigTargetLabels names each target as "user (SID) connector",
// looking the account up when the target carries only its SID, as the other
// Windows notices do (GAP-2571, GAP-2290 class); "an account (SID)" only when
// the SID does not resolve.
func windowsHotConfigTargetLabels(targets []enterprisehooks.ManifestTarget) []string {
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		user := enterpriseHookWindowsAccountName(target.User, target.SID)
		if user == "" {
			user = "an account"
		}
		labels = append(labels, fmt.Sprintf("%s (%s) %s", user, strings.TrimSpace(target.SID), strings.TrimSpace(target.Connector)))
	}
	return labels
}

// windowsEnterpriseHotConfigTargetHooksProven waits, up to wait, until the
// installed gateway's read-only live registration proof (enterprise hooks readiness)
// reports each of targets verified, or pending its own Windows session (its
// hook is registered at that logon), under the service pins. It names the
// targets still without a verified hook at the deadline. A seam for tests.
var windowsEnterpriseHotConfigTargetHooksProven = func(ctx context.Context, layout managed.StandaloneLayout, targets []enterprisehooks.ManifestTarget, wait time.Duration) error {
	installedGateway, err := windowsEnterpriseInstalledAdminGateway()
	if err != nil {
		return fmt.Errorf("resolve the installed gateway for the hook proof: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		unproven, err := windowsEnterpriseHotConfigUnprovenTargetHooks(ctx, installedGateway, layout, targets)
		if err == nil && len(unproven) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			if err != nil {
				return err
			}
			return fmt.Errorf("no verified DefenseClaw hook for %s", strings.Join(windowsHotConfigTargetLabels(unproven), ", "))
		}
		select {
		case <-ctx.Done():
		case <-time.After(windowsEnterpriseHotConfigPoll):
		}
	}
}

// windowsEnterpriseHotConfigUnprovenTargetHooks runs enterprise hooks readiness
// --json for the installed Windows manifest. It returns targets whose row is
// neither verified nor pending. Unrelated target failures may make the command
// exit nonzero; protected authorization and the report scope must still hold.
func windowsEnterpriseHotConfigUnprovenTargetHooks(ctx context.Context, installedGateway string, layout managed.StandaloneLayout, targets []enterprisehooks.ManifestTarget) ([]enterprisehooks.ManifestTarget, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, runErr := windowsEnterpriseHotConfigReadinessCommand(ctx, installedGateway, layout).Output()
	var report struct {
		OK                 *bool                        `json:"ok"`
		Scope              string                       `json:"scope"`
		AuthorizationError string                       `json:"authorization_error"`
		Results            []enterpriseHookReconcileRow `json:"results"`
		Excused            []enterpriseHookReconcileRow `json:"excused"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		if runErr != nil {
			return targets, fmt.Errorf("enterprise hooks readiness: %w", runErr)
		}
		return targets, fmt.Errorf("read the enterprise hooks readiness report: %w", err)
	}
	if report.OK == nil || report.Scope != "machine_hook_registration" || report.AuthorizationError != "" ||
		(*report.OK && runErr != nil) {
		return targets, errors.New("enterprise hooks readiness did not prove protected authorization")
	}
	if !*report.OK {
		unrelatedFailure := false
		for _, row := range report.Results {
			if !row.OK && !row.Pending {
				unrelatedFailure = true
				break
			}
		}
		if !unrelatedFailure || runErr == nil {
			return targets, errors.New("enterprise hooks readiness returned an invalid result")
		}
	}
	return windowsHotConfigUnprovenTargets(targets, report.Results, report.Excused...), nil
}

// windowsEnterpriseHotConfigReadinessCommand runs enterprise hooks readiness
// under the service pins and the two the guardian's protected records need:
// its authorization directory and the gateway service name, as the
// lifecycle's own readiness probe sets them. Without them readiness refused
// before its report (the authorization directory resolved to a path that
// does not exist), so no hook proof could pass (GAP-1418).
func windowsEnterpriseHotConfigReadinessCommand(ctx context.Context, installedGateway string, layout managed.StandaloneLayout) *exec.Cmd {
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.HookGuardianAuthorizationDirEnv] = layout.GuardianAuthDir
	pins[gwconnector.WindowsGatewayServiceNameEnv] = managed.StandaloneWindowsGatewaySvc
	command := exec.CommandContext(ctx, installedGateway, "enterprise", "hooks", "readiness", "--manifest", layout.ManifestPath, "--json")
	command.Env = windowsEnterpriseEnvironmentWith(os.Environ(), pins)
	return command
}

// windowsHotConfigUnprovenTargets returns each of targets whose readiness row is
// missing, or neither verified nor pending nor excused as verify excuses it
// (a confirmed removed account, one waiting for its sign-in).
func windowsHotConfigUnprovenTargets(targets []enterprisehooks.ManifestTarget, rows []enterpriseHookReconcileRow, excused ...enterpriseHookReconcileRow) []enterprisehooks.ManifestTarget {
	proven := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.OK || row.Pending {
			proven[strings.ToUpper(strings.TrimSpace(row.SID))+"\x00"+strings.ToLower(strings.TrimSpace(row.Connector))] = true
		}
	}
	for _, row := range excused {
		proven[strings.ToUpper(strings.TrimSpace(row.SID))+"\x00"+strings.ToLower(strings.TrimSpace(row.Connector))] = true
	}
	var unproven []enterprisehooks.ManifestTarget
	for _, target := range targets {
		if !proven[strings.ToUpper(strings.TrimSpace(target.SID))+"\x00"+strings.ToLower(strings.TrimSpace(target.Connector))] {
			unproven = append(unproven, target)
		}
	}
	return unproven
}

// windowsEnterpriseHotConfigAdopted waits for the gateway to report the
// effective policy the installed config computes to, with no rejected reload,
// the config recorded and, for a bundle config (bundle.ID set), that bundle's
// ID and version (windowsHotConfigReportAdopted).
func windowsEnterpriseHotConfigAdopted(ctx context.Context, wait time.Duration, bundle configwrite.BundleRef) bool {
	deadline := time.Now().Add(wait)
	for {
		out, _ := windowsEnterprisePolicyDigest(ctx)
		var report policyDigestReport
		if json.Unmarshal(out, &report) == nil && windowsHotConfigReportAdopted(report, bundle) {
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(windowsEnterpriseHotConfigPoll):
		}
	}
}

// windowsEnterpriseHotConfigEnforcesInstalled waits for the gateway to
// report the effective policy the installed config computes to: the proof
// that an undo reached the running gateway. The reported digest is the live
// generation's, the one every hook is decided by. A reload error is not
// part of the proof: a rejected rebuild keeps the live generation, so a
// gateway that rejected the undone config and still runs the restored
// policy is proven, while one that runs the undone policy never reports
// the restored digest, whatever its reload error says.
func windowsEnterpriseHotConfigEnforcesInstalled(ctx context.Context, wait time.Duration) (enforced, cliUnavailable bool) {
	deadline := time.Now().Add(wait)
	for {
		out, err := windowsEnterprisePolicyDigest(ctx)
		var report policyDigestReport
		if err != nil || json.Unmarshal(out, &report) != nil || report.Digest == "" {
			return false, true
		}
		if report.Digest == report.GatewayReportedDigest {
			return true, false
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return false, false
		}
		select {
		case <-ctx.Done():
			return false, false
		case <-time.After(windowsEnterpriseHotConfigPoll):
		}
	}
}

// windowsEnterpriseHotConfigUndoState says which config an undo that could
// not be proven left installed, and whose enrolled targets are published.
func windowsEnterpriseHotConfigUndoState(configPath string, previous, next []byte, targetsRefreshed, targetsRepublished bool) string {
	installed, err := readWindowsEnterpriseBoundedFile(configPath, windowsEnterpriseHotConfigMaxBytes)
	state := ""
	switch {
	case err != nil:
		state = "config.yaml cannot be read (" + windowsEnterpriseBoundedDiagnostic(err.Error()) + ")"
	case bytes.Equal(installed, previous):
		state = "config.yaml holds the previous config"
	case bytes.Equal(installed, next):
		state = "config.yaml still holds the config that was not applied"
	default:
		state = "config.yaml holds neither config (sha256 " + configwrite.SHA256Hex(installed) + ")"
	}
	switch {
	case !targetsRefreshed:
		state += "; the enrolled targets were not changed"
	case targetsRepublished:
		state += "; the enrolled targets were published again for the previous config"
	default:
		state += "; the enrolled targets are still the ones the config that was not applied enrolls, so a user it does not enroll has no DefenseClaw hooks until a repair"
	}
	return state
}

// keepInstalledWindowsEnterpriseEditedConfig is keepWindowsEnterpriseEditedConfig
// for the installed config, for the upgrade transaction that restores it.
func keepInstalledWindowsEnterpriseEditedConfig() string {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return ""
	}
	current, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return ""
	}
	return keepWindowsEnterpriseEditedConfig(layout, current)
}

// keepWindowsEnterpriseEditedConfig keeps a config.yaml that was changed
// outside the lifecycle (its sha256 is not the one config.generation.json
// records) as rejected-config.yaml beside it, before ensure replaces it with
// the managed config. It returns the kept path, or "" when the file was not
// edited or could not be kept. Only administrators can read or change the
// copy.
func keepWindowsEnterpriseEditedConfig(layout managed.StandaloneLayout, current []byte) string {
	state, err := configwrite.ReadGenerationState(layout.ConfigPath)
	if err != nil || state.ConfigSHA256 == "" {
		return ""
	}
	// A content write the hook guardian recorded as a hand edit is still an
	// edit the managed config replaces (GAP-0617).
	if strings.EqualFold(state.ConfigSHA256, configwrite.SHA256Hex(current)) && !configwrite.IsHandEditActor(state.Actor) {
		return ""
	}
	return keepWindowsEnterpriseRejectedConfig(layout, current)
}

// keepWindowsEnterpriseRejectedConfig writes current as rejected-config.yaml
// beside config.yaml. It returns the kept path, or "" when it could not be
// kept.
func keepWindowsEnterpriseRejectedConfig(layout managed.StandaloneLayout, current []byte) string {
	return keepWindowsEnterpriseRejectedFile(filepath.Join(layout.ConfigDir, "rejected-config.yaml"), current)
}

// keepWindowsEnterpriseRejectedFile writes current to kept as a new file
// that only administrators can read or change, under Setup's own AdminFile
// descriptor. It used to copy deployment.json's access list, or the
// rejected file's own when deployment.json was missing or unreadable, so a
// kept copy could carry the very entry it was rejected for (GAP-0590 review
// S3). It returns kept, or "" when it could not be kept.
func keepWindowsEnterpriseRejectedFile(kept string, current []byte) string {
	if _, err := writeFreshFileWithDACL(kept, current, windowsBundleAdminFileSDDL()); err != nil {
		return ""
	}
	return kept
}

// windowsEnterpriseConfigParses reports whether body is a YAML document whose
// root is a mapping, the least any reader of config.yaml needs.
func windowsEnterpriseConfigParses(body []byte) bool {
	var document map[string]any
	return yaml.Unmarshal(trimWindowsJSONBOM(body), &document) == nil && document != nil
}

// windowsEnterpriseUntrustedProblem says, for a message, what is wrong
// with a managed file another account owns or can change.
func windowsEnterpriseUntrustedProblem(untrusted *managed.UntrustedPrincipalError) string {
	switch untrusted.ACL {
	case "null":
		return "has no access list, so any account can change it, which only SYSTEM, Administrators and TrustedInstaller may do"
	case "unsupported":
		return "has an access entry of a type DefenseClaw cannot read, so it cannot tell which account can change it"
	}
	if untrusted.Owner {
		return "is owned by " + untrusted.SID + ", which only SYSTEM, Administrators or TrustedInstaller may be"
	}
	return "can be changed by " + untrusted.SID + ", which only SYSTEM, Administrators and TrustedInstaller may do"
}

// windowsEnterpriseReplacedFile is a managed content file Setup wrote new
// before the lifecycle transaction; the zero value means nothing was written.
type windowsEnterpriseReplacedFile struct {
	kept      string                           // where the replaced bytes are kept, administrators only
	untrusted *managed.UntrustedPrincipalError // why it was replaced; nil for a config.yaml that did not parse
	pending   string                           // the replaced object is held open and is deleted at the next restart
}

// windowsEnterpriseFreshRewrite is a managed content file that Setup writes
// again from an approved source when another account could change it.
type windowsEnterpriseFreshRewrite struct {
	path, label string
	kept        string // where the replaced bytes are kept, administrators only
	sddl        string // Setup's descriptor for the file
	approved    []byte
}

// rewriteWindowsEnterpriseDriftedFile is the one rule for a standalone
// content file that another account owns or can change (GAP-0561, GAP-0590):
// Setup never puts a trusted descriptor back over it, because those bytes
// may be that account's. When this run carries an approved source, Setup
// writes the source as a new file under Setup's descriptor before the
// lifecycle transaction, keeps the replaced bytes for the administrator,
// and moves the old object aside first, so a handle opened during the drift
// points at the replaced object. The snapshot and the rollback then hold
// approved bytes. It works under the lifecycle lock and checks the drift
// again there; it returns "" when there is nothing to do: the file is
// trusted again, a transaction is pending (its recovery restores its own
// preimage), or the lock is busy (the transaction then refuses the file).
func rewriteWindowsEnterpriseDriftedFile(layout managed.StandaloneLayout, rewrite windowsEnterpriseFreshRewrite) (windowsEnterpriseReplacedFile, error) {
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	defer release()
	untrusted := windowsEnterpriseInstalledLeafDrift(rewrite.path, rewrite.label)
	if untrusted == nil || windowsBundleInstallTransactionPending(layout) {
		return windowsEnterpriseReplacedFile{}, nil
	}
	current, err := readWindowsEnterpriseBoundedFile(rewrite.path, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("read the installed %s to keep it: %w", rewrite.path, err)
	}
	kept := keepWindowsEnterpriseRejectedFile(rewrite.kept, current)
	if kept == "" {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s %s and could not be kept as %s", rewrite.path, windowsEnterpriseUntrustedProblem(untrusted), rewrite.kept)
	}
	pending, err := writeFreshFileWithDACL(rewrite.path, rewrite.approved, rewrite.sddl)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("write a new %s from the approved source: %w", rewrite.path, err)
	}
	return windowsEnterpriseReplacedFile{kept: kept, untrusted: untrusted, pending: pending}, nil
}

// installWindowsEnterpriseSuppliedConfigOverRefused puts the supplied config
// in place of an installed config.yaml the lifecycle transaction refuses, and
// keeps the refused file as rejected-config.yaml. Ensure CONFIG= and repair
// CONFIG= loaded the installed file before they used the supplied one, and
// stopped every service and left the transaction pending when it was
// refused:
//   - a config.yaml another account owns or can change, under trusted
//     folders: the ACL repair refused it after the stop, and its rollback
//     refused it again (GAP-0590). The supplied config is the
//     administrator's approved source: rewriteWindowsEnterpriseDriftedFile
//     writes it as a new file under Setup's ConfigFile descriptor.
//   - a config.yaml that does not parse: the snapshot refused it and the
//     rollback wrote its bytes back (GAP-0948). The supplied config replaces
//     it with the file's access list.
//
// It returns the kept path and, for an untrusted owner or writer, which one;
// "" when there is nothing to do: no supplied config, an installed config the
// transaction accepts, a pending transaction, a supplied config that is the
// installed file (a drifted file is never its own approved source), a source
// a standard user can write (the transaction refuses it), or a busy lock.
func installWindowsEnterpriseSuppliedConfigOverRefused(configPath string) (windowsEnterpriseReplacedFile, error) {
	supplied := strings.TrimSpace(configPath)
	if supplied == "" || !windowsEnterpriseIsElevated() {
		return windowsEnterpriseReplacedFile{}, nil
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	current, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	untrusted := windowsEnterpriseInstalledLeafDrift(layout.ConfigPath, "managed config")
	if (untrusted == nil && windowsEnterpriseConfigParses(current)) || windowsBundleInstallTransactionPending(layout) {
		return windowsEnterpriseReplacedFile{}, nil
	}
	if windowsEnterpriseSamePath(supplied, layout.ConfigPath) || windowsEnterpriseHotConfigSourceCheck(supplied) != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	next, err := readWindowsEnterpriseBoundedFile(supplied, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("read the supplied config %s: %w", supplied, err)
	}
	if !windowsEnterpriseConfigParses(next) {
		if untrusted == nil {
			return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s does not parse, and neither does the supplied config %s: its root must be a YAML mapping", layout.ConfigPath, supplied)
		}
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s %s, and the supplied config %s does not parse: its root must be a YAML mapping", layout.ConfigPath, windowsEnterpriseUntrustedProblem(untrusted), supplied)
	}
	// This file becomes the transaction snapshot. Check it with the same
	// service pins and rule-pack compiler before replacing the refused file.
	if err := windowsEnterpriseStandaloneConfigPreflight(supplied); err != nil {
		return windowsEnterpriseReplacedFile{}, err
	}
	if untrusted != nil {
		service, err := managed.WindowsServiceAccountSID(layout.ServiceUser)
		if err != nil || service == nil {
			return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s %s, and the gateway service account %q to write a new one for cannot be resolved: %v",
				layout.ConfigPath, windowsEnterpriseUntrustedProblem(untrusted), layout.ServiceUser, err)
		}
		return rewriteWindowsEnterpriseDriftedFile(layout, windowsEnterpriseFreshRewrite{
			path: layout.ConfigPath, label: "managed config",
			kept: filepath.Join(layout.ConfigDir, "rejected-config.yaml"),
			sddl: windowsConfigFileSDDL(service.String()), approved: next,
		})
	}
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return windowsEnterpriseReplacedFile{}, nil
	}
	defer release()
	// Another lifecycle run may have committed a config while the preflight
	// ran or this call waited for the lock. Read the installed file again
	// under the lock: one that parses now is that run's commit and stays,
	// and the bytes kept are the ones being replaced, not the ones read
	// before (GAP-1177).
	current, err = readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || windowsEnterpriseConfigParses(current) || windowsBundleInstallTransactionPending(layout) {
		return windowsEnterpriseReplacedFile{}, nil
	}
	kept := keepWindowsEnterpriseRejectedConfig(layout, current)
	if kept == "" {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s does not parse and could not be kept as rejected-config.yaml", layout.ConfigPath)
	}
	if err := recordWindowsEnterpriseLifecycleConfigWrite(layout.ConfigPath, next, windowsEnterpriseSuppliedConfigRecordReason, func() error {
		return writeFileKeepingDACL(layout.ConfigPath, next, layout.ConfigPath)
	}); err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("install the supplied config over the unparseable %s: %w", layout.ConfigPath, err)
	}
	return windowsEnterpriseReplacedFile{kept: kept}, nil
}

// installWindowsEnterpriseApprovedManifestOverDrift writes the hook guardian
// manifest again when another account owns or can change the installed one
// (GAP-0590). Standalone Repair used to put the AdminFile descriptor back
// over it in place, which trusted a roster that account may have edited. The
// approved source is MANIFEST= when it is given, otherwise a manifest
// enumerated from the approved CONFIG=, as a first install stages one; in
// manifest enrollment mode only MANIFEST= is a source. With neither, nothing
// is written and the lifecycle refuses the manifest before any service
// stops, naming MANIFEST=.
func installWindowsEnterpriseApprovedManifestOverDrift(
	ctx context.Context,
	logf enterprisehooks.EnumerationLogger,
	configPath, manifestPath string,
) (windowsEnterpriseReplacedFile, error) {
	if !windowsEnterpriseIsElevated() {
		return windowsEnterpriseReplacedFile{}, nil
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil || strings.TrimSpace(layout.ManifestPath) == "" {
		return windowsEnterpriseReplacedFile{}, nil
	}
	const label = "hook guardian manifest"
	if windowsEnterpriseInstalledLeafDrift(layout.ManifestPath, label) == nil || windowsBundleInstallTransactionPending(layout) {
		return windowsEnterpriseReplacedFile{}, nil
	}
	source := strings.TrimSpace(manifestPath)
	if source != "" {
		if windowsEnterpriseSamePath(source, layout.ManifestPath) || windowsEnterpriseManifestSourceCheck(source) != nil {
			return windowsEnterpriseReplacedFile{}, nil
		}
	} else {
		approved := strings.TrimSpace(configPath)
		if approved == "" || windowsEnterpriseSamePath(approved, layout.ConfigPath) || windowsEnterpriseHotConfigSourceCheck(approved) != nil {
			return windowsEnterpriseReplacedFile{}, nil
		}
		staged, cleanup, err := windowsEnterpriseApprovedManifestStager(ctx, logf, approved)
		if errors.Is(err, errWindowsEnterpriseEnsureManifestRequired) {
			return windowsEnterpriseReplacedFile{}, nil
		}
		if err != nil {
			return windowsEnterpriseReplacedFile{}, fmt.Errorf("the installed %s needs a new manifest, and none could be enumerated from the supplied config %s: %w", layout.ManifestPath, approved, err)
		}
		defer cleanup()
		source = staged
	}
	if _, err := enterprisehooks.LoadManifest(source); err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("the hook guardian manifest %s to write over the installed %s does not load: %w", source, layout.ManifestPath, err)
	}
	approved, err := readWindowsEnterpriseBoundedFile(source, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return windowsEnterpriseReplacedFile{}, fmt.Errorf("read the hook guardian manifest %s: %w", source, err)
	}
	return rewriteWindowsEnterpriseDriftedFile(layout, windowsEnterpriseFreshRewrite{
		path: layout.ManifestPath, label: label,
		kept: filepath.Join(layout.ConfigDir, "rejected-targets.yaml"),
		sddl: windowsBundleAdminFileSDDL(), approved: approved,
	})
}

// windowsEnterpriseGateRefusal starts every refusal of the lifecycle's
// content gate (Assert-DefenseClawStandaloneContentTrusted), which runs
// before the lifecycle changes anything.
const windowsEnterpriseGateRefusal = "refusing to change the deployment, and nothing was changed"

// noteWindowsEnterpriseRewriteBeforeRefusal makes a content-gate refusal say
// what this run had already done: Setup wrote config.yaml or targets.yaml
// new from the approved source before the lifecycle ran, and the gate then
// refused another file, so "nothing was changed" was not true (GAP-0590
// review S4). The changes list the rewrite and the kept file.
func noteWindowsEnterpriseRewriteBeforeRefusal(result *enterprisestatus.Result, rewritten []string) {
	if len(rewritten) == 0 {
		return
	}
	said := "refusing to change the rest of the deployment: Setup first wrote a new " + strings.Join(rewritten, " and ") +
		" from the approved source (see changes), and then stopped no service and changed nothing else"
	for i := range result.Errors {
		result.Errors[i].Message = strings.Replace(result.Errors[i].Message, windowsEnterpriseGateRefusal, said, 1)
	}
}

// windowsEnterpriseSamePath reports whether two paths name one file.
func windowsEnterpriseSamePath(left, right string) bool {
	a, errA := filepath.Abs(left)
	b, errB := filepath.Abs(right)
	return errA == nil && errB == nil && strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// windowsEnterpriseReplacedFileChange is the result line for a managed file
// Setup replaced before the lifecycle transaction: name is config.yaml or
// targets.yaml.
func windowsEnterpriseReplacedFileChange(name string, replaced windowsEnterpriseReplacedFile, action string) string {
	if replaced.untrusted == nil {
		return "the installed " + name + " did not parse; kept it as " + replaced.kept + " and installed the supplied config before the " + action
	}
	change := "the installed " + name + " " + windowsEnterpriseUntrustedProblem(replaced.untrusted) + "; kept it as " + replaced.kept +
		" and wrote a new " + name + " from the approved source, with Setup's access list, before the " + action
	if replaced.pending != "" {
		change += "; " + replaced.pending
	}
	return change
}

// windowsEnterpriseSuppliedConfigRecordReason is the reason of the config
// generation Setup records when it writes the supplied config over a
// config.yaml the transaction refuses.
const windowsEnterpriseSuppliedConfigRecordReason = "enterprise windows lifecycle (the supplied config replaced a refused config.yaml)"

// recordWindowsEnterpriseLifecycleConfigWrite runs write, which puts approved
// at the managed config path, and records approved as the lifecycle's config
// generation in the same config.yaml.lock critical section, while the caller
// holds lifecycle.lock (GAP-0646). Setup used to write the supplied config
// here with no record and release lifecycle.lock before the transaction took
// it again: the hook guardian then found bytes config.generation.json did not
// record, recorded them as hand-edit:unattributed, and the gateway refused to
// start on them, so the repair ended 1603. The record carries the options the
// lifecycle's config step records for the same bytes
// (managedStandaloneLifecycleRecordOptions) and config.yaml's access list, as
// that step gives it. A record that is there but does not read is the only
// proof of the counter (GAP-0236): the bytes are written without one, and the
// transaction's config step refuses that record as before.
func recordWindowsEnterpriseLifecycleConfigWrite(path string, approved []byte, reason string, write func() error) error {
	if _, err := configwrite.ReadGenerationState(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return write()
	}
	opt, err := managedStandaloneLifecycleRecordOptions(path, approved, reason)
	if err != nil {
		return err
	}
	opt.RecordSHA256 = configwrite.SHA256Hex(approved)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := configwrite.Locked(ctx, path, opt, func() (bool, error) { return true, write() }); err != nil {
		return err
	}
	restoreACL, err := keepConfigDACL(path)
	if err != nil {
		return fmt.Errorf("read the access control list of %s: %w", path, err)
	}
	return restoreACL(configwrite.GenerationPath(path))
}

// acquireWindowsEnterpriseLifecycleLock opens the lifecycle lock the way the
// PowerShell lifecycle does for a mutation, exclusively. It waits up to
// windowsEnterpriseLifecycleLockWait, and only on a sharing violation, so the
// hook guardian's short hold never turns a step into "nothing to do"; a busy
// lock after that sends the change to the upgrade transaction, which waits
// for it. Only the windowsEnterpriseHotConfigLock seam uses it (Setup's
// pre-step, hot apply, bundle restore, generation repair); passes that must
// not wait take tryWindowsEnterpriseLifecycleLock (GAP-0646 review 2).
func acquireWindowsEnterpriseLifecycleLock(path string) (func(), error) {
	deadline := time.Now().Add(windowsEnterpriseLifecycleLockWait)
	for {
		release, err := tryWindowsEnterpriseLifecycleLock(path)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || !time.Now().Before(deadline) {
			return release, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// windowsEnterpriseLifecycleLockWait bounds how long a Go lifecycle step
// waits for lifecycle.lock. The hook guardian holds it only while it records
// an administrator's edit of config.yaml (GAP-0646), at most
// managedConfigRecordHold; a lifecycle run holds it for minutes, so a take
// during a run still fails as busy. A seam for tests.
var windowsEnterpriseLifecycleLockWait = 5 * time.Second

// tryWindowsEnterpriseLifecycleLock opens lifecycle.lock with no sharing,
// once: the error wraps windows.ERROR_SHARING_VIOLATION when another process
// holds it, and fs.ErrNotExist when there is no lock file. A lock that is not
// there says so as the base did ("is not a regular file"), and still wraps
// the cause (GAP-0646 review L1, the port of 93d99c758d).
func tryWindowsEnterpriseLifecycleLock(path string) (func(), error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lifecycle lock %s is not a regular file: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lifecycle lock %s is not a regular file", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(handle) }, nil
}

// windowsHotConfigWriteOptions records the hot-applied config as the
// lifecycle, or, when the run applies a signed policy bundle, as the bundle
// principal with the bundle fields, so config.generation.json and the
// gateway's config.change.applied event name the bundle. For a bundle run it
// also returns the bundle the gateway must then report before the config is
// adopted (windowsHotBundleIdentity); the zero BundleRef otherwise.
func windowsHotConfigWriteOptions(opts *windowsEnterpriseLifecycleOptions, expectSHA string) (configwrite.Options, configwrite.BundleRef, error) {
	if opts != nil && opts.bundleRollbackTo != nil {
		// A rollback to the confirmed bundle records it as that bundle again,
		// so /health and the digest scope name the bundle that enforces. It
		// is adopted only once the gateway names that bundle and version
		// (GAP-0445): an incomplete reference refuses before the write.
		opt, err := opts.bundleRollbackTo.writeOptions(expectSHA)
		if err != nil {
			return opt, configwrite.BundleRef{}, err
		}
		identity, err := windowsBundleRollbackIdentity(opts.bundleRollbackTo.ref, opt.Bundle)
		return opt, identity, err
	}
	if opts == nil || opts.bundle == nil || opts.bundle.prepared == nil || (opts.bundle.prepared.Receipt == nil && !opts.bundle.prepared.AlreadyApplied) {
		return configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "enterprise windows ensure", ExpectSHA256: expectSHA}, configwrite.BundleRef{}, nil
	}
	prepared := opts.bundle.prepared
	var opt configwrite.Options
	var current []byte
	var ref *enterprisebundle.Ref
	if !prepared.AlreadyApplied {
		var ok bool
		if opt, ok = enterprisebundle.GenerationOptions(prepared.Receipt); !ok {
			return configwrite.Options{}, configwrite.BundleRef{}, errors.New("staged bundle has no principal")
		}
	} else {
		var err error
		if opt, current, ref, err = windowsHotConfirmedBundle(opts.bundle.driver, prepared.Config); err != nil {
			return configwrite.Options{}, configwrite.BundleRef{}, err
		}
	}
	bundle, err := windowsHotBundleIdentity(prepared, opt.Bundle, current, ref)
	if err != nil {
		return configwrite.Options{}, configwrite.BundleRef{}, err
	}
	opt.ExpectSHA256 = expectSHA
	return opt, bundle, nil
}

// windowsHotConfirmedBundle reads, for a repeated delivery of the confirmed
// bundle, the options that record config as that bundle's principal, and the
// confirmed current bundle's rendered config and reference. A seam for tests.
var windowsHotConfirmedBundle = func(driver *enterprisebundle.Driver, config []byte) (configwrite.Options, []byte, *enterprisebundle.Ref, error) {
	if driver == nil {
		return configwrite.Options{}, nil, nil, errors.New("confirmed bundle store is unavailable")
	}
	opt, ok, err := driver.ConfigGenerationOptions(config)
	if err != nil {
		return configwrite.Options{}, nil, nil, err
	}
	if !ok {
		return configwrite.Options{}, nil, nil, errors.New("confirmed bundle principal is unavailable")
	}
	current, ref, err := driver.CurrentConfig()
	if err != nil {
		return configwrite.Options{}, nil, nil, err
	}
	return opt, current, ref, nil
}
