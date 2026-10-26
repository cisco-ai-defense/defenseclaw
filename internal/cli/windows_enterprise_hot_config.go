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
	windowsEnterpriseHotConfigLayout         = managed.StandaloneWindowsLayout
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

// windowsEnterpriseHotConfigApply applies the supplied config to the running
// gateway and fills result from a verify of the host. For a signed bundle,
// start-only keys restart only the gateway. It returns false after attempting
// to restore the old config on failure; ordinary CONFIG= uses the upgrade transaction
// for start-only keys.
func windowsEnterpriseHotConfigApply(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	status *windowsEnterpriseInstallerReport,
	result *enterprisestatus.Result,
) (bool, []string) {
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
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
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
	// A bundle rollback by the installed CLI has no payload for the upgrade
	// transaction: it restarts only the gateway, as the bundle it undoes did.
	gatewayOnlyRestart := bundleChange || payloadlessRollback
	if len(startOnly) > 0 && !gatewayOnlyRestart {
		return false, startOnly
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
		var targetsErr, gatewayErr error
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
		if restoreErr == nil && targetsErr == nil && gatewayErr == nil {
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
	accepted := *verifyReport
	accepted.OK = true
	applyWindowsEnterpriseInstallerReport(result, opts, &accepted, verifyRun)
	if refreshTargets {
		warnWindowsEnterpriseHotAgentSessions(result, previous, next, connectorChangeStartedAt)
	}
	if len(startOnly) > 0 {
		result.Changes = append(result.Changes, "applied the config change after restarting the gateway")
	} else {
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
	if len(startOnly) > 0 {
		result.AddWarning("ensure_bundle_applied", "ensure applied the policy bundle after restarting the gateway: "+applied)
	} else if bundleChange {
		result.AddWarning("ensure_bundle_applied", "ensure applied the policy bundle in the running gateway: "+applied)
	} else {
		result.AddWarning("ensure_config_applied", "ensure applied drift:config in the running gateway, without stopping any service: "+applied)
	}
	return true, nil
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
	if beforeCfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes("config.yaml", previous); err == nil {
		if afterCfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes("config.yaml", next); err == nil {
			change.beforeCfg, change.afterCfg = beforeCfg, afterCfg
		}
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
	before, err := enterprisehooks.LoadManifest(layout.ManifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return windowsHotConfigPublishedTargets{restore: func() error { return nil }, dropped: func() []enterprisehooks.ManifestTarget { return nil }}, nil
	}
	if err != nil {
		return windowsHotConfigPublishedTargets{}, err
	}
	return windowsHotConfigPublishedTargets{
		restore: func() error {
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

// windowsHotConfigTargetLabels names each target as "user (SID) connector".
func windowsHotConfigTargetLabels(targets []enterprisehooks.ManifestTarget) []string {
	labels := make([]string, 0, len(targets))
	for _, target := range targets {
		user := strings.TrimSpace(target.User)
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
// edited or could not be kept. The copy has deployment.json's access
// control, administrators only.
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
// beside config.yaml, with deployment.json's access control (administrators
// only). It returns the kept path, or "" when it could not be kept.
func keepWindowsEnterpriseRejectedConfig(layout managed.StandaloneLayout, current []byte) string {
	sibling := layout.ConfigPath
	if deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone); err == nil && deployment.MetadataPath != "" {
		if _, err := os.Stat(deployment.MetadataPath); err == nil {
			sibling = deployment.MetadataPath
		}
	}
	kept := filepath.Join(layout.ConfigDir, "rejected-config.yaml")
	if err := writeFileKeepingDACL(kept, current, sibling); err != nil {
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

// installWindowsEnterpriseSuppliedConfigOverUnparseable puts the supplied
// config in place of an installed config.yaml that does not parse, after it
// keeps the broken file as rejected-config.yaml (GAP-0948). Ensure CONFIG=
// and repair CONFIG= loaded the installed file before they used the supplied
// one: the transaction snapshot refused it, the rollback wrote its bytes
// back, and the transaction stayed pending with every service stopped. With
// the supplied config in place the transaction snapshots a config that
// loads, and a rollback puts that config back. It returns the kept path, or
// "" when there is nothing to do: no supplied config, an installed config
// that parses, a pending transaction (its recovery restores its own
// preimage), a source a standard user can write (the transaction refuses
// it), or a busy lifecycle lock.
func installWindowsEnterpriseSuppliedConfigOverUnparseable(configPath string) (string, error) {
	supplied := strings.TrimSpace(configPath)
	if supplied == "" || !windowsEnterpriseIsElevated() {
		return "", nil
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return "", nil
	}
	current, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || windowsEnterpriseConfigParses(current) {
		return "", nil
	}
	if windowsBundleInstallTransactionPending(layout) {
		return "", nil
	}
	if windowsEnterpriseHotConfigSourceCheck(supplied) != nil {
		return "", nil
	}
	next, err := readWindowsEnterpriseBoundedFile(supplied, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return "", fmt.Errorf("read the supplied config %s: %w", supplied, err)
	}
	if !windowsEnterpriseConfigParses(next) {
		return "", fmt.Errorf("the installed %s does not parse, and neither does the supplied config %s: its root must be a YAML mapping", layout.ConfigPath, supplied)
	}
	// This file becomes the transaction snapshot. Check it with the same
	// service pins and rule-pack compiler before replacing the broken file.
	if err := windowsEnterpriseStandaloneConfigPreflight(supplied); err != nil {
		return "", err
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return "", nil
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return "", nil
	}
	defer release()
	// Another lifecycle run may have committed a config while the preflight
	// ran or this call waited for the lock. Read the installed file again
	// under the lock: one that parses now is that run's commit and stays,
	// and the bytes kept are the ones being replaced, not the ones read
	// before (GAP-1177).
	current, err = readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || windowsEnterpriseConfigParses(current) || windowsBundleInstallTransactionPending(layout) {
		return "", nil
	}
	kept := keepWindowsEnterpriseRejectedConfig(layout, current)
	if kept == "" {
		return "", fmt.Errorf("the installed %s does not parse and could not be kept as rejected-config.yaml", layout.ConfigPath)
	}
	if err := writeFileKeepingDACL(layout.ConfigPath, next, layout.ConfigPath); err != nil {
		return "", fmt.Errorf("install the supplied config over the unparseable %s: %w", layout.ConfigPath, err)
	}
	return kept, nil
}

// windowsEnterpriseUnparseableConfigChange is the result line for a config
// installWindowsEnterpriseSuppliedConfigOverUnparseable replaced.
func windowsEnterpriseUnparseableConfigChange(kept, action string) string {
	return "the installed config.yaml did not parse; kept it as " + kept + " and installed the supplied config before the " + action
}

// acquireWindowsEnterpriseLifecycleLock opens the lifecycle lock the way the
// PowerShell lifecycle does for a mutation, exclusively, and does not wait:
// a busy lock sends the change to the upgrade transaction, which waits for
// it.
func acquireWindowsEnterpriseLifecycleLock(path string) (func(), error) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
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
