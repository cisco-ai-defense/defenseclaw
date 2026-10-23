//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// bundleNotAppliedCode is the lifecycle error of a bundle-mode device whose
// confirmed signed policy bundle does not enforce: config.yaml is not the
// bundle's config, or the running gateway reports another policy. status,
// verify and every changing action report it, so an MDM health check never
// reads compliant while the gateway enforces a policy nobody signed
// (GAP-0114). ensure and repair re-apply the bundle first.
const bundleNotAppliedCode = "bundle_not_applied"

// In bundle mode the confirmed signed bundle is the policy (management plane
// spec P1 section 7: repair and verify re-apply the current bundle, so
// in-place edits of config.yaml revert). A config.yaml changed outside the
// lifecycle used to stay: the guardian recorded the edit as a hand-edit
// generation, ensure restarted the gateway on it, verify passed with a
// config_edited_outside_lifecycle warning, and Intune's Remediations read the
// device as compliant while the gateway enforced a policy nobody signed
// (GAP-0114). Now ensure and repair put the confirmed bundle's config back
// from the bundle store before anything starts the gateway, and every health
// result of a bundle-mode device fails with bundle_not_applied unless the
// gateway enforces the confirmed bundle.

// windowsBundleRestoreGatewayRunning reports a running gateway service, which
// the restore asks to reload the re-applied config. A seam for tests.
var windowsBundleRestoreGatewayRunning = func() bool { return windowsStandaloneGatewayPID() != 0 }

// readWindowsBundleEnforcement reads the confirmed bundle and the installed
// config. ok is false when the device is not in bundle mode or this account
// cannot read the bundle store (a standard user's status).
func readWindowsBundleEnforcement() (bundleEnforcement, managed.StandaloneLayout, *enterprisebundle.Driver, bool) {
	layout, err := windowsBundleLayout()
	if err != nil {
		return bundleEnforcement{}, layout, nil, false
	}
	driver := newWindowsBundleDriver(layout)
	bundleMode, err := windowsBundleMode(driver)
	if err != nil || !bundleMode {
		return bundleEnforcement{}, layout, driver, false
	}
	// A store this account cannot read (a standard user's status) or a
	// damaged one: bundle status reports the latter as state_invalid, and the
	// MDM bundle detection fails on it.
	st, err := driver.Store.LoadState()
	if err != nil || st.Current == nil {
		return bundleEnforcement{}, layout, driver, false
	}
	e := bundleEnforcement{Current: st.Current}
	e.CurrentConfig, _, e.CurrentErr = driver.CurrentConfig()
	if installed, err := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig); err == nil {
		e.InstalledConfig = installed
	}
	return e, layout, driver, true
}

// addWindowsBundleEnforcementError adds bundle_not_applied to a health
// result of a bundle-mode device whose confirmed bundle does not enforce.
// A run that delivered a new bundle settled it in finishWindowsEnterpriseBundle,
// which reports its own failure and rollback.
func addWindowsBundleEnforcementError(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions, deliveredBundle bool) {
	if result == nil || opts == nil || opts.bundleRollback || deliveredBundle || !result.Installed ||
		!bundleEnforcementCheckedAction(result.Action) || !windowsEnterpriseIsElevated() {
		return
	}
	e, _, driver, ok := readWindowsBundleEnforcement()
	if !ok {
		return
	}
	e.GatewayReady, e.Policy = result.Readiness.Gateway, result.Policy
	problem := e.Problem()
	if e.ConfigReplaced() && driver != nil {
		if pending, err := driver.CommittedPendingConfig(e.InstalledConfig); err == nil && pending != nil {
			problem = "config.yaml is the committed config of policy bundle " + pending.BundleID +
				" whose receipt remains pending; the gateway has not confirmed it yet, so " + bundleLabel(e.Current) + " remains current"
		}
	}
	if problem != "" && !windowsBundleHasCode(result.Errors, bundleNotAppliedCode) {
		result.AddError(bundleNotAppliedCode, problem)
	}
}

// windowsBundleRestore is what restoreWindowsBundleConfig did, for the
// result of the run that called it.
type windowsBundleRestore struct {
	changes  []string
	warnings []enterprisestatus.Message
	errors   []enterprisestatus.Message
}

func (r windowsBundleRestore) apply(result *enterprisestatus.Result) {
	result.Changes = append(result.Changes, r.changes...)
	for _, w := range r.warnings {
		result.AddWarning(w.Code, w.Message)
	}
	for _, e := range r.errors {
		result.AddError(e.Code, e.Message)
	}
}

func (r windowsBundleRestore) failed() bool { return len(r.errors) != 0 }

// windowsBundleRestoreRequested reports an ensure or repair that names no
// config of its own and delivers no bundle: the confirmed bundle is the
// config it keeps.
func windowsBundleRestoreRequested(action string, opts *windowsEnterpriseLifecycleOptions) bool {
	return (action == "ensure" || action == "repair") && opts != nil && opts.bundle == nil && !opts.bundleRollback &&
		opts.bundlePath == "" && opts.trustAnchors == "" &&
		strings.TrimSpace(opts.configPath) == "" && strings.TrimSpace(opts.mode) == "" && opts.installedBeforeRun
}

// restoreWindowsBundleConfig puts the confirmed bundle's config back over a
// config.yaml changed outside the lifecycle, or deleted, with the lifecycle
// writer and the bundle's principal, so config.generation.json and /health
// name the bundle again. It takes nothing from the network: the config is
// rendered from the verified, immutable version directory in the bundle
// store. An edited file is kept as rejected-config.yaml. A running gateway is
// asked to reload (and restarted when it does not adopt the policy); a
// stopped one starts on the restored config in the ensure that follows. Any
// failure is an error and the caller stops before it starts a service on the
// edit.
//
// It writes nothing while an install transaction is pending: that
// transaction's recovery, which the run performs next, puts back the config
// it recorded, and the next ensure re-applies the bundle over it. It does not
// validate the config again after the write: these are the confirmed bundle's
// bytes, which validated at their first apply, and undoing the write would
// put the unsigned edit back in force; a gateway that cannot take them fails
// the run with bundle_not_applied.
//
// replacing names the bundle a killed run installed and the gateway never
// confirmed, when this run settled it (windowsBundleSettle.replacing): the
// change says that config is what the restore replaced, not an edit.
// windowsBundleRestoreGenerationOptions binds the confirmed bundle config to
// its principal (enterprisebundle.Driver.ConfigGenerationOptions); a seam
// for tests.
var windowsBundleRestoreGenerationOptions = func(driver *enterprisebundle.Driver, config []byte) (configwrite.Options, bool, error) {
	return driver.ConfigGenerationOptions(config)
}

func restoreWindowsBundleConfig(ctx context.Context, replacing string) windowsBundleRestore {
	var out windowsBundleRestore
	fail := func(code, message string) windowsBundleRestore {
		out.errors = append(out.errors, enterprisestatus.Message{Code: code, Message: message})
		return out
	}
	if !windowsEnterpriseIsElevated() {
		return out
	}
	e, layout, driver, ok := readWindowsBundleEnforcement()
	if !ok || driver == nil {
		return out
	}
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		if errors.Is(err, errWindowsBundleStoreBusy) {
			return fail("lifecycle_busy", "another policy bundle run holds the bundle store; the confirmed bundle was not checked against config.yaml, and the run can be retried")
		}
		return fail("bundle_restore_failed", "cannot lock the policy bundle store to re-apply the confirmed bundle: "+windowsEnterpriseBoundedDiagnostic(err.Error()))
	}
	defer unlock()
	// Read again under the store lock: a bundle run may have just finished.
	e, layout, driver, ok = readWindowsBundleEnforcement()
	if !ok {
		return out
	}
	label := bundleLabel(e.Current)
	if e.CurrentErr != nil || e.CurrentConfig == nil {
		return fail("bundle_restore_failed", e.Problem())
	}
	if !e.ConfigReplaced() && e.InstalledConfig != nil {
		return out
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return fail("bundle_restore_failed", "cannot resolve the trusted enterprise roots to re-apply "+label+": "+windowsEnterpriseBoundedDiagnostic(err.Error()))
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fail("lifecycle_busy", "another DefenseClaw lifecycle run holds lifecycle.lock; "+label+" was not re-applied and the run can be retried")
		}
		return fail("bundle_restore_failed", "cannot open lifecycle.lock to re-apply "+label+": "+windowsEnterpriseBoundedDiagnostic(err.Error()))
	}
	defer release()
	if windowsBundleInstallTransactionPending(layout) {
		out.warnings = append(out.warnings, enterprisestatus.Message{Code: "bundle_restore_deferred",
			Message: "an install transaction is pending; its recovery restores the config it recorded first, and the next ensure re-applies " + label})
		return out
	}
	previous, err := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig)
	plan, err := e.planRestore(previous, err)
	if err != nil {
		return fail("bundle_restore_failed", "cannot read the installed config.yaml to re-apply "+label+": "+windowsEnterpriseBoundedDiagnostic(err.Error()))
	}
	if !plan.Write {
		return out
	}
	// A plain ensure already tried to settle unfinished receipts. If the
	// gateway could not answer, a committed candidate remains pending even
	// though the previous confirmed bundle is still current. Replacing the
	// candidate here would turn a confirmable receipt into a later failure.
	if pending, err := driver.CommittedPendingConfig(previous); err != nil {
		return fail("bundle_restore_failed", "cannot check pending policy bundle receipts before re-applying "+label+": "+windowsEnterpriseBoundedDiagnostic(err.Error()))
	} else if pending != nil {
		return out
	}
	// Every read comes before the first write: a restore that cannot prove
	// the bundle principal changed nothing, the edited config.yaml and its
	// rejected copy included (q-win-lifecycle review, loop round 3).
	restoreEnvironment := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer restoreEnvironment()
	writeOptions, ok, err := windowsBundleRestoreGenerationOptions(driver, e.CurrentConfig)
	if err != nil || !ok {
		detail := "the confirmed bundle config changed while waiting for the lifecycle lock"
		if err != nil {
			detail = windowsEnterpriseBoundedDiagnostic(err.Error())
		}
		return fail("bundle_restore_failed", "cannot prove the confirmed bundle principal ("+detail+"); run defenseclaw.exe enterprise windows ensure --profile standalone from an elevated prompt")
	}
	writeOptions.ExpectSHA256 = plan.ExpectSHA256
	missing := plan.Missing
	kept, was := "", "missing"
	if !missing {
		kept, was = keepWindowsEnterpriseRejectedConfig(layout, previous), "not the config of "+label
	}
	if err := windowsEnterpriseHotConfigWrite(ctx, layout.ConfigPath, e.CurrentConfig, writeOptions); err != nil {
		return fail("bundle_restore_failed", "config.yaml is "+was+" and re-applying "+label+" from the bundle store failed: "+
			windowsEnterpriseBoundedDiagnostic(err.Error()))
	}
	change := "config.yaml had been changed outside the lifecycle; re-applied " + label + " from the bundle store"
	if missing {
		change = "config.yaml was missing; re-applied " + label + " from the bundle store"
	} else if replacing != "" {
		change = "config.yaml was the config of " + replacing + ", which an interrupted run installed and the gateway never confirmed; re-applied " + label + " from the bundle store"
	}
	if kept != "" {
		change += " and kept the edited file at " + kept
	}
	out.changes = append(out.changes, change)
	if missing {
		out.warnings = append(out.warnings, enterprisestatus.Message{Code: "bundle_config_restored",
			Message: "config.yaml was missing; ensure re-applied " + label + " from the bundle store"})
	} else {
		out.warnings = append(out.warnings, enterprisestatus.Message{Code: "bundle_config_restored",
			Message: "config.yaml was not the config of " + label + "; ensure re-applied the bundle from the bundle store"})
	}
	if !windowsBundleRestoreGatewayRunning() {
		// The ensure that follows starts the gateway on the restored config.
		return out
	}
	if err := windowsEnterpriseHotBundleReload(ctx, layout); err != nil {
		out.warnings = append(out.warnings, enterprisestatus.Message{Code: "bundle_reload_request_failed",
			Message: "the direct gateway reload request failed; waiting for the gateway's file watcher: " + windowsEnterpriseBoundedDiagnostic(err.Error())})
	}
	if windowsEnterpriseHotConfigAdopted(ctx, windowsEnterpriseHotConfigTimeout, configwrite.BundleRef{}) {
		return out
	}
	// A key the gateway reads only at start (the edit may have changed one)
	// needs a restart. The health check of this run reports bundle_not_applied
	// when the gateway still does not enforce the bundle after it.
	if restarted, err := windowsEnterpriseHotConfigRestart(); err != nil || !restarted {
		detail := "the gateway did not restart"
		if err != nil {
			detail += ": " + windowsEnterpriseBoundedDiagnostic(err.Error())
		}
		out.warnings = append(out.warnings, enterprisestatus.Message{Code: "bundle_gateway_restart_failed",
			Message: "the gateway did not adopt the re-applied " + label + " and " + detail})
		return out
	}
	out.changes = append(out.changes, "restarted the gateway on the re-applied "+label)
	_ = windowsEnterpriseHotConfigAdopted(ctx, windowsEnterpriseHotConfigRestartTimeout, configwrite.BundleRef{})
	return out
}
