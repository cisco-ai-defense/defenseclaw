// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsEnterpriseConfigGenerationRepair is
// repairWindowsEnterpriseConfigGeneration; tests replace it.
var windowsEnterpriseConfigGenerationRepair = repairWindowsEnterpriseConfigGeneration

// windowsEnterpriseNewBundleDelivery reports a signed bundle this run applies
// for the first time. Its staged config is not the administrator's approved
// copy of the installed one: when its bytes equal the installed base, the
// recovery below read the record (not yet bound to the bundle) as damaged and
// rewrote it under a new generation, so the installed CLI's policy proof no
// longer matched the running gateway and the first bundle failed
// bundle_hot_apply_unavailable, then not_confirmed (GAP-1577, a regression of
// GAP-0359). The bundle apply records its own generation.
func windowsEnterpriseNewBundleDelivery(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && opts.bundle != nil && opts.bundle.prepared != nil && !opts.bundle.prepared.AlreadyApplied
}

// Recover a damaged counter only when the administrator supplied the exact
// installed config. The live gateway provides a counter that must not be
// lost when the service stops. Both lifecycle and config locks protect the
// repair; a changed file or unproven counter is refused before any write.
func repairWindowsEnterpriseConfigGeneration(ctx context.Context, opts *windowsEnterpriseLifecycleOptions, status *windowsEnterpriseInstallerReport) (bool, error) {
	if windowsEnterpriseNewBundleDelivery(opts) {
		return false, nil
	}
	if !status.Installed || status.TransactionPending || opts.configPath == "" ||
		!windowsEnterpriseIsElevated() || compareWindowsEnterpriseVersions(opts.productVersion, status.InstalledVersion) < 0 {
		return false, nil
	}
	approved, err := readWindowsEnterpriseBoundedFile(opts.configPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return false, nil
	} // The ordinary source preflight reports it.
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	installed, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || !bytes.Equal(approved, installed) {
		return false, nil
	}
	attribution, _, err := managedStandaloneBundleGeneration(layout.ConfigPath, installed)
	if err != nil {
		return false, err
	}
	state, stateErr := configwrite.ReadGenerationState(layout.ConfigPath)
	if stateErr == nil && managedStandaloneGenerationMatches(state, installed, attribution) {
		return false, nil
	}
	// 0.8.10 and 1.0.0 predate generation tracking. Keep their supported
	// bootstrap, but never infer legacy state from an unknown version or
	// merely because this package is newer than the installed one.
	_, _, knownVersion := parseWindowsEnterpriseVersion(status.InstalledVersion)
	if errors.Is(stateErr, os.ErrNotExist) && knownVersion && compareWindowsEnterpriseVersions(status.InstalledVersion, "1.0.1") < 0 {
		return false, nil
	}
	if err := windowsEnterpriseStandaloneConfigSource(opts.configPath); err != nil {
		return false, err
	}
	if err := managed.ValidateTrustedFilePath(layout.ConfigPath, "installed config for generation recovery"); err != nil {
		return false, fmt.Errorf("refuse generation recovery from an untrusted installed config: %w; restore its administrator-only write ACL, then run DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=<approved absolute config path> JSON=1", err)
	}
	out, _ := windowsEnterprisePolicyDigest(ctx)
	var report policyDigestReport
	_ = json.Unmarshal(out, &report)
	floor := max(state.Generation, attribution.GenerationFloor)
	if report.GatewayReportedDigest != "" {
		floor = max(floor, report.GatewayReportedConfigGeneration)
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, err
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return false, fmt.Errorf("lifecycle_busy: cannot take lifecycle.lock to recover config generation; retry ensure after the current lifecycle finishes: %w", err)
	}
	defer release()
	pins := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer pins()
	return repairManagedStandaloneConfigGeneration(ctx, layout.ConfigPath, approved, floor)
}
