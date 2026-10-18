// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// restart_prediction values of bundle verify --json.
const (
	bundleRestartRequired    = "required"
	bundleRestartNotRequired = "not_required"
	bundleRestartUnknown     = "unknown"

	restartReasonSettings            = "restart_settings"
	restartReasonCodexMachinePolicy  = "codex_machine_policy"
	restartReasonFleetSetup          = "fleet_setup_required"
	restartReasonAlreadyApplied      = "already_applied"
	restartReasonInstalledUnreadable = "installed_config_unreadable"
)

// bundleInstalledConfigMaxBytes bounds the installed config.yaml read for
// the prediction, as the apply bounds it.
const bundleInstalledConfigMaxBytes = 4 << 20

// bundleInstalledConfig reads the config.yaml an apply on this device
// replaces; a seam for tests.
var bundleInstalledConfig = func(platform string) ([]byte, error) {
	layout, err := enterprisebundle.Layout(platform)
	if err != nil {
		return nil, err
	}
	return safefile.ReadRegularFileBounded(layout.ConfigPath, bundleInstalledConfigMaxBytes)
}

// bundleRestartPrediction is restart_prediction: whether applying the
// verified bundle restarts the gateway (managed hooks fail closed while it
// restarts), so an agent can apply a required one only in its maintenance
// window. Settings are the restart-required settings, never change paths.
type bundleRestartPrediction struct {
	GatewayRestart string   `json:"gateway_restart"`
	ReasonCodes    []string `json:"reason_codes"`
	Settings       []string `json:"settings,omitempty"`
}

// predictBundleRestart classifies the change from the installed config to
// the bundle config verify rendered with the classifier the apply uses on
// goos. Linux and macOS keep the gateway running when no changed key is
// restart-required (enterpriseunix hotConfigApply). Windows refuses a Fleet
// change, runs the full transaction for a Codex protection change and
// restarts the gateway alone for the start-only keys (Windows hot config).
// not_required still restarts a gateway that is down or does not adopt the
// change in time, as the apply does.
func predictBundleRestart(goos string, installed []byte, readErr error, next []byte) *bundleRestartPrediction {
	unknown := &bundleRestartPrediction{GatewayRestart: bundleRestartUnknown, ReasonCodes: []string{restartReasonInstalledUnreadable}}
	if readErr != nil || len(installed) == 0 {
		return unknown
	}
	if goos == "windows" {
		before, beforeErr := config.FleetEnabledFromSource(enterprisebundle.ConfigName, installed)
		after, afterErr := config.FleetEnabledFromSource(enterprisebundle.ConfigName, next)
		switch {
		case beforeErr != nil || afterErr != nil:
			return unknown
		case before != after:
			return &bundleRestartPrediction{GatewayRestart: bundleRestartUnknown, ReasonCodes: []string{restartReasonFleetSetup}}
		}
	}
	restart, err := configwrite.ManagedConfigRestartRequired(installed, next)
	if err != nil {
		return unknown
	}
	if goos == "windows" {
		if windowsConfigCodexTargetChanged(installed, next) {
			return &bundleRestartPrediction{GatewayRestart: bundleRestartRequired, ReasonCodes: []string{restartReasonCodexMachinePolicy},
				Settings: configwrite.RestartSettingPatterns(restart)}
		}
		restart, _ = windowsBundleStartOnlyPaths(restart)
	}
	if len(restart) == 0 {
		return &bundleRestartPrediction{GatewayRestart: bundleRestartNotRequired, ReasonCodes: []string{}}
	}
	return &bundleRestartPrediction{GatewayRestart: bundleRestartRequired, ReasonCodes: []string{restartReasonSettings},
		Settings: configwrite.RestartSettingPatterns(restart)}
}

// windowsBundleStartOnlyPaths splits the restart-required paths of a
// Windows config change into the start-only ones, which restart the
// gateway, and reports whether the rest change the enrolled targets, which
// the running deployment applies (windowsEnterpriseHotTargetsPath). The
// Windows hot config path and the bundle verify prediction share it.
func windowsBundleStartOnlyPaths(restart []string) (startOnly []string, refreshTargets bool) {
	for _, path := range restart {
		if !windowsEnterpriseHotTargetsPath(path) {
			startOnly = append(startOnly, path)
			continue
		}
		refreshTargets = true
	}
	return startOnly, refreshTargets
}

// windowsEnterpriseHotTargetsPath reports a restart-required change
// (configwrite.ManagedRestartRequired) that the Windows hot path applies
// all the same: an enrollment list (enterprise.enrollment include_users,
// exclude_users, include_groups, exclude_groups, exempt_users) or the
// connector set (guardrail.connectors.<name>[.enabled]). The gateway reads
// neither at start here, the enumerator reads config.yaml on every cycle,
// and the guardian reloads a changed config before it reconciles. Every
// other enterprise key still goes through the upgrade transaction.
func windowsEnterpriseHotTargetsPath(path string) bool {
	switch path {
	case "enterprise.enrollment.include_users", "enterprise.enrollment.exclude_users",
		"enterprise.enrollment.include_groups", "enterprise.enrollment.exclude_groups",
		"enterprise.enrollment.exempt_users":
		return true
	}
	parts := strings.Split(path, ".")
	return len(parts) >= 3 && len(parts) <= 4 && parts[0] == "guardrail" && parts[1] == "connectors" &&
		(len(parts) == 3 || parts[3] == "enabled")
}

// bundleVerifyRestartPrediction is the prediction for a verified bundle on
// this device: the repeat of the confirmed bundle changes nothing, any
// other bundle is classified against the installed config.
func bundleVerifyRestartPrediction(platform string, out *enterprisebundle.VerifyResult) *bundleRestartPrediction {
	if out.AlreadyApplied {
		return &bundleRestartPrediction{GatewayRestart: bundleRestartNotRequired, ReasonCodes: []string{restartReasonAlreadyApplied}}
	}
	installed, err := bundleInstalledConfig(platform)
	return predictBundleRestart(platform, installed, err, out.Rendered)
}
