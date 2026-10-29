// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

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

// bundleCurrentConfig is the config.yaml of the confirmed bundle rendered
// from the bundle store against its version directory: the bytes the apply
// of a repeat (already_applied) installs again over a drifted config.yaml;
// nil when no bundle is confirmed. A seam for tests.
var bundleCurrentConfig = func() ([]byte, error) {
	store, err := bundleStore()
	if err != nil {
		return nil, err
	}
	raw, _, err := (&enterprisebundle.Driver{Store: store}).CurrentConfig()
	return raw, err
}

// bundleManagedDefaults are the omitted-setting values of this device's
// layout; none when the layout does not resolve, so every change counts.
func bundleManagedDefaults(platform string) configwrite.ManagedDefaults {
	layout, err := enterprisebundle.Layout(platform)
	if err != nil {
		return configwrite.ManagedDefaults{}
	}
	return configwrite.ManagedDefaultsFor(layout)
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
// change in time, as the apply does. defaults are the device's, as the
// apply passes them.
func predictBundleRestart(goos string, defaults configwrite.ManagedDefaults, installed []byte, readErr error, next []byte) *bundleRestartPrediction {
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
	restart, err := configwrite.ManagedConfigRestartRequired(installed, next, defaults)
	if err != nil {
		return unknown
	}
	if goos == "windows" {
		if windowsConfigCodexTargetChanged(installed, next) {
			return &bundleRestartPrediction{GatewayRestart: bundleRestartRequired, ReasonCodes: []string{restartReasonCodexMachinePolicy},
				Settings: configwrite.RestartSettingPatterns(restart)}
		}
		restart, _ = windowsBundleStartOnlyPaths(restart)
		restart = append(restart, windowsPrimaryConnectorChange(installed, next)...)
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

// windowsPrimaryConnectorChange returns guardrail.connector when the change
// moves the gateway's primary connector: the explicit guardrail.connector,
// or, when none is set, the first guardrail.connectors key in sorted order
// (config.dropRetiredConnectorSettings). The gateway reads it only at start
// and holds the running one on a reload (guardrailNeedsRestart), so a
// connector-set change that moves it, such as removing the first connector
// entry, is start-only even though the connector set itself applies in
// place: without a restart the gateway never reports the bundle policy
// (bundle_policy_not_adopted, GAP-1498). A config that does not parse
// counts as a change.
func windowsPrimaryConnectorChange(before, after []byte) []string {
	b, errB := windowsPrimaryConnector(before)
	a, errA := windowsPrimaryConnector(after)
	if errB == nil && errA == nil && a == b {
		return nil
	}
	return []string{"guardrail.connector"}
}

func windowsPrimaryConnector(raw []byte) (string, error) {
	var doc struct {
		Guardrail struct {
			Connector  string               `yaml:"connector"`
			Connectors map[string]yaml.Node `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	if primary := strings.ToLower(strings.TrimSpace(doc.Guardrail.Connector)); primary != "" {
		return primary, nil
	}
	keys := make([]string, 0, len(doc.Guardrail.Connectors))
	for key := range doc.Guardrail.Connectors {
		keys = append(keys, strings.ToLower(strings.TrimSpace(key)))
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "", nil
	}
	return keys[0], nil
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
// this device, classified against the installed config. For a repeat of the
// confirmed bundle (already_applied) it also returns config_drift: whether
// the installed config.yaml is not the confirmed bundle's config, which the
// apply then installs again (nil when that could not be checked). The
// prediction of a repeat compares the installed config with exactly those
// bytes: no drift is not_required, reason already_applied; drift is
// classified like any change, so a drift in hot settings is not_required
// with no reason code and still needs the apply.
func bundleVerifyRestartPrediction(platform string, out *enterprisebundle.VerifyResult) (*bundleRestartPrediction, *bool) {
	installed, err := bundleInstalledConfig(platform)
	next := out.Rendered
	var drift *bool
	if out.AlreadyApplied {
		if current, currentErr := bundleCurrentConfig(); currentErr == nil && current != nil {
			next = current
			switch {
			case err == nil:
				drifted := !bytes.Equal(installed, current)
				drift = &drifted
			case errors.Is(err, fs.ErrNotExist):
				// The apply restores a deleted config.yaml too (GAP-0114).
				drifted := true
				drift = &drifted
			}
		}
	}
	if drift != nil && !*drift {
		return &bundleRestartPrediction{GatewayRestart: bundleRestartNotRequired, ReasonCodes: []string{restartReasonAlreadyApplied}}, drift
	}
	return predictBundleRestart(platform, bundleManagedDefaults(platform), installed, err, next), drift
}

// windowsBundleRestartDeferral is the Driver.RefuseRestart of a Windows
// apply --defer-restart: the reason the verify restart prediction gives for
// a bundle that restarts the gateway or whose restart cannot be told.
func windowsBundleRestartDeferral(enforced, rendered []byte) string {
	return bundleRestartDeferral(predictBundleRestart("windows", bundleManagedDefaults("windows"), enforced, nil, rendered))
}

// bundleRestartDeferral is the restart_deferred detail of a prediction; ""
// when the bundle applies without a restart.
func bundleRestartDeferral(p *bundleRestartPrediction) string {
	switch p.GatewayRestart {
	case bundleRestartNotRequired:
		return ""
	case bundleRestartRequired:
		settings := p.Settings
		if len(settings) == 0 {
			settings = p.ReasonCodes
		}
		return enterprisebundle.RestartDeferralReason(settings, false)
	}
	return enterprisebundle.RestartDeferralReason(nil, true)
}

// windowsBundleConfigChange includes a signed delivery that must restore
// drift in the currently confirmed config.
func windowsBundleConfigChange(p *enterprisebundle.Prepared) bool {
	return p != nil && (p.Receipt != nil || p.AlreadyApplied)
}
