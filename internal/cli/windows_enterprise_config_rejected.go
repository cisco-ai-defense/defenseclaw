// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The rejected-config record of the standalone Windows deployment
// (enterprisestatus/config_rejected.go, rel-1-0-10 GAP-1027). Setup /ensure
// CONFIG= with a config whose run failed and rolled back left status and
// verify at ok and coverage_complete, as if the requested config were
// applied. A failed run given a config now records the rejection beside
// deployment.json, a successful one clears it, and status warns and verify
// fails with config_rejected while config.yaml is still the config it ran
// before the request.

// windowsEnterpriseConfigRejectedDir is the install state folder that holds
// deployment.json, and deployment.json itself, or "" without a trusted
// installed deployment record. A seam for tests.
var windowsEnterpriseConfigRejectedDir = func() (dir, deploymentRecord string) {
	deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone)
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled || deployment.MetadataPath == "" {
		return "", ""
	}
	return filepath.Dir(deployment.MetadataPath), deployment.MetadataPath
}

// writeWindowsEnterpriseConfigRejectedFile writes the record with
// deployment.json's access control; a seam for tests.
var writeWindowsEnterpriseConfigRejectedFile = writeFileKeepingDACL

// windowsEnterpriseConfigRequestAction reports an action that applies a
// supplied config.
func windowsEnterpriseConfigRequestAction(action string) bool {
	switch action {
	case "ensure", "install", "upgrade", "repair":
		return true
	}
	return false
}

func windowsEnterpriseBoundedConfigSHA256(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	raw, err := readWindowsEnterpriseBoundedFile(path, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return ""
	}
	return sha256HexBytes(raw)
}

// windowsEnterpriseInstalledConfigSHA256 is the digest of the installed
// config.yaml, or "" when it cannot be read.
func windowsEnterpriseInstalledConfigSHA256() string {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return ""
	}
	return windowsEnterpriseBoundedConfigSHA256(layout.ConfigPath)
}

// noteWindowsEnterpriseConfigRequest records, once per run and before it
// changes anything, the digests of the supplied config and of the installed
// config.yaml. A run without a supplied config, and a signed bundle run (its
// receipts report a failed bundle), records nothing.
func noteWindowsEnterpriseConfigRequest(action string, opts *windowsEnterpriseLifecycleOptions) {
	if opts == nil || opts.configRequestNoted {
		return
	}
	opts.configRequestNoted = true
	if !windowsEnterpriseConfigRequestAction(action) || strings.TrimSpace(opts.configPath) == "" || opts.bundle != nil {
		return
	}
	opts.configRequestedSHA256 = windowsEnterpriseBoundedConfigSHA256(opts.configPath)
	opts.configInstalledSHA256AtStart = windowsEnterpriseInstalledConfigSHA256()
}

// recordWindowsEnterpriseConfigOutcome writes or clears the record for a
// finished run given a config (enterprisestatus.DecideConfigRejected). A
// failure to write is a warning: it never changes the run's verdict.
func recordWindowsEnterpriseConfigOutcome(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil || opts == nil || opts.configRequestedSHA256 == "" || !windowsEnterpriseConfigRequestAction(result.Action) ||
		!windowsEnterpriseIsElevated() || windowsEnterpriseOutsideProductionScope(opts) {
		return
	}
	dir, deploymentRecord := windowsEnterpriseConfigRejectedDir()
	if dir == "" {
		return
	}
	path := filepath.Join(dir, enterprisestatus.ConfigRejectedFileName)
	installed := windowsEnterpriseInstalledConfigSHA256()
	switch enterprisestatus.DecideConfigRejected(result, opts.configRequestedSHA256, opts.configInstalledSHA256AtStart, installed, enterprisestatus.WindowsExitFailure) {
	case enterprisestatus.ConfigRejectedWrite:
		data, err := enterprisestatus.NewConfigRejectedRecord(result, opts.configRequestedSHA256, installed, windowsEnterpriseNow()).Marshal()
		if err == nil {
			err = writeWindowsEnterpriseConfigRejectedFile(path, data, deploymentRecord)
		}
		if err != nil {
			result.AddWarning("config_rejected_unrecorded", "could not record "+enterprisestatus.ConfigRejectedFileName+
				", so status and verify cannot report that the supplied config is not applied: "+err.Error())
		}
	case enterprisestatus.ConfigRejectedClear:
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			result.AddWarning("config_rejected_unsettled", "could not remove "+enterprisestatus.ConfigRejectedFileName+
				", so status and verify may still report the previous request as not applied: "+err.Error())
		}
	}
}

// applyWindowsEnterpriseConfigRejected reports a current record on status
// and verify of an elevated caller.
func applyWindowsEnterpriseConfigRejected(result *enterprisestatus.Result) {
	if result == nil || !windowsEnterpriseIsElevated() {
		return
	}
	dir, _ := windowsEnterpriseConfigRejectedDir()
	if dir == "" {
		return
	}
	raw, err := readWindowsEnterpriseBoundedFile(filepath.Join(dir, enterprisestatus.ConfigRejectedFileName), enterprisestatus.ConfigRejectedMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		// Unreadable is reported, not taken as absent.
		raw = []byte{}
	}
	logPath := ""
	if directory, err := windowsEnterpriseLogDirectory(); err == nil {
		logPath = filepath.Join(directory, windowsEnterpriseLogName)
	}
	result.ApplyConfigRejected(raw, windowsEnterpriseInstalledConfigSHA256(),
		windowsEnterpriseSetupCommand("/ensure", "CONFIG=<approved absolute config path>", "JSON=1")+" from an elevated PowerShell prompt", logPath)
}
