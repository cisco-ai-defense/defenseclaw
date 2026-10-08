// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

var (
	// windowsEnterpriseProcessSnapshot reads the process table; a seam for
	// tests.
	windowsEnterpriseProcessSnapshot = procprobe.Snapshot
	// windowsEnterpriseInstalledAt is when the standalone deployment was
	// installed: the creation time of its install root, which an upgrade
	// keeps and an uninstall removes. A seam for tests.
	windowsEnterpriseInstalledAt = func() (time.Time, bool) {
		roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
		if err != nil || strings.TrimSpace(roots.InstallRoot) == "" {
			return time.Time{}, false
		}
		info, err := os.Stat(filepath.Clean(roots.InstallRoot))
		if err != nil {
			return time.Time{}, false
		}
		data, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !ok || data.CreationTime.Nanoseconds() <= 0 {
			return time.Time{}, false
		}
		return time.Unix(0, data.CreationTime.Nanoseconds()), true
	}
)

// addWindowsEnterpriseAgentSessionWarnings names, per account, the agent CLI
// sessions that started before the deployment was installed, in the result
// of ensure, status and verify, as the Linux and macOS lifecycle does: such a
// session runs without DefenseClaw until it is restarted (GAP-0755). Only an
// administrator can read other users processes.
func addWindowsEnterpriseAgentSessionWarnings(result *enterprisestatus.Result) {
	switch result.Action {
	case "status", "verify", "install", "upgrade", "repair", "ensure":
	default:
		return
	}
	if !result.Installed || windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) || !windowsEnterpriseIsElevated() {
		return
	}
	installed, ok := windowsEnterpriseInstalledAt()
	if !ok {
		return
	}
	rows, _, err := windowsEnterpriseProcessSnapshot()
	if err != nil {
		return
	}
	for _, warning := range windowsAgentSessionWarnings(windowsAgentSessionsBefore(rows, installed), installed) {
		result.AddWarning(warning.Code, warning.Message)
	}
}
