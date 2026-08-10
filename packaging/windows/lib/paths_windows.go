// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package winpackage exposes the path anchors for the machine-level Windows
// bundle. These are the Windows peer of the anchors used by
// packaging/macos/lib/installer_lib.sh — install files under %ProgramFiles%,
// mutable state under %ProgramData%, matching the AVC-bundled shape agreed
// with the Cisco Secure Client AnyConnect team.
package winpackage

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	// ProductVendorDir is the directory segment shared with the rest of
	// Cisco Secure Client — every AVC-shipped module installs under a
	// sibling directory of this one.
	ProductVendorDir = `Cisco\Cisco Secure Client`

	// ProductLeafDir is the DefenseClaw leaf under the vendor directory.
	// Kept as a single segment so both %ProgramFiles% and %ProgramData%
	// use identical structure.
	ProductLeafDir = "DefenseClaw"

	// ServiceName is the SCM service name registered by
	// `defenseclaw-mgr service register`.
	ServiceName = "DefenseClawGateway"

	// ServiceDisplayName is the human-readable service name.
	ServiceDisplayName = "Cisco DefenseClaw Gateway"

	// EventLogSource is the Windows Event Log source registered by the
	// installer. Every mgr/service log write also emits to this source so
	// AVC's log-collection tooling picks it up without extra plumbing.
	EventLogSource = "DefenseClaw"

	// DeploymentModeEnv is the environment variable set on the
	// registered service — matches the macOS launchd EnvironmentVariables
	// entry and is read by internal/config/env_config_windows.go to route
	// data paths into %ProgramData%.
	DeploymentModeEnv = "DEFENSECLAW_DEPLOYMENT_MODE"

	// DeploymentModeManagedEnterprise is the value of DeploymentModeEnv
	// pinned on the service — see internal/config for the semantics.
	DeploymentModeManagedEnterprise = "managed_enterprise"
)

// InstallRoot returns %ProgramFiles%\Cisco\Cisco Secure Client\DefenseClaw.
//
// On ARM64 hosts running the amd64 bundle under x64 emulation the returned
// path is still the 64-bit Program Files tree — SHGetKnownFolderPath resolves
// FOLDERID_ProgramFiles to the 64-bit view for a native amd64 process, which
// is what AVC's MSI targets.
func InstallRoot() (string, error) {
	pf, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_ProgramFiles)
	if err != nil {
		return "", fmt.Errorf("resolve %%ProgramFiles%%: %w", err)
	}
	return filepath.Join(pf, ProductVendorDir, ProductLeafDir), nil
}

// DataRoot returns %ProgramData%\Cisco\Cisco Secure Client\DefenseClaw.
//
// This is the machine-level counterpart to %LOCALAPPDATA% used by the per-user
// Setup. Every file under this tree is ACLed so only SYSTEM and
// BUILTIN\Administrators can read or write it.
func DataRoot() (string, error) {
	pd, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_ProgramData)
	if err != nil {
		return "", fmt.Errorf("resolve %%ProgramData%%: %w", err)
	}
	return filepath.Join(pd, ProductVendorDir, ProductLeafDir), nil
}

// BinDir returns the install-root subdirectory that holds every PE shipped by
// the bundle.
func BinDir(installRoot string) string {
	return filepath.Join(installRoot, "bin")
}

// ConfigPath returns %ProgramData%\...\etc\config.yaml.
func ConfigPath(dataRoot string) string {
	return filepath.Join(dataRoot, "etc", "config.yaml")
}

// RuntimeDir returns %ProgramData%\...\runtime — audit DB, device.key, and
// other mutable state that must survive an upgrade.
func RuntimeDir(dataRoot string) string {
	return filepath.Join(dataRoot, "runtime")
}

// HookManifestPath returns the hook-guardian manifest path under %ProgramData%.
func HookManifestPath(dataRoot string) string {
	return filepath.Join(dataRoot, "hook-guardian", "targets.yaml")
}

// HookStateDir returns the hook-guardian auth-state directory.
func HookStateDir(dataRoot string) string {
	return filepath.Join(dataRoot, "hook-guardian-state")
}

// LogDir returns the log directory.
func LogDir(dataRoot string) string {
	return filepath.Join(dataRoot, "logs")
}

// LogFile returns %ProgramData%\...\logs\<name>.log for the named component
// (e.g. "mgr", "gateway").
func LogFile(dataRoot, name string) string {
	return filepath.Join(LogDir(dataRoot), name+".log")
}
