// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func managedProcessOwnedBy(_, _, _ string) (bool, error) { return false, nil }
func acquireSetupLock() (func() error, error) {
	return func() error { return nil }, nil
}
func rejectReparseAncestors(_ string) error { return nil }
func rejectReparseExisting(_ string) error  { return nil }
func isReparsePoint(_ string) (bool, error) { return false, nil }
func addUserPath(_ string) (bool, bool, bool, error) {
	return false, false, false, errors.New("windows-only operation")
}
func captureUserPath() (userPathSnapshot, error) {
	return userPathSnapshot{}, errors.New("windows-only operation")
}
func removeUserPath(_ string, _, _ bool) error { return errors.New("windows-only operation") }
func validateInstalledAppMutation(_ string, _ *installState) error {
	return errors.New("windows-only operation")
}
func registerInstalledAppOwned(_, _, _, _ string, _ bool, _ *installState) error {
	return errors.New("windows-only operation")
}
func retireInstalledAppPendingOwned(_, _ string) error {
	return errors.New("windows-only operation")
}
func unregisterInstalledAppOwned(_ string, _ *installState) error {
	return errors.New("windows-only operation")
}
func configureGatewayAutoStart(_ string, _ bool) (gatewayAutoStartSnapshot, bool, error) {
	return gatewayAutoStartSnapshot{}, false, errors.New("windows-only operation")
}
func captureGatewayAutoStart() (gatewayAutoStartSnapshot, error) {
	return gatewayAutoStartSnapshot{}, errors.New("windows-only operation")
}
func createExclusiveUnpublishedFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
func gatewayAutoStartValueOwned(gatewayPath, value string) (bool, error) {
	return value == gatewayAutoStartCommand(gatewayPath) || value == legacyGatewayAutoStartCommand(gatewayPath), nil
}
func defaultInstallRoot() (string, error)                   { return "", errors.New("windows-only operation") }
func defaultDataRoot() (string, error)                      { return "", errors.New("windows-only operation") }
func defaultProfileRoot() (string, error)                   { return "", errors.New("windows-only operation") }
func defaultOpenClawRoot() (string, error)                  { return "", errors.New("windows-only operation") }
func defaultMaintenancePath() (string, error)               { return "", errors.New("windows-only operation") }
func defaultTransactionRoot() (string, error)               { return "", errors.New("windows-only operation") }
func defaultPayloadTempRoot() (string, error)               { return "", errors.New("windows-only operation") }
func renameDurableFile(source, destination string) error    { return os.Rename(source, destination) }
func replaceDurableFile(source, destination string) error   { return os.Rename(source, destination) }
func validatePrivateTransactionPath(_ string, _ bool) error { return nil }
func waitForProcessExit(_ uint32, _ time.Duration) error    { return errors.New("windows-only operation") }
func removeDirectoryAfterExit(_, _ string, _ int, _ string) error {
	return errors.New("windows-only operation")
}
func publishStableHookRuntime(_, _, _, _ string) error { return errors.New("windows-only operation") }
func disableStableHookRuntime(_ string) error          { return errors.New("windows-only operation") }

// These pure helpers keep the transaction package cross-compilable for the
// repository-wide Linux/macOS test lanes. Production setup is Windows-only,
// but common transaction validation still references the Windows PATH shape.
func prependUserPathEntry(current, commandDir string) (string, bool) {
	reusedSeparator := strings.HasPrefix(current, ";")
	separator := ";"
	if current == "" || reusedSeparator {
		separator = ""
	}
	return commandDir + separator + current, reusedSeparator
}

func pathContains(entries []string, needle string) bool {
	needle = filepath.Clean(strings.Trim(needle, ` "`))
	for _, entry := range entries {
		if strings.EqualFold(filepath.Clean(strings.Trim(entry, ` "`)), needle) {
			return true
		}
	}
	return false
}
