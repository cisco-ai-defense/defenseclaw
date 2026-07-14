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
	return false, false, false, errors.New("Windows-only operation")
}
func captureUserPath() (userPathSnapshot, error) {
	return userPathSnapshot{}, errors.New("Windows-only operation")
}
func removeUserPath(_ string, _, _ bool) error { return errors.New("Windows-only operation") }
func registerInstalledApp(_, _, _, _ string, _ bool) error {
	return errors.New("Windows-only operation")
}
func unregisterInstalledApp() error               { return errors.New("Windows-only operation") }
func validateInstalledAppMutation(_ string) error { return errors.New("Windows-only operation") }
func registerInstalledAppOwned(_, _, _, _ string, _ bool) error {
	return errors.New("Windows-only operation")
}
func unregisterInstalledAppOwned(_ string) error { return errors.New("Windows-only operation") }
func configureGatewayAutoStart(_ string, _ bool) (gatewayAutoStartSnapshot, bool, error) {
	return gatewayAutoStartSnapshot{}, false, errors.New("Windows-only operation")
}
func captureGatewayAutoStart() (gatewayAutoStartSnapshot, error) {
	return gatewayAutoStartSnapshot{}, errors.New("Windows-only operation")
}
func defaultInstallRoot() (string, error)                   { return "", errors.New("Windows-only operation") }
func defaultDataRoot() (string, error)                      { return "", errors.New("Windows-only operation") }
func defaultProfileRoot() (string, error)                   { return "", errors.New("Windows-only operation") }
func defaultOpenClawRoot() (string, error)                  { return "", errors.New("Windows-only operation") }
func defaultMaintenancePath() (string, error)               { return "", errors.New("Windows-only operation") }
func defaultTransactionRoot() (string, error)               { return "", errors.New("Windows-only operation") }
func defaultPayloadTempRoot() (string, error)               { return "", errors.New("Windows-only operation") }
func renameDurableFile(source, destination string) error    { return os.Rename(source, destination) }
func replaceDurableFile(source, destination string) error   { return os.Rename(source, destination) }
func validatePrivateTransactionPath(_ string, _ bool) error { return nil }
func waitForProcessExit(_ uint32, _ time.Duration) error    { return errors.New("Windows-only operation") }
func removeDirectoryAfterExit(_ string, _ int) error        { return errors.New("Windows-only operation") }
func publishStableHookRuntime(_, _, _ string) error         { return errors.New("Windows-only operation") }
func disableStableHookRuntime(_ string) error               { return errors.New("Windows-only operation") }

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
