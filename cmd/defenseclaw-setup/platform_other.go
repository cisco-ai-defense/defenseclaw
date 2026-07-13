// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"time"
)

func managedProcessOwnedBy(_, _, _ string) (bool, error) { return false, nil }
func acquireSetupLock() (func() error, error) {
	return func() error { return nil }, nil
}
func rejectReparseAncestors(_ string) error { return nil }
func rejectReparseExisting(_ string) error  { return nil }
func isReparsePoint(_ string) (bool, error) { return false, nil }
func addUserPath(_ string) (bool, bool, error) {
	return false, false, errors.New("Windows-only operation")
}
func captureUserPath() (userPathSnapshot, error) {
	return userPathSnapshot{}, errors.New("Windows-only operation")
}
func removeUserPath(_ string, _ bool) error { return errors.New("Windows-only operation") }
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
