// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"time"
)

func managedProcessOwnedBy(_, _, _ string) (bool, error) { return false, nil }
func rejectReparseAncestors(_ string) error              { return nil }
func rejectReparseExisting(_ string) error               { return nil }
func isReparsePoint(_ string) (bool, error)              { return false, nil }
func addUserPath(_ string) (bool, error)                 { return false, errors.New("Windows-only operation") }
func removeUserPath(_ string) error                      { return errors.New("Windows-only operation") }
func registerInstalledApp(_, _, _ string, _ bool) error  { return errors.New("Windows-only operation") }
func unregisterInstalledApp() error                      { return errors.New("Windows-only operation") }
func defaultInstallRoot() (string, error)                { return "", errors.New("Windows-only operation") }
func defaultDataRoot() (string, error)                   { return "", errors.New("Windows-only operation") }
func defaultOpenClawRoot() (string, error)               { return "", errors.New("Windows-only operation") }
func defaultMaintenancePath() (string, error)            { return "", errors.New("Windows-only operation") }
func waitForProcessExit(_ uint32, _ time.Duration) error { return errors.New("Windows-only operation") }
func removeDirectoryAfterExit(_ string, _ int) error     { return errors.New("Windows-only operation") }
