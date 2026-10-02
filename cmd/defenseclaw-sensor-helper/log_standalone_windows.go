// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// standaloneSensorHelperLogSDDL is the administrator-only directory the
// standalone helper creates for its log: owned by Administrators, SYSTEM and
// Administrators full control, inheritance protected.
const standaloneSensorHelperLogSDDL = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

var (
	standaloneServiceHosted    = svc.IsWindowsService
	standaloneWindowsLayout    = managed.StandaloneWindowsLayout
	standaloneLogDirTrustCheck = func(path string) error {
		return managed.ValidateTrustedDirectoryAncestor(path, "sensor helper log root")
	}
	standaloneLogDirectoryMaker = createStandaloneSensorHelperLogDirectory
)

func init() {
	if path := standaloneSensorHelperServiceLogPath(); path != "" {
		_ = os.Setenv(windowsServiceLogEnv, path)
	}
}

// standaloneSensorHelperServiceLogPath names the standalone helper's service
// log when the service environment does not: the standalone lifecycle pins
// the profile (DEFENSECLAW_ENTERPRISE_PROFILE=standalone) in the helper's
// protected SCM environment, so the helper derives
// <state root>\logs\sensor-helper\sensor-helper.log from the fixed standalone
// layout and creates the directory administrator-only. Everything else (a
// Secure Client helper, a console run, an explicit log path) returns "" and
// keeps its current behavior. A path that cannot be prepared returns "" and
// the helper logs to stderr, exactly as without a log.
func standaloneSensorHelperServiceLogPath() string {
	if strings.TrimSpace(os.Getenv(windowsServiceLogEnv)) != "" {
		return ""
	}
	if !managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(os.Getenv(managed.EnterpriseProfileEnv))) {
		return ""
	}
	if hosted, err := standaloneServiceHosted(); err != nil || !hosted {
		return ""
	}
	layout, err := standaloneWindowsLayout()
	if err != nil || strings.TrimSpace(layout.LogDir) == "" {
		return ""
	}
	directory := filepath.Join(filepath.Clean(layout.LogDir), "sensor-helper")
	if err := prepareStandaloneSensorHelperLogDirectory(filepath.Clean(layout.LogDir), directory); err != nil {
		return ""
	}
	return filepath.Join(directory, "sensor-helper.log")
}

func prepareStandaloneSensorHelperLogDirectory(root, directory string) error {
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() {
			return errors.New("sensor helper log directory is not a directory")
		}
		// openHelperLog re-validates the directory before every open.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := standaloneLogDirTrustCheck(root); err != nil {
		return err
	}
	return standaloneLogDirectoryMaker(directory)
}

func createStandaloneSensorHelperLogDirectory(directory string) error {
	descriptor, err := windows.SecurityDescriptorFromString(standaloneSensorHelperLogSDDL)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(directory)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create sensor helper log directory: %w", err)
	}
	return nil
}
