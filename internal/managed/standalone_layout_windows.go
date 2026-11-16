//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "github.com/defenseclaw/defenseclaw/internal/winpath"

// StandaloneWindowsScannerRuntimeDir resolves the scanner runtime root from
// the trusted ProgramData registration.
func StandaloneWindowsScannerRuntimeDir() (string, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", err
	}
	return StandaloneWindowsScannerRuntimeDirForRoot(programData), nil
}

// StandaloneWindowsLayout resolves the standalone layout from the protected
// HKLM Program Files and ProgramData registration, never from the caller's
// ProgramFiles/ProgramData environment variables.
func StandaloneWindowsLayout() (StandaloneLayout, error) {
	programFiles, programData, err := TrustedStandaloneWindowsRoots()
	if err != nil {
		return StandaloneLayout{}, err
	}
	return StandaloneWindowsLayoutForRoots(programFiles, programData)
}

// TrustedStandaloneWindowsRoots returns the Program Files and ProgramData
// roots from the protected HKLM registration.
func TrustedStandaloneWindowsRoots() (programFiles, programData string, err error) {
	if programFiles, err = winpath.TrustedProgramFiles(); err != nil {
		return "", "", err
	}
	if programData, err = winpath.TrustedProgramData(); err != nil {
		return "", "", err
	}
	return programFiles, programData, nil
}
