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

package hookcli

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// StandaloneEnterprisePolicyLayout resolves the layout from the protected
// HKLM machine roots, never from the caller's environment.
func StandaloneEnterprisePolicyLayout() (managed.StandaloneLayout, string, string, error) {
	programFiles, err := TrustedWindowsEnterpriseProgramFiles()
	if err != nil {
		return managed.StandaloneLayout{}, "", "", err
	}
	programData, err := TrustedWindowsEnterpriseProgramData()
	if err != nil {
		return managed.StandaloneLayout{}, "", "", err
	}
	layout, err := managed.StandaloneWindowsLayoutForRoots(programFiles, programData)
	return layout, programFiles, programData, err
}

// HookForeignGuardAccountHome returns the profile directory of the
// process token (never the agent's environment): the guardian installs
// DefenseClaw's per-user registrations there. Replaceable in tests.
var HookForeignGuardAccountHome = func() string {
	if account, err := user.Current(); err == nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	return ""
}

// HookForeignGuardEnvHomes lists the homes the agent's environment names
// (USERPROFILE as inherited from the agent), which it may read hook config
// from. Replaceable in tests.
var HookForeignGuardEnvHomes = func() []string {
	return []string{os.Getenv("USERPROFILE")}
}
