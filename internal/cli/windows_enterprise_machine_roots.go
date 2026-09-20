// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/winpath"

type windowsEnterpriseMachineRoots = winpath.TrustedMachineRoots

func resolveWindowsEnterpriseMachineRoots() (windowsEnterpriseMachineRoots, error) {
	return winpath.ResolveTrustedMachineRoots()
}

func validateWindowsEnterpriseMachineRoot(value, label string) (string, error) {
	return winpath.ValidateTrustedMachineRoot(value, label)
}

func trustedWindowsEnterpriseProgramFiles() (string, error) {
	return winpath.TrustedProgramFiles()
}

func trustedWindowsEnterpriseProgramData() (string, error) {
	return winpath.TrustedProgramData()
}
