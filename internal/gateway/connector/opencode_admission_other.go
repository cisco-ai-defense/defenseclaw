// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

func validateOpenCodeWindowsSetupAdmission(SetupOpts) error { return nil }

func validateOpenCodeWindowsLockPublication(string, HookContractLockEntry) error { return nil }

// OpenCodeWindowsPackageIdentityVerified is Windows-only; other platforms do
// not select OpenCode images.
func OpenCodeWindowsPackageIdentityVerified(string) bool { return false }
