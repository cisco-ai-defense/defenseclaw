// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import "testing"

// requireElevatedMachinePolicyWindows is a no-op off Windows: only the
// Windows publisher creates Administrators-owned folders a standard user
// cannot assign (see elevated_windows_test.go).
func requireElevatedMachinePolicyWindows(t *testing.T) { t.Helper() }
