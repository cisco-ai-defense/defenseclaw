// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsManagedLayout is where internal/cli finds this computer's own
// standalone deployment: its layout (managed.StandaloneWindowsLayout) and
// its trusted enterprise roots (winpath.TrustedEnterpriseRoots), both
// resolved from the protected HKLM Program Files and ProgramData
// registration. Every non-test file asks it, at the moment it asked the
// resolver before, so production resolves the same values at the same time.
//
// The package's tests point it at roots under their own temp folder once, in
// TestMain (isolateTestDeploymentReaders), so a test that reaches a lifecycle,
// guardian or status path without its own stub reads a missing deployment
// instead of a managed computer's real one (cowork-1-0-8 GAP-0093). Several
// callers decide trust from these roots (the hook executable check, the
// install and lifecycle folders), so nothing outside the tests may change
// it: TestWindowsManagedLayoutIsTheOneSourceOfTheDeploymentRoots fails on a
// non-test file that assigns it or that calls either resolver directly. The
// Secure Client profile's own lookups are left as they are.
var windowsManagedLayout = struct {
	standalone func() (managed.StandaloneLayout, error)
	roots      func(profile string) (winpath.EnterpriseRoots, error)
	// programRoots is the protected 64-bit Program Files and ProgramData
	// registrations, each empty when it cannot be read. The guardian's
	// self-heal asks it (repairEnterpriseHookManagedInstallPlatform) for the
	// roots it derives its install and state layout from.
	programRoots func() (programFiles, programData string)
}{
	standalone:   managed.StandaloneWindowsLayout,
	roots:        winpath.TrustedEnterpriseRoots,
	programRoots: trustedWindowsProgramRoots,
}

// trustedWindowsProgramRoots is windowsManagedLayout.programRoots in
// production: the two registrations, an unreadable one as an empty path.
func trustedWindowsProgramRoots() (programFiles, programData string) {
	programFiles, _ = winpath.TrustedProgramFiles()
	programData, _ = winpath.TrustedProgramData()
	return programFiles, programData
}

// windowsManagedStandaloneLayout is windowsManagedLayout's layout as a
// function value, for the package's layout seams that default to it.
func windowsManagedStandaloneLayout() (managed.StandaloneLayout, error) {
	return windowsManagedLayout.standalone()
}

// windowsManagedRoots is windowsManagedLayout's roots as a function value,
// for the package's roots seams that default to it.
func windowsManagedRoots(profile string) (winpath.EnterpriseRoots, error) {
	return windowsManagedLayout.roots(profile)
}
