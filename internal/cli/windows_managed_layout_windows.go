// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsManagedStandaloneLayout is windowsManagedLayout's layout as a
// function value, for the package's layout seams that default to it.
func windowsManagedStandaloneLayout() (managed.StandaloneLayout, error) {
	return hookcli.WindowsManagedLayout.Standalone()
}

// windowsManagedRoots is windowsManagedLayout's roots as a function value,
// for the package's roots seams that default to it.
func windowsManagedRoots(profile string) (winpath.EnterpriseRoots, error) {
	return hookcli.WindowsManagedLayout.Roots(profile)
}
