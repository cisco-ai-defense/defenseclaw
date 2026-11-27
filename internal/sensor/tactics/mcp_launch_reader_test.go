// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import "github.com/defenseclaw/defenseclaw/internal/effects"

// The tests read launchers with the effects program table, as the host plane
// does (package sensor installs the same reader; it cannot be imported here).
func init() {
	flavor := func(windows bool) effects.Flavor {
		if windows {
			return effects.FlavorWindows
		}
		return effects.FlavorPOSIX
	}
	SetLaunchReader(LaunchReader{
		Launched: func(argv []string, windows bool) ([]string, bool) {
			child, _, known := effects.LaunchedArgv(argv, flavor(windows))
			return child, known
		},
		Modeled: func(program string, windows bool) bool { return effects.ModeledProgram(program, flavor(windows)) },
	})
}
