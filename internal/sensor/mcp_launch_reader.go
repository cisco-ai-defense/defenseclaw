// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// The exec classifier reads a command's launchers with the effects program
// table (rel-1-0-10 GAP-1190). The host plane installs the reader: tactics
// cannot import effects without growing the slim hook binary past its budget.
func init() {
	tactics.SetLaunchReader(effectsLaunchReader())
}

// effectsLaunchReader is the tactics.LaunchReader of the effects program table.
func effectsLaunchReader() tactics.LaunchReader {
	return tactics.LaunchReader{
		Launched: func(argv []string, windows bool) ([]string, bool) {
			child, _, known := effects.LaunchedArgv(argv, launchFlavor(windows))
			return child, known
		},
		Modeled: func(program string, windows bool) bool {
			return effects.ModeledProgram(program, launchFlavor(windows))
		},
	}
}

func launchFlavor(windows bool) effects.Flavor {
	if windows {
		return effects.FlavorWindows
	}
	return effects.FlavorPOSIX
}
