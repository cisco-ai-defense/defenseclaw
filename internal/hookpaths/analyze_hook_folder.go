// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

// analyzeAtHookFolder is actionfacts.Analyze with every path read in the
// folder of the call (Facts.AtHookFolder). The readers here place each
// command by their own walk of the cd chain of the call (placed statements,
// evidence directories) and key the facts they send the gateway by it, so
// they read the facts the way they did before actionfacts tracked the
// working folder itself (rel-1-0-10:GAP-0870, GAP-0426): applying both moves
// would place a command twice, and keys the walk did not place would not
// match the gateway reading.
func analyzeAtHookFolder(input actionfacts.Input) actionfacts.Facts {
	return actionfacts.Analyze(input).AtHookFolder()
}
