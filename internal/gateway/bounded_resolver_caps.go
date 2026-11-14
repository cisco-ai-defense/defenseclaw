// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// trustedResolverCaps are the caps the one write-operand resolver hit reading
// the call (bounded.Paths: a word expanded past hookpaths.MaxResolvedCandidates).
// A managed gateway cannot read the home: the hook client tells it under
// UnprovenReasonKey (hookpaths.UnprovenBoundedPaths). A per-user gateway reads
// the call itself, as it reads the shell parse bound
// (trustedCallShellParseBound).
func trustedResolverCaps(request trustedActionRequest) bounded.CapSet {
	if request.ProtectedHomeHook {
		if request.ResolvedWriteTargets[hookpaths.UnprovenReasonKey] == hookpaths.UnprovenBoundedPaths {
			return bounded.Of(bounded.Paths)
		}
		return bounded.CapSet{}
	}
	command, ok := trustedBashCommandInput(request.Input)
	if !ok {
		return bounded.CapSet{}
	}
	return hookpaths.WriteOperandCaps(command, request.Input.CWD, request.Input.ActiveHome)
}
