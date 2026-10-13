// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import "github.com/defenseclaw/defenseclaw/internal/config"

// Codes of the sandbox policy warnings every ensure, status and verify adds
// on Linux, macOS and Windows.
const (
	// CodeSandboxDefaultProfile: a field where default_profile (what offline
	// and unmatched users get) is looser than an assigned profile.
	CodeSandboxDefaultProfile = "sandbox_default_profile_looser"
	// CodeSandboxAdvisory: what the administrator should know about the
	// sandbox floors (config.SandboxAdvisories).
	CodeSandboxAdvisory = "sandbox_policy_advisory"
)

// AddSandboxPolicyWarnings adds, never as an error, each field where cfg's
// default_profile floor is looser than an assigned profile's (GAP-0188,
// GAP-0331) and each sandbox advisory for goos (GAP-0393), the defaults
// first, both in a stable order so a rerun repeats them. The Linux, macOS
// and Windows lifecycles share it, so no OS prints fewer (GAP-0536).
func (r *Result) AddSandboxPolicyWarnings(cfg *config.Config, goos string) {
	if r == nil || cfg == nil {
		return
	}
	for _, warning := range cfg.SandboxDefaultProfileWarnings() {
		r.AddWarning(CodeSandboxDefaultProfile, warning)
	}
	for _, advisory := range cfg.SandboxAdvisories(goos) {
		r.AddWarning(CodeSandboxAdvisory, advisory)
	}
}
