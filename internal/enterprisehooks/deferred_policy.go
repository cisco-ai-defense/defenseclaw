// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// StageWindowsEnterpriseDeferredPolicies activates the token-free protected
// machine-policy envelope for manifest-authorized pending rows. It never
// creates or repairs target-owned runtime; that still requires the exact
// user's WTS token in Install.
func StageWindowsEnterpriseDeferredPolicies(
	manifest Manifest,
	pending []ManifestTarget,
	apiAddr string,
) error {
	return stageWindowsEnterpriseDeferredPoliciesPlatform(manifest, pending, apiAddr)
}
