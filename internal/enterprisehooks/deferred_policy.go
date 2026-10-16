// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// StageWindowsEnterpriseDeferredPolicies activates the token-free protected
// machine-policy envelope for manifest-authorized pending rows. It never
// creates or repairs target-owned runtime; that still requires the exact
// user's WTS token in Install. The optional mode is the configured Cursor
// delivery policy. Under Secure Client an omitted policy defaults open, with
// version fallback applied (#1163); every other profile stages closed.
func StageWindowsEnterpriseDeferredPolicies(
	manifest Manifest,
	pending []ManifestTarget,
	apiAddr string,
	hookFailMode ...string,
) error {
	return stageWindowsEnterpriseDeferredPoliciesPlatform(manifest, pending, apiAddr, hookFailMode...)
}
