//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// ValidateTrustedConfigPath rejects managed_enterprise config paths that a
// standard user could replace or edit. The managed service may run as a
// dedicated non-root user, but the authoritative config must stay admin-owned.
func ValidateTrustedConfigPath(path string) error {
	return ValidateTrustedFilePath(path, "managed config")
}

// ValidateTrustedPolicyFilePath is ValidateTrustedFilePath on Unix. On Windows
// it accepts and logs permission drift on a managed policy or data file.
func ValidateTrustedPolicyFilePath(path, label string) error {
	return ValidateTrustedFilePath(path, label)
}

// ValidateTrustedServiceRuntimeDir is the cross-platform service-runtime
// entry point. On unix the packaged defenseclaw account is resolved by
// username (via user.Lookup) inside trustedRuntimeOwner; the
// Windows-format `NT SERVICE\...` account name in the third argument
// cannot be reused for a unix user lookup, so it is intentionally
// dropped here. To point unix trust at a non-default username, set the
// DEFENSECLAW_UNIX_SERVICE_ACCOUNT env — trustedRuntimeOwner reads it
// on every check. When neither the env is set nor the "defenseclaw"
// user exists, the ancestor walk fails with a clear "owner uid N is
// not trusted" error instead of silently allowing any owner.
func ValidateTrustedServiceRuntimeDir(path, label, _ string) error {
	return ValidateTrustedRuntimeDir(path, label)
}

// ValidateExecutableFilePath validates a binary or library DefenseClaw loads.
// The advisory code-integrity rule is Windows-only; here it is the strict
// ValidateTrustedFilePath check, unchanged.
func ValidateExecutableFilePath(path, label string) error {
	return ValidateTrustedFilePath(path, label)
}

// AcceptServiceRuntimeFileDrift is the gateway's drift-accepting judgement of
// a runtime file it reads. Descriptor drift is a Windows concept; here it is
// the existing ValidateTrustedServiceRuntimeFilePath check.
func AcceptServiceRuntimeFileDrift(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount)
}
