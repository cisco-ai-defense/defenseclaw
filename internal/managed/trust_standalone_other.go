// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

// Off Windows the ordinary service-runtime walk is the standalone profile's
// walk, so the *Standalone validators the cross-platform standalone checks
// call are the ordinary ones.

// ValidateTrustedFilePathStandalone is ValidateTrustedFilePath.
func ValidateTrustedFilePathStandalone(path, label string) error {
	return ValidateTrustedFilePath(path, label)
}

// ValidateTrustedServiceRuntimeDirStandalone is ValidateTrustedServiceRuntimeDir.
func ValidateTrustedServiceRuntimeDirStandalone(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeDir(path, label, serviceAccount)
}

// ValidateTrustedServiceRuntimeTreeStandalone is ValidateTrustedServiceRuntimeTree.
func ValidateTrustedServiceRuntimeTreeStandalone(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeTree(path, label, serviceAccount)
}

// ValidateTrustedServiceRuntimeFilePathStandalone is
// ValidateTrustedServiceRuntimeFilePath.
func ValidateTrustedServiceRuntimeFilePathStandalone(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount)
}

// standaloneContentDriftRecovery is the config.yaml recovery off Windows,
// where no standalone reader refuses content drift.
func standaloneContentDriftRecovery(error) string { return standaloneConfigDriftRecovery() }

// StandaloneRefusesContentDrift is false off Windows: the repair-then-use
// paths there keep their own rules.
func StandaloneRefusesContentDrift() bool { return false }
