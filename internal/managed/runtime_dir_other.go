//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// validateServiceRuntimeParent judges the folder a runtime directory is made
// in with the strict service-runtime rule.
func validateServiceRuntimeParent(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeDir(path, label, serviceAccount)
}

// validateExistingServiceRuntimeFile requires a runtime file that is about to
// be replaced to be trusted, because the replacement keeps its descriptor.
func validateExistingServiceRuntimeFile(path, label, serviceAccount string) error {
	return ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount)
}
