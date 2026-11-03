// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

// The *Standalone validators are the standalone profile's trust walk: the
// verdicts main gives, without the Secure Client drift acceptances of the
// ordinary walk (an administrator-equivalent owner or writer, an inherited
// create-child entry, the operating system roots as advisory ancestors, an
// unreadable ancestor descriptor). Standalone code that can run without the
// standalone process pin (Setup, the standalone policy-input check, the
// hook's machine policy summary lookup) calls them. Structural checks are
// the same as in the ordinary walk.

// ValidateTrustedFilePathStandalone is ValidateTrustedFilePath with the
// standalone profile's verdicts.
func ValidateTrustedFilePathStandalone(path, label string) error {
	if label == "" {
		label = "managed file"
	}
	return validateTrustedWindowsFilePath(path, label, nil, windowsTrustStrictLeaf, windowsStandaloneAncestorScope)
}

// ValidateTrustedRuntimeDirStandalone is ValidateTrustedRuntimeDir with the
// standalone profile's verdicts.
func ValidateTrustedRuntimeDirStandalone(path, label string) error {
	return validateTrustedWindowsRuntimeDirWith(path, label, nil, windowsTrustStrictLeaf, windowsStandaloneAncestorScope)
}

// ValidateTrustedServiceRuntimeDirStandalone is ValidateTrustedServiceRuntimeDir
// with the standalone profile's verdicts.
func ValidateTrustedServiceRuntimeDirStandalone(path, label, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateTrustedWindowsRuntimeDirWith(path, label, serviceSID, windowsTrustStrictLeaf, windowsStandaloneAncestorScope)
}

// ValidateTrustedServiceRuntimeTreeStandalone is
// ValidateTrustedServiceRuntimeTree with the standalone profile's verdicts.
func ValidateTrustedServiceRuntimeTreeStandalone(path, label, serviceAccount string) error {
	return validateTrustedWindowsRulePackTree(path, label, serviceAccount, windowsTrustStrictLeaf, windowsStandaloneAncestorScope)
}

// ValidateTrustedServiceRuntimeFilePathStandalone is
// ValidateTrustedServiceRuntimeFilePath with the standalone profile's
// verdicts.
func ValidateTrustedServiceRuntimeFilePathStandalone(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateTrustedWindowsFilePath(path, label, serviceSID, windowsTrustStrictLeaf, windowsStandaloneAncestorScope)
}

// windowsStandaloneAncestorScope is the standalone ancestor rule: only a
// folder inside the platform installer's roots is advisory, and no ancestor
// takes the principal drift acceptances.
func windowsStandaloneAncestorScope(path string) windowsTrustScope {
	scope := windowsTrustStrictAncestor
	if PlatformInstallerOwnedPath(path) {
		scope.advisory = true
	}
	return scope
}
