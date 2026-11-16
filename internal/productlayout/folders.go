// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package productlayout holds the fixed folder names DefenseClaw creates on a
// machine. It is a leaf package (standard library only) so the layout builders
// and the audit redaction detector read the same constants: a folder the
// product adds is registered once and is then known both to the installer and
// to the code that must not mistake the name for a secret.
package productlayout

import "strings"

const (
	// ProductFolder is the install and state folder.
	ProductFolder = "DefenseClaw"
	// WindowsCertificationFolder holds run-scoped certification installs.
	WindowsCertificationFolder = ProductFolder + "-Cert"
	// WindowsLifecycleFolder holds enterprise lifecycle state.
	WindowsLifecycleFolder = ProductFolder + "-Lifecycle"
	// WindowsHookRuntimeFolder holds the standalone hook runtime.
	WindowsHookRuntimeFolder = ProductFolder + "-HookRuntime"
	// WindowsScannerRuntimeFolder holds the standalone scanner runtime.
	WindowsScannerRuntimeFolder = ProductFolder + "-ScannerRuntime"
)

var folderNames = [...]string{
	ProductFolder,
	WindowsCertificationFolder,
	WindowsLifecycleFolder,
	WindowsHookRuntimeFolder,
	WindowsScannerRuntimeFolder,
}

// IsFolderName reports whether name is exactly one of the product folder
// names. The comparison ignores case because Windows paths do.
func IsFolderName(name string) bool {
	for _, folder := range folderNames {
		if strings.EqualFold(name, folder) {
			return true
		}
	}
	return false
}

// FolderNames returns a copy of the registered folder names.
func FolderNames() []string {
	return append([]string(nil), folderNames[:]...)
}
