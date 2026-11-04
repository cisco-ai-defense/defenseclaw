// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

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

// windowsStandaloneTrustScope reports whether this process judges managed
// trust by the standalone profile's rules, the Windows counterpart of the
// macOS StandaloneTrustScope gate: the protected profile pin every standalone
// service and lifecycle helper carries (StandaloneTrustScope), or a binary
// running from the standalone install root (WindowsStandaloneInstallExecutable),
// which is how a hook or CLI without the pin is told apart. A standard user
// can forge neither toward Secure Client: the pin is in the services' HKLM
// registration, and the install root is resolved from the protected HKLM
// Program Files registration and only administrators write it. A process
// with neither, such as one a user starts from a copied binary, gets the
// Secure Client rules, which then judge only what that user could already
// read and write. Tests replace it.
var windowsStandaloneTrustScope = func() bool {
	return StandaloneTrustScope() || WindowsStandaloneInstallExecutable()
}

// WindowsStandaloneTrustScope is windowsStandaloneTrustScope for drift
// acceptances outside this package (the managed lock gate).
func WindowsStandaloneTrustScope() bool {
	return windowsStandaloneTrustScope()
}

// StandaloneRefusesContentDrift reports whether a drifted policy or data
// file (config.yaml, the guardian manifest, the managed-hook journals, the
// Codex machine requirements) must be refused without an in-place ACL
// repair: true in the standalone scope. A repair restores the descriptor,
// not the content an untrusted writer may have changed, and a handle opened
// during the drift (write data or WRITE_DAC) keeps its authority after it.
// Recovery is a trusted rewrite only: Setup /repair writes a fresh file
// from the protected source under the admin-only descriptor and replaces
// the old one, so a retained handle points at the replaced object (GAP-0561
// reviews 1 to 3).
func StandaloneRefusesContentDrift() bool {
	return windowsStandaloneTrustScope()
}

// WindowsStandaloneInstallExecutable reports whether the running binary sits
// in <standalone install root>\bin, a production or run-scoped certification
// root under the protected Program Files registration. Hooks never carry the
// profile pin, so the protected location of the running binary decides.
func WindowsStandaloneInstallExecutable() bool {
	return windowsStandaloneInstallExecutable()
}

var windowsStandaloneInstallExecutable = sync.OnceValue(func() bool {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return false
	}
	bin := filepath.Dir(filepath.Clean(executable))
	if !strings.EqualFold(filepath.Base(bin), "bin") {
		return false
	}
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return false
	}
	return winpath.ValidateEnterpriseInstallRoot(roots, filepath.Dir(bin)) == nil
})
