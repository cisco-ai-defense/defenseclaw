// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
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

// WindowsStandaloneTrustScope is the shared standalone rule for managed
// lock validation in the connector.
func WindowsStandaloneTrustScope() bool {
	return windowsStandaloneTrustScope()
}

// StandaloneRefusesContentDrift reports whether a drifted policy or data
// file (config.yaml, the guardian manifest, the managed-hook journals, the
// Codex machine requirements) must be refused without an in-place ACL
// repair: true in the standalone scope. A repair restores the descriptor,
// not the content an untrusted writer may have changed, and a handle opened
// during the drift (write data or WRITE_DAC) keeps its authority after it.
// Recovery is a trusted rewrite only: Setup /ensure writes a fresh file
// from the approved source under the admin-only descriptor and replaces
// the old one, so a retained handle points at the replaced object (GAP-0561
// reviews 1 to 4). The guardian's layout self-heal and the enumerator leave
// such a file unrepaired too.
func StandaloneRefusesContentDrift() bool {
	return windowsStandaloneTrustScope()
}

// StandaloneFileLeafDrift returns the untrusted owner or write-like entry
// of path itself, or a stand-in for its untrusted access list (a null DACL,
// an allow entry the walk cannot read), when that is the standalone walk's
// only objection to it: path fails the standalone check on its own
// descriptor, and every folder above it passes. A trusted rewrite recovers
// exactly this drift: a fresh file from the administrator's approved source,
// under the admin-only descriptor, takes the name, and the old object moves
// aside (GAP-0561, GAP-0590). It returns nil for a trusted path, a
// structural failure, and drift on a folder above path, which a new file in
// that folder does not recover.
func StandaloneFileLeafDrift(path, label string) *UntrustedPrincipalError {
	if label == "" {
		label = "managed file"
	}
	refused := standaloneLeafVerdict(ValidateTrustedFilePathStandalone(path, label))
	if refused == nil {
		return nil
	}
	clean, err := filepath.Abs(path)
	if err != nil || !strings.EqualFold(filepath.Clean(refused.Path), clean) {
		return nil
	}
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, windowsStandaloneAncestorScope(dir)) != nil {
			return nil
		}
		if dir == filepath.Dir(dir) {
			return refused
		}
	}
}

// standaloneLeafVerdict is the principal of a standalone verdict that a
// trusted rewrite recovers from: an untrusted owner or writer, or an access
// list that is itself untrusted, which stands in as Everyone (a null DACL)
// or as no account it can name (an entry the walk cannot read). Before, only
// the first counted, so a null DACL or such an entry on config.yaml was
// refused with a CONFIG= recovery that wrote nothing (GAP-0590 review S1).
// It is nil for no verdict and for a structural failure.
func standaloneLeafVerdict(err error) *UntrustedPrincipalError {
	var principal *UntrustedPrincipalError
	if errors.As(err, &principal) {
		return principal
	}
	var dacl *UntrustedDACLError
	if !errors.As(err, &dacl) {
		return nil
	}
	if dacl.Null {
		return &UntrustedPrincipalError{Path: dacl.Path, SID: "S-1-1-0", ACL: "null", text: dacl.text}
	}
	return &UntrustedPrincipalError{Path: dacl.Path, ACL: "unsupported", text: dacl.text}
}

// standaloneContentDriftRecovery is the recovery that works for the file
// err refuses: Setup writes config.yaml and the guardian manifest new from
// the approved source; every other content file is the administrator's to
// check (GAP-0590).
func standaloneContentDriftRecovery(err error) string {
	if refused := standaloneLeafVerdict(err); refused != nil {
		switch strings.ToLower(filepath.Base(refused.Path)) {
		case "config.yaml":
			return standaloneConfigDriftRecovery()
		case "targets.yaml":
			return standaloneManifestDriftRecovery()
		}
	}
	return standaloneRecordDriftRecovery()
}

// WindowsStandaloneInstallExecutable reports whether the running binary sits
// in <standalone install root>\bin, a production or run-scoped certification
// root under the protected Program Files registration. Hooks never carry the
// profile pin, so the protected location of the running binary decides.
func WindowsStandaloneInstallExecutable() bool {
	return windowsStandaloneInstallExecutable()
}

var windowsStandaloneInstallExecutable = func() bool {
	return windowsStandaloneInstallService() != ""
}

// windowsStandaloneInstallService is the gateway service the installer
// registers for the install root the running binary sits in, or "" when it
// sits in none: DefenseClawGateway for the production root,
// DefenseClawCertGateway_<run id> for a run-scoped certification root. It is
// the trusted deployment scope of an unpinned console. Tests replace it.
var windowsStandaloneInstallService = sync.OnceValue(func() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return ""
	}
	return gatewayServiceForExecutable(executable, roots)
})

// gatewayServiceForExecutable is the gateway service of the standalone
// install root that holds executable in its bin folder, or "".
func gatewayServiceForExecutable(executable string, roots winpath.EnterpriseRoots) string {
	if !filepath.IsAbs(executable) {
		return ""
	}
	bin := filepath.Dir(filepath.Clean(executable))
	if !strings.EqualFold(filepath.Base(bin), "bin") {
		return ""
	}
	service, err := winpath.EnterpriseGatewayServiceForRoot(roots, filepath.Dir(bin))
	if err != nil {
		return ""
	}
	return service
}
