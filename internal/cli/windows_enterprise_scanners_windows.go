// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone payload's scanner runtime (cmd/defenseclaw-scanners) lives
// in its own administrator-owned root, not under InstallRoot or StateRoot:
// the installer module checks those trees file by file, and the runtime is
// thousands of files. This lifecycle step owns it: after a successful
// install, upgrade, repair or ensure it installs the staged executable and
// unpacks the runtime; uninstall removes the root; status and verify report
// it, and verify fails while it is not ready, since every scan then fails
// closed.

var (
	windowsScannerRuntimeDir     = managed.StandaloneWindowsScannerRuntimeDir
	windowsScannerGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
	windowsScannerPrepareTimeout = 15 * time.Minute
	// The staged scanner is hashed, signature-checked and copied by path:
	// a folder above it that a standard user can replace children of would
	// let one swap it between those steps (review loop round 4).
	windowsScannerSourceCheck = managed.ValidateTrustedFilePathStrictAncestors
)

// windowsScannerRuntimeSDDL: Administrators own the root; LocalSystem and
// Administrators hold full control and the gateway service reads and runs
// it, all inherited. No other account has access.
func windowsScannerRuntimeSDDL(gateway *windows.SID) string {
	return "O:BAG:SY" + windowsScannerRuntimeDACL(gateway)
}

func windowsScannerRuntimeDACL(gateway *windows.SID) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + gateway.String() + ")"
}

// ensureWindowsScannerRuntimeRoot makes root a folder this lifecycle created.
// "prepare" runs a python.exe from under it as an administrator and the
// gateway service runs the same one, so a folder a standard user made first
// (ProgramData lets users create folders) is not adopted: its owner keeps
// WRITE_DAC over everything in it. A root that is not owned by Administrators
// or LocalSystem is removed and created again, with the protected ACL set at
// creation so no user can add a file before the lockdown.
func ensureWindowsScannerRuntimeRoot(root string, gateway *windows.SID) error {
	info, err := os.Lstat(root)
	if err == nil {
		if !info.IsDir() || winpath.RejectReparseChain(root) != nil {
			return fmt.Errorf("%s is not a real folder", root)
		}
		trusted, ownerErr := windowsPathOwnedByAdministrators(root)
		if ownerErr != nil {
			return fmt.Errorf("read the owner of %s: %w", root, ownerErr)
		}
		if !trusted {
			if err := removeWindowsScannerRuntime(); err != nil {
				return fmt.Errorf("replace %s, which an unprivileged account created: %w", root, err)
			}
			err = os.ErrNotExist
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		descriptor, err := windows.SecurityDescriptorFromString(windowsScannerRuntimeDACL(gateway))
		if err != nil {
			return err
		}
		attributes := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
		pointer, err := winpath.UTF16Ptr(root)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(pointer, attributes); err != nil {
			return fmt.Errorf("create %s: %w", root, err)
		}
	} else if err != nil {
		return err
	}
	if err := applyWindowsSDDL(root, windowsScannerRuntimeSDDL(gateway)); err != nil {
		return fmt.Errorf("protect %s: %w", root, err)
	}
	return nil
}

func windowsPathOwnedByAdministrators(path string) (bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	return owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid), nil
}

func applyWindowsStandaloneScannerRuntime(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	if result == nil {
		return
	}
	if opts != nil && opts.scannerRuntimeRetired != "" {
		result.AddWarning("scanner_runtime_untrusted_removed", "the scanner runtime "+opts.scannerRuntimeRetired+
			" failed the trust check, so this run removed it before the services started: the gateway does not start on it (GAP-0490). "+
			"A run from the DefenseClaw Setup installs it again; otherwise every scan fails closed until DefenseClawSetup-Enterprise-Standalone-x64.exe /repair")
	}
	action := result.Action
	if opts != nil && opts.runningDeploymentLabel {
		// A refused config installed nothing: report the running
		// deployment's scanners as status does (GAP-0103).
		action = "status"
	}
	if windowsScannerRuntimeCertificationRun(opts) {
		// The runtime root, its admission record and its service ACL are
		// the production deployment's, whichever scope this run targets
		// (review loop round 3).
		switch action {
		case "install", "upgrade", "repair", "ensure", "uninstall":
			if len(result.Errors) != 0 {
				// A failed run changes nothing shared: the production
				// deployment's admission record stays as it is, whatever it
				// names, as a failed run left the runtime before 1.0.4. Only the
				// production Setup's /repair or upgrade, or a certification run
				// that succeeds, settles a legacy record; a failed one quarantined
				// the record of a healthy signed 1.0.3 production scanner it could
				// not prove, and the 1.0.3 gateway stopped scanning (W2B-G-win
				// fifth review loop, round 1).
				return
			}
			// Such a run can only take trust away: an admission record that
			// does not prove a production admission (the record a 1.0.3
			// --allow-unsigned certification install wrote for its unsigned
			// scanner) is removed unless the production deployment's own trust
			// settings prove the executable it names, so no gateway runs that
			// scanner (W2B-G-win review loop round 1). A record those settings
			// prove is the production deployment's and stays: a 1.0.3 gateway
			// keeps scanning with it (loop round 2). One they cannot prove is
			// removed too: a 1.0.3 gateway runs whatever a schema 1 record
			// names (loop round 3).
			quarantined, err := quarantineUnprovenWindowsScannerRuntimeAdmission()
			switch {
			case err != nil:
				result.AddError("scanner_runtime_admission_unproven",
					"the shared scanner runtime has an admission record that does not prove the production deployment admitted it, "+
						"and this run could not quarantine it ("+err.Error()+"); remove "+managed.StandaloneWindowsScannerRuntimeAdmissionName+
						" from the scanner runtime folder as an administrator, then run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair")
			case quarantined != "":
				result.AddWarning("scanner_runtime_admission_quarantined", windowsScannerRuntimeAdmissionQuarantined+" (not proven: "+quarantined+")")
			}
			if err == nil {
				result.AddWarning("scanner_runtime_not_scoped", windowsScannerRuntimeNotScoped)
			}
		case "status", "verify", "recover":
			if result.Installed {
				result.AddWarning("scanner_runtime_not_scoped", windowsScannerRuntimeNotScoped)
			}
		}
		return
	}
	switch action {
	case "install", "upgrade", "repair", "ensure":
		if len(result.Errors) != 0 || opts == nil {
			return
		}
		if opts.jsonOutput {
			// A JSON run keeps the progress for the lifecycle log, as it keeps
			// the enumerator lines: on stderr an Intune platform script was
			// reported Failed and run again, and each run was a /repair that
			// stopped the services (GAP-1069).
			previous := windowsScannerProgress
			windowsScannerProgress = &windowsScannerDiagnostics{opts: opts}
			defer func() { windowsScannerProgress = previous }()
		}
		source := ""
		if installer := strings.TrimSpace(opts.resolvedInstaller); installer != "" {
			candidate := filepath.Join(filepath.Dir(installer), managed.StandaloneWindowsScannerRuntimeName)
			if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
				source = candidate
			}
		}
		if source == "" {
			// No staged copy to install from (a repair or ensure run from the installed
			// CLI): a runtime that is installed but not unpacked is prepared again, so a
			// prepare that failed half way is not left for a hand clean-up (GAP-0263),
			// and a missing one is reported with the Setup command that installs it.
			reprepareInstalledWindowsScannerRuntime(result, opts)
		} else {
			var superseded *windowsScannerRuntimeSupersededError
			if err := installWindowsScannerRuntime(source, action, opts); errors.As(err, &superseded) {
				result.AddWarning("scanner_runtime_superseded", superseded.Error())
			} else if err != nil {
				result.AddError("scanner_runtime_unavailable", windowsScannerRuntimePrepareFailed(err))
			}
			result.Scanners = windowsScannerRuntimeReader()
		}
		// A ready runtime the gateway service cannot run blocks every scan
		// as a missing one does, so the run fails as verify does; before,
		// an ensure with no other drift reported success (GAP-1361).
		if result.Scanners != nil && result.Scanners.State == "ready" &&
			!windowsEnterpriseResultHasError(result, "scanner_runtime_unavailable") {
			if message := windowsScannerRuntimeServiceProblem(); message != "" {
				result.AddError("scanner_runtime_unavailable", message)
			}
		}
	case "uninstall":
		if len(result.Errors) != 0 {
			return
		}
		// Under the scanner runtime lock, and only while no deployment is
		// installed: a later install's runtime stays (GAP-1166 review).
		kept, err := retireWindowsScannerRuntime(opts)
		switch {
		case err != nil:
			result.AddWarning("scanner_runtime_left", "the scanner runtime folder could not be removed: "+err.Error())
		case kept != "":
			result.AddWarning("scanner_runtime_left", "the scanner runtime folder was kept: "+kept)
		}
	case "status", "verify", "recover":
		// A request refused before its health checks ran reports only the
		// recorded deployment; a standard account cannot read the runtime
		// folder anyway. Recovery must also prove this shared executable tree.
		if result.Installed && !windowsEnterpriseResultHasWarning(result, windowsEnterpriseHealthNotChecked) {
			result.Scanners = windowsScannerRuntimeReader()
			// Every scan fails closed without a ready runtime, so verify
			// fails and an MDM detection remediates (GAP-0294).
			message := ""
			if result.Scanners.State != "ready" {
				message = windowsScannerRuntimeUnavailable(result.Scanners)
			} else {
				// Prepared, but not as the gateway service runs it: every
				// scan failed while status and verify said ok (GAP-0686).
				message = windowsScannerRuntimeServiceProblem()
			}
			if message != "" {
				if result.Action == "verify" || result.Action == "recover" {
					result.AddError("scanner_runtime_unavailable", message)
				} else {
					result.AddWarning("scanner_runtime_unavailable", message)
				}
			}
			if result.Scanners.State != "missing" && result.Scanners.JudgeModel == "" {
				if windowsStandaloneSkillJudgeDisabled() {
					result.AddWarning("scanner_judge_missing",
						"the skill scanner runs without its LLM judge because scanners.skill_scanner.use_llm is false in the admin config "+
							"(recommended: the quiet policy with the LLM judge); set it to true, with llm.model and its key stored by `enterprise secret set`")
				} else {
					result.AddWarning("scanner_judge_missing",
						"the scanners run without an LLM judge (recommended: the quiet policy with the LLM judge); "+
							"set llm.model in the admin config and store its key with `enterprise secret set`, named by enterprise.inspection.llm.credential")
				}
			}
		}
	}
}

// windowsScannerRuntimeReader is readWindowsScannerRuntime; a seam for tests.
var windowsScannerRuntimeReader = readWindowsScannerRuntime

// windowsScannerRuntimeTreeCheck is the trust check the gateway makes on the
// scanner runtime before it starts and before every scan; a seam for tests.
var windowsScannerRuntimeTreeCheck = func(root string) error {
	return managed.ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime")
}

// retireUntrustedWindowsScannerRuntimeBeforeStart removes a scanner runtime
// that fails the trust check before a module action that can start the
// gateway service. The gateway refuses to start on that tree (GAP-0490), so
// without this step a /repair would fail at the service start and roll back
// before its scanner step could replace the tree. Removing it loses nothing
// trusted: the scanner step after the transaction installs the runtime again
// from the signed payload, and until then every scan fails closed. Nothing
// untrusted is adopted or re-protected. A certification run leaves the
// production runtime alone, as it does after its transaction.
func retireUntrustedWindowsScannerRuntimeBeforeStart(moduleAction string, opts *windowsEnterpriseLifecycleOptions) error {
	switch moduleAction {
	case "Install", "Upgrade", "Repair", "Reconcile", "Recover":
	default:
		return nil
	}
	if opts == nil || windowsScannerRuntimeCertificationRun(opts) || !windowsEnterpriseIsElevated() {
		return nil
	}
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return nil
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("scanner_runtime_untrusted: read the scanner runtime folder %s before the services start: %w", root, err)
	}
	if windowsScannerRuntimeTreeCheck(root) == nil {
		return nil
	}
	if err := checkWindowsScannerRuntimeRootForRemoval(root); err != nil {
		return fmt.Errorf("scanner_runtime_untrusted: the scanner runtime %s fails the trust check and cannot be removed: %w", root, err)
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		return fmt.Errorf("scanner_runtime_untrusted: lock the untrusted scanner runtime %s: %w", root, err)
	}
	// Another run's scanner step may have replaced it while this one waited.
	problem := windowsScannerRuntimeTreeCheck(root)
	if problem == nil {
		release()
		return nil
	}
	if err := removeWindowsScannerRuntimeLocked(root, release); err != nil {
		return fmt.Errorf("scanner_runtime_untrusted: the scanner runtime %s fails the trust check (%v) and could not be removed before the services start: %w",
			root, problem, err)
	}
	opts.scannerRuntimeRetired = fmt.Sprintf("%s (%v)", root, problem)
	return nil
}

// windowsScannerRuntimeNotScoped is the warning of a certification-scope run.
const windowsScannerRuntimeNotScoped = "this certification scope does not install, replace, prepare, remove or report the scanner runtime: " +
	"its folder, admission record and access list belong to the production deployment, which every gateway on this computer runs scans from; " +
	"scans in this scope fail closed unless the production deployment has a ready runtime"

// windowsScannerRuntimeAdmissionQuarantined is the warning of a run that
// removed an admission record no production admission proves.
const windowsScannerRuntimeAdmissionQuarantined = "the shared scanner runtime had an admission record that does not prove the production deployment admitted it " +
	"(DefenseClaw 1.0.3 and earlier wrote the same record for an --allow-unsigned or certification run's unsigned scanner), " +
	"so the record was removed and no gateway runs that scanner; every scan fails closed until " +
	"DefenseClawSetup-Enterprise-Standalone-x64.exe /repair, or its upgrade, admits the production payload copy again"

// quarantineUnprovenWindowsScannerRuntimeAdmission is the certification-run
// step for an admission record in the shared runtime root that does not
// prove a production admission (schema 1, which a 1.0.3 --allow-unsigned run
// wrote alike for its unsigned scanner). A certification or --allow-unsigned
// run cannot admit anything for the production deployment, so it never
// writes the record; it checks the executable against the production
// deployment's own trust settings (windowsScannerRuntimeProductionProves). A
// record they prove stays as it is. Any other record is removed under the
// scanner runtime lock, so every gateway, a 1.0.3 one included, refuses the
// executable it named, and the reason is returned: one they refuse, and one
// they cannot prove (an unsigned scanner under a hash-pinned deployment,
// whose pins only the production Setup's payload manifest has, a signed one
// whose production signer pins nothing durable records, or trust settings
// that cannot be read). A 1.0.3 gateway runs any executable whose
// digest a schema 1 record names, so a record nothing proves was kept for it
// to run, a certification run's unsigned scanner included (W2B-G-win review
// loop round 3); the production Setup's /repair or upgrade admits the payload
// copy again. A root that is not the runtime's own real folder is refused. A
// record that already proves a production admission, or none, leaves the
// root untouched (no lock file is made).
func quarantineUnprovenWindowsScannerRuntimeAdmission() (string, error) {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return "", err
	}
	recorded, unproven, err := managed.UnprovenScannerRuntimeAdmission(root)
	if err != nil || !unproven {
		return "", err
	}
	why := windowsScannerRuntimeProductionProves(root, recorded)
	if why == "" {
		return "", nil
	}
	if err := checkWindowsScannerRuntimeRootForRemoval(root); err != nil {
		return "", err
	}
	if err := winpath.RejectReparseChain(root); err != nil {
		return "", err
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		return "", err
	}
	defer release()
	// Another run may have settled or replaced the record meanwhile; that
	// record is the next run's to check.
	if current, unproven, err := managed.UnprovenScannerRuntimeAdmission(root); err != nil || !unproven || current != recorded {
		return "", err
	}
	if err := managed.RemoveScannerRuntimeAdmission(root); err != nil {
		return "", err
	}
	return why, nil
}

// windowsScannerRuntimeProductionSigners is enterprise.trust.allowed_signers
// of the production deployment's installed config. When it pins any signer,
// every production run applies exactly those pins: one without
// --allowed-signer takes them, and one with other thumbprints is refused
// (applyWindowsEnterpriseConfiguredTrust, alike since 1.0.2). An absent
// config or one that pins none is no evidence: the production run may have
// pinned signers with --allowed-signer alone, which nothing records. The
// config must pass the managed config trust check first; a seam for tests.
var windowsScannerRuntimeProductionSigners = func() ([]string, error) {
	path, err := windowsEnterpriseInstalledConfigPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := managed.ValidateTrustedConfigPath(path); err != nil {
		return nil, err
	}
	body, err := windowsEnterpriseTrustConfigReader(path, windowsEnterpriseConfigProfileLimit)
	if err != nil {
		return nil, err
	}
	var document windowsEnterpriseTrustDocument
	if err := yaml.Unmarshal(trimWindowsJSONBOM(body), &document); err != nil {
		return nil, fmt.Errorf("%s does not parse %s", path, windowsEnterpriseYAMLProblem(err))
	}
	configured, err := windowsEnterpriseTrustFromDocument(path, document)
	if err != nil {
		return nil, err
	}
	return configured.allowedSigners, nil
}

// windowsScannerRuntimeProductionProves checks, for a certification run,
// the executable an unproven record in root names against the production
// deployment, not against this run, and returns why it is not proven, or ""
// when it is. Proof needs all of these: the root and the executable pass the
// trust check every run makes and the executable still has the recorded
// digest; the production deployment record is installed (an absent,
// untrusted or tombstoned one admitted nothing); and the executable carries
// a valid Authenticode signature from a signer the production config pins.
// A config that pins no signer proves no signed executable: a production
// run's --allowed-signer pins are recorded nowhere, so a scanner from a
// signer they leave out would be kept (W2B-G-win third review loop, round
// 1). An unsigned executable is never proven here: an
// Authenticode-only deployment refuses it, and a hash-pinned one pins it only
// in its Setup's payload manifest, which only a production run has. Anything
// that cannot be read proves nothing.
func windowsScannerRuntimeProductionProves(root, recorded string) string {
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := windowsScannerRuntimeACLCheck(root, target); err != nil {
		return err.Error()
	}
	got, err := windowsEnterpriseFileSHA256(target)
	if err != nil {
		return "hash " + target + ": " + err.Error()
	}
	if got != recorded {
		return fmt.Sprintf("%s (SHA-256 %s) is not the executable its record names (SHA-256 %s)", target, got, recorded)
	}
	deployment, err := windowsScannerRuntimeDeployment(nil)
	if err != nil {
		return "read the production deployment record: " + err.Error()
	}
	switch deployment.State {
	case winpath.EnterpriseDeploymentInstalled:
	case winpath.EnterpriseDeploymentAbsent, winpath.EnterpriseDeploymentTombstone:
		return "no production deployment is installed, so none admitted " + target
	default:
		return "the production deployment record " + deployment.MetadataPath + " cannot be read"
	}
	if _, certificate, err := windowsScannerRuntimeAuthenticode(target); err == nil {
		signers, err := windowsScannerRuntimeProductionSigners()
		if err != nil {
			return "read the production signer pins: " + err.Error()
		}
		if len(signers) == 0 {
			return target + " is signed, but the production config's enterprise.trust.allowed_signers pins no signer, and a production run's " +
				"--allowed-signer pins are recorded nowhere, so this certification run cannot prove the signer"
		}
		if windowsScannerRuntimeSignerPinned(certificate, signers) {
			return ""
		}
		return target + " is signed by a signer the production config's enterprise.trust.allowed_signers does not pin"
	}
	if deployment.TrustMode == windowsEnterpriseTrustAuthenticode {
		return target + " has no valid Authenticode signature, and the production deployment admits only Authenticode-signed payloads"
	}
	return target + " has no valid Authenticode signature, and the production deployment is hash-pinned by its Setup's payload manifest, " +
		"which only a production run has, so this certification run cannot prove it"
}

// proveWindowsScannerRuntimeAdmissionLocked settles, under the scanner
// runtime lock, in a production run whose deployment is installed, an
// admission record that does not prove a production admission (one
// DefenseClaw 1.0.3 or earlier wrote, which an --allow-unsigned run wrote
// alike for an unsigned scanner). The executable it names is recorded again,
// as a production admission, only when the runtime root and the executable
// pass the trust check every run makes, the executable still has the digest
// the record names, and this run's payload trust policy admits it as it
// admits a staged copy. Otherwise the record is removed, so no gateway runs
// the executable until a production /repair admits the payload copy, and
// the reason is returned. A record that cannot be read is left: every reader
// refuses it, and a staged copy replaces it.
func proveWindowsScannerRuntimeAdmissionLocked(root string, opts *windowsEnterpriseLifecycleOptions) (string, error) {
	recorded, unproven, err := managed.UnprovenScannerRuntimeAdmission(root)
	if err != nil || !unproven {
		return "", nil
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	proveErr := windowsScannerRuntimeACLCheck(root, target)
	if proveErr == nil {
		var got string
		if got, proveErr = windowsEnterpriseFileSHA256(target); proveErr == nil && got != recorded {
			proveErr = fmt.Errorf("%s (SHA-256 %s) is not the executable its record names (SHA-256 %s)", target, got, recorded)
		}
	}
	trust := ""
	if proveErr == nil {
		trust, proveErr = admitWindowsScannerRuntimePayload(target, recorded, opts)
	}
	if proveErr == nil {
		if err := managed.WriteScannerRuntimeAdmission(root, recorded, trust); err != nil {
			return "", fmt.Errorf("record the proven scanner runtime: %w", err)
		}
		return "", nil
	}
	if err := managed.RemoveScannerRuntimeAdmission(root); err != nil {
		return "", fmt.Errorf("quarantine the unproven scanner runtime admission record (%v): %w", proveErr, err)
	}
	return proveErr.Error(), nil
}

// settleUnprovenWindowsScannerRuntimeAdmission is
// proveWindowsScannerRuntimeAdmissionLocked for a production run from the
// installed CLI: it takes the scanner runtime lock and acts only while the
// deployment record names this run's deployment. It returns why it
// quarantined the record, or "".
func settleUnprovenWindowsScannerRuntimeAdmission(action string, opts *windowsEnterpriseLifecycleOptions) (string, error) {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return "", err
	}
	if _, unproven, err := managed.UnprovenScannerRuntimeAdmission(root); err != nil || !unproven {
		return "", nil
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return "", nil
		}
		return "", err
	}
	defer release()
	owner, err := windowsScannerRuntimeOwnerOf(action, opts)
	if err != nil {
		return "", err
	}
	if !owner.ours {
		// The run that owns the runtime now settles it; the gateway refuses
		// the record meanwhile.
		return "", nil
	}
	return proveWindowsScannerRuntimeAdmissionLocked(root, opts)
}

// windowsScannerRuntimeCertificationRun reports a run that must leave the
// scanner runtime alone: a certification scope (its own roots or service
// names) or an unsigned certification run. The runtime root is one folder
// per computer, the one the production gateway runs every scan from, while
// such a run reads and writes its own deployment record. Before, a
// certification install published an unsigned scanner and its admission
// record into that folder, and a certification uninstall removed it while
// production stayed installed (review loop round 3). Roots and service
// names that name the production layout itself are a production run: the
// installer accepts an override only as an exact certification scope or as
// the exact production layout, and runs the production lifecycle for the
// latter, so its upgrade or repair installs and proves the scanner runtime
// as a run without the overrides does (W2B-G-win review loop round 2).
func windowsScannerRuntimeCertificationRun(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && ((windowsEnterpriseCertificationScope(opts) && !windowsEnterpriseOverridesNameProduction(opts)) ||
		strings.TrimSpace(opts.certificationCodexHome) != "" || opts.allowUnsigned)
}

// windowsEnterpriseProductionRoots are the production standalone install
// and state roots, from the trusted known folders as the installer resolves
// them; a seam for tests.
var windowsEnterpriseProductionRoots = func() (install, state string, err error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", "", err
	}
	return layout.InstallRoot, filepath.Dir(layout.ConfigDir), nil
}

// windowsStandaloneGuardianService is the production guardian SCM service
// name (install-enterprise.ps1 -GuardianServiceName).
const windowsStandaloneGuardianService = "DefenseClawHookGuardian"

// windowsEnterpriseOverridesNameProduction reports whether every root and
// service name override this run supplies is the production default: a
// root that resolves to the production root, compared as the installer
// compares it (full path, case-insensitive, no trailing separator), and a
// service name equal to the production one (SCM names are case-insensitive).
// When the production roots cannot be resolved the overrides are not
// production.
func windowsEnterpriseOverridesNameProduction(opts *windowsEnterpriseLifecycleOptions) bool {
	install, state, err := windowsEnterpriseProductionRoots()
	if err != nil {
		return false
	}
	sameRoot := func(requested, production string) bool {
		requested = strings.TrimSpace(requested)
		if requested == "" {
			return true
		}
		full, err := filepath.Abs(requested)
		if err != nil {
			return false
		}
		return strings.EqualFold(strings.TrimRight(full, `\/`), strings.TrimRight(filepath.Clean(production), `\/`))
	}
	sameName := func(requested, production string) bool {
		requested = strings.TrimSpace(requested)
		return requested == "" || strings.EqualFold(requested, production)
	}
	return sameRoot(opts.installRoot, install) && sameRoot(opts.stateRoot, state) &&
		sameName(opts.gatewayServiceName, managed.StandaloneWindowsGatewaySvc) &&
		sameName(opts.guardianServiceName, windowsStandaloneGuardianService)
}

// windowsScannerRuntimeACLCheck checks that only administrators and
// LocalSystem can change the installed runtime root and executable, or
// replace either through a folder above them: every verdict is fatal,
// ProgramData\Cisco included, since an elevated lifecycle runs the
// executable by its path (review loop round 4). A seam for tests, whose
// temporary folders are not trusted.
var windowsScannerRuntimeACLCheck = func(root, target string) error {
	return managed.ValidateTrustedRuntimeImage(root, target, "scanner runtime")
}

// windowsInstalledScannerRuntimeCheck is every check made before the
// lifecycle runs the installed executable: its access control, then that it
// is the one the payload trust policy admitted (GAP-0311).
func windowsInstalledScannerRuntimeCheck(root, target string) error {
	if err := windowsScannerRuntimeACLCheck(root, target); err != nil {
		return err
	}
	return managed.CheckScannerRuntimeAdmitted(root, target)
}

// windowsScannerRuntimeServiceCheck checks the runtime the way the gateway
// service runs it: the trust check every scan makes, and that the service
// account can read the runtime folder and the security descriptors of its
// parents. A seam for tests.
var windowsScannerRuntimeServiceCheck = func() error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	if err := managed.ValidateTrustedRuntimeImage(root, filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName), "scanner runtime"); err != nil {
		return err
	}
	if err := managed.ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
		return err
	}
	if err := managed.ValidateServiceCanReadTree(root, "scanner runtime", windowsScannerGatewayAccount); err != nil && !managed.IsServiceAccountUnresolved(err) {
		return err
	}
	return nil
}

// windowsScannerRuntimeSupersededError is the scanner step of a lifecycle
// run whose deployment is no longer the one installed: a later run
// committed another release, whose own scanner step installs the matching
// runtime, or uninstalled DefenseClaw.
type windowsScannerRuntimeSupersededError struct {
	run, installed string
	uninstalled    bool
}

func (e *windowsScannerRuntimeSupersededError) Error() string {
	if e.uninstalled {
		return "a later lifecycle run uninstalled DefenseClaw; this run (" + e.run + ") did not install the scanner runtime"
	}
	installed := "DefenseClaw"
	if e.installed != "" {
		installed += " " + e.installed
	}
	return "a later lifecycle run installed " + installed + "; this run (" + e.run + ") left the scanner runtime to it"
}

// windowsScannerRuntimeDeployment reads the production standalone deployment
// record, the owner of the scanner runtime, which the scanner step checks
// while it holds the scanner runtime lock, and a certification run reads
// to check a 1.0.3-or-earlier admission record against the production
// deployment (windowsScannerRuntimeProductionVerdict); a seam for tests.
var windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
	return windowsEnterpriseDeploymentInspector(managed.ProfileStandalone)
}

// windowsScannerRuntimeOwner is whose runtime the scanner root holds now.
type windowsScannerRuntimeOwner struct {
	// ours: the deployment this run installed or kept is still installed.
	ours bool
	// uninstalled: no deployment is installed (a later uninstall).
	uninstalled bool
	// installed is the release the deployment record names.
	installed string
}

// windowsScannerRuntimeOwnerOf reads the deployment record. The scanner step
// runs after the PowerShell lifecycle released its lock, so another run can
// have uninstalled DefenseClaw or installed another release since this run
// committed; a record that cannot be read is an error, so nothing is
// published or removed on a guess (GAP-1166 review). A repair keeps the
// installed binaries and records their release, which a newer Setup's
// repair is not; any other run records its own.
func windowsScannerRuntimeOwnerOf(action string, opts *windowsEnterpriseLifecycleOptions) (windowsScannerRuntimeOwner, error) {
	deployment, err := windowsScannerRuntimeDeployment(opts)
	if err != nil {
		return windowsScannerRuntimeOwner{}, fmt.Errorf("read the deployment record: %w", err)
	}
	switch deployment.State {
	case winpath.EnterpriseDeploymentAbsent, winpath.EnterpriseDeploymentTombstone:
		return windowsScannerRuntimeOwner{uninstalled: true}, nil
	case winpath.EnterpriseDeploymentInstalled:
	default:
		return windowsScannerRuntimeOwner{}, fmt.Errorf("the deployment record %s cannot be read", deployment.MetadataPath)
	}
	owner := windowsScannerRuntimeOwner{installed: strings.TrimSpace(deployment.ProductVersion)}
	run := ""
	if opts != nil {
		run = strings.TrimSpace(opts.productVersion)
	}
	owner.ours = windowsScannerRuntimeReleaseMatches(action, run, owner.installed)
	return owner, nil
}

// windowsScannerRuntimeReleaseMatches reports whether the installed release
// is the one this run's action installed or kept.
func windowsScannerRuntimeReleaseMatches(action, run, installed string) bool {
	if run == installed {
		return true
	}
	_, _, runOK := parseWindowsEnterpriseVersion(run)
	_, _, installedOK := parseWindowsEnterpriseVersion(installed)
	if !runOK || !installedOK {
		return false
	}
	switch compare := compareWindowsEnterpriseVersions(installed, run); {
	case compare == 0:
		return true
	case compare < 0:
		return strings.EqualFold(strings.TrimSpace(action), "repair")
	default:
		return false
	}
}

// windowsScannerRuntimeLockName is the file in the runtime root that
// serializes the scanner step of overlapping lifecycle runs, and the
// uninstall step that removes the root.
const windowsScannerRuntimeLockName = "scanner-runtime.lock"

// windowsScannerRuntimeLockWait bounds the wait for another run's scanner
// step; a seam for tests.
var windowsScannerRuntimeLockWait = 20 * time.Minute

// lockWindowsScannerRuntime opens the scanner step lock exclusively,
// waiting for another run that holds it.
func lockWindowsScannerRuntime(root string) (func(), error) {
	name, err := windows.UTF16PtrFromString(filepath.Join(root, windowsScannerRuntimeLockName))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(windowsScannerRuntimeLockWait)
	for {
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil {
			return func() { _ = windows.CloseHandle(handle) }, nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("open the scanner runtime lock: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// checkWindowsScannerRuntimeRootForRemoval refuses a root that is not the
// runtime's own real folder.
func checkWindowsScannerRuntimeRootForRemoval(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real folder", root)
	}
	if !strings.EqualFold(filepath.Base(root), "DefenseClaw-ScannerRuntime") {
		return fmt.Errorf("refusing to remove %s", root)
	}
	return nil
}

// retireWindowsScannerRuntime removes the runtime root once no deployment is
// installed. It takes the scanner runtime lock and reads the deployment
// record under it, so it runs after a scanner step that started before it
// and before one that starts after it, and an uninstall whose step runs after
// a later install leaves that install's runtime alone: it returns what kept
// the root instead.
func retireWindowsScannerRuntime(opts *windowsEnterpriseLifecycleOptions) (string, error) {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return "", err
	}
	if err := checkWindowsScannerRuntimeRootForRemoval(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return "", nil
		}
		return "", err
	}
	owner, err := windowsScannerRuntimeOwnerOf("uninstall", opts)
	if err != nil {
		release()
		return "", err
	}
	if !owner.uninstalled {
		release()
		installed := "DefenseClaw"
		if owner.installed != "" {
			installed += " " + owner.installed
		}
		return "a later lifecycle run installed " + installed + ", whose runtime it is", nil
	}
	return "", removeWindowsScannerRuntimeLocked(root, release)
}

// removeWindowsScannerRuntimeLocked removes everything in root but the lock
// while the lock is held, then releases it and removes the lock and root. A
// run that opened the lock in between reads the record itself and either
// leaves (nothing installed) or installs into the root, which then stays.
func removeWindowsScannerRuntimeLocked(root string, release func()) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		release()
		return err
	}
	var removeErr error
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), windowsScannerRuntimeLockName) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil && removeErr == nil {
			removeErr = err
		}
	}
	release()
	if removeErr != nil {
		return removeErr
	}
	if err := os.Remove(filepath.Join(root, windowsScannerRuntimeLockName)); err != nil &&
		!errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return err
	}
	if err := os.Remove(root); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
		return err
	}
	return nil
}

// windowsScannerRuntimeLeftTo is the scanner step of a run whose deployment
// is no longer installed: after an uninstall the runtime is retired (the
// uninstall's own step may have run first, or been skipped), and either way
// the run reports that it left the runtime.
func windowsScannerRuntimeLeftTo(owner windowsScannerRuntimeOwner, opts *windowsEnterpriseLifecycleOptions) error {
	superseded := &windowsScannerRuntimeSupersededError{installed: owner.installed, uninstalled: owner.uninstalled}
	if opts != nil {
		superseded.run = strings.TrimSpace(opts.productVersion)
	}
	if owner.uninstalled {
		if kept, err := retireWindowsScannerRuntime(opts); err != nil {
			return fmt.Errorf("%s, and the scanner runtime folder could not be removed: %w", superseded.Error(), err)
		} else if kept != "" {
			return &windowsScannerRuntimeSupersededError{run: superseded.run}
		}
	}
	return superseded
}

// installWindowsScannerRuntime copies source into the protected root unless
// the installed copy already matches, then unpacks and compiles the runtime.
// The staged executable is admitted on every run, like every other payload
// file. Overlapping runs, and the uninstall step that removes the root, take
// the step in turn. The runtime is published only while the deployment
// record names this run's deployment: a delayed older upgrade cannot replace
// a newer runtime (GAP-1166), and a run that an uninstall overtook does not
// recreate the runtime after it; that is checked before the root is made and
// again under the lock.
func installWindowsScannerRuntime(source, action string, opts *windowsEnterpriseLifecycleOptions) error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	owner, err := windowsScannerRuntimeOwnerOf(action, opts)
	if err != nil {
		return err
	}
	if !owner.ours {
		return windowsScannerRuntimeLeftTo(owner, opts)
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil || gateway == nil {
		return fmt.Errorf("resolve the gateway service SID: %v", err)
	}
	if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
		return err
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		return err
	}
	held := true
	defer func() {
		if held {
			release()
		}
	}()
	owner, err = windowsScannerRuntimeOwnerOf(action, opts)
	if err != nil {
		return err
	}
	if !owner.ours {
		superseded := &windowsScannerRuntimeSupersededError{
			run: strings.TrimSpace(opts.productVersion), installed: owner.installed, uninstalled: owner.uninstalled,
		}
		if owner.uninstalled {
			held = false
			if err := removeWindowsScannerRuntimeLocked(root, release); err != nil {
				return fmt.Errorf("%s, and the scanner runtime folder could not be removed: %w", superseded.Error(), err)
			}
		}
		return superseded
	}
	// A record that does not prove a production admission is proven again
	// or quarantined first, so a staged copy the trust policy refuses below
	// does not leave it behind for a gateway to run (W2B-G-win review loop
	// round 1).
	if _, err := proveWindowsScannerRuntimeAdmissionLocked(root, opts); err != nil {
		return err
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	want, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		return err
	}
	// The staged copy is admitted under the current trust policy even when
	// the installed bytes match it: a signer restriction added since the
	// last run applies to this run too (GAP-0919). The installed copy is
	// kept when it has the staged bytes; otherwise the staged copy is
	// installed (a copy changed in place is restored). The admission is
	// recorded: every later run of the installed executable checks it
	// against that record first (GAP-0311).
	trust, err := admitWindowsScannerRuntimePayload(source, want, opts)
	if err != nil {
		return err
	}
	got, gotErr := windowsEnterpriseFileSHA256(target)
	admitted, _ := managed.ReadScannerRuntimeAdmission(root)
	copied := false
	if gotErr != nil || got != want || admitted != want {
		if gotErr != nil || got != want {
			if err := copyWindowsScannerRuntime(source, target, root, want); err != nil {
				return err
			}
			copied = true
		}
		if err := managed.WriteScannerRuntimeAdmission(root, want, trust); err != nil {
			return fmt.Errorf("record the admitted scanner runtime: %w", err)
		}
	}
	if err := windowsInstalledScannerRuntimeCheck(root, target); err != nil {
		return err
	}
	// prepare checks every file of an unpacked runtime against the archive
	// and compiles what is not compiled; prune drops the runtimes earlier
	// builds left. A copy has just prepared the same bytes under their
	// temporary name, so it only prunes: a second prepare read the whole
	// tree again, minutes on a slow disk (GAP-1063).
	steps := []string{"prepare", "prune"}
	if copied {
		steps = steps[1:]
	}
	for _, step := range steps {
		if err := runWindowsScannerRuntime(target, step); err != nil {
			return err
		}
	}
	return nil
}

// admitWindowsScannerRuntimePayload admits the staged scanner executable as
// the installer module admits every other standalone payload file
// (Get-DefenseClawSourceDescriptor), before this lifecycle copies it into the
// protected root and runs it as an administrator, and the gateway service
// runs it on every scan (GAP-0311). The source must be writable only by
// administrators, and carry a valid Authenticode signature (from a signer
// --allowed-signer pins, when any is given) or, in hash_pinned mode, the
// SHA-256 the payload manifest pins. An --allow-unsigned run never gets
// here (windowsScannerRuntimeCertificationRun), so nothing waives the
// signature. digest is the SHA-256 of source. It returns the trust basis
// that admitted source, which the admission record names.
func admitWindowsScannerRuntimePayload(source, digest string, opts *windowsEnterpriseLifecycleOptions) (string, error) {
	if opts == nil || windowsScannerRuntimeCertificationRun(opts) {
		return "", errors.New("only a production run admits a scanner runtime payload")
	}
	if err := windowsScannerSourceCheck(source, "scanner runtime payload"); err != nil {
		return "", err
	}
	status := "not valid"
	if _, certificate, err := windowsScannerRuntimeAuthenticode(source); err == nil {
		if windowsScannerRuntimeSignerPinned(certificate, opts.allowedSigners) {
			return managed.ScannerRuntimeTrustAuthenticode, nil
		}
		status = "valid, from a signer --allowed-signer does not pin"
	} else if opts.trustMode == windowsEnterpriseTrustHashPinned {
		if pin, ok := opts.payloadPins[strings.ToLower(filepath.Base(source))]; ok && pin == digest {
			return managed.ScannerRuntimeTrustHashPinned, nil
		}
	}
	return "", fmt.Errorf("%s is not admitted by the standalone payload trust policy (Authenticode %s; trust mode %s)",
		source, status, opts.trustMode)
}

// windowsScannerRuntimeAuthenticode is verifyWindowsAuthenticode; a seam
// for tests, whose scanner files are not signed.
var windowsScannerRuntimeAuthenticode = verifyWindowsAuthenticode

// windowsScannerRuntimeSignerPinned reports whether a valid signature's
// signer certificate is admitted by the signer pins: any signer when none
// is pinned, otherwise one whose SHA-256 thumbprint is pinned.
func windowsScannerRuntimeSignerPinned(certificate []byte, signers []string) bool {
	if len(signers) == 0 {
		return true
	}
	thumbprint := sha256.Sum256(certificate)
	return slices.Contains(signers, hex.EncodeToString(thumbprint[:]))
}

func windowsEnterpriseResultHasWarning(result *enterprisestatus.Result, code string) bool {
	for _, warning := range result.Warnings {
		if warning.Code == code {
			return true
		}
	}
	return false
}

func windowsEnterpriseResultHasError(result *enterprisestatus.Result, code string) bool {
	for _, message := range result.Errors {
		if message.Code == code {
			return true
		}
	}
	return false
}

// windowsScannerRuntimeServiceProblem says why the gateway service cannot
// run a prepared scanner runtime, or "" when it can.
func windowsScannerRuntimeServiceProblem() string {
	err := windowsScannerRuntimeServiceCheck()
	if err == nil {
		return ""
	}
	return "the skill, MCP and plugin scanner runtime is prepared but the gateway service cannot run it (" + err.Error() +
		"), so every skill, MCP server and plugin install is blocked (scanner failure, fail-closed); " +
		"restore the access it names, then run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair"
}

// windowsScannerRuntimeUnavailable says what a scanner runtime that is not
// ready blocks and what restores it.
func windowsScannerRuntimeUnavailable(scanners *enterprisestatus.ScannerRuntime) string {
	const blocked = "so every skill, MCP server and plugin install is blocked (scanner failure, fail-closed)"
	state := scanners.State
	if state == "not_prepared" && scanners.Problem != "" {
		return "the skill, MCP and plugin scanner runtime is prepared but damaged (" + scanners.Problem + "), " + blocked +
			"; run enterprise windows repair, or DefenseClawSetup-Enterprise-Standalone-x64.exe /repair, to unpack it again"
	}
	if state == "untrusted" && scanners.Problem != "" {
		return "the skill, MCP and plugin scanner runtime can be changed by an account other than SYSTEM and Administrators (" +
			scanners.Problem + "), so DefenseClaw does not run it, " + blocked +
			"; remove any access it names on a folder above the runtime (Setup does not change those), then run " +
			"DefenseClawSetup-Enterprise-Standalone-x64.exe /repair, which puts back the runtime folder's protected permissions and the payload copy"
	}
	if state == "untrusted" {
		return "the skill, MCP and plugin scanner runtime executable is not one the production payload trust policy admitted " +
			"(it was changed or replaced outside DefenseClaw, or its admission record, from DefenseClaw 1.0.3 or earlier, " +
			"does not prove a production admission), so DefenseClaw does not run it, " + blocked +
			"; run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair to restore the payload copy"
	}
	if state == "not_prepared" {
		return "the skill, MCP and plugin scanner runtime is installed but not prepared, " + blocked +
			"; run enterprise windows repair, or DefenseClawSetup-Enterprise-Standalone-x64.exe /repair, to prepare it"
	}
	return "the skill, MCP and plugin scanner runtime is missing, " + blocked +
		"; run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair (or /ensure) to install it"
}

// reprepareInstalledWindowsScannerRuntime unpacks the runtime of an installed
// scanners executable whose state is not_prepared. A ready runtime is left
// alone. A missing one can only come from a Setup payload, which this run
// does not have, so it is reported. The prepare runs under the scanner
// runtime lock and only while the deployment record names this run's
// deployment, as the install from a payload does.
func reprepareInstalledWindowsScannerRuntime(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) {
	// An admission record that does not prove a production admission is
	// proven again by this run's payload trust policy, or quarantined, before
	// the runtime is read (W2B-G-win review loop round 1).
	why, err := settleUnprovenWindowsScannerRuntimeAdmission(result.Action, opts)
	if err != nil {
		result.AddError("scanner_runtime_unavailable", windowsScannerRuntimePrepareFailed(err))
		result.Scanners = windowsScannerRuntimeReader()
		return
	}
	if why != "" {
		result.AddWarning("scanner_runtime_admission_quarantined", windowsScannerRuntimeAdmissionQuarantined+" (not proven: "+why+")")
	}
	current := windowsScannerRuntimeReader()
	if current.State == "ready" {
		result.Scanners = current
		return
	}
	if current.State == "missing" || current.State == "untrusted" {
		result.AddWarning("scanner_runtime_unavailable", windowsScannerRuntimeUnavailable(current))
		result.Scanners = current
		return
	}
	if err := reprepareWindowsScannerRuntimeLocked(result.Action, opts); err != nil {
		var superseded *windowsScannerRuntimeSupersededError
		switch {
		case errors.As(err, &superseded):
			result.AddWarning("scanner_runtime_superseded", superseded.Error())
		case errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
			// The root went (an uninstall step) after it was read.
			current = windowsScannerRuntimeReader()
			result.AddWarning("scanner_runtime_unavailable", windowsScannerRuntimeUnavailable(current))
			result.Scanners = current
			return
		default:
			result.AddError("scanner_runtime_unavailable", windowsScannerRuntimePrepareFailed(err))
		}
	}
	result.Scanners = windowsScannerRuntimeReader()
}

func reprepareWindowsScannerRuntimeLocked(action string, opts *windowsEnterpriseLifecycleOptions) error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		return err
	}
	defer release()
	owner, err := windowsScannerRuntimeOwnerOf(action, opts)
	if err != nil {
		return err
	}
	if !owner.ours {
		superseded := &windowsScannerRuntimeSupersededError{installed: owner.installed, uninstalled: owner.uninstalled}
		if opts != nil {
			superseded.run = strings.TrimSpace(opts.productVersion)
		}
		return superseded
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := windowsInstalledScannerRuntimeCheck(root, target); err != nil {
		return err
	}
	for _, step := range []string{"prepare", "prune"} {
		if err := runWindowsScannerRuntime(target, step); err != nil {
			return err
		}
	}
	return nil
}

// windowsScannerRuntimePrepareFailed is the error of a lifecycle run whose
// scanner runtime step failed. The run fails: an ensure that hit the
// prepare bound exited 0 with ok=true and a warning, and verify then failed
// with every skill, MCP server and plugin install blocked (GAP-1063).
func windowsScannerRuntimePrepareFailed(err error) string {
	return "DefenseClaw is installed and its services run, but the skill, MCP and plugin scanner runtime could not be prepared (" +
		err.Error() + "), so every skill, MCP server and plugin install is blocked (scanner failure, fail-closed) and verify fails; " +
		"run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1 as LocalSystem to prepare it"
}

// windowsScannerProgress receives a scanner runtime step progress lines:
// standard output for a person, the lifecycle log's diagnostics in a JSON
// run (whose standard output is the result alone), and never standard
// error, which an MDM such as Intune reads as a failed script (GAP-1069).
// The heartbeat paces the still-running lines. Seams for tests.
var (
	windowsScannerProgress  io.Writer = os.Stdout
	windowsScannerHeartbeat           = time.Minute
)

// windowsScannerDiagnostics keeps each progress line in the run's
// diagnostics, which the lifecycle log records.
type windowsScannerDiagnostics struct {
	opts    *windowsEnterpriseLifecycleOptions
	pending []byte
}

func (d *windowsScannerDiagnostics) Write(p []byte) (int, error) {
	d.pending = append(d.pending, p...)
	for {
		index := bytes.IndexByte(d.pending, '\n')
		if index < 0 {
			return len(p), nil
		}
		if line := strings.TrimSpace(string(d.pending[:index])); line != "" &&
			len(d.opts.diagnostics) < windowsEnterpriseEnsureDiagnosticsLimit {
			d.opts.diagnostics = append(d.opts.diagnostics, line)
		}
		d.pending = d.pending[index+1:]
	}
}

// runWindowsScannerRuntime runs one scanner runtime step with a bounded wait.
// Its own messages and a line every heartbeat go to windowsScannerProgress as
// it runs: a first prepare on a cold disk took 13 minutes with no output, so
// an administrator could not tell it from a hang (GAP-0642).
func runWindowsScannerRuntime(executable, step string) error {
	ctx, cancel := context.WithTimeout(context.Background(), windowsScannerPrepareTimeout)
	defer cancel()
	progress := &windowsScannerLockedWriter{w: windowsScannerProgress}
	if step == "prepare" {
		fmt.Fprintf(progress, "[scanners] preparing the skill, MCP and plugin scanner runtime; a first install takes a few minutes, at most %s\n", windowsScannerPrepareTimeout)
	}
	var stdout bytes.Buffer
	lines := &windowsScannerLineWriter{out: progress}
	command := processutil.CommandContext(ctx, executable, step)
	command.Stdout, command.Stderr = &stdout, lines
	start := time.Now()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(windowsScannerHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(progress, "[scanners] %s is still running: %s elapsed, stopped after %s\n",
					step, time.Since(start).Round(time.Second), windowsScannerPrepareTimeout)
			}
		}
	}()
	err := processutil.RunTree(command)
	close(done)
	lines.flush()
	out := append(stdout.Bytes(), lines.captured.Bytes()...)
	if err == nil && step == "prepare" {
		fmt.Fprintf(progress, "[scanners] the scanner runtime is prepared (%s)\n", time.Since(start).Round(time.Second))
	}
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// GAP-0297: Windows reports a process the deadline killed as a bare
		// "exit status 1", which hid the cause.
		return fmt.Errorf("%s the scanner runtime: timed out after %s", step, windowsScannerPrepareTimeout)
	}
	if err != nil {
		return fmt.Errorf("%s the scanner runtime: %v: %s", step, err, windowsEnterpriseBoundedDiagnostic(strings.TrimSpace(string(out))))
	}
	return nil
}

// windowsScannerLockedWriter serializes the step output and the heartbeat.
type windowsScannerLockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *windowsScannerLockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// windowsScannerLineWriter passes the step stderr on line by line, prefixed,
// and keeps a bounded copy for the error diagnostic.
type windowsScannerLineWriter struct {
	out      io.Writer
	pending  []byte
	captured bytes.Buffer
}

func (l *windowsScannerLineWriter) Write(p []byte) (int, error) {
	if l.captured.Len() < 64<<10 {
		l.captured.Write(p)
	}
	l.pending = append(l.pending, p...)
	for {
		index := bytes.IndexByte(l.pending, '\n')
		if index < 0 {
			break
		}
		if line := bytes.TrimSpace(l.pending[:index]); len(line) > 0 {
			fmt.Fprintf(l.out, "[scanners] %s\n", line)
		}
		l.pending = l.pending[index+1:]
	}
	return len(p), nil
}

func (l *windowsScannerLineWriter) flush() {
	if line := bytes.TrimSpace(l.pending); len(line) > 0 {
		fmt.Fprintf(l.out, "[scanners] %s\n", line)
	}
	l.pending = nil
}

// copyWindowsScannerRuntime copies source next to target, unpacks its
// runtime from there, and only then swaps it into place, so the gateway's
// scans never run an installed image whose runtime is not unpacked yet.
func copyWindowsScannerRuntime(source, target, root, want string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(root, ".scanners-"+hex.EncodeToString(suffix)+".tmp")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if want != "" {
		if got, err := windowsEnterpriseFileSHA256(tmp); err != nil || got != want {
			_ = os.Remove(tmp)
			return errors.New("the copied scanner runtime does not match the payload")
		}
		// The copy runs elevated by its path: checked as the installed
		// runtime is, before it runs.
		if err := windowsScannerRuntimeACLCheck(root, tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := runWindowsScannerRuntime(tmp, "prepare"); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	// A scan the gateway is running keeps the installed image mapped, and
	// Windows refuses to replace a mapped image but lets it be renamed: move
	// it aside first, and remove it once nothing runs it.
	previous := ""
	if _, err := os.Lstat(target); err == nil {
		previous = filepath.Join(root, ".scanners-"+hex.EncodeToString(suffix)+".old")
		if err := os.Rename(target, previous); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("move the installed scanner runtime aside: %w", err)
		}
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		if previous != "" {
			_ = os.Rename(previous, target)
		}
		return fmt.Errorf("install the scanner runtime: %w", err)
	}
	removeStaleWindowsScannerCopies(root)
	return nil
}

// removeStaleWindowsScannerCopies removes earlier runtimes moved aside and
// interrupted copies. One a scan still runs stays until the next install.
func removeStaleWindowsScannerCopies(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasPrefix(name, ".scanners-") &&
			(strings.HasSuffix(name, ".old") || strings.HasSuffix(name, ".tmp")) {
			_ = os.Remove(filepath.Join(root, name))
		}
	}
}

// removeWindowsScannerRuntime removes a scanner runtime root an unprivileged
// account created, before the lifecycle makes its own. It refuses a root that
// is a link, so it never follows one out of ProgramData. The uninstall step
// uses retireWindowsScannerRuntime.
func removeWindowsScannerRuntime() error {
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return err
	}
	if err := checkWindowsScannerRuntimeRootForRemoval(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.RemoveAll(root)
}

// readWindowsScannerRuntime reports the installed runtime, its versions and
// the scanner policy and judge the admin config sets.
func readWindowsScannerRuntime() *enterprisestatus.ScannerRuntime {
	state := &enterprisestatus.ScannerRuntime{State: "missing"}
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		return state
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if info, err := os.Lstat(target); err != nil || !info.Mode().IsRegular() {
		return state
	}
	state.Policy, state.JudgeModel = readWindowsStandaloneScannerSettings()
	// Status and verify run this executable with elevated caller privileges.
	// Check the runtime root as a protected directory, then the executable
	// and its ancestors, before invoking even the read-only versions command.
	// A runtime an unprivileged account can change is not run, and it is not
	// missing either: it was reported as missing, and the advice left out the
	// access that keeps it from running (GAP-0827).
	if err := windowsScannerRuntimeACLCheck(root, target); err != nil {
		state.State = "untrusted"
		state.Problem = err.Error()
		return state
	}
	// Then that it is the executable the payload trust policy admitted: an
	// administrator-only folder does not stop an administrator, or a process
	// running as one, from replacing it in place (GAP-0311).
	if managed.CheckScannerRuntimeAdmitted(root, target) != nil {
		state.State = "untrusted"
		return state
	}
	state.State = "not_prepared"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, target, "versions").Output(); err == nil {
		var report struct {
			Versions map[string]string `json:"versions"`
			Prepared bool              `json:"prepared"`
			Problem  string            `json:"problem"`
		}
		if json.Unmarshal(out, &report) == nil {
			state.Versions = report.Versions
			state.Problem = report.Problem
			if report.Prepared {
				if err := managed.ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
					state.State = "untrusted"
					state.Problem = err.Error()
				} else {
					state.State = "ready"
				}
			}
		}
	}
	return state
}

// readWindowsStandaloneScannerSettings reads the skill scanner policy and
// its judge model from the installed admin config. The model is "" when
// scanners.skill_scanner.use_llm is false: no scan runs the judge then, and
// status named the configured model as the judge (GAP-1016).
func readWindowsStandaloneScannerSettings() (string, string) {
	document, ok := readWindowsStandaloneScannerDocument()
	if !ok {
		return "", ""
	}
	model := strings.TrimSpace(document.Scanners.SkillScanner.LLM.Model)
	if model == "" {
		model = strings.TrimSpace(document.LLM.Model)
	}
	if document.skillJudgeDisabled() {
		model = ""
	}
	policy := strings.TrimSpace(document.Scanners.SkillScanner.Policy)
	if policy == "" {
		policy = config.DefaultSkillScannerPolicy
	}
	return policy, model
}

// windowsStandaloneScannerDocument is the part of the installed admin
// config that names the skill scanner's policy and judge.
type windowsStandaloneScannerDocument struct {
	LLM struct {
		Model string `yaml:"model"`
	} `yaml:"llm"`
	Scanners struct {
		SkillScanner struct {
			Policy string `yaml:"policy"`
			// UseLLM is nil when the key is absent: the standalone default
			// runs the judge.
			UseLLM *bool `yaml:"use_llm"`
			LLM    struct {
				Model string `yaml:"model"`
			} `yaml:"llm"`
		} `yaml:"skill_scanner"`
	} `yaml:"scanners"`
}

func (d windowsStandaloneScannerDocument) skillJudgeDisabled() bool {
	return d.Scanners.SkillScanner.UseLLM != nil && !*d.Scanners.SkillScanner.UseLLM
}

// readWindowsStandaloneScannerConfig reads the installed admin config; a
// seam for tests.
var readWindowsStandaloneScannerConfig = func() ([]byte, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return nil, err
	}
	return readWindowsEnterpriseBoundedFile(layout.ConfigPath, 4<<20)
}

func readWindowsStandaloneScannerDocument() (windowsStandaloneScannerDocument, bool) {
	var document windowsStandaloneScannerDocument
	body, err := readWindowsStandaloneScannerConfig()
	if err != nil || yaml.Unmarshal(trimWindowsJSONBOM(body), &document) != nil {
		return windowsStandaloneScannerDocument{}, false
	}
	return document, true
}

// windowsStandaloneSkillJudgeDisabled reports an admin config that turns
// the skill scanner's judge off.
func windowsStandaloneSkillJudgeDisabled() bool {
	document, ok := readWindowsStandaloneScannerDocument()
	return ok && document.skillJudgeDisabled()
}

// writeWindowsEnterpriseScanners prints the scanners line of a status
// summary: state, the pinned versions, the policy and the judge model.
func writeWindowsEnterpriseScanners(output io.Writer, scanners *enterprisestatus.ScannerRuntime) {
	if scanners == nil {
		return
	}
	versions := make([]string, 0, len(scanners.Versions))
	for _, name := range []string{"skill-scanner", "mcp-scanner", "litellm", "python"} {
		if version := scanners.Versions[name]; version != "" {
			versions = append(versions, name+" "+version)
		}
	}
	judge := scanners.JudgeModel
	if judge == "" {
		judge = "none"
	}
	fmt.Fprintf(output, "  Scanners: %s (%s); policy %s; judge %s\n",
		scanners.State, strings.Join(versions, ", "), scanners.Policy, judge)
}
