//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ValidateTrustedConfigPath validates config.yaml. When the caller is a root
// managed service and path is the config its LaunchDaemon environment pins,
// drift on the file and its folder is repaired first; what survives is
// accepted and logged by ValidateTrustedPolicyFilePath. Structural failures
// stay errors. Pin TrustStrictAncestorsEnv to make every verdict fatal again.
func ValidateTrustedConfigPath(path string) error {
	const label = "managed config"
	err := ValidateTrustedFilePath(path, label)
	if err == nil || trustStrictAncestors() {
		return err
	}
	if layout, ok := PinnedManagedServiceLayout(); ok && layout.ConfigPath != "" &&
		sameCleanPath(layout.ConfigPath, path) && SelfRepairEnabled() {
		RepairOwnedObjects([]OwnedObject{
			{Path: filepath.Dir(layout.ConfigPath), Kind: ObjectConfigDirectory},
			{Path: layout.ConfigPath, Kind: ObjectConfigFile},
		})
		if ValidateTrustedFilePath(path, label) == nil {
			return nil
		}
	}
	return ValidateTrustedPolicyFilePath(path, label)
}

// ValidateTrustedPolicyFilePath validates a managed policy or data file that
// DefenseClaw reads (config.yaml, targets.yaml). It walks like
// ValidateTrustedFilePath, but a permission verdict on the file or an
// ancestor is accepted and logged instead of refusing the file, and an
// untrusted owner or writer on the file itself is logged once as a
// MarkerBoundary finding naming the principal. The root services repair the
// file on their next pass. Structural failures (a missing element, a symlink,
// the wrong type, a hard-linked file) stay errors. Pin TrustStrictAncestorsEnv
// to make every verdict fatal again.
func ValidateTrustedPolicyFilePath(path, label string) error {
	err := ValidateTrustedFilePath(path, label)
	if err == nil || trustStrictAncestors() {
		return err
	}
	return validateDarwinFilePathTolerant(path, label, darwinTolerantLeaf{kind: ObjectAdminFile})
}

// ValidateExecutableFilePath validates a binary or library DefenseClaw runs or
// loads. Code integrity is advisory: structural failures stay errors, every
// permission verdict is accepted, and an untrusted owner or writer on the file
// itself is logged once as a MarkerBoundary finding. The caller keeps running
// and loading the file; the hook guardian re-stamps its metadata and only
// Install re-copies content. Pin TrustStrictAncestorsEnv to make every verdict
// fatal again.
func ValidateExecutableFilePath(path, label string) error {
	err := ValidateTrustedFilePath(path, label)
	if err == nil || trustStrictAncestors() {
		return err
	}
	return validateDarwinFilePathTolerant(path, label, darwinTolerantLeaf{kind: ObjectInstallFile})
}

// ValidateTrustedFilePathTolerant is ValidateExecutableFilePath under the name
// the Windows callers use.
func ValidateTrustedFilePathTolerant(path, label string) error {
	return ValidateExecutableFilePath(path, label)
}

// ValidateTrustedFileStructureTolerant checks only the structure of the named
// file, for a caller that judges its owner and mode on its own descriptor;
// every ancestor is walked drift-tolerantly.
func ValidateTrustedFileStructureTolerant(path, label string) error {
	return validateDarwinFilePathTolerant(path, label, darwinTolerantLeaf{structureOnly: true})
}

// ValidateTrustedRuntimeDirTolerant is ValidateTrustedRuntimeDir with every
// permission verdict accepted and logged. Structural failures stay errors.
func ValidateTrustedRuntimeDirTolerant(path, label string) error {
	if label == "" {
		label = "managed runtime dir"
	}
	clean, err := darwinAbsPath(path, label)
	if err != nil {
		return err
	}
	if err := darwinTolerantElement(clean, true, label, darwinTolerantLeaf{kind: ObjectRuntimeDirectory}, true); err != nil {
		return err
	}
	return darwinTolerantAncestors(clean, label)
}

// ValidateTrustedServiceRuntimeDir validates a managed runtime directory.
// When the caller is a root managed service and path is inside the runtime
// folder its LaunchDaemon environment pins, drift is repaired before the
// verdict, so a re-permissioned runtime/ never stops the service that owns it.
// The verdict itself stays the strict ValidateTrustedRuntimeDir one.
func ValidateTrustedServiceRuntimeDir(path, label, _ string) error {
	err := ValidateTrustedRuntimeDir(path, label)
	if err == nil || trustStrictAncestors() {
		return err
	}
	layout, ok := PinnedManagedServiceLayout()
	if !ok || !SelfRepairEnabled() || !pathInsideRuntime(layout, path) {
		return err
	}
	RepairOwnedObject(OwnedObject{Path: path, Kind: ObjectRuntimeDirectory})
	return ValidateTrustedRuntimeDir(path, label)
}

// AcceptServiceRuntimeFileDrift is the gateway's read-only judgement of a
// managed runtime file it reads, such as a hook or OTLP token. Structure is
// an error, and so is a boundary: a principal other than root or an
// administrator owns or can write the file. Everything else (a tighter mode,
// an administrator owner, a read ACL entry, a write-blocking flag) is accepted
// and logged once; the root services repair it.
func AcceptServiceRuntimeFileDrift(path, label, _ string) error {
	if label == "" {
		label = "managed runtime file"
	}
	if err := ValidateTrustedRuntimeDirTolerant(filepath.Dir(path), label+" directory"); err != nil {
		return err
	}
	result, err := AssessCanonical(path, ObjectRuntimeSecretFile, CanonicalOptions{})
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	switch result.Outcome {
	case CanonicalMissing:
		return fmt.Errorf("%s %s: %w", label, result.Path, os.ErrNotExist)
	case CanonicalBoundary:
		return fmt.Errorf("%s %s: %s", label, result.Path, strings.Join(result.Drift, "; "))
	}
	return nil
}

// validateServiceRuntimeParent judges the folder a runtime directory is made
// in. Inside the Secure Client tree that folder is the install prefix, an
// ancestor whose permissions the platform installer maintains, so it gets the
// ancestor rule: structure is checked and permission verdicts are advisory,
// the same as the config walk.
func validateServiceRuntimeParent(path, label, serviceAccount string) error {
	if !AdvisoryAncestorPath(path) || trustStrictAncestors() {
		return ValidateTrustedServiceRuntimeDir(path, label, serviceAccount)
	}
	clean, err := darwinAbsPath(path, label)
	if err != nil {
		return err
	}
	if err := darwinTolerantElement(clean, true, label, darwinTolerantLeaf{}, false); err != nil {
		return err
	}
	return darwinTolerantAncestors(clean, label)
}

// validateExistingServiceRuntimeFile judges a runtime file that is about to be
// replaced. The replacement is a new inode published by rename, which is
// itself the repair, so only the structure of the old entry matters: a
// directory in its place is an error; permission drift is logged.
func validateExistingServiceRuntimeFile(path, label, serviceAccount string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s: expected regular %s file", path, label)
	}
	if verdict := ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount); verdict != nil {
		EmitResilienceEvent(MarkerRepair, map[string]string{
			"path":   filepath.Clean(path),
			"reason": "replacing a drifted runtime file with a fresh one: " + verdict.Error(),
		})
	}
	return nil
}

func pathInsideRuntime(layout ManagedServiceLayout, path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil || layout.RuntimeDir == "" {
		return false
	}
	return pathAtOrUnder(filepath.Clean(abs), layout.RuntimeDir)
}

func sameCleanPath(a, b string) bool {
	left, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	right, err := filepath.Abs(b)
	if err != nil {
		return false
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

// darwinTolerantLeaf says how a tolerant walk judges the named path.
type darwinTolerantLeaf struct {
	// kind is the canonical form a permission verdict is assessed against
	// for the boundary log line.
	kind ObjectKind
	// structureOnly skips the permission verdict on the named path.
	structureOnly bool
}

func darwinAbsPath(path, label string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	return filepath.Clean(clean), nil
}

func validateDarwinFilePathTolerant(path, label string, leaf darwinTolerantLeaf) error {
	if label == "" {
		label = "managed file"
	}
	clean, err := darwinAbsPath(path, label)
	if err != nil {
		return err
	}
	if err := darwinTolerantElement(clean, false, label, leaf, true); err != nil {
		return err
	}
	return darwinTolerantAncestors(clean, label)
}

func darwinTolerantAncestors(clean, label string) error {
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if !trustedRootAlias(dir) {
			if err := darwinTolerantElement(dir, true, label, darwinTolerantLeaf{}, false); err != nil {
				return err
			}
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// darwinTolerantElement checks one element's structure and then accepts any
// permission verdict on it with a log line. The element is re-read after the
// verdict, so a swap to a symlink or another object while it was judged is
// still reported as structure.
func darwinTolerantElement(path string, wantDir bool, label string, leaf darwinTolerantLeaf, named bool) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := darwinElementStructure(path, before, wantDir, label, named); err != nil {
		return err
	}
	if named && leaf.structureOnly {
		return nil
	}
	verdict := validateTrustedPathElement(path, wantDir, label, false)
	if verdict == nil {
		return nil
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Type() != before.Mode().Type() {
		return verdict
	}
	if err := darwinElementStructure(path, after, wantDir, label, named); err != nil {
		return err
	}
	switch {
	case named:
		if leaf.kind != "" {
			// Logs MarkerAccept, or MarkerBoundary when an untrusted
			// principal owns or can write the object, once per streak.
			_, _ = AssessCanonical(path, leaf.kind, CanonicalOptions{})
		}
		reportTrustDrift(path, label, verdict.Error())
	case AdvisoryAncestorPath(path):
		reportTrustAdvisory(path, label, verdict.Error())
	default:
		reportTrustDrift(path, label, verdict.Error())
	}
	return nil
}

func darwinElementStructure(path string, info os.FileInfo, wantDir bool, label string, named bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected directory in %s path", path, label)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected regular %s file", path, label)
	}
	if named && !wantDir {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			return fmt.Errorf("%s: %s has %d hard links; a managed file must have exactly one", path, label, st.Nlink)
		}
	}
	return nil
}

// AcceptTrustedFileDrift is the read-only judgement a reader applies to a
// root-owned trust record it cannot repair, such as the gateway reading the
// guardian's authorization record. The strict ValidateTrustedFilePath verdict
// is tried first; drift that grants no untrusted principal write (an
// administrator owner, wheel or admin group write, a read ACL entry, a
// write-blocking flag) is then accepted and logged once. An untrusted owner
// or writer and every structural failure keep the strict error.
func AcceptTrustedFileDrift(path, label string) error {
	err := ValidateTrustedFilePath(path, label)
	if err == nil || trustStrictAncestors() {
		return err
	}
	if structureErr := ValidateTrustedFileStructureTolerant(path, label); structureErr != nil {
		return err
	}
	result, assessErr := AssessCanonical(path, ObjectAdminFile, CanonicalOptions{})
	if assessErr != nil || result.Outcome == CanonicalBoundary || result.Outcome == CanonicalMissing {
		return err
	}
	return nil
}
