// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// StandaloneWindowsScannerRuntimeAdmissionName is the record, in the scanner
// runtime root, of the defenseclaw-scanners.exe the standalone lifecycle
// admitted by the payload trust policy (a valid Authenticode signature, or
// the SHA-256 the payload manifest pins). An administrator or a process that
// replaces the executable in place changes its digest, and nothing runs it
// again until Setup installs an admitted copy (GAP-0311).
const StandaloneWindowsScannerRuntimeAdmissionName = "admission.json"

// maxScannerRuntimeAdmissionBytes bounds the record read.
const maxScannerRuntimeAdmissionBytes = 4 << 10

var scannerRuntimeDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrScannerRuntimeNotAdmitted marks an installed scanner runtime that is not
// the one the lifecycle admitted.
var ErrScannerRuntimeNotAdmitted = errors.New("scanner runtime not admitted")

type scannerRuntimeAdmission struct {
	SchemaVersion int    `json:"schema_version"`
	SHA256        string `json:"sha256"`
	AdmittedAt    string `json:"admitted_at,omitempty"`
}

// WriteScannerRuntimeAdmission records digest as the admitted scanner
// runtime in root. The file inherits the root access control.
func WriteScannerRuntimeAdmission(root, digest string) error {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !scannerRuntimeDigestPattern.MatchString(digest) {
		return fmt.Errorf("scanner runtime digest %q is not a SHA-256", digest)
	}
	data, err := json.Marshal(scannerRuntimeAdmission{
		SchemaVersion: 1, SHA256: digest, AdmittedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	path := filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName)
	temporary := filepath.Join(root, ".admission-"+hex.EncodeToString(suffix)+".tmp")
	if err := os.WriteFile(temporary, append(data, "\n"...), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

// ReadScannerRuntimeAdmission returns the admitted digest root records, or
// "" when it records none.
func ReadScannerRuntimeAdmission(root string) (string, error) {
	path := filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxScannerRuntimeAdmissionBytes {
		return "", fmt.Errorf("%s is not a scanner runtime admission record", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var record scannerRuntimeAdmission
	if err := json.Unmarshal(data, &record); err != nil || !scannerRuntimeDigestPattern.MatchString(record.SHA256) {
		return "", fmt.Errorf("%s is not a scanner runtime admission record", path)
	}
	return record.SHA256, nil
}

// FileSHA256 is the lowercase hex SHA-256 of the file at path.
func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CheckScannerRuntimeAdmitted returns nil when executable, the scanner
// runtime installed in root, is the one the lifecycle admitted, and an
// ErrScannerRuntimeNotAdmitted error that names both digests otherwise.
// Nothing may run an executable that fails it.
func CheckScannerRuntimeAdmitted(root, executable string) error {
	_, err := CheckScannerRuntimeAdmittedDigest(root, executable)
	return err
}

// CheckScannerRuntimeAdmittedDigest is CheckScannerRuntimeAdmitted that also
// returns the admitted digest.
func CheckScannerRuntimeAdmittedDigest(root, executable string) (string, error) {
	admitted, err := ReadScannerRuntimeAdmission(root)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrScannerRuntimeNotAdmitted, err)
	}
	got, err := FileSHA256(executable)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", executable, err)
	}
	const restore = "run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair to install the payload copy"
	if admitted == "" {
		return "", fmt.Errorf("%w: %s (SHA-256 %s) has no admission record, so it is not run; %s",
			ErrScannerRuntimeNotAdmitted, executable, got, restore)
	}
	if got != admitted {
		return "", fmt.Errorf("%w: %s (SHA-256 %s) is not the scanner runtime the payload trust policy admitted (SHA-256 %s): "+
			"it was changed outside DefenseClaw, so it is not run; %s", ErrScannerRuntimeNotAdmitted, executable, got, admitted, restore)
	}
	return admitted, nil
}
