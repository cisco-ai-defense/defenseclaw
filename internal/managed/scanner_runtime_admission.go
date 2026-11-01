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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// StandaloneWindowsScannerRuntimeAdmissionName is the record, in the scanner
// runtime root, of the defenseclaw-scanners.exe the standalone lifecycle
// admitted by the payload trust policy (a valid Authenticode signature, or
// the SHA-256 the payload manifest pins). An administrator or a process that
// replaces the executable in place changes its digest, and nothing runs it
// again until Setup installs an admitted copy (GAP-0311).
const StandaloneWindowsScannerRuntimeAdmissionName = "admission.json"

// scannerRuntimeAdmissionSchema is the record schema that proves a production
// admission. A schema 1 record (DefenseClaw 1.0.3 and earlier) holds only a
// digest: an --allow-unsigned run, a certification scope's included, wrote
// the same record for an unsigned scanner that a production run wrote for a
// signed one, so the record cannot tell them apart. Nothing runs the
// executable such a record names; a production lifecycle run proves it again
// by the payload trust policy or quarantines the record (W2B-G-win review
// loop round 1). Schema 2 records name the production deployment and the
// trust basis that admitted the bytes.
const scannerRuntimeAdmissionSchema = 2

// ScannerRuntimeAdmittedByProduction is the only admitter a record may name:
// the production standalone lifecycle, never a certification scope or an
// --allow-unsigned run.
const ScannerRuntimeAdmittedByProduction = "production"

// The payload trust bases a production admission records.
const (
	ScannerRuntimeTrustAuthenticode = "authenticode"
	ScannerRuntimeTrustHashPinned   = "hash_pinned"
)

// maxScannerRuntimeAdmissionBytes bounds the record read.
const maxScannerRuntimeAdmissionBytes = 4 << 10

var scannerRuntimeDigestPattern = lazyregexp.New(`^[0-9a-f]{64}$`)

// ErrScannerRuntimeNotAdmitted marks an installed scanner runtime that is not
// the one the lifecycle admitted.
var ErrScannerRuntimeNotAdmitted = errors.New("scanner runtime not admitted")

// ErrScannerRuntimeAdmissionUnproven marks a well-formed admission record
// that does not prove the production deployment admitted the digest it
// names (a schema 1 record, or one naming another admitter or no trust
// basis). It is refused like a missing record.
var ErrScannerRuntimeAdmissionUnproven = errors.New("scanner runtime admission record does not prove a production admission")

type scannerRuntimeAdmission struct {
	SchemaVersion int    `json:"schema_version"`
	SHA256        string `json:"sha256"`
	AdmittedBy    string `json:"admitted_by,omitempty"`
	Trust         string `json:"trust,omitempty"`
	AdmittedAt    string `json:"admitted_at,omitempty"`
}

func validScannerRuntimeTrust(trust string) bool {
	return trust == ScannerRuntimeTrustAuthenticode || trust == ScannerRuntimeTrustHashPinned
}

func (r scannerRuntimeAdmission) proven() bool {
	return r.SchemaVersion == scannerRuntimeAdmissionSchema &&
		r.AdmittedBy == ScannerRuntimeAdmittedByProduction && validScannerRuntimeTrust(r.Trust)
}

// WriteScannerRuntimeAdmission records digest as the scanner runtime the
// production lifecycle admitted in root by trust (ScannerRuntimeTrust*).
// The file inherits the root access control.
func WriteScannerRuntimeAdmission(root, digest, trust string) error {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !scannerRuntimeDigestPattern.MatchString(digest) {
		return fmt.Errorf("scanner runtime digest %q is not a SHA-256", digest)
	}
	if !validScannerRuntimeTrust(trust) {
		return fmt.Errorf("scanner runtime trust basis %q is not one the production payload trust policy admits by", trust)
	}
	data, err := json.Marshal(scannerRuntimeAdmission{
		SchemaVersion: scannerRuntimeAdmissionSchema, SHA256: digest,
		AdmittedBy: ScannerRuntimeAdmittedByProduction, Trust: trust,
		AdmittedAt: time.Now().UTC().Format(time.RFC3339),
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

// readScannerRuntimeAdmissionRecord reads the record in root whatever it
// proves; present is false when there is none.
func readScannerRuntimeAdmissionRecord(root string) (record scannerRuntimeAdmission, present bool, err error) {
	path := filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return scannerRuntimeAdmission{}, false, nil
	}
	if err != nil {
		return scannerRuntimeAdmission{}, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxScannerRuntimeAdmissionBytes {
		return scannerRuntimeAdmission{}, false, fmt.Errorf("%s is not a scanner runtime admission record", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return scannerRuntimeAdmission{}, false, err
	}
	if err := json.Unmarshal(data, &record); err != nil || !scannerRuntimeDigestPattern.MatchString(record.SHA256) {
		return scannerRuntimeAdmission{}, false, fmt.Errorf("%s is not a scanner runtime admission record", path)
	}
	return record, true, nil
}

// ReadScannerRuntimeAdmission returns the digest the production lifecycle
// admitted in root, or "" when root records none. A record that does not
// prove a production admission is an ErrScannerRuntimeAdmissionUnproven
// error.
func ReadScannerRuntimeAdmission(root string) (string, error) {
	record, present, err := readScannerRuntimeAdmissionRecord(root)
	if err != nil || !present {
		return "", err
	}
	if !record.proven() {
		return "", fmt.Errorf("%w: %s (schema %d, admitted by %q) was not written by the production deployment's lifecycle",
			ErrScannerRuntimeAdmissionUnproven, filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName),
			record.SchemaVersion, record.AdmittedBy)
	}
	return record.SHA256, nil
}

// UnprovenScannerRuntimeAdmission returns the digest a well-formed record in
// root names when that record does not prove a production admission, and
// ok=false when root has no record or a proven one. A record that cannot be
// read is an error.
func UnprovenScannerRuntimeAdmission(root string) (digest string, ok bool, err error) {
	record, present, err := readScannerRuntimeAdmissionRecord(root)
	if err != nil || !present || record.proven() {
		return "", false, err
	}
	return record.SHA256, true, nil
}

// RemoveScannerRuntimeAdmission removes the record in root, so nothing runs
// the executable it named until the production lifecycle admits one again.
func RemoveScannerRuntimeAdmission(root string) error {
	err := os.Remove(filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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
	const restore = "run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair to install the payload copy"
	admitted, err := ReadScannerRuntimeAdmission(root)
	if errors.Is(err, ErrScannerRuntimeAdmissionUnproven) {
		return "", fmt.Errorf("%w: %s is not run: its admission record, from DefenseClaw 1.0.3 or earlier or an "+
			"--allow-unsigned or certification run, does not show that the production payload trust policy admitted it (%w); %s",
			ErrScannerRuntimeNotAdmitted, executable, err, restore)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrScannerRuntimeNotAdmitted, err)
	}
	got, err := FileSHA256(executable)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", executable, err)
	}
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
