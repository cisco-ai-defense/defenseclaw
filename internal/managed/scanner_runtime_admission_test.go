// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W2B-G-win review loop round 1: an admission record that does not prove
// the production deployment admitted its digest is refused like a missing
// one. A 1.0.3 --allow-unsigned certification install wrote a schema 1
// record for an unsigned scanner in the shared production runtime, the same
// record a signed production install wrote, and the gateway ran whatever it
// named. Every unproven variant is refused; only a schema 2 production
// record with a trust basis admits, and the writer refuses to write
// anything else.
func TestScannerRuntimeAdmissionMustProveProduction(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, StandaloneWindowsScannerRuntimeName)
	if err := os.WriteFile(executable, []byte("unsigned scanner"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := FileSHA256(executable)
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, StandaloneWindowsScannerRuntimeAdmissionName)
	for name, body := range map[string]string{
		"1.0.3 record":           `{"schema_version":1,"sha256":"` + digest + `","admitted_at":"2026-10-01T00:00:00Z"}`,
		"no schema":              `{"sha256":"` + digest + `"}`,
		"schema 1 dressed up":    `{"schema_version":1,"sha256":"` + digest + `","admitted_by":"production","trust":"authenticode"}`,
		"certification admitter": `{"schema_version":2,"sha256":"` + digest + `","admitted_by":"certification","trust":"authenticode"}`,
		"no admitter":            `{"schema_version":2,"sha256":"` + digest + `","trust":"authenticode"}`,
		"waived signature":       `{"schema_version":2,"sha256":"` + digest + `","admitted_by":"production","trust":"allow_unsigned"}`,
		"no trust basis":         `{"schema_version":2,"sha256":"` + digest + `","admitted_by":"production"}`,
		"a later schema":         `{"schema_version":3,"sha256":"` + digest + `","admitted_by":"production","trust":"authenticode"}`,
	} {
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadScannerRuntimeAdmission(root); got != "" || !errors.Is(err, ErrScannerRuntimeAdmissionUnproven) {
			t.Fatalf("%s: read %q, %v; want it refused as unproven", name, got, err)
		}
		err := CheckScannerRuntimeAdmitted(root, executable)
		if !errors.Is(err, ErrScannerRuntimeNotAdmitted) || !strings.Contains(err.Error(), "/repair") {
			t.Fatalf("%s: the executable it names was admitted: %v", name, err)
		}
		if got, ok, err := UnprovenScannerRuntimeAdmission(root); err != nil || !ok || got != digest {
			t.Fatalf("%s: unproven = %q, %v, %v; want the digest it names", name, got, ok, err)
		}
	}
	for _, trust := range []string{"", "allow_unsigned", "certification"} {
		if err := WriteScannerRuntimeAdmission(root, digest, trust); err == nil {
			t.Fatalf("a record with trust basis %q was written", trust)
		}
	}
	for _, trust := range []string{ScannerRuntimeTrustAuthenticode, ScannerRuntimeTrustHashPinned} {
		if err := WriteScannerRuntimeAdmission(root, digest, trust); err != nil {
			t.Fatal(err)
		}
		if err := CheckScannerRuntimeAdmitted(root, executable); err != nil {
			t.Fatalf("a production %s record was refused: %v", trust, err)
		}
		if _, ok, err := UnprovenScannerRuntimeAdmission(root); ok || err != nil {
			t.Fatalf("a production %s record reads as unproven (%v)", trust, err)
		}
	}
	if err := RemoveScannerRuntimeAdmission(root); err != nil {
		t.Fatal(err)
	}
	if err := RemoveScannerRuntimeAdmission(root); err != nil {
		t.Fatalf("removing an absent record: %v", err)
	}
	if err := CheckScannerRuntimeAdmitted(root, executable); !errors.Is(err, ErrScannerRuntimeNotAdmitted) {
		t.Fatalf("the executable was admitted after its record was removed: %v", err)
	}
}
