// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The TestMain guard names what a run adds to the Secure Client folders, an
// absent tree included, and ignores what was already there (GAP-0780).
func TestSecureClientTreeGuardNamesWhatARunAdds(t *testing.T) {
	base := t.TempDir()
	present := filepath.Join(base, "Cisco Secure Client")
	absent := filepath.Join(base, "Other", "Cisco Secure Client")
	if err := os.MkdirAll(filepath.Join(present, "Existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	check := guardTreesAdditions([]string{present, absent})
	if added := check(); len(added) != 0 {
		t.Fatalf("a quiet run added %v", added)
	}
	cert := filepath.Join(present, "DefenseClaw-Cert")
	if err := os.MkdirAll(filepath.Join(absent, "DefenseClaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cert, 0o700); err != nil {
		t.Fatal(err)
	}
	want := []string{cert, absent, filepath.Join(absent, "DefenseClaw")}
	if added := check(); !reflect.DeepEqual(added, want) {
		t.Fatalf("added = %v, want %v", added, want)
	}
}
