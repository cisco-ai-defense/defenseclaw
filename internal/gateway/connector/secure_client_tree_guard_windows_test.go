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

func noServiceInstalled() string { return "" }

// The TestMain guard names the tree root and the DefenseClaw* folders a run
// adds directly under it, an absent tree included, and ignores what was
// already there (GAP-0780).
func TestSecureClientTreeGuardNamesWhatARunAdds(t *testing.T) {
	base := t.TempDir()
	present := filepath.Join(base, "Cisco Secure Client")
	absent := filepath.Join(base, "Other", "Cisco Secure Client")
	if err := os.MkdirAll(filepath.Join(present, "Existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	check := guardSecureClientTreeWith([]string{present, absent}, noServiceInstalled)
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

// Secure Client writes its own logs and state below the tree while a run
// goes on; a new child that is not a DefenseClaw folder is not the run's.
func TestSecureClientTreeGuardIgnoresNewNonDefenseClawChildren(t *testing.T) {
	tree := filepath.Join(t.TempDir(), "Cisco Secure Client")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	check := guardSecureClientTreeWith([]string{tree}, noServiceInstalled)
	for _, name := range []string{"Logs", "vpn", "NVM"} {
		if err := os.MkdirAll(filepath.Join(tree, name, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if added := check(); len(added) != 0 {
		t.Fatalf("a new non-DefenseClaw child was reported: %v", added)
	}
}

// A DefenseClaw* folder that was already there belongs to the services of
// the module: new entries inside it are not walked, a new sibling is reported
// whatever the case of its name.
func TestSecureClientTreeGuardDoesNotWalkExistingDefenseClawFolder(t *testing.T) {
	tree := filepath.Join(t.TempDir(), "Cisco Secure Client")
	owned := filepath.Join(tree, "DefenseClaw-Lifecycle")
	if err := os.MkdirAll(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	check := guardSecureClientTreeWith([]string{tree}, noServiceInstalled)
	if err := os.MkdirAll(filepath.Join(owned, "logs", "new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if added := check(); len(added) != 0 {
		t.Fatalf("a new entry inside a pre-existing DefenseClaw folder was reported: %v", added)
	}
	lower := filepath.Join(tree, "defenseclaw-cert")
	if err := os.Mkdir(lower, 0o700); err != nil {
		t.Fatal(err)
	}
	if added := check(); !reflect.DeepEqual(added, []string{lower}) {
		t.Fatalf("added = %v, want %v", added, []string{lower})
	}
}

// With a DefenseClaw or Secure Client service installed the guard is off.
func TestSecureClientTreeGuardSkipsWhenAServiceIsInstalled(t *testing.T) {
	tree := filepath.Join(t.TempDir(), "Cisco Secure Client")
	check := guardSecureClientTreeWith([]string{tree}, func() string { return "DefenseClawGateway" })
	if err := os.MkdirAll(filepath.Join(tree, "DefenseClaw-Cert"), 0o700); err != nil {
		t.Fatal(err)
	}
	if added := check(); len(added) != 0 {
		t.Fatalf("the guard ran with a service installed: %v", added)
	}
}
