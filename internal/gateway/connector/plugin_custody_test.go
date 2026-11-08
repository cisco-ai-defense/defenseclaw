// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"strings"
	"testing"
)

// Secure Client behaviour is unchanged: a refusal that was classed as managed
// permission drift keeps that class once the fix is added to its text, and the
// plain refusal does not become drift.
func TestGAP0730CustodyRefusalKeepsTheCausesClass(t *testing.T) {
	drift := &pluginCustodyError{cause: managedDriftError{err: errors.New("x")}, failing: []string{"/a"}, fix: "chmod go-w /a"}
	if !isManagedPermissionDrift(drift) || !errors.Is(drift, ErrPluginFolderCustody) {
		t.Fatalf("managed drift class lost: %v", drift)
	}
	plain := &pluginCustodyError{cause: errors.New("x"), failing: []string{"/a"}, fix: "chmod go-w /a"}
	if isManagedPermissionDrift(plain) {
		t.Fatal("a plain refusal became permission drift")
	}
}

// The refusal hands its repair over as fields: the text a caller shows is the
// cause plus the repair, and the cause alone never holds the repair, whatever
// the names in it say.
func TestPluginCustodyRefusalCarriesItsRepairApartFromItsCause(t *testing.T) {
	odd := "/a/Open; fix: Code  Dir"
	err := &pluginCustodyError{cause: errors.New("refused " + odd), failing: []string{"/a", odd}, fix: "chmod go-w '" + odd + "'", manual: "replace the link '" + odd + "'"}
	var refusal RepairedRefusal = err
	fix, manual := refusal.Repair()
	if fix != err.fix || manual != err.manual {
		t.Fatalf("Repair = %q, %q", fix, manual)
	}
	if cause := refusal.CauseText(); strings.Contains(cause, "chmod") || strings.Contains(cause, "replace the link") || !strings.Contains(cause, odd) {
		t.Fatalf("CauseText = %q", cause)
	}
	if want := refusal.CauseText() + "; fix: " + fix + "; then by hand: " + manual; refusal.Error() != want {
		t.Fatalf("Error = %q, want %q", refusal.Error(), want)
	}
	plain := &pluginCustodyError{cause: errors.New("x"), failing: []string{"/a"}}
	if plain.Error() != "x" {
		t.Fatalf("a refusal with no repair added text: %q", plain.Error())
	}
}
