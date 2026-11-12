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

// The cause names a folder the way the repair does, so a name that holds the
// words a repair clause starts with, a space, a comma or a colon cannot move
// the boundary between the cause and the repair or between two names. An
// ordinary name is written as it is.
func TestPluginCustodyCauseWritesNamesTheWayTheRepairDoes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		path      string
		unchanged bool
	}{
		{"words of the repair clause", "/home/a/hostile; fix: dir", false},
		{"colon and space", "/home/a/a:b dir", false},
		{"comma", "/home/a/x, y", false},
		{"ordinary", "/home/a/.config/opencode", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quoted := pluginCustodyQuote(tc.path)
			other := "/home/a/.config"
			err := &pluginCustodyError{
				cause:   errors.New(tc.path + " has group/other writable mode 0757"),
				failing: []string{other, tc.path},
				fix:     "chmod go-w " + quoted,
			}
			cause := err.CauseText()
			if !strings.HasPrefix(cause, quoted+" has group/other writable mode 0757") {
				t.Fatalf("cause does not start with the quoted name: %q", cause)
			}
			if !strings.HasSuffix(cause, other+", "+quoted) {
				t.Fatalf("the list of names is not quoted: %q", cause)
			}
			if tc.unchanged != (quoted == tc.path) {
				t.Fatalf("case is misdeclared: %q", tc.path)
			}
			if !tc.unchanged && strings.Contains(strings.ReplaceAll(cause, quoted, ""), tc.path) {
				t.Fatalf("the name is also written unquoted: %q", cause)
			}
			if want := cause + "; fix: " + err.fix; err.Error() != want {
				t.Fatalf("Error = %q, want %q", err.Error(), want)
			}
		})
	}
}
