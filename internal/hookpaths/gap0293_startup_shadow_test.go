// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// A startup that can change what the statement runs withholds the safe
// proofs (touch -h entry proof, replace-verb proof) and never the protected
// reading. Rows come from the shared corpus: the ordinary-name touch -h and
// mv rows hold the proof with no startup; the alias rows stay protected.
func TestGAP0293StartupThatCanShadowTheVerbWithholdsTheSafeProofs(t *testing.T) {
	f := newShellWordFixture(t)
	startupFile := filepath.Join(f.home, "startup.sh")
	if err := os.WriteFile(startupFile, []byte(":\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var touchOrdinary, mvOrdinary, touchAlias string
	for _, row := range hlinkmatrix.Rows(f.names) {
		switch row.ID {
		case "HL-ordinary-single-touch-h":
			touchOrdinary = row.Command
		case "HL-ordinary-single-mv":
			mvOrdinary = row.Command
		case "HL-hard-single-touch":
			touchAlias = row.Command
		}
	}
	if touchOrdinary == "" || mvOrdinary == "" || touchAlias == "" {
		t.Fatal("corpus rows missing")
	}
	safe := func() (touch, mv bool) {
		touch, _ = noDereferenceTouchStatus(touchOrdinary, f.project, f.home)
		return touch, replaceVerbSafe(mvOrdinary, f.project, f.home)
	}
	if touch, mv := safe(); !touch || !mv {
		t.Fatalf("no startup: touch proof %t, replace proof %t, want both", touch, mv)
	}
	for _, tc := range []struct {
		id, name, value string
		touchShadowed   bool
		mvShadowed      bool
	}{
		{"touch-function", "BASH_FUNC_touch%%", "() {  :\n}", true, false},
		{"touch-path-function", "BASH_FUNC_/usr/bin/touch%%", "() {  :\n}", true, false},
		{"mv-function", "BASH_FUNC_mv%%", "() {  :\n}", false, true},
		{"command-not-found", "BASH_FUNC_command_not_found_handle%%", "() {  :\n}", true, true},
		{"unknown-spelling", "BASH_FUNC_s7probe", "() {  :\n}", true, true},
		{"startup-file", "BASH_ENV", startupFile, true, true},
		{"unrelated-function", "BASH_FUNC_s7probe%%", "() {  :\n}", false, false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			touch, mv := safe()
			if touch == tc.touchShadowed || mv == tc.mvShadowed {
				t.Errorf("touch proof %t (shadowed %t), replace proof %t (shadowed %t)", touch, tc.touchShadowed, mv, tc.mvShadowed)
			}
			// the protected reading is never withheld
			if ActionCommandDecision(touchAlias, f.project, f.home) == "" {
				t.Error("the startup removed the protected reading of the alias row")
			}
		})
	}
}
