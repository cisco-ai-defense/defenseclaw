// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// TestGAP1731ControlOnlySourceFallsThrough: Claude Code skips a managed source
// that carries only managedSourcesBehavior / wslInheritsWindowsSettings and
// applies the next one. Fails on a64bfdb931, which selected the control-only
// HKLM source and then found no DefenseClaw hooks in it.
func TestGAP1731ControlOnlySourceFallsThrough(t *testing.T) {
	osAdmin := &claudeCodeSettingsSource{name: "MDM", settings: map[string]interface{}{"managedSourcesBehavior": "merge", "wslInheritsWindowsSettings": false}}
	file := &claudeCodeSettingsSource{name: "file", settings: map[string]interface{}{"allowManagedHooksOnly": true}}
	set := claudeCodeManagedSourceSet{osAdmin: osAdmin, file: file}
	if got := set.active(); got != file {
		t.Fatalf("active source = %v, want the file tier after a control-only OS-admin source", got.label())
	}
	osAdmin.settings["model"] = nil
	if got := set.active(); got != file {
		t.Fatalf("a null policy key selected the OS-admin source")
	}
	osAdmin.settings["model"] = "x"
	if got := set.active(); got != osAdmin {
		t.Fatalf("active source = %v, want the OS-admin source once it carries a policy key", got.label())
	}
}
