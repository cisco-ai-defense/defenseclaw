// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

// until 1.1: the wizard never offers a removed connector as the selection.
func TestWizardDefaultsDoNotSelectRetiredOmnigent(t *testing.T) {
	got := applyInteractiveInstallDefaults(options{Connector: "none", Mode: "observe", ModeSet: true},
		&installState{Connector: "omnigent", Mode: "action"}, false, false)
	if got.Connector != "none" {
		t.Fatalf("wizard connector over an OmniGent install = %q, want none", got.Connector)
	}
	for _, choice := range wizardConnectorChoices {
		if choice.Value == "omnigent" {
			t.Fatal("the wizard still offers OmniGent")
		}
	}
}

// An uninstall that tore OmniGent down records it as verified for deferred
// cleanup.
func TestDeferredCleanupRecordAcceptsRetiredOmnigent(t *testing.T) {
	fixture := newDeferredCleanupFixture(t)
	fixture.record.VerifiedConnectors = []string{"claudecode", "codex", "omnigent"}
	paths := hookruntime.Paths{
		Root:     fixture.record.RuntimeRoot,
		Launcher: fixture.record.LauncherPath,
		State:    fixture.record.StatePath,
	}
	if err := validateDeferredUninstallCleanupRecord(
		fixture.record,
		paths,
		fixture.record.InstallerStateRoot,
		fixture.record.MaintenancePath,
		fixture.record.RunValueName,
		fixture.record.RunCommand,
	); err != nil {
		t.Fatalf("OmniGent deferred-cleanup record rejected: %v", err)
	}
}
