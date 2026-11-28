// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	gap1892Alice = "S-1-5-21-111-222-333-1001"
	gap1892Bob   = "S-1-5-21-111-222-333-1002"
)

func gap1892Target(connectorName, sid, user string) windowsManagedHooksTeardownTarget {
	return windowsManagedHooksTeardownTarget{
		Connector: connectorName, SID: sid, DataDir: `C:\Users\` + user + `\.defenseclaw`,
	}
}

// gap1892Identity is an activated deployment with alice protected for every
// machine-enrolled connector and bob failed for each, as the Guardian records
// an account it skipped (GAP-1733: its folder holds a per-user DefenseClaw
// install). The Guardian publishes alice alone, so the enrollment lists are
// alice's.
func gap1892Identity(t *testing.T) windowsManagedHooksTeardownJournal {
	t.Helper()
	connectors := []string{"claudecode", "codex", "copilot", "cursor"}
	var targets, failed []windowsManagedHooksTeardownTarget
	for _, name := range connectors {
		targets = append(targets, gap1892Target(name, gap1892Alice, "alice"), gap1892Target(name, gap1892Bob, "bob"))
		failed = append(failed, gap1892Target(name, gap1892Bob, "bob"))
	}
	identity := windowsManagedHooksTeardownJournal{
		SchemaVersion:          windowsManagedHooksTeardownJournalSchema,
		Phase:                  "captured",
		ManifestPath:           `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		ManifestSHA256:         strings.Repeat("a", 64),
		ActivationState:        windowsManagedHooksActivated,
		DeploymentGenerationID: strings.Repeat("b", 32),
		HookBinary:             `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:            "127.0.0.1:18970",
		GatewayServiceName:     "DefenseClawGateway",
		Targets:                targets,
		FailedTargets:          failed,
		ClaudeTargetSIDs:       []string{gap1892Alice},
		CodexPolicyActive:      true,
		CodexTargets:           []connector.WindowsCodexManagedRuntimeTarget{{SID: gap1892Alice, DataDir: `C:\Users\alice\.defenseclaw`}},
		CursorTargets:          []enterprisehooks.WindowsCursorManagedRuntimeTarget{{SID: gap1892Alice, DataDir: `C:\Users\alice\.defenseclaw`}},
	}
	var err error
	if identity.ManifestFingerprint, err = windowsManagedHooksTeardownFingerprint(targets); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		identity.SelectorTargets = append(identity.SelectorTargets, enterprisehooks.WindowsManagedRuntimeSelectorTargetSnapshot{
			SchemaVersion: 1, Connector: target.Connector, TargetSID: target.SID,
		})
	}
	return identity
}

// GAP-1892: Setup /uninstall refused 1603 while one account kept an old
// per-user .defenseclaw: the teardown required every manifest target in the
// machine enrollment, and the Guardian leaves out a failed target it never
// protected. The journal of that published set is valid; a protected target
// left out, or a SID outside the manifest, is still refused.
func TestGAP1892TeardownJournalAcceptsTheGuardiansPublishedEnrollment(t *testing.T) {
	// Every connector behind a kept link: the snapshots are empty reads
	// (GAP-0773), so only the enrollment lists are under test.
	keepConnectorFolders(t, "claudecode", "codex", "copilot", "cursor")
	identity := gap1892Identity(t)
	if err := validateWindowsManagedHooksTeardownJournal(identity, identity); err != nil {
		t.Fatalf("the journal of the enrollment the Guardian published was refused: %v", err)
	}

	protectedLeftOut := gap1892Identity(t)
	protectedLeftOut.ClaudeTargetSIDs = []string{}
	if err := validateWindowsManagedHooksTeardownJournal(protectedLeftOut, protectedLeftOut); err == nil {
		t.Fatal("a journal that leaves out a protected Claude target was accepted")
	}
	codexLeftOut := gap1892Identity(t)
	codexLeftOut.CodexTargets = []connector.WindowsCodexManagedRuntimeTarget{}
	if err := validateWindowsManagedHooksTeardownJournal(codexLeftOut, codexLeftOut); err == nil {
		t.Fatal("a journal that leaves out a protected Codex target was accepted")
	}
	cursorLeftOut := gap1892Identity(t)
	cursorLeftOut.CursorTargets = []enterprisehooks.WindowsCursorManagedRuntimeTarget{}
	if err := validateWindowsManagedHooksTeardownJournal(cursorLeftOut, cursorLeftOut); err == nil {
		t.Fatal("a journal that leaves out a protected Cursor target was accepted")
	}
	outside := gap1892Identity(t)
	outside.ClaudeTargetSIDs = []string{gap1892Alice, "S-1-5-21-111-222-333-1099"}
	if err := validateWindowsManagedHooksTeardownJournal(outside, outside); err == nil {
		t.Fatal("a journal naming a Claude SID outside the manifest was accepted")
	}
	wrongDir := gap1892Identity(t)
	wrongDir.CodexTargets = []connector.WindowsCodexManagedRuntimeTarget{{SID: gap1892Alice, DataDir: `C:\Users\mallory\.defenseclaw`}}
	if err := validateWindowsManagedHooksTeardownJournal(wrongDir, wrongDir); err == nil {
		t.Fatal("a journal naming another data directory for a Codex target was accepted")
	}
	notFailed := gap1892Identity(t)
	notFailed.FailedTargets = nil
	if err := validateWindowsManagedHooksTeardownJournal(notFailed, notFailed); err == nil {
		t.Fatal("a journal that leaves out targets the Guardian did not report failed was accepted")
	}
}

// GAP-1892, per-user connectors: the Copilot enrollment the Guardian
// published names alice only, because bob failed and was never protected.
func TestGAP1892TeardownPerUserCheckAcceptsTheGuardiansPublishedEnrollment(t *testing.T) {
	keepConnectorFolders(t)
	previous := windowsManagedHooksPerUserEnrollmentReader
	t.Cleanup(func() { windowsManagedHooksPerUserEnrollmentReader = previous })
	alice := enterprisehooks.WindowsPerUserManagedEnrollmentTarget{SID: gap1892Alice, DataDir: `C:\Users\alice\.defenseclaw`}
	var current []enterprisehooks.WindowsPerUserManagedEnrollmentTarget
	exists := true
	windowsManagedHooksPerUserEnrollmentReader = func(name string) ([]enterprisehooks.WindowsPerUserManagedEnrollmentTarget, bool, error) {
		if name != "copilot" {
			return nil, false, nil
		}
		return current, exists, nil
	}
	identity := windowsManagedHooksTeardownJournal{
		ActivationState: windowsManagedHooksActivated,
		Targets: []windowsManagedHooksTeardownTarget{
			gap1892Target("copilot", gap1892Alice, "alice"), gap1892Target("copilot", gap1892Bob, "bob"),
		},
		FailedTargets: []windowsManagedHooksTeardownTarget{gap1892Target("copilot", gap1892Bob, "bob")},
	}
	current = []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{alice}
	if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err != nil {
		t.Fatalf("the Copilot enrollment the Guardian published was refused: %v", err)
	}
	// A failed target an earlier pass protected keeps its enrollment.
	current = append(current, enterprisehooks.WindowsPerUserManagedEnrollmentTarget{SID: gap1892Bob, DataDir: `C:\Users\bob\.defenseclaw`})
	if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err != nil {
		t.Fatalf("a failed target that kept its enrollment was refused: %v", err)
	}
	for name, test := range map[string]struct {
		current []enterprisehooks.WindowsPerUserManagedEnrollmentTarget
		exists  bool
	}{
		"protected target missing": {current: []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{}, exists: true},
		"enrollment absent":        {exists: false},
		"SID outside the manifest": {current: []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{
			alice, {SID: "S-1-5-21-111-222-333-1099", DataDir: `C:\Users\eve\.defenseclaw`},
		}, exists: true},
		"failed target at another folder": {current: []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{
			alice, {SID: gap1892Bob, DataDir: `C:\Users\eve\.defenseclaw`},
		}, exists: true},
		"duplicate SID": {current: []enterprisehooks.WindowsPerUserManagedEnrollmentTarget{alice, alice}, exists: true},
	} {
		current, exists = test.current, test.exists
		if err := validateWindowsManagedHooksStandalonePerUserEnrollment(identity); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
