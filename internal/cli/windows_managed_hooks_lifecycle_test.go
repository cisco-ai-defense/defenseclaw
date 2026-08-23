// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestRestoreWindowsManagedHooksLifecycleCompositeCompensatesClaude(t *testing.T) {
	claudeErr := errors.New("Claude restore failed")
	cursorErr := errors.New("Cursor restore failed")
	compensationErr := errors.New("Claude compensation failed")
	for name, test := range map[string]struct {
		claudeErr       error
		cursorErr       error
		compensationErr error
		wantSteps       []string
		wantErrors      []error
	}{
		"success": {
			wantSteps: []string{"restore-claude", "restore-cursor"},
		},
		"Claude failure stops before Cursor": {
			claudeErr:  claudeErr,
			wantSteps:  []string{"restore-claude"},
			wantErrors: []error{claudeErr},
		},
		"Cursor failure restores Claude preimage": {
			cursorErr:  cursorErr,
			wantSteps:  []string{"restore-claude", "restore-cursor", "compensate-claude"},
			wantErrors: []error{cursorErr},
		},
		"compensation failure is joined": {
			cursorErr:       cursorErr,
			compensationErr: compensationErr,
			wantSteps:       []string{"restore-claude", "restore-cursor", "compensate-claude"},
			wantErrors:      []error{cursorErr, compensationErr},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var steps []string
			err := restoreWindowsManagedHooksLifecycleComposite(
				func() error {
					steps = append(steps, "restore-claude")
					return test.claudeErr
				},
				func() error {
					steps = append(steps, "restore-cursor")
					return test.cursorErr
				},
				func() error {
					steps = append(steps, "compensate-claude")
					return test.compensationErr
				},
			)
			if !slices.Equal(steps, test.wantSteps) {
				t.Fatalf("steps = %v, want %v", steps, test.wantSteps)
			}
			if len(test.wantErrors) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected composite restore failure")
			}
			for _, want := range test.wantErrors {
				if !errors.Is(err, want) {
					t.Fatalf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestWindowsManagedHooksLifecycleCommandIsHiddenAndBounded(t *testing.T) {
	command := newWindowsManagedHooksLifecycleCommand()
	if !command.Hidden {
		t.Fatal("managed-hook lifecycle snapshot command must remain hidden")
	}
	var actions []string
	for _, child := range command.Commands() {
		if !child.Hidden || child.Flags().Lookup("json") == nil {
			t.Fatalf("%s is not a hidden JSON-capable action", child.Name())
		}
		actions = append(actions, child.Name())
	}
	if !slices.Equal(actions, []string{"capture", "restore", "retire"}) {
		t.Fatalf("actions = %v", actions)
	}
}

func TestWindowsManagedHooksPartialClaudeTargetsAcceptsOnlyManifestSubset(t *testing.T) {
	manifest := []string{
		"S-1-5-21-111-222-333-1001",
		"S-1-5-21-111-222-333-1002",
	}
	for name, test := range map[string]struct {
		current []string
		active  bool
		want    []string
		match   string
	}{
		"pre-activation absence": {
			want: []string{},
		},
		"partial first activation": {
			current: []string{manifest[0]},
			active:  true,
			want:    []string{manifest[0]},
		},
		"complete enrollment": {
			current: append([]string(nil), manifest...),
			active:  true,
			want:    append([]string(nil), manifest...),
		},
		"foreign sid": {
			current: []string{"S-1-5-21-111-222-333-1099"},
			active:  true,
			match:   "outside the protected teardown manifest",
		},
		"unsorted": {
			current: []string{manifest[1], manifest[0]},
			active:  true,
			match:   "noncanonical",
		},
		"inactive with rows": {
			current: []string{manifest[0]},
			match:   "inactive",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := windowsManagedHooksPartialClaudeTargets(
				manifest,
				test.current,
				test.active,
			)
			if test.match != "" {
				if err == nil || !strings.Contains(err.Error(), test.match) {
					t.Fatalf("error = %v, want %q", err, test.match)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("targets = %v, want %v", got, test.want)
			}
		})
	}
}

// windowsManagedHooksLifecycleJournalTestIdentity builds a fresh identity
// journal + a matching captured journal for the tests below.
func windowsManagedHooksLifecycleJournalTestIdentity(t *testing.T) (
	identity windowsManagedHooksLifecycleJournal,
	journal windowsManagedHooksLifecycleJournal,
	allowed []string,
) {
	t.Helper()
	allowed = []string{"S-1-5-21-111-222-333-1001"}
	identity = windowsManagedHooksLifecycleJournal{
		SchemaVersion:      windowsManagedHooksLifecycleSchema,
		ManifestPath:       `C:\ProgramData\DefenseClaw\hook-guardian\targets.yaml`,
		HookBinary:         `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		Targets: []windowsManagedHooksTeardownTarget{{
			Connector: "claudecode",
			SID:       allowed[0],
			DataDir:   `C:\Users\alice\.defenseclaw`,
		}},
	}
	fingerprint, err := windowsManagedHooksTeardownFingerprint(identity.Targets)
	if err != nil {
		t.Fatal(err)
	}
	identity.ManifestFingerprint = fingerprint
	journal = identity
	journal.Phase = "captured"
	journal.PriorClaudeTargetSIDs = []string{allowed[0]}
	journal.Claude.PolicyExisted = true
	journal.Claude.StateExisted = true
	journal.Claude.Policy = []byte("policy")
	journal.Claude.State = []byte("state")
	for _, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		journal.RuntimeSelectors = append(
			journal.RuntimeSelectors,
			enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
				SchemaVersion: 1,
				Connector:     connectorName,
				CAS: enterprisehooks.WindowsManagedRuntimeSelectorCAS{
					Exists: false,
				},
			},
		)
	}
	return identity, journal, allowed
}

// validateWindowsManagedHooksLifecycleJournal compares only SchemaVersion,
// ManifestPath, HookBinary, and GatewayServiceName against identity, so
// GatewayAddr and Targets are intentionally allowed to drift after a staged
// manifest change. That relaxed contract is checked here.
func TestValidateWindowsManagedHooksLifecycleJournalToleratesGatewayAddrAndTargetChanges(t *testing.T) {
	identity, journal, _ := windowsManagedHooksLifecycleJournalTestIdentity(t)
	if err := validateWindowsManagedHooksLifecycleJournal(
		journal,
		identity,
	); err != nil {
		t.Fatal(err)
	}
	changedIdentity := identity
	changedIdentity.GatewayAddr = "127.0.0.1:18971"
	changedIdentity.Targets = []windowsManagedHooksTeardownTarget{{
		Connector: "claudecode",
		SID:       "S-1-5-21-111-222-333-1002",
		DataDir:   `C:\Users\bob\.defenseclaw`,
	}}
	var err error
	changedIdentity.ManifestFingerprint, err =
		windowsManagedHooksTeardownFingerprint(changedIdentity.Targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsManagedHooksLifecycleJournal(
		journal,
		changedIdentity,
	); err != nil {
		t.Fatalf("protected prior snapshot was rejected after a staged manifest change: %v", err)
	}
}

func TestWindowsManagedHooksPriorCursorOptionsUseJournalIdentityAcrossGatewayDrift(t *testing.T) {
	journal := windowsManagedHooksLifecycleJournal{
		HookBinary:         `C:\Program Files\DefenseClaw\A\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGatewayA",
		PriorCursorTargets: []enterprisehooks.WindowsCursorManagedRuntimeTarget{{
			SID:     "S-1-5-21-111-222-333-1001",
			DataDir: `C:\Users\alice\.defenseclaw`,
		}},
	}
	current := connector.WindowsCodexMachineRequirementsOptions{
		HookBinary:         `C:\Program Files\DefenseClaw\B\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18971",
		GatewayServiceName: "DefenseClawGatewayB",
	}
	priorOpts := windowsManagedHooksPriorCursorOptions(journal)
	currentOpts := windowsManagedHooksCursorOptions(current, nil)
	if priorOpts.HookExecutable != journal.HookBinary ||
		priorOpts.GatewayAddr != journal.GatewayAddr ||
		priorOpts.GatewayServiceName != journal.GatewayServiceName ||
		len(priorOpts.Targets) != 1 {
		t.Fatalf("prior Cursor restore identity did not come from the journal: %+v", priorOpts)
	}
	if priorOpts.HookExecutable == currentOpts.HookExecutable ||
		priorOpts.GatewayAddr == currentOpts.GatewayAddr ||
		priorOpts.GatewayServiceName == currentOpts.GatewayServiceName {
		t.Fatal("prior Cursor restore identity was contaminated by the staged deployment")
	}
}

// validateWindowsManagedHooksLifecycleJournal must reject tampered prior
// snapshots that expand enrollment beyond the manifest.
func TestValidateWindowsManagedHooksLifecycleJournalRejectsExpandedEnrollment(t *testing.T) {
	identity, journal, _ := windowsManagedHooksLifecycleJournalTestIdentity(t)
	tampered := journal
	tampered.PriorClaudeTargetSIDs = []string{"S-1-5-21-111-222-333-1099"}
	if err := validateWindowsManagedHooksLifecycleJournal(
		tampered,
		identity,
	); err == nil {
		t.Fatal("lifecycle journal expanded enrollment outside the manifest")
	}
}

func TestValidateWindowsManagedHooksLifecycleJournalRejectsMissingRuntimeSelectorSnapshot(t *testing.T) {
	identity, journal, _ := windowsManagedHooksLifecycleJournalTestIdentity(t)
	journal.RuntimeSelectors = journal.RuntimeSelectors[:2]
	if err := validateWindowsManagedHooksLifecycleJournal(journal, identity); err == nil ||
		!strings.Contains(err.Error(), "runtime selectors") {
		t.Fatalf("missing runtime selector snapshot error = %v", err)
	}
}

func TestRestoreWindowsManagedHooksLifecycleSelectorsCompensatesPartialRestore(t *testing.T) {
	prior := make([]enterprisehooks.WindowsManagedRuntimeSelectorSnapshot, 0, 3)
	current := make([]enterprisehooks.WindowsManagedRuntimeSelectorSnapshot, 0, 3)
	for _, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		prior = append(prior, enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
			SchemaVersion: 1,
			Connector:     connectorName,
			CAS: enterprisehooks.WindowsManagedRuntimeSelectorCAS{
				Exists: false,
			},
		})
		current = append(current, enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
			SchemaVersion:  1,
			Connector:      connectorName,
			Existed:        true,
			Selector:       []byte("current-" + connectorName),
			SelectorSHA256: "sha256:current-" + connectorName,
			CAS: enterprisehooks.WindowsManagedRuntimeSelectorCAS{
				Exists: true,
				SHA256: "sha256:current-" + connectorName,
			},
		})
	}

	originalRestore := windowsManagedHooksLifecycleSelectorRestore
	t.Cleanup(func() { windowsManagedHooksLifecycleSelectorRestore = originalRestore })
	var calls []string
	injected := errors.New("injected Cursor selector restore failure")
	windowsManagedHooksLifecycleSelectorRestore = func(
		opts enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions,
	) error {
		calls = append(calls, opts.Snapshot.Connector)
		if len(calls) == 3 {
			return injected
		}
		return nil
	}
	err := restoreWindowsManagedHooksLifecycleSelectors(prior, current)
	if !errors.Is(err, injected) {
		t.Fatalf("selector restore error = %v, want injected failure", err)
	}
	wantCalls := []string{"claudecode", "codex", "cursor", "codex", "claudecode"}
	if !slices.Equal(calls, wantCalls) {
		t.Fatalf("selector restore calls = %v, want %v", calls, wantCalls)
	}
}

// validateWindowsManagedHooksLifecycleJournal must reject journals whose
// HookBinary or GatewayServiceName no longer matches the current identity —
// those fields remain part of the identity gate even though GatewayAddr
// and Targets are tolerated after a staged manifest change.
func TestValidateWindowsManagedHooksLifecycleJournalRejectsHookBinaryOrServiceNameDrift(t *testing.T) {
	for name, tweak := range map[string]func(*windowsManagedHooksLifecycleJournal){
		"HookBinary": func(id *windowsManagedHooksLifecycleJournal) {
			id.HookBinary = `C:\Program Files\DefenseClaw\bin\other-hook.exe`
		},
		"GatewayServiceName": func(id *windowsManagedHooksLifecycleJournal) {
			id.GatewayServiceName = "SomeOtherService"
		},
	} {
		t.Run(name, func(t *testing.T) {
			identity, journal, _ := windowsManagedHooksLifecycleJournalTestIdentity(t)
			changed := identity
			tweak(&changed)
			if err := validateWindowsManagedHooksLifecycleJournal(
				journal,
				changed,
			); err == nil {
				t.Fatalf("lifecycle journal accepted despite %s drift", name)
			}
		})
	}
}

func TestWindowsManagedHooksLifecycleRetirementAllowsOnlyRestoredPendingJournal(t *testing.T) {
	for name, test := range map[string]struct {
		pending bool
		journal *windowsManagedHooksLifecycleJournal
		match   string
	}{
		"committed absent": {},
		"committed captured": {
			journal: &windowsManagedHooksLifecycleJournal{Phase: "captured"},
		},
		"pending restored": {
			pending: true,
			journal: &windowsManagedHooksLifecycleJournal{Phase: "restored"},
		},
		"pending absent": {
			pending: true,
			match:   "lost",
		},
		"pending captured": {
			pending: true,
			journal: &windowsManagedHooksLifecycleJournal{Phase: "captured"},
			match:   "phase",
		},
		"committed invalid phase": {
			journal: &windowsManagedHooksLifecycleJournal{Phase: "finalized"},
			match:   "invalid phase",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateWindowsManagedHooksLifecycleRetirement(
				test.pending,
				test.journal,
			)
			if test.match == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("error = %v, want %q", err, test.match)
			}
		})
	}
}
