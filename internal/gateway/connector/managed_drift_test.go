// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	driftTestTarget    = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	driftTestHelpdesk  = "S-1-5-21-1111111111-2222222222-3333333333-5120"
	driftTestAdminUser = "S-1-5-21-1111111111-2222222222-3333333333-500"
	driftTestBackup    = "S-1-5-21-1111111111-2222222222-3333333333-7777"
)

func codexMachineDriftPolicy() managedDriftPolicy {
	return managedDriftPolicy{Canonical: managedDescriptor{
		Owner:     managedSIDAdministrators,
		Protected: true,
		ACEs: []managedACE{
			{SID: managedSIDAdministrators, Mask: managedFileAllAccess},
			{SID: managedSIDLocalSystem, Mask: managedFileAllAccess},
			{SID: managedSIDUsers, Mask: managedFileGenericRead},
		},
	}}
}

func targetRuntimeDriftPolicy() managedDriftPolicy {
	return managedDriftPolicy{
		Canonical:    managedTargetRuntimeCanonicalModel(driftTestTarget),
		ExtraTrusted: []string{driftTestTarget},
	}
}

func cloneDescriptor(d managedDescriptor) managedDescriptor {
	d.ACEs = append([]managedACE(nil), d.ACEs...)
	return d
}

func TestClassifyManagedDriftCanonicalAcceptsGenericRights(t *testing.T) {
	policy := codexMachineDriftPolicy()
	live := managedDescriptor{
		Owner:     managedSIDAdministrators,
		Protected: true,
		// SetEntriesInAcl may store generic bits; the kernel may store the
		// mapped file rights. Both are the same descriptor.
		ACEs: []managedACE{
			{SID: managedSIDUsers, Mask: managedGenericRead},
			{SID: managedSIDLocalSystem, Mask: managedGenericAll},
			{SID: managedSIDAdministrators, Mask: managedFileAllAccess},
		},
	}
	drift := classifyManagedDrift(live, policy)
	if !drift.Canonical {
		t.Fatalf("generic-rights descriptor = %+v (%s), want canonical", drift, drift.Reason())
	}
	if got := decideManagedDrift(drift, true); got != managedDriftNone {
		t.Fatalf("canonical action = %v, want none", got)
	}
}

func TestClassifyManagedDriftHarmlessShapes(t *testing.T) {
	cases := map[string]func(*managedDescriptor){
		"inherited entries": func(d *managedDescriptor) {
			d.Protected = false
			d.ACEs = append(d.ACEs, managedACE{
				SID: managedSIDAdministrators, Flags: managedACEFlagInherited, Mask: managedFileAllAccess,
			})
		},
		"extra read entry": func(d *managedDescriptor) {
			d.ACEs = append(d.ACEs, managedACE{SID: driftTestBackup, Mask: managedFileGenericRead})
		},
		"administrators owner": func(d *managedDescriptor) {
			d.Owner = managedSIDAdministrators
		},
		"trusted installer owner": func(d *managedDescriptor) {
			d.Owner = managedSIDTrustedInstaller
		},
		"inherit-only creator owner": func(d *managedDescriptor) {
			d.ACEs = append(d.ACEs, managedACE{
				SID:   managedSIDCreatorOwner,
				Flags: managedACEFlagInheritOnly | managedACEFlagObjectInherit | managedACEFlagContainerInherit,
				Mask:  managedGenericAll,
			})
		},
		"owner rights write": func(d *managedDescriptor) {
			d.ACEs = append(d.ACEs, managedACE{SID: managedSIDOwnerRights, Mask: managedFileGenericWrite})
		},
		"deny entry": func(d *managedDescriptor) {
			d.ACEs = append(d.ACEs, managedACE{SID: driftTestHelpdesk, Type: managedACETypeDenied, Mask: managedGenericAll})
		},
		"inherited users read": func(d *managedDescriptor) {
			d.ACEs = append(d.ACEs, managedACE{SID: managedSIDUsers, Flags: managedACEFlagInherited, Mask: managedFileGenericRead})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := targetRuntimeDriftPolicy()
			live := cloneDescriptor(policy.Canonical)
			mutate(&live)
			drift := classifyManagedDrift(live, policy)
			if drift.Canonical {
				t.Fatalf("%s classified canonical", name)
			}
			if drift.Boundary() {
				t.Fatalf("%s is harmless drift, got boundary: %s", name, drift.Reason())
			}
			if got := decideManagedDrift(drift, false); got != managedDriftAccept {
				t.Fatalf("unprivileged action = %v, want accept", got)
			}
			if got := decideManagedDrift(drift, true); got != managedDriftRepair {
				t.Fatalf("privileged action = %v, want repair", got)
			}
			if marker := managedDriftMarker(drift, false, true); marker != managed.MarkerAccept {
				t.Fatalf("accepted marker = %s, want %s", marker, managed.MarkerAccept)
			}
			if marker := managedDriftMarker(drift, true, true); marker != managed.MarkerRepair {
				t.Fatalf("repaired marker = %s, want %s", marker, managed.MarkerRepair)
			}
		})
	}
}

func TestClassifyManagedDriftUntrustedWriterIsBoundary(t *testing.T) {
	policy := codexMachineDriftPolicy()
	live := cloneDescriptor(policy.Canonical)
	live.ACEs = append(live.ACEs,
		managedACE{SID: driftTestHelpdesk, Mask: managedFileGenericRead | managedFileGenericWrite},
		managedACE{SID: managedSIDUsers, Flags: managedACEFlagInherited, Mask: managedFileWriteData},
	)
	drift := classifyManagedDrift(live, policy)
	want := []string{strings.ToUpper(driftTestHelpdesk), managedSIDUsers}
	if !reflect.DeepEqual(drift.UntrustedWriters, want) {
		t.Fatalf("untrusted writers = %v, want %v", drift.UntrustedWriters, want)
	}
	if !drift.Boundary() || !drift.Inherited || !drift.Extra {
		t.Fatalf("drift = %+v, want boundary with inherited extra entries", drift)
	}
	if marker := managedDriftMarker(drift, true, true); marker != managed.MarkerBoundary {
		t.Fatalf("repaired policy marker = %s, want boundary", marker)
	}
	if marker := managedDriftMarker(drift, true, false); marker != managed.MarkerRepair {
		t.Fatalf("repaired data marker = %s, want repair", marker)
	}
	if !strings.Contains(drift.Reason(), "untrusted writer") {
		t.Fatalf("reason %q does not name the writer", drift.Reason())
	}
}

func TestClassifyManagedDriftOwners(t *testing.T) {
	for name, tc := range map[string]struct {
		owner     string
		untrusted bool
	}{
		"administrator user": {owner: driftTestAdminUser, untrusted: true},
		"trusted installer":  {owner: managedSIDTrustedInstaller},
		"local system":       {owner: managedSIDLocalSystem},
		"target user":        {owner: driftTestTarget},
	} {
		t.Run(name, func(t *testing.T) {
			live := cloneDescriptor(codexMachineDriftPolicy().Canonical)
			live.Owner = tc.owner
			policy := codexMachineDriftPolicy()
			if tc.owner == driftTestTarget {
				policy.ExtraTrusted = []string{driftTestTarget}
			}
			drift := classifyManagedDrift(live, policy)
			if !drift.OwnerDrift {
				t.Fatalf("owner %s not reported as drift", tc.owner)
			}
			if drift.UntrustedOwner != tc.untrusted {
				t.Fatalf("untrusted owner = %v, want %v", drift.UntrustedOwner, tc.untrusted)
			}
		})
	}
}

func TestClassifyManagedDriftMissingAndNullDACL(t *testing.T) {
	policy := targetRuntimeDriftPolicy()
	live := cloneDescriptor(policy.Canonical)
	live.ACEs = live.ACEs[:2]
	drift := classifyManagedDrift(live, policy)
	if !drift.Missing || drift.Boundary() {
		t.Fatalf("missing entries drift = %+v", drift)
	}

	null := managedDescriptor{Owner: driftTestTarget, Protected: true, NullDACL: true}
	drift = classifyManagedDrift(null, policy)
	if !drift.Boundary() || drift.Canonical {
		t.Fatalf("null DACL drift = %+v, want boundary", drift)
	}
}

func TestManagedReadOnlyPlan(t *testing.T) {
	for name, tc := range map[string]struct {
		attributes     uint32
		clear, restore uint32
	}{
		"plain":              {attributes: 0x80},
		"readonly":           {attributes: managedFileAttrReadOnly, clear: managedFileAttrReadOnly, restore: managedFileAttrReadOnly},
		"readonly hidden":    {attributes: managedFileAttrReadOnly | managedFileAttrHidden, clear: managedFileAttrReadOnly, restore: managedFileAttrReadOnly},
		"hidden system only": {attributes: managedFileAttrHidden | managedFileAttrSystem},
		"readonly directory": {attributes: managedFileAttrReadOnly | managedFileAttrDirectory},
		"readonly reparse":   {attributes: managedFileAttrReadOnly | managedFileAttrReparse},
	} {
		t.Run(name, func(t *testing.T) {
			clear, restore := managedReadOnlyPlan(tc.attributes)
			if clear != tc.clear || restore != tc.restore {
				t.Fatalf("plan(0x%x) = (0x%x, 0x%x), want (0x%x, 0x%x)",
					tc.attributes, clear, restore, tc.clear, tc.restore)
			}
		})
	}
}

func TestManagedTransientRetry(t *testing.T) {
	errBusy := errors.New("busy")
	errDenied := errors.New("denied")
	retry := managedTransientRetry{Attempts: 4, Initial: time.Millisecond, Max: 3 * time.Millisecond}
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }
	transient := func(err error) bool { return errors.Is(err, errBusy) }

	calls := 0
	err := retry.run(func() error {
		calls++
		if calls < 3 {
			return errBusy
		}
		return nil
	}, transient, sleep)
	if err != nil || calls != 3 {
		t.Fatalf("transient retry = %v after %d calls, want success after 3", err, calls)
	}
	if want := []time.Duration{time.Millisecond, 2 * time.Millisecond}; !reflect.DeepEqual(slept, want) {
		t.Fatalf("backoff = %v, want %v", slept, want)
	}

	calls = 0
	slept = nil
	if err := retry.run(func() error { calls++; return errDenied }, transient, sleep); !errors.Is(err, errDenied) || calls != 1 {
		t.Fatalf("access denied retried: err=%v calls=%d", err, calls)
	}

	calls = 0
	slept = nil
	if err := retry.run(func() error { calls++; return errBusy }, transient, sleep); !errors.Is(err, errBusy) || calls != 4 {
		t.Fatalf("budget not bounded: err=%v calls=%d", err, calls)
	}
	if got := retry.delay(10); got != 3*time.Millisecond {
		t.Fatalf("delay cap = %v, want 3ms", got)
	}
}

func TestEmitManagedResilienceDedupesAcceptsOnly(t *testing.T) {
	original := managed.ReportResilienceEvent
	t.Cleanup(func() { managed.ReportResilienceEvent = original })
	var markers []string
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		if fields["path"] == "" || fields["reason"] == "" {
			t.Errorf("event %s without path or reason: %v", marker, fields)
		}
		markers = append(markers, marker)
	}
	path := fmt.Sprintf(`C:\drift-test\%d`, time.Now().UnixNano())
	emitManagedResilience(managed.MarkerAccept, path, "extra reader", nil)
	emitManagedResilience(managed.MarkerAccept, path, "extra reader", nil)
	emitManagedResilience(managed.MarkerRepair, path, "re-stamped", nil)
	emitManagedResilience(managed.MarkerRepair, path, "re-stamped", nil)
	managedPinMismatch(path, "state", "aa", "bb")
	want := []string{managed.MarkerAccept, managed.MarkerRepair, managed.MarkerRepair, managed.MarkerAccept}
	if !reflect.DeepEqual(markers, want) {
		t.Fatalf("markers = %v, want %v", markers, want)
	}
}

func TestIsManagedPermissionDrift(t *testing.T) {
	drift := managedPermissionDrift("owner %s is not trusted", driftTestAdminUser)
	if !IsManagedPermissionDrift(drift) || !IsManagedPermissionDrift(fmt.Errorf("read token: %w", drift)) {
		t.Fatal("wrapped permission drift not recognised")
	}
	if IsManagedPermissionDrift(errors.New("reparse points are not allowed")) || IsManagedPermissionDrift(nil) {
		t.Fatal("structural error recognised as drift")
	}
}
