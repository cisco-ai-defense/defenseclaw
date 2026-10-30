// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testGatewaySID = "S-1-5-80-1-2-3-4-5"

const oici = aceFlagObjectInherit | aceFlagContainerInherit

func canonicalRuntimeDir() objectDescriptor {
	return objectDescriptor{
		Owner:     sidAdministrators,
		Protected: true,
		ACEs: []descriptorACE{
			{Type: aceTypeAllowed, Flags: oici, Mask: maskFullControl, SID: sidLocalSystem},
			{Type: aceTypeAllowed, Flags: oici, Mask: maskFullControl, SID: sidAdministrators},
			{Type: aceTypeAllowed, Flags: oici, Mask: maskModify, SID: testGatewaySID},
		},
	}
}

func canonicalRuntimeFile() objectDescriptor {
	desc := canonicalRuntimeDir()
	for index := range desc.ACEs {
		desc.ACEs[index].Flags = 0
	}
	return desc
}

func TestAssessCanonicalDescriptorRuntimeDirectoryDrift(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(*objectDescriptor)
		want          CanonicalOutcome
		gatewayAccess bool
	}{
		{name: "canonical", mutate: func(*objectDescriptor) {}, want: CanonicalOK},
		{name: "inheritance re-enabled with trusted inherited entries", mutate: func(d *objectDescriptor) {
			d.Protected = false
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: aceFlagInherited | oici, Mask: maskFullControl, SID: sidLocalSystem})
		}, want: CanonicalAccepted},
		{name: "extra read entry", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskReadAndExecute, SID: sidUsers})
		}, want: CanonicalAccepted},
		{name: "extra untrusted write entry", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskModify, SID: sidUsers})
		}, want: CanonicalBoundary},
		{name: "built-in administrator account owner", mutate: func(d *objectDescriptor) {
			d.Owner = "S-1-5-21-111-222-333-500"
		}, want: CanonicalAccepted},
		{name: "domain admins write entry", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskModify, SID: "S-1-5-21-111-222-333-512"})
		}, want: CanonicalAccepted},
		{name: "trusted installer owner", mutate: func(d *objectDescriptor) {
			d.Owner = sidTrustedInstaller
		}, want: CanonicalAccepted},
		{name: "standard user owner", mutate: func(d *objectDescriptor) {
			d.Owner = "S-1-5-21-111-222-333-1001"
		}, want: CanonicalBoundary},
		{name: "gateway writer entry missing", mutate: func(d *objectDescriptor) {
			d.ACEs = d.ACEs[:2]
		}, want: CanonicalAccepted, gatewayAccess: true},
		{name: "gateway writer not inheritable", mutate: func(d *objectDescriptor) {
			d.ACEs[2].Flags = 0
		}, want: CanonicalAccepted, gatewayAccess: true},
		{name: "inherit-only creator owner", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: aceFlagInheritOnly | oici, Mask: maskFullControl, SID: sidCreatorOwner})
		}, want: CanonicalAccepted},
		{name: "inherited users create-child", mutate: func(d *objectDescriptor) {
			d.Protected = false
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: aceFlagInherited | aceFlagContainerInherit, Mask: maskAppendData | maskWriteData, SID: sidUsers})
		}, want: CanonicalAccepted},
		{name: "inherited object-inheritable users create-child", mutate: func(d *objectDescriptor) {
			d.Protected = false
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: aceFlagInherited | oici, Mask: maskAppendData | maskWriteData, SID: sidUsers})
		}, want: CanonicalBoundary},
		{name: "deny entry for unrelated principal", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeDenied, Mask: maskWriteData, SID: sidUsers})
		}, want: CanonicalAccepted},
		{name: "generic rights for trusted principals", mutate: func(d *objectDescriptor) {
			d.ACEs[0].Mask = maskGenericAll
		}, want: CanonicalAccepted},
		{name: "null DACL", mutate: func(d *objectDescriptor) {
			d.NullDACL = true
			d.ACEs = nil
		}, want: CanonicalBoundary},
		{name: "object entry with write", mutate: func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowedObject, Mask: maskModify})
		}, want: CanonicalBoundary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desc := canonicalRuntimeDir()
			tc.mutate(&desc)
			got := assessCanonicalDescriptor(desc, ObjectRuntimeDirectory, testGatewaySID, nil)
			if got.outcome() != tc.want {
				t.Fatalf("outcome = %s, want %s (drift %v)", got.outcome(), tc.want, got.Drift)
			}
			if got.GatewayAccessMissing != tc.gatewayAccess {
				t.Fatalf("gateway access missing = %t, want %t", got.GatewayAccessMissing, tc.gatewayAccess)
			}
			if tc.want != CanonicalOK && len(got.Drift) == 0 {
				t.Fatal("drift without a reason")
			}
		})
	}
}

func TestAssessCanonicalDescriptorAdminMembership(t *testing.T) {
	desc := canonicalRuntimeDir()
	desc.Owner = "S-1-5-21-111-222-333-1105"
	member := func(sid string) bool { return sid == "S-1-5-21-111-222-333-1105" }
	if got := assessCanonicalDescriptor(desc, ObjectRuntimeDirectory, testGatewaySID, member).outcome(); got != CanonicalAccepted {
		t.Fatalf("administrator member owner = %s, want accepted", got)
	}
	if got := assessCanonicalDescriptor(desc, ObjectRuntimeDirectory, testGatewaySID, nil).outcome(); got != CanonicalBoundary {
		t.Fatalf("unknown owner = %s, want boundary", got)
	}
}

func TestAssessCanonicalDescriptorRuntimeFileForms(t *testing.T) {
	if got := assessCanonicalDescriptor(canonicalRuntimeFile(), ObjectRuntimeFile, testGatewaySID, nil); !got.Canonical {
		t.Fatalf("installer runtime file form not canonical: %v", got.Drift)
	}
	gatewayOwned := canonicalRuntimeFile()
	gatewayOwned.Owner = testGatewaySID
	gatewayOwned.ACEs = append([]descriptorACE{{Type: aceTypeAllowed, Mask: maskReadControl, SID: sidOwnerRights}}, gatewayOwned.ACEs...)
	if got := assessCanonicalDescriptor(gatewayOwned, ObjectRuntimeFile, testGatewaySID, nil); !got.Canonical {
		t.Fatalf("gateway-owned runtime file form not canonical: %v", got.Drift)
	}
	readOnly := canonicalRuntimeFile()
	readOnly.ACEs[2].Mask = maskRead
	got := assessCanonicalDescriptor(readOnly, ObjectRuntimeFile, testGatewaySID, nil)
	if got.outcome() != CanonicalAccepted || !got.GatewayAccessMissing {
		t.Fatalf("read-only gateway entry: outcome %s, missing %t", got.outcome(), got.GatewayAccessMissing)
	}
}

func TestAssessCanonicalDescriptorSecretFile(t *testing.T) {
	desc := objectDescriptor{
		Owner:     testGatewaySID,
		Protected: true,
		ACEs: []descriptorACE{
			{Type: aceTypeAllowed, Mask: maskReadControl, SID: sidOwnerRights},
			{Type: aceTypeAllowed, Mask: maskFullControl, SID: sidLocalSystem},
			{Type: aceTypeAllowed, Mask: maskFullControl, SID: sidAdministrators},
			{Type: aceTypeAllowed, Mask: maskRead, SID: testGatewaySID},
		},
	}
	if got := assessCanonicalDescriptor(desc, ObjectRuntimeSecretFile, testGatewaySID, nil); !got.Canonical {
		t.Fatalf("secret form not canonical: %v", got.Drift)
	}
	desc.Owner = sidAdministrators
	desc.ACEs = append(desc.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskRead, SID: "S-1-5-32-551"})
	if got := assessCanonicalDescriptor(desc, ObjectRuntimeSecretFile, testGatewaySID, nil).outcome(); got != CanonicalAccepted {
		t.Fatalf("admin owner plus backup operators read = %s, want accepted", got)
	}
}

func TestCanonicalSDDL(t *testing.T) {
	got := canonicalSpecFor(ObjectRuntimeDirectory, testGatewaySID).canonicalSDDL()
	want := "O:S-1-5-32-544G:BAD:P(A;OICI;0x1f01ff;;;S-1-5-18)(A;OICI;0x1f01ff;;;S-1-5-32-544)(A;OICI;0x1301bf;;;" + testGatewaySID + ")"
	if got != want {
		t.Fatalf("SDDL = %s, want %s", got, want)
	}
	got = canonicalSpecFor(ObjectRuntimeSecretFile, testGatewaySID).canonicalSDDL()
	if !strings.HasPrefix(got, "O:"+testGatewaySID+"G:BAD:P(A;;0x20000;;;S-1-3-4)") {
		t.Fatalf("secret SDDL = %s", got)
	}
}

func TestManagedDataPathsTargets(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "data")
	paths := ManagedDataPaths{
		DataDir:          root,
		AuditDBPath:      filepath.Join(root, "audit", "audit.db"),
		RedactionKeyPath: filepath.Join(root, "redaction", "key"),
		LogPaths:         []string{filepath.Join(root, "audit", "gateway.log")},
		RuntimeDirs:      []string{root},
	}
	targets := paths.targets()
	var got []string
	for _, target := range targets {
		got = append(got, string(target.kind)+":"+target.path)
	}
	want := []string{
		"RuntimeDirectory:" + root,
		"RuntimeDirectory:" + filepath.Join(root, "audit"),
		"RuntimeDirectory:" + filepath.Join(root, "redaction"),
		"RuntimeFile:" + filepath.Join(root, "audit", "audit.db"),
		"RuntimeFile:" + filepath.Join(root, "audit", "audit.db-wal"),
		"RuntimeFile:" + filepath.Join(root, "audit", "audit.db-shm"),
		"RuntimeFile:" + filepath.Join(root, "audit", "audit.db-journal"),
		"RuntimeSecretFile:" + filepath.Join(root, "redaction", "key"),
		"RuntimeFile:" + filepath.Join(root, "audit", "gateway.log"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("targets:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestReportCanonicalResultMarkersAndDedupe(t *testing.T) {
	advisoryLogDedupe.reset()
	t.Cleanup(advisoryLogDedupe.reset)
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })

	accepted := CanonicalResult{Path: "p", Kind: ObjectRuntimeFile, Outcome: CanonicalAccepted, Drift: []string{"extra read"}}
	reportCanonicalResult(accepted, CanonicalOptions{})
	reportCanonicalResult(accepted, CanonicalOptions{})
	repaired := CanonicalResult{Path: "p", Kind: ObjectRuntimeFile, Outcome: CanonicalRepaired, Drift: []string{"x"}}
	reportCanonicalResult(repaired, CanonicalOptions{})
	reportCanonicalResult(repaired, CanonicalOptions{})
	reportCanonicalResult(CanonicalResult{Path: "q", Outcome: CanonicalOK}, CanonicalOptions{})
	out := buf.String()
	if strings.Count(out, MarkerAccept) != 1 {
		t.Fatalf("accept lines = %d, want 1:\n%s", strings.Count(out, MarkerAccept), out)
	}
	if strings.Count(out, MarkerRepair) != 2 {
		t.Fatalf("repair lines = %d, want 2:\n%s", strings.Count(out, MarkerRepair), out)
	}
}

func TestRepairManagedDataPathsUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows build")
	}
	results := RepairWindowsManagedDataPaths(ManagedDataPaths{DataDir: t.TempDir()}, CanonicalOptions{})
	if len(results) != 1 || results[0].Outcome != CanonicalUnsupported {
		t.Fatalf("results = %+v", results)
	}
}
