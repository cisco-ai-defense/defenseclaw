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

func TestCanonicalSDDLInstallerKinds(t *testing.T) {
	const (
		sy   = "(A;%s;0x1f01ff;;;S-1-5-18)"
		ba   = "(A;%s;0x1f01ff;;;S-1-5-32-544)"
		head = "O:S-1-5-32-544G:BAD:P"
	)
	entries := func(flags string, extra ...string) string {
		out := strings.ReplaceAll(sy, "%s", flags) + strings.ReplaceAll(ba, "%s", flags)
		for _, entry := range extra {
			out += strings.ReplaceAll(entry, "%s", flags)
		}
		return head + out
	}
	users := "(A;%s;0x1200a9;;;S-1-5-32-545)"
	gatewayRX := "(A;%s;0x1200a9;;;" + testGatewaySID + ")"
	cases := map[ObjectKind]string{
		ObjectInstallDirectory:        entries("OICI", users),
		ObjectInstallFile:             entries("", users),
		ObjectServiceInstallDirectory: entries("OICI", gatewayRX, users),
		ObjectServiceInstallFile:      entries("", gatewayRX, users),
		ObjectStateDirectory:          entries("OICI", gatewayRX),
		ObjectAuthorizationDirectory:  entries("OICI", gatewayRX),
		ObjectAdminDirectory:          entries("OICI"),
		ObjectLogDirectory:            entries("OICI"),
		ObjectAdminFile:               entries(""),
		ObjectManagedIPCDirectory: entries("", "(A;%s;0x1f01ff;;;"+testGatewaySID+")",
			"(A;%s;0x1200a9;;;S-1-5-11)"),
	}
	for kind, want := range cases {
		if got := canonicalSpecFor(kind, testGatewaySID).canonicalSDDL(); got != want {
			t.Errorf("%s SDDL = %s, want %s", kind, got, want)
		}
	}
}

func installerDescriptor(kind ObjectKind) objectDescriptor {
	form := canonicalSpecFor(kind, testGatewaySID).Forms[0]
	desc := objectDescriptor{Owner: form.Owner, Protected: true}
	for _, ace := range form.ACEs {
		desc.ACEs = append(desc.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: ace.Flags, Mask: ace.Mask, SID: ace.SID})
	}
	return desc
}

func TestAssessCanonicalDescriptorInstallerKinds(t *testing.T) {
	for _, kind := range []ObjectKind{
		ObjectInstallDirectory, ObjectInstallFile, ObjectServiceInstallDirectory,
		ObjectServiceInstallFile, ObjectStateDirectory, ObjectAdminDirectory, ObjectAdminFile,
		ObjectAuthorizationDirectory, ObjectLogDirectory, ObjectManagedIPCDirectory,
	} {
		if got := assessCanonicalDescriptor(installerDescriptor(kind), kind, testGatewaySID, nil); !got.Canonical {
			t.Errorf("%s installer form not canonical: %v", kind, got.Drift)
		}
		usersWrite := installerDescriptor(kind)
		usersWrite.ACEs = append(usersWrite.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskModify, SID: sidUsers})
		if got := assessCanonicalDescriptor(usersWrite, kind, testGatewaySID, nil).outcome(); got != CanonicalBoundary {
			t.Errorf("%s with Users write = %s, want boundary", kind, got)
		}
	}

	// Admin-only kinds never name the gateway, so its absence is not drift.
	if got := assessCanonicalDescriptor(installerDescriptor(ObjectAdminFile), ObjectAdminFile, testGatewaySID, nil); got.GatewayAccessMissing {
		t.Fatalf("admin file reported missing gateway access: %v", got.Drift)
	}

	// The bin folder loses the gateway's read entry: drift the guardian
	// repairs, and the gateway cannot start its executable until it does.
	bin := installerDescriptor(ObjectServiceInstallDirectory)
	bin.ACEs = append(bin.ACEs[:2], bin.ACEs[3:]...)
	if got := assessCanonicalDescriptor(bin, ObjectServiceInstallDirectory, testGatewaySID, nil); got.outcome() != CanonicalAccepted || !got.GatewayAccessMissing {
		t.Fatalf("bin without gateway entry: outcome %s, missing %t", got.outcome(), got.GatewayAccessMissing)
	}

	// The gateway re-applies its IPC baseline with generic full control.
	ipc := objectDescriptor{Owner: sidAdministrators, Protected: true, ACEs: []descriptorACE{
		{Type: aceTypeAllowed, Mask: maskGenericAll, SID: sidLocalSystem},
		{Type: aceTypeAllowed, Mask: maskGenericAll, SID: sidAdministrators},
		{Type: aceTypeAllowed, Mask: maskGenericAll, SID: testGatewaySID},
		{Type: aceTypeAllowed, Mask: maskReadAndExecute, SID: sidAuthenticatedUser},
	}}
	if got := assessCanonicalDescriptor(ipc, ObjectManagedIPCDirectory, testGatewaySID, nil); !got.Canonical {
		t.Fatalf("gateway IPC baseline not canonical: %v", got.Drift)
	}
	ipc.ACEs = append(ipc.ACEs[:2], ipc.ACEs[3])
	if got := assessCanonicalDescriptor(ipc, ObjectManagedIPCDirectory, testGatewaySID, nil); !got.GatewayAccessMissing {
		t.Fatalf("IPC folder without the gateway entry not reported: %v", got.Drift)
	}
}

func TestObjectKindPropagatesRepairOnlyForDataFolders(t *testing.T) {
	for _, kind := range []ObjectKind{ObjectRuntimeDirectory, ObjectConfigDirectory} {
		if !kind.propagatesRepair() {
			t.Errorf("%s no longer propagates", kind)
		}
	}
	for _, kind := range []ObjectKind{
		ObjectInstallDirectory, ObjectServiceInstallDirectory, ObjectStateDirectory,
		ObjectAdminDirectory, ObjectAuthorizationDirectory, ObjectLogDirectory, ObjectManagedIPCDirectory,
	} {
		if !kind.Directory() || kind.propagatesRepair() {
			t.Errorf("%s: directory %t, propagates %t", kind, kind.Directory(), kind.propagatesRepair())
		}
	}
}

func TestManagedInstallLayoutTargets(t *testing.T) {
	sep := string(filepath.Separator)
	install := filepath.Join(sep, "pf", "DefenseClaw")
	state := filepath.Join(sep, "pd", "DefenseClaw")
	ipc := filepath.Join(install, "ipc")
	targets := ManagedInstallLayout{InstallRoot: install, StateRoot: state, IPCDirectory: ipc}.targets()
	var got []string
	for _, target := range targets {
		got = append(got, string(target.kind)+":"+target.path)
	}
	want := []string{
		"ServiceInstallDirectory:" + install,
		"ServiceInstallDirectory:" + filepath.Join(install, "bin"),
		"InstallDirectory:" + filepath.Join(install, "libexec"),
		"ServiceInstallFile:" + filepath.Join(install, "bin", "defenseclaw-gateway.exe"),
		"InstallFile:" + filepath.Join(install, "bin", "defenseclaw-hook.exe"),
		"InstallFile:" + filepath.Join(install, "bin", "defenseclaw-cmid-broker.exe"),
		"InstallFile:" + filepath.Join(install, "bin", "defenseclaw.exe"),
		"InstallFile:" + filepath.Join(install, "libexec", "install-enterprise.ps1"),
		"InstallFile:" + filepath.Join(install, "libexec", "DefenseClawEnterprise.psm1"),
		"ManagedIPCDirectory:" + ipc,
		"StateDirectory:" + state,
		"ConfigDirectory:" + filepath.Join(state, "etc"),
		"AdminDirectory:" + filepath.Join(state, "hook-guardian"),
		"AdminDirectory:" + filepath.Join(state, "install"),
		"AuthorizationDirectory:" + filepath.Join(state, "cmid-broker"),
		"LogDirectory:" + filepath.Join(state, "logs"),
		"AdminDirectory:" + filepath.Join(state, "logs", "guardian"),
		"AdminDirectory:" + filepath.Join(state, "logs", "cmid-broker"),
		"ConfigFile:" + filepath.Join(state, "etc", "config.yaml"),
		"AdminFile:" + filepath.Join(state, "hook-guardian", "targets.yaml"),
		"AdminFile:" + filepath.Join(state, "install", "deployment.json"),
		"AdminFile:" + filepath.Join(state, "install", "agent-application-control-attestation.json"),
		"AdminFile:" + filepath.Join(state, "install", "codex-requirements-ownership.json"),
		"AdminFile:" + filepath.Join(state, "install", "codex-requirements-acl-backup.json"),
		"AdminFile:" + filepath.Join(state, "install", "managed-hooks-teardown-journal.json"),
		"AdminFile:" + filepath.Join(state, "logs", "guardian", "hook-guardian.log"),
		"AdminFile:" + filepath.Join(state, "logs", "cmid-broker", "cmid-broker.log"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("targets:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := (ManagedInstallLayout{StateRoot: state}).targets(); len(got) == 0 || got[0].kind != ObjectStateDirectory {
		t.Fatalf("state-only layout targets = %+v", got)
	}
	if got := (ManagedInstallLayout{}).targets(); len(got) != 0 {
		t.Fatalf("empty layout targets = %+v", got)
	}
}

func TestRepairWindowsManagedInstallUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows build")
	}
	results := RepairWindowsManagedInstall(ManagedInstallLayout{StateRoot: t.TempDir()}, CanonicalOptions{})
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, result := range results {
		if result.Outcome != CanonicalUnsupported {
			t.Fatalf("result = %+v", result)
		}
	}
	if got := RepairWindowsManagedServiceSecurity([]string{"DefenseClawGateway"}); got != nil {
		t.Fatalf("service results off Windows = %+v", got)
	}
}

func TestManagedServiceNames(t *testing.T) {
	cases := []struct {
		gateway, guardian string
		want              []string
	}{
		{"DefenseClawGateway", "DefenseClawHookGuardian",
			[]string{"DefenseClawGateway", "DefenseClawCMIDBroker", "DefenseClawHookGuardian", "DefenseClawHookEnumerator"}},
		{"DefenseClawCertGateway_0123456789", "DefenseClawCertGuardian_abcdef0123",
			[]string{"DefenseClawCertGateway_0123456789", "DefenseClawCMIDBroker_0123456789",
				"DefenseClawCertGuardian_abcdef0123", "DefenseClawCertEnumerator_abcdef0123"}},
		{" DefenseClawGateway ", "", []string{"DefenseClawGateway", "DefenseClawCMIDBroker"}},
		{"Spooler", "DefenseClawCertGuardian_ABCDEF0123", nil},
		{"DefenseClawCertGateway_01234", "DefenseClawHookGuardian2", nil},
	}
	for _, tc := range cases {
		got := ManagedServiceNames(tc.gateway, tc.guardian)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ManagedServiceNames(%q, %q) = %v, want %v", tc.gateway, tc.guardian, got, tc.want)
		}
	}
}

func serviceDescriptor(form canonicalForm) objectDescriptor {
	desc := objectDescriptor{Owner: form.Owner, Protected: true}
	for _, ace := range form.ACEs {
		desc.ACEs = append(desc.ACEs, descriptorACE{Type: aceTypeAllowed, Flags: ace.Flags, Mask: ace.Mask, SID: ace.SID})
	}
	return desc
}

func TestExactDescriptorMatchServiceForms(t *testing.T) {
	form := managedServiceDACLForm()
	desc := serviceDescriptor(form)
	if !exactDescriptorMatch(desc, form) {
		t.Fatal("canonical service DACL does not match")
	}
	reordered := serviceDescriptor(form)
	reordered.ACEs[0], reordered.ACEs[2] = reordered.ACEs[2], reordered.ACEs[0]
	if !exactDescriptorMatch(reordered, form) {
		t.Fatal("reordered canonical service DACL does not match")
	}
	for name, mutate := range map[string]func(*objectDescriptor){
		"users read removed": func(d *objectDescriptor) { d.ACEs = d.ACEs[:2] },
		"unprotected":        func(d *objectDescriptor) { d.Protected = false },
		"null DACL":          func(d *objectDescriptor) { d.NullDACL = true; d.ACEs = nil },
		"users deny": func(d *objectDescriptor) {
			d.ACEs[2].Type = aceTypeDenied
		},
		"extra interactive read": func(d *objectDescriptor) {
			d.ACEs = append(d.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskServiceUserQuery, SID: "S-1-5-4"})
		},
	} {
		drifted := serviceDescriptor(form)
		mutate(&drifted)
		if exactDescriptorMatch(drifted, form) {
			t.Errorf("%s still matches", name)
		}
	}

	key := managedServiceRegistryForm()
	keyDesc := serviceDescriptor(key)
	if !exactDescriptorMatch(keyDesc, key) {
		t.Fatal("canonical service key descriptor does not match")
	}
	keyDesc.Owner = sidLocalSystem
	if exactDescriptorMatch(keyDesc, key) {
		t.Fatal("service key with SYSTEM owner still matches")
	}
}

func TestDescriptorUntrustedWriters(t *testing.T) {
	desc := serviceDescriptor(managedServiceDACLForm())
	if got := descriptorUntrustedWriters(desc, serviceDescriptorWriteMask); len(got) != 0 {
		t.Fatalf("canonical service DACL writers = %v", got)
	}
	desc.ACEs = append(desc.ACEs,
		descriptorACE{Type: aceTypeAllowed, Mask: maskServiceChangeConfig, SID: sidUsers},
		descriptorACE{Type: aceTypeAllowed, Flags: aceFlagInheritOnly, Mask: maskGenericAll, SID: "S-1-5-4"},
		descriptorACE{Type: aceTypeAllowed, Mask: maskWriteDAC, SID: sidTrustedInstaller},
	)
	if got := descriptorUntrustedWriters(desc, serviceDescriptorWriteMask); strings.Join(got, ",") != sidUsers {
		t.Fatalf("writers = %v, want only Users", got)
	}
	key := serviceDescriptor(managedServiceRegistryForm())
	key.Owner = "S-1-5-21-1-2-3-1001"
	key.ACEs = append(key.ACEs, descriptorACE{Type: aceTypeAllowed, Mask: maskKeySetValue, SID: sidAuthenticatedUser})
	got := descriptorUntrustedWriters(key, registryKeyWriteMask)
	if len(got) != 2 || got[0] != "owner S-1-5-21-1-2-3-1001" || got[1] != sidAuthenticatedUser {
		t.Fatalf("key writers = %v", got)
	}
}

func TestReportServiceSecurityResultDedupe(t *testing.T) {
	advisoryLogDedupe.reset()
	t.Cleanup(advisoryLogDedupe.reset)
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })

	accepted := ServiceSecurityResult{Service: "DefenseClawGateway", Object: "scm", Outcome: CanonicalAccepted, Drift: "d"}
	reportServiceSecurityResult(accepted)
	reportServiceSecurityResult(accepted)
	repaired := ServiceSecurityResult{Service: "DefenseClawGateway", Object: "scm", Outcome: CanonicalRepaired, Drift: "d"}
	reportServiceSecurityResult(repaired)
	reportServiceSecurityResult(ServiceSecurityResult{Service: "DefenseClawGateway", Object: "registry", Outcome: CanonicalOK})
	out := buf.String()
	if strings.Count(out, MarkerAccept) != 1 || strings.Count(out, MarkerRepair) != 1 {
		t.Fatalf("unexpected log lines:\n%s", out)
	}
	if !strings.Contains(out, `service="DefenseClawGateway"`) {
		t.Fatalf("service field missing:\n%s", out)
	}
}
