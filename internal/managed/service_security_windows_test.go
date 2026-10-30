// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The canonical forms the guardian compares against must be exactly the
// installer's SDDL, as Windows parses it.
func TestManagedServiceSDDLMatchesCanonicalForms(t *testing.T) {
	service, err := windows.SecurityDescriptorFromString(managedServiceSDDL)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := objectDescriptorFromSD(service)
	if err != nil {
		t.Fatal(err)
	}
	if !exactDescriptorMatch(desc, managedServiceDACLForm()) {
		t.Fatalf("service SDDL %s does not parse to the canonical form: %+v", managedServiceSDDL, desc)
	}

	key, err := windows.SecurityDescriptorFromString(managedServiceRegistrySDDL)
	if err != nil {
		t.Fatal(err)
	}
	keyDesc, err := objectDescriptorFromSD(key)
	if err != nil {
		t.Fatal(err)
	}
	group, _, err := key.Group()
	if err != nil || group == nil || group.String() != sidAdministrators {
		t.Fatalf("service key group = %v, %v", group, err)
	}
	if !exactDescriptorMatch(keyDesc, managedServiceRegistryForm()) {
		t.Fatalf("service key SDDL %s does not parse to the canonical form: %+v", managedServiceRegistrySDDL, keyDesc)
	}
}

func TestRepairWindowsManagedServiceSecuritySkipsMissingServices(t *testing.T) {
	results := RepairWindowsManagedServiceSecurity([]string{"DefenseClawCertGateway_ffffffffff"})
	for _, result := range results {
		if result.Outcome != CanonicalMissing && result.Outcome != CanonicalAccepted {
			t.Fatalf("missing service result = %+v", result)
		}
	}
}
