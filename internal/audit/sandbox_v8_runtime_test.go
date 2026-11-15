// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package audit

import "testing"

// The runtime and driver enums take Agent Substrate's runtime and sandbox
// classes beside OpenShell's, and still refuse unregistered values.
func TestSandboxIdentityRuntimesAndDrivers(t *testing.T) {
	for _, identity := range []SandboxIdentity{
		{Name: "dc-claudecode-a", Runtime: SandboxRuntimeOpenShell, Driver: SandboxDriverDocker},
		{Name: "dc-claudecode-a", Runtime: SandboxRuntimeOpenShell, Driver: SandboxDriverVM},
		{Name: "cc-payments-1", Runtime: SandboxRuntimeSubstrate, Driver: SandboxDriverGVisor},
		{Name: "cc-payments-1", Runtime: SandboxRuntimeSubstrate, Driver: SandboxDriverMicroVM},
	} {
		if err := identity.validate(true); err != nil {
			t.Errorf("%s/%s refused: %v", identity.Runtime, identity.Driver, err)
		}
		if got, ok := identity.ManagedV8().Driver.Get(); !ok || got != identity.Driver {
			t.Errorf("%s driver left out of the managed stamps", identity.Driver)
		}
	}
	for _, identity := range []SandboxIdentity{
		{Name: "a", Runtime: "kata"},
		{Name: "a", Runtime: "Substrate"},
		{Name: "a", Driver: "firecracker"},
	} {
		if err := identity.validate(true); err == nil {
			t.Errorf("%+v accepted", identity)
		}
	}
}
