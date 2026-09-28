// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winenterprise

import "testing"

func TestDetectServiceDeploymentIgnoresAbsentAndUnrelatedServices(t *testing.T) {
	if _, present, err := detectServiceDeployment("DefenseClawGatewayAbsent_0123456789"); err != nil || present {
		t.Fatalf("absent service: present=%v err=%v", present, err)
	}
	// EventLog always exists and runs svchost.exe, not the DefenseClaw gateway.
	if _, present, err := detectServiceDeployment("EventLog"); err != nil || present {
		t.Fatalf("unrelated service: present=%v err=%v", present, err)
	}
}

func TestCurrentProcessIsServiceIsFalseForAnInteractiveTestProcess(t *testing.T) {
	service, err := platformCurrentProcessIsService()
	if err != nil {
		t.Fatal(err)
	}
	if service {
		t.Skip("test process runs as a service account")
	}
}
