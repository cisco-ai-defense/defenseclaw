// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// rel-1-0-6 GAP-0648: the service watch acts only on a state the service
// manager gave: running, or proven not running. Access denied, a missing
// service or an RPC failure is not known, and the call keeps its deadline.
func TestManagedGatewayServiceRunningMapsTheSCMState(t *testing.T) {
	previous := managedEnterpriseQueryServicePID
	t.Cleanup(func() { managedEnterpriseQueryServicePID = previous })
	for _, test := range []struct {
		name           string
		err            error
		running, known bool
	}{
		{"running", nil, true, true},
		{"not running", fmt.Errorf("%w (state=3 pid=0)", errManagedGatewayNotRunning), false, true},
		{"access denied", fmt.Errorf("open service: %w", windows.ERROR_ACCESS_DENIED), false, false},
		{"no such service", fmt.Errorf("open service: %w", windows.ERROR_SERVICE_DOES_NOT_EXIST), false, false},
		{"RPC failure", fmt.Errorf("query service: %w", windows.RPC_S_SERVER_UNAVAILABLE), false, false},
	} {
		managedEnterpriseQueryServicePID = func(string) (uint32, error) { return 4242, test.err }
		if running, known := platformManagedGatewayServiceRunning("DefenseClawGateway"); running != test.running || known != test.known {
			t.Errorf("%s: running, known = %t, %t; want %t, %t", test.name, running, known, test.running, test.known)
		}
	}
}
