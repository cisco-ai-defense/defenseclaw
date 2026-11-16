// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"fmt"
	"testing"
)

// rel-1-0-3 GAP-0319: only a service the SCM reports not running proves the
// stop; a running service or a query that fails proves nothing.
func TestManagedGatewayServiceStoppedNeedsTheSCMToSayNotRunning(t *testing.T) {
	previous := managedEnterpriseQueryServicePID
	t.Cleanup(func() { managedEnterpriseQueryServicePID = previous })
	for _, test := range []struct {
		name string
		pid  uint32
		err  error
		want bool
	}{
		{"stopped", 0, fmt.Errorf("%w (state=1 pid=0)", errManagedGatewayNotRunning), true},
		{"running", 4242, nil, false},
		{"query failed", 0, errors.New("access is denied"), false},
	} {
		managedEnterpriseQueryServicePID = func(string) (uint32, error) { return test.pid, test.err }
		if got := platformManagedGatewayServiceStopped("DefenseClawGateway"); got != test.want {
			t.Errorf("%s: stopped = %t, want %t", test.name, got, test.want)
		}
	}
}
