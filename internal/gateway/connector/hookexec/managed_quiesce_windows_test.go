// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0993: a stopped gateway service is a package transition when its
// start type is disabled (the lifecycle's quiesce) or cannot be read, and an
// outage otherwise.
func TestManagedGatewayStoppedErrorNamesTheLifecycleQuiesce(t *testing.T) {
	for _, test := range []struct {
		name      string
		startType uint32
		known     bool
		quiesced  bool
	}{
		{"disabled", windows.SERVICE_DISABLED, true, true},
		{"start type unreadable", 0, false, true},
		{"automatic", windows.SERVICE_AUTO_START, true, false},
		{"manual", windows.SERVICE_DEMAND_START, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := managedGatewayStoppedError(windows.SERVICE_STOPPED, 0, test.startType, test.known)
			if !errors.Is(err, errManagedGatewayNotRunning) {
				t.Fatalf("%v does not say the service is not running", err)
			}
			if got := errors.Is(err, errManagedGatewayQuiesced); got != test.quiesced {
				t.Fatalf("%v: quiesced=%v, want %v", err, got, test.quiesced)
			}
		})
	}
}
