// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestManagedWindowsStopReadLateNamesNotRunning is
// TestManagedStopProvenLateNamesNotRunningInAnswerAndRow through the real
// Windows transport: a fake SCM reports DefenseClawGateway SERVICE_STOPPED
// pid 0 (with nothing on the port), the verified dial turns that into the
// call's not-running failure, and the deadline passes while its row is
// written. Answer and row both say enterprise_managed_gateway_not_running
// (rel-1-0-6 GAP-0294).
func TestManagedWindowsStopReadLateNamesNotRunning(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 0, fakeStoppedServiceStatus() },
		func(net.Conn) (uint32, error) {
			t.Error("a stopped service must not be dialed")
			return 0, errors.New("dialed a stopped service")
		},
	)
	oldListening := managedEnterpriseListening
	managedEnterpriseListening = func(string) (bool, bool) { return false, true }
	t.Cleanup(func() {
		managedTransportTestMu.Lock()
		defer managedTransportTestMu.Unlock()
		managedEnterpriseListening = oldListening
	})
	readSCM := func() error {
		client, err := managedEnterpriseHTTPClient(time.Minute, "127.0.0.1:18970", "DefenseClawGateway")
		if err != nil {
			return err
		}
		resp, err := client.Get("http://127.0.0.1:18970/api/v1/hook")
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	for _, form := range managedStoppedForms[:2] {
		t.Run(form.name, func(t *testing.T) {
			assertLateStopAnswer(t, form.connector, form.shape, readSCM)
		})
	}
}
