// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// NewManagedEnterpriseGatewayHTTPClient verifies the connected gateway
// service before any HTTP request bytes leave this process. The service name
// selects the administrator-owned SCM service on Windows; macOS uses the
// Secure Client LaunchDaemon identity.
func NewManagedEnterpriseGatewayHTTPClient(timeout time.Duration, apiAddr, serviceName string) (*http.Client, error) {
	return managedEnterpriseHTTPClient(timeout, apiAddr, serviceName)
}

// NewManagedEnterpriseGatewayHTTPClientAwaitingStart is
// NewManagedEnterpriseGatewayHTTPClient for an administrator command: when
// the gateway service runs but has no listener on its port yet (it has just
// started, for example because secret set restarted it), the connection is
// tried again until startBudget has passed instead of failing at once
// (GAP-2442). Nothing is sent before a connection is verified, so a retried
// connection never repeats any request bytes. A hook keeps its own restart
// budget and uses NewManagedEnterpriseGatewayHTTPClient.
func NewManagedEnterpriseGatewayHTTPClientAwaitingStart(timeout time.Duration, apiAddr, serviceName string, startBudget time.Duration) (*http.Client, error) {
	client, err := managedEnterpriseHTTPClient(timeout, apiAddr, serviceName)
	if err != nil || startBudget <= 0 {
		return client, err
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		return client, nil
	}
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline := time.Now().Add(startBudget)
		for {
			conn, err := dial(ctx, network, address)
			if err == nil || !errors.Is(err, errGatewayNotConnected) || !time.Now().Add(managedGatewayStartPoll).Before(deadline) {
				return conn, err
			}
			timer := time.NewTimer(managedGatewayStartPoll)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, err
			case <-timer.C:
			}
		}
	}
	return client, nil
}

// managedGatewayStartPoll is how often an administrator command looks for
// the listener of a gateway that is still starting.
var managedGatewayStartPoll = 200 * time.Millisecond

// NewManagedStandaloneHookSocketHTTPClient verifies the protected socket path
// and the connected gateway UID before an internal guardian report is sent.
func NewManagedStandaloneHookSocketHTTPClient(timeout time.Duration, socketPath string, serviceUID int) (*http.Client, error) {
	return managedStandaloneHTTPClient(timeout, socketPath, serviceUID)
}
