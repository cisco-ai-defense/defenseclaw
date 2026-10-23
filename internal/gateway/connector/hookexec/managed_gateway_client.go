// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
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

// NewManagedStandaloneHookSocketHTTPClient verifies the protected socket path
// and the connected gateway UID before an internal guardian report is sent.
func NewManagedStandaloneHookSocketHTTPClient(timeout time.Duration, socketPath string, serviceUID int) (*http.Client, error) {
	return managedStandaloneHTTPClient(timeout, socketPath, serviceUID)
}
