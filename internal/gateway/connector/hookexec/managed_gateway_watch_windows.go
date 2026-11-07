// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import "errors"

// platformManagedGatewayServiceRunning reads the SCM state of the managed
// gateway service: running with a process, or proven not running; known is
// false when the service manager could not say (access, a missing
// service, an RPC failure).
func platformManagedGatewayServiceRunning(serviceName string) (running, known bool) {
	_, err := managedEnterpriseQueryServicePID(serviceName)
	switch {
	case err == nil:
		return true, true
	case errors.Is(err, errManagedGatewayNotRunning):
		return false, true
	}
	return false, false
}
