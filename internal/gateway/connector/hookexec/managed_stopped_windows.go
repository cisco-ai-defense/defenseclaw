// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import "errors"

// platformManagedGatewayServiceStopped reports whether the SCM service
// serviceName is proven stopped now (not running, or no process).
func platformManagedGatewayServiceStopped(serviceName string) bool {
	_, err := managedEnterpriseQueryServicePID(serviceName)
	return errors.Is(err, errManagedGatewayNotRunning)
}
