// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
)

// managedLifecycleHeld reads the Windows lifecycle marker: the start type of
// the managed gateway service (managedLifecycleActive). A variable for
// tests.
var managedLifecycleHeld = func(opts Options) bool {
	return managedGatewayServiceInTransition(opts.ManagedGatewayServiceName)
}

// managedGatewayServiceInTransition reports a gateway service whose start
// type is not automatic, or cannot be read (users may read it: the service
// DACL grants BU SERVICE_QUERY_CONFIG). A hook with no service name, or one
// whose service does not exist, has no gateway to restart: its transport
// refuses the call anyway (queryManagedGatewayServicePID).
func managedGatewayServiceInTransition(serviceName string) bool {
	if strings.TrimSpace(serviceName) == "" {
		return false
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return true
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return true
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false
	}
	if err != nil {
		return true
	}
	defer windows.CloseServiceHandle(service)
	return startTypeInTransition(managedGatewayServiceStartType(service))
}

// startTypeInTransition is the lifecycle's reading of a gateway start type:
// a deployment outside a transaction is automatic (the readiness proof
// promotes it, and the lifecycle's own service check requires it); disabled
// is a transaction's quiesce and demand start its activation before
// readiness (GAP-1075); one that cannot be read cannot be shown to be
// neither.
func startTypeInTransition(startType uint32, known bool) bool {
	return !known || startType != windows.SERVICE_AUTO_START
}
