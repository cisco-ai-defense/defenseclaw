// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"

	"golang.org/x/sys/windows"
)

// EnterpriseServiceState reads a service's state from the service
// manager, which any account may query.
func EnterpriseServiceState(name string) string {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(manager)
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "unknown"
	}
	service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "absent"
	}
	if err != nil {
		return "unknown"
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return "unknown"
	}
	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "startpending"
	case windows.SERVICE_STOP_PENDING:
		return "stoppending"
	case windows.SERVICE_PAUSED:
		return "paused"
	}
	return "unknown"
}
