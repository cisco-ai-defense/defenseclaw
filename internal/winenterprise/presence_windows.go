// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winenterprise

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const gatewayImageName = `\defenseclaw-gateway.exe`

func platformDetectDeployment() (Deployment, bool, error) {
	return detectServiceDeployment(GatewayServiceName)
}

// detectServiceDeployment treats name as an enterprise deployment when the
// service exists and runs the DefenseClaw gateway. A service whose
// configuration cannot be read still counts: only an administrator can create
// a service with this name, and the per-user product never does.
func detectServiceDeployment(name string) (Deployment, bool, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Deployment{}, false, err
	}
	defer windows.CloseServiceHandle(manager)
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Deployment{}, false, err
	}
	service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_CONFIG)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return Deployment{}, false, nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return Deployment{ServiceName: name}, true, nil
	case err != nil:
		return Deployment{}, false, err
	}
	defer windows.CloseServiceHandle(service)
	image, err := serviceImagePath(service)
	if err != nil {
		return Deployment{ServiceName: name}, true, nil
	}
	if !strings.Contains(strings.ToLower(image), gatewayImageName) {
		return Deployment{}, false, nil
	}
	return Deployment{ServiceName: name}, true, nil
}

func serviceImagePath(service windows.Handle) (string, error) {
	var needed uint32
	err := windows.QueryServiceConfig(service, nil, 0, &needed)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", err
	}
	if needed == 0 || needed > 64<<10 {
		return "", errors.New("service configuration has an invalid size")
	}
	buffer := make([]byte, needed)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, config, needed, &needed); err != nil {
		return "", err
	}
	if config.BinaryPathName == nil {
		return "", errors.New("service configuration has no image path")
	}
	return windows.UTF16PtrToString(config.BinaryPathName), nil
}

// platformCurrentProcessIsService reports whether this process runs as
// LocalSystem or a virtual service account (NT SERVICE\...), as the
// enterprise gateway service does.
func platformCurrentProcessIsService() (bool, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	sid := user.User.Sid.String()
	return sid == "S-1-5-18" || strings.HasPrefix(sid, "S-1-5-80-"), nil
}
