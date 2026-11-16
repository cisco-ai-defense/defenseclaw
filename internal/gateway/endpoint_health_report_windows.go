// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/peversion"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// endpointHealthAVCServiceName is the SCM service of the Secure Client AVC
// module that hosts DefenseClaw.
const endpointHealthAVCServiceName = "csc_avcagent"

// readAVCVersion is the FileVersion of the csc_avcagent service binary, the
// path taken from the service's ImagePath in the SCM. It only reads; the
// AVC integration point is untouched.
func readAVCVersion(ctx context.Context) (string, error) {
	return endpointHealthRead(ctx, endpointHealthSourceTimeout, func(ctx context.Context) (string, error) {
		image, err := endpointHealthServiceImagePath(endpointHealthAVCServiceName)
		if err != nil {
			return "", err
		}
		executable := endpointHealthServiceExecutable(image)
		if expanded, err := registry.ExpandString(executable); err == nil {
			executable = expanded
		}
		if executable == "" || !filepath.IsAbs(executable) {
			return "", errors.New("the AVC service image path is not absolute")
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		raw, err := peversion.StringValue(executable, "FileVersion")
		if err != nil {
			return "", err
		}
		value, ok := normalizeEndpointHealthVersion(raw)
		if !ok {
			return "", errors.New("the AVC FileVersion is not a valid version")
		}
		return value, nil
	})
}

// endpointHealthServiceImagePath is a service's configured ImagePath.
func endpointHealthServiceImagePath(name string) (string, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(service)
	var needed uint32
	_ = windows.QueryServiceConfig(service, nil, 0, &needed)
	if needed == 0 || needed > 64<<10 {
		return "", windows.ERROR_INVALID_DATA
	}
	buffer := make([]byte, needed)
	configuration := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, configuration, needed, &needed); err != nil {
		return "", err
	}
	return windows.UTF16PtrToString(configuration.BinaryPathName), nil
}

// readInstalledProductVersion is the ProductVersion of the installed Secure
// Client gateway binary.
func readInstalledProductVersion() (string, error) {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		return "", err
	}
	return peversion.StringValue(filepath.Join(roots.InstallRoot, "bin", "defenseclaw-gateway.exe"), "ProductVersion")
}

// readOSVersion is major.minor.build from RtlGetVersion, which, unlike
// GetVersionEx, is not subject to manifest compatibility shims.
func readOSVersion() string {
	info := windows.RtlGetVersion()
	if info == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", info.MajorVersion, info.MinorVersion, info.BuildNumber)
}
