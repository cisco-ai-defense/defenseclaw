//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The service configuration is administrator-controlled and is queryable by
// standard users. The protected Secure Client state root itself is not
// readable by an ACP client's user token.
var secureClientHost = func() bool {
	roots, err := winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient)
	if err != nil {
		return false
	}
	image, err := secureClientGatewayImage()
	if err != nil {
		return false
	}
	want := filepath.Join(roots.InstallRoot, "bin", "defenseclaw-gateway.exe")
	return strings.EqualFold(secureClientServiceExecutable(image), want)
}

var secureClientGatewayImage = func() (string, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString("DefenseClawGateway")
	if err != nil {
		return "", err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
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

func secureClientServiceExecutable(image string) string {
	image = strings.TrimSpace(image)
	if strings.HasPrefix(image, `"`) {
		end := strings.IndexByte(image[1:], '"')
		if end < 0 {
			return ""
		}
		return image[1 : end+1]
	}
	if end := strings.IndexAny(image, " \t"); end >= 0 {
		return image[:end]
	}
	return image
}
