//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

func setEnterpriseHookAuthorizationOwnership(path string) error {
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	serviceSID, err := enterpriseWindowsGatewayServiceSID()
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	servicePermissions := windows.ACCESS_MASK(windows.GENERIC_READ)
	if info.IsDir() {
		servicePermissions |= windows.GENERIC_EXECUTE
	}
	return setEnterpriseWindowsManagedProtection(path, owner, serviceSID, servicePermissions, info.IsDir())
}

func setEnterpriseHookGuardianStateOwnership(path string) error {
	return setEnterpriseHookAuthorizationOwnership(path)
}
