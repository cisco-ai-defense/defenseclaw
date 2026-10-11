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

package cli

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedHostWindowsStandalone reports a standalone managed deployment. Two
// administrator-written signals count, and nothing a standard user can
// create does (%ProgramData% lets any user create folders, so a planted
// record would otherwise refuse every other user's per-user gateway):
//
//   - the HKLM marker the elevated standalone lifecycle publishes after a
//     successful install and removes after uninstall, honored only when its
//     key is owned by SYSTEM, Administrators or TrustedInstaller and no
//     other principal can write it (managedHostStandaloneMarker);
//   - the ProgramData deployment record, when no one but an administrator
//     could have written it (managedHostRecordTrusted) or the
//     administrator-registered standalone gateway service confirms it
//     (managedStandaloneRecordCounts). An uninstalled deployment (tombstone)
//     does not count.
//
// Secure Client hosts are unaffected: only the standalone profile writes the
// marker, and their record lives under the Secure Client roots, which this
// profile's inspection never reads.
// secureClientHost reports a Secure Client DefenseClaw install: its state
// root under ProgramData exists. A seam for tests.
var secureClientHost = func() bool {
	roots, err := winpath.EnterpriseRootsFor(winpath.EnterpriseProfileSecureClient, os.Getenv("ProgramFiles"), os.Getenv("ProgramData"))
	if err != nil {
		return false
	}
	_, err = os.Stat(roots.StateRoot)
	return err == nil
}

var managedHostWindowsStandalone = func() (string, bool) {
	if where, ok := managedHostStandaloneMarker(); ok {
		return where, true
	}
	return managedHostStandaloneRecord()
}

// managedHostStandaloneMarker reports the administrator-written HKLM
// standalone marker.
func managedHostStandaloneMarker() (string, bool) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		WindowsEnterpriseMarkerKey,
		registry.QUERY_VALUE|registry.WOW64_64KEY|windows.READ_CONTROL,
	)
	if err != nil {
		return "", false
	}
	defer key.Close()
	if !windowsEnterpriseMarkerStandalone(key) {
		return "", false
	}
	return `HKLM\` + WindowsEnterpriseMarkerKey, true
}

// managedHostStandaloneRecord reports a trusted or service-confirmed
// standalone deployment record.
func managedHostStandaloneRecord() (string, bool) {
	deployment, err := winpath.InspectEnterpriseDeployment(managed.ProfileStandalone)
	if err != nil {
		return "", false
	}
	switch deployment.State {
	case winpath.EnterpriseDeploymentInstalled, winpath.EnterpriseDeploymentUnknown:
		where, err := managedStandaloneRecordCounts(deployment.MetadataPath, managedHostRecordTrusted, managedHostStandaloneService)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[defenseclaw] ignoring an untrusted managed deployment record: %v\n", err)
			return "", false
		}
		return where, true
	}
	return "", false
}

// windowsEnterpriseMarkerStandalone reports whether an administrator-written
// marker key names the standalone profile.
func windowsEnterpriseMarkerStandalone(key registry.Key) bool {
	if validateWindowsEnterpriseAdminRegistryKey(key) != nil {
		return false
	}
	profile, _, err := key.GetStringValue("Profile")
	return err == nil && managed.IsStandaloneProfile(profile)
}

// validateWindowsEnterpriseAdminRegistryKey requires an open key to be owned
// by SYSTEM, Administrators, or TrustedInstaller with no allow ACE that
// grants anyone else a way to change it.
func validateWindowsEnterpriseAdminRegistryKey(key registry.Key) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(key),
		windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read the registry key security descriptor: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read the registry key owner: %w", err)
	}
	if !windowsEnterpriseAdminSID(owner) {
		return fmt.Errorf("registry key owner %s is not an administrator", owner)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read the registry key DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("registry key has a null DACL")
	}
	const keyWriteLike = windows.ACCESS_MASK(
		windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE |
			windows.WRITE_DAC | windows.WRITE_OWNER |
			windows.KEY_SET_VALUE | windows.KEY_CREATE_SUB_KEY | windows.KEY_CREATE_LINK,
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("read registry key ACE %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("registry key carries unsupported ACE type 0x%x", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Mask&keyWriteLike != 0 && !windowsEnterpriseAdminSID(sid) {
			return fmt.Errorf("registry key grants %s write-like access 0x%x", sid, uint32(ace.Mask))
		}
	}
	return nil
}

func windowsEnterpriseAdminSID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

// managedHostRecordTrusted accepts a managed-deployment record, or runtime
// descriptor, under %ProgramData% only when an administrator must have
// written it. A seam for tests.
var managedHostRecordTrusted = func(path string) error {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return err
	}
	return managedRecordTrusted(
		path,
		programData,
		func(file string) error { return managed.ValidateTrustedFilePath(file, "managed deployment record") },
		func(dir string) error { return managed.ValidateTrustedRuntimeDir(dir, "managed deployment directory") },
	)
}

// managedHostStandaloneService describes the standalone gateway service when
// the Service Control Manager has it registered to run
// <Program Files>\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe. Only an
// administrator can register a service. The lifecycle's service DACL grants
// standard users query-config access, so any caller can read the image path.
// The Secure Client profile registers the same service name with its own
// executable; the image path tells them apart. A seam for tests.
var managedHostStandaloneService = func() (string, error) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return "", err
	}
	gatewayPath := roots.InstallRoot + `\bin\defenseclaw-gateway.exe`
	image, err := windowsServiceImagePath(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return "", err
	}
	if err := standaloneGatewayServiceImageMatches(image, gatewayPath); err != nil {
		return "", fmt.Errorf("service %s: %w", managed.StandaloneWindowsGatewaySvc, err)
	}
	return fmt.Sprintf("service %s runs %s", managed.StandaloneWindowsGatewaySvc, gatewayPath), nil
}

// windowsServiceImagePath reads a service's registered image path with
// connect and query-config access only, which standard users hold.
func windowsServiceImagePath(name string) (string, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", fmt.Errorf("open service %s: %w", name, err)
	}
	defer windows.CloseServiceHandle(service)
	var needed uint32
	_ = windows.QueryServiceConfig(service, nil, 0, &needed)
	if needed == 0 || needed > 64<<10 {
		return "", fmt.Errorf("service %s: invalid configuration size %d", name, needed)
	}
	buffer := make([]byte, needed)
	configuration := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, configuration, needed, &needed); err != nil {
		return "", fmt.Errorf("query service %s: %w", name, err)
	}
	return windows.UTF16PtrToString(configuration.BinaryPathName), nil
}
