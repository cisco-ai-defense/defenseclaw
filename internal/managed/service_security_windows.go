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

package managed

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The canonical service descriptors, exactly as the installer module applies
// them: $script:ServiceSDDL for the SCM object (sc sdset) and the
// Set-DefenseClawServiceRegistryAcl descriptor for the service key.
const (
	managedServiceSDDL         = "D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;BU)"
	managedServiceRegistrySDDL = "O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"
)

// RepairWindowsManagedServiceSecurity keeps the SCM descriptor and the service
// registry key of each named service at the installer's canonical form. Each
// descriptor is read first and written only when it is not exactly canonical,
// with SetServiceObjectSecurity (sc sdset) for the SCM object and the key
// descriptor the installer stamps for the registry key. A service that does
// not exist is skipped. One service's failure never stops the others.
// Every repair is logged once with MarkerRepair; what cannot be repaired is
// logged once as accepted, or as a boundary when another principal can
// reconfigure the service. Never inside the gateway service.
func RepairWindowsManagedServiceSecurity(names []string) []ServiceSecurityResult {
	if WindowsCurrentProcessIsGatewayService() || len(names) == 0 {
		return nil
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		result := ServiceSecurityResult{Object: "scm", Outcome: CanonicalAccepted, Err: err,
			Drift: "service control manager is not reachable: " + err.Error()}
		reportServiceSecurityResult(result)
		return []ServiceSecurityResult{result}
	}
	defer func() { _ = windows.CloseServiceHandle(manager) }()
	var results []ServiceSecurityResult
	for _, name := range names {
		scm := repairWindowsServiceDescriptor(manager, name)
		results = append(results, scm)
		if scm.Outcome == CanonicalMissing {
			continue
		}
		results = append(results, repairWindowsServiceRegistryKey(name))
	}
	return results
}

func repairWindowsServiceDescriptor(manager windows.Handle, name string) ServiceSecurityResult {
	result := ServiceSecurityResult{Service: name, Object: "scm"}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		result.Outcome, result.Err = CanonicalStructural, err
		return result
	}
	writable := true
	service, err := windows.OpenService(manager, namePtr, windows.READ_CONTROL|windows.WRITE_DAC)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		writable = false
		service, err = windows.OpenService(manager, namePtr, windows.READ_CONTROL)
	}
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		result.Outcome = CanonicalMissing
		return result
	}
	if err != nil {
		result.Outcome, result.Err = CanonicalAccepted, err
		result.Drift = "service descriptor could not be opened: " + err.Error()
		reportServiceSecurityResult(result)
		return result
	}
	defer func() { _ = windows.CloseServiceHandle(service) }()

	before, beforeText, err := readWindowsServiceDACL(service)
	if err != nil {
		result.Outcome, result.Err = CanonicalAccepted, err
		result.Drift = "service descriptor is not readable: " + err.Error()
		reportServiceSecurityResult(result)
		return result
	}
	form := managedServiceDACLForm()
	if exactDescriptorMatch(before, form) {
		result.Outcome = CanonicalOK
		return result
	}
	result.Drift = "service descriptor differs from the canonical form: " + beforeText
	judge := func(desc objectDescriptor) {
		if writers := descriptorUntrustedWriters(desc, serviceDescriptorWriteMask); len(writers) > 0 {
			result.Outcome = CanonicalBoundary
			result.Drift += "; principals that can reconfigure the service: " + strings.Join(writers, ",")
			return
		}
		result.Outcome = CanonicalAccepted
	}
	if !writable {
		result.RepairError = "write access to the service descriptor is denied"
		judge(before)
		reportServiceSecurityResult(result)
		return result
	}
	canonical, err := windows.SecurityDescriptorFromString(managedServiceSDDL)
	if err != nil {
		result.Outcome, result.Err = CanonicalAccepted, err
		result.RepairError = "build canonical service descriptor: " + err.Error()
		reportServiceSecurityResult(result)
		return result
	}
	dacl, _, err := canonical.DACL()
	if err != nil || dacl == nil {
		result.Outcome = CanonicalAccepted
		result.RepairError = fmt.Sprintf("read canonical service DACL: %v", err)
		reportServiceSecurityResult(result)
		return result
	}
	if err := windows.SetSecurityInfo(
		service,
		windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		result.RepairError = "re-apply the canonical service descriptor: " + err.Error()
		judge(before)
		reportServiceSecurityResult(result)
		return result
	}
	after, afterText, err := readWindowsServiceDACL(service)
	switch {
	case err != nil:
		result.Outcome = CanonicalAccepted
		result.RepairError = "re-read the service descriptor: " + err.Error()
	case exactDescriptorMatch(after, form):
		result.Outcome = CanonicalRepaired
		result.Drift = "re-applied the canonical service descriptor after: " + beforeText
	default:
		result.RepairError = "service descriptor still differs after repair: " + afterText
		judge(after)
	}
	reportServiceSecurityResult(result)
	return result
}

func readWindowsServiceDACL(service windows.Handle) (objectDescriptor, string, error) {
	sd, err := windows.GetSecurityInfo(service, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return objectDescriptor{}, "", err
	}
	desc, err := objectDescriptorFromSD(sd)
	if err != nil {
		return objectDescriptor{}, "", err
	}
	return desc, sd.String(), nil
}

const windowsServicesKey = `SYSTEM\CurrentControlSet\Services\`

// repairWindowsServiceRegistryKey mirrors Set-DefenseClawServiceRegistryAcl:
// the key gets the canonical owner, group and protected DACL (propagated to
// its subkeys, as the installer's write is) and its Security subkey is put
// back to inheriting from it.
func repairWindowsServiceRegistryKey(name string) ServiceSecurityResult {
	result := ServiceSecurityResult{Service: name, Object: "registry"}
	path := windowsServicesKey + name
	writable := true
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		path,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
	)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		writable = false
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, path, windows.READ_CONTROL)
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		result.Outcome = CanonicalMissing
		return result
	}
	if err != nil {
		result.Outcome, result.Err = CanonicalAccepted, err
		result.Drift = "service registry key could not be opened: " + err.Error()
		reportServiceSecurityResult(result)
		return result
	}
	defer func() { _ = key.Close() }()
	handle := windows.Handle(key)

	before, beforeText, err := readWindowsRegistryKeyDescriptor(handle)
	if err != nil {
		result.Outcome, result.Err = CanonicalAccepted, err
		result.Drift = "service registry key descriptor is not readable: " + err.Error()
		reportServiceSecurityResult(result)
		return result
	}
	form := managedServiceRegistryForm()
	canonicalKey := func(desc objectDescriptor) bool {
		return desc.Group == sidAdministrators && exactDescriptorMatch(desc, form)
	}
	if canonicalKey(before) {
		result.Outcome = CanonicalOK
		return result
	}
	result.Drift = "service registry key descriptor differs from the canonical form: " + beforeText
	judge := func(desc objectDescriptor) {
		if writers := descriptorUntrustedWriters(desc, registryKeyWriteMask); len(writers) > 0 {
			result.Outcome = CanonicalBoundary
			result.Drift += "; principals that can change the service key: " + strings.Join(writers, ",")
			return
		}
		result.Outcome = CanonicalAccepted
	}
	if !writable {
		result.RepairError = "write access to the service registry key descriptor is denied"
		judge(before)
		reportServiceSecurityResult(result)
		return result
	}
	if err := stampWindowsServiceRegistryKey(handle); err != nil {
		result.RepairError = err.Error()
		judge(before)
		reportServiceSecurityResult(result)
		return result
	}
	if err := resetWindowsServiceSecuritySubkeyInheritance(path + `\Security`); err != nil {
		// The subkey keeps working with its own entries; only report it.
		result.RepairError = "reset Security subkey inheritance: " + err.Error()
	}
	after, afterText, err := readWindowsRegistryKeyDescriptor(handle)
	switch {
	case err != nil:
		result.Outcome = CanonicalAccepted
		result.RepairError = "re-read the service registry key descriptor: " + err.Error()
	case canonicalKey(after):
		result.Outcome = CanonicalRepaired
		result.Drift = "re-applied the canonical service registry key descriptor after: " + beforeText
	default:
		result.RepairError = "service registry key descriptor still differs after repair: " + afterText
		judge(after)
	}
	reportServiceSecurityResult(result)
	return result
}

func readWindowsRegistryKeyDescriptor(key windows.Handle) (objectDescriptor, string, error) {
	sd, err := windows.GetSecurityInfo(
		key,
		windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return objectDescriptor{}, "", err
	}
	desc, err := objectDescriptorFromSD(sd)
	if err != nil {
		return objectDescriptor{}, "", err
	}
	group, _, err := sd.Group()
	if err != nil {
		return objectDescriptor{}, "", err
	}
	if group != nil {
		desc.Group = group.String()
	}
	return desc, sd.String(), nil
}

func stampWindowsServiceRegistryKey(key windows.Handle) error {
	canonical, err := windows.SecurityDescriptorFromString(managedServiceRegistrySDDL)
	if err != nil {
		return fmt.Errorf("build canonical service key descriptor: %w", err)
	}
	owner, _, err := canonical.Owner()
	if err != nil {
		return fmt.Errorf("read canonical service key owner: %w", err)
	}
	group, _, err := canonical.Group()
	if err != nil {
		return fmt.Errorf("read canonical service key group: %w", err)
	}
	dacl, _, err := canonical.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("read canonical service key DACL: %v", err)
	}
	return RunWithWindowsRepairPrivileges(func() error {
		info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
		if err := windows.SetSecurityInfo(key, windows.SE_REGISTRY_KEY, info, owner, group, dacl, nil); err != nil {
			return fmt.Errorf("re-apply the canonical service key descriptor: %w", err)
		}
		return nil
	})
}

// resetWindowsServiceSecuritySubkeyInheritance mirrors
// Reset-DefenseClawServiceSecuritySubkeyInheritance: sc sdset leaves the
// Security subkey with a protected DACL of explicit entries; drop them and let
// it inherit from the managed service key. The Security value is untouched.
func resetWindowsServiceSecuritySubkeyInheritance(path string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, windows.READ_CONTROL|windows.WRITE_DAC)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = key.Close() }()
	handle := windows.Handle(key)
	desc, _, err := readWindowsRegistryKeyDescriptor(handle)
	if err != nil {
		return err
	}
	explicit := false
	for _, ace := range desc.ACEs {
		if ace.Flags&aceFlagInherited == 0 {
			explicit = true
			break
		}
	}
	if !desc.Protected && !explicit && !desc.NullDACL {
		return nil
	}
	// "D:" is a present, empty DACL. A nil DACL here would be a null DACL,
	// which grants everyone everything, so refuse rather than write one.
	empty, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return err
	}
	dacl, _, err := empty.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("build empty DACL: %v", err)
	}
	return windows.SetSecurityInfo(
		handle,
		windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
