// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	windowsEnterprisePowerShellPolicyKey = `SOFTWARE\Policies\Microsoft\Windows\PowerShell`
	windowsEnterpriseMachineEnvKey       = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	windowsEnterpriseConfigReadMax       = 4 << 20
	windowsEnterpriseLoopbackTimeout     = 3 * time.Second
)

// windowsEnterprisePrerequisiteChecker runs the lifecycle preflight. It is a
// variable, like the resolvers, so tests substitute it.
var windowsEnterprisePrerequisiteChecker = checkWindowsEnterprisePrerequisites

func checkWindowsEnterprisePrerequisites(input windowsEnterprisePrereqInput) error {
	return evaluateWindowsEnterprisePrerequisites(input, windowsEnterprisePrereqOps{
		elevated:          func() bool { return windows.GetCurrentProcessToken().IsElevated() },
		volumeFindings:    windowsEnterpriseVolumeFindings,
		executionPolicies: windowsEnterpriseExecutionPolicies,
		lockdownPolicy:    windowsEnterpriseLockdownPolicy,
		missingPrivileges: windowsEnterpriseTokenMissingPrivileges,
		gatewayPort:       windowsEnterpriseGatewayPort,
		gatewayImage:      windowsEnterpriseGatewayImage,
		loopback: windowsEnterpriseLoopbackOps{
			listenerPID:    daemon.ListenerOwnerPID,
			processImage:   windowsEnterpriseProcessImage,
			bindAndConnect: windowsEnterpriseBindAndConnect,
		},
	})
}

// windowsEnterpriseVolumeFindings checks the system drive and the volumes
// holding Program Files and ProgramData.
func windowsEnterpriseVolumeFindings() []windowsEnterpriseVolumeFinding {
	var roots []string
	if windowsDirectory, err := windows.GetSystemWindowsDirectory(); err == nil {
		roots = append(roots, filepath.VolumeName(windowsDirectory)+`\`)
	}
	if machineRoots, err := windowsEnterpriseMachineRootsResolver(); err == nil {
		roots = append(roots, machineRoots.ProgramFiles, machineRoots.ProgramData)
	}
	seen := map[string]bool{}
	var findings []windowsEnterpriseVolumeFinding
	for _, root := range roots {
		volume := strings.ToUpper(filepath.VolumeName(root))
		if volume == "" || seen[volume] {
			continue
		}
		seen[volume] = true
		if _, err := winpath.ValidateFixedNTFSMountedPath(root); err != nil {
			findings = append(findings, windowsEnterpriseVolumeFinding{Root: root, Err: err})
		}
	}
	return findings
}

// windowsEnterpriseExecutionPolicies reads the Group Policy execution policy
// for the machine and for the user running the lifecycle (HKU\S-1-5-18 for
// LocalSystem), in precedence order.
func windowsEnterpriseExecutionPolicies() []windowsEnterpriseExecutionPolicyScope {
	scopes := []windowsEnterpriseExecutionPolicyScope{
		readWindowsEnterpriseExecutionPolicy(registry.LOCAL_MACHINE, windowsEnterprisePowerShellPolicyKey,
			"MachinePolicy", `HKLM\`+windowsEnterprisePowerShellPolicyKey),
	}
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user != nil && user.User.Sid != nil {
		sid := user.User.Sid.String()
		scopes = append(scopes, readWindowsEnterpriseExecutionPolicy(registry.USERS,
			sid+`\`+windowsEnterprisePowerShellPolicyKey, "UserPolicy", `HKU\`+sid+`\`+windowsEnterprisePowerShellPolicyKey))
	}
	return scopes
}

func readWindowsEnterpriseExecutionPolicy(root registry.Key, path, scope, label string) windowsEnterpriseExecutionPolicyScope {
	result := windowsEnterpriseExecutionPolicyScope{Scope: scope, Key: label}
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return result
	}
	defer key.Close()
	if value, _, err := key.GetIntegerValue("EnableScripts"); err == nil {
		result.EnableScriptsSet = true
		result.EnableScripts = value
	}
	if value, _, err := key.GetStringValue("ExecutionPolicy"); err == nil {
		result.Policy = value
	}
	return result
}

func windowsEnterpriseLockdownPolicy() (string, bool) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsEnterpriseMachineEnvKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", false
	}
	defer key.Close()
	if value, _, err := key.GetStringValue("__PSLockdownPolicy"); err == nil {
		return value, true
	}
	if value, _, err := key.GetIntegerValue("__PSLockdownPolicy"); err == nil {
		return fmt.Sprintf("%d", value), true
	}
	return "", false
}

func windowsEnterpriseTokenMissingPrivileges() ([]string, error) {
	token := windows.GetCurrentProcessToken()
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if size == 0 {
		return nil, errors.New("token privilege list is empty")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], size, &size); err != nil {
		return nil, err
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	held := make(map[windows.LUID]bool)
	for _, entry := range privileges.AllPrivileges() {
		held[entry.Luid] = true
	}
	var names []string
	for _, name := range windowsEnterpriseRepairPrivileges {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
			continue
		}
		if held[luid] {
			names = append(names, name)
		}
	}
	return windowsEnterpriseMissingPrivileges(names), nil
}

// windowsEnterpriseGatewayPort reads gateway.api_port from --config, else
// from the installed config under the state root, else uses the default.
func windowsEnterpriseGatewayPort(input windowsEnterprisePrereqInput) int {
	candidates := []string{}
	if strings.TrimSpace(input.ConfigPath) != "" {
		candidates = append(candidates, input.ConfigPath)
	}
	stateRoot := strings.TrimSpace(input.StateRoot)
	if stateRoot == "" {
		if programData, err := windowsEnterpriseProgramDataResolver(); err == nil {
			stateRoot = filepath.Join(programData, "Cisco", "Cisco Secure Client", "DefenseClaw")
		}
	}
	if stateRoot != "" {
		candidates = append(candidates, filepath.Join(stateRoot, "etc", "config.yaml"))
	}
	for _, candidate := range candidates {
		body, err := readWindowsEnterpriseBoundedFile(candidate, windowsEnterpriseConfigReadMax)
		if err != nil {
			continue
		}
		return windowsEnterpriseGatewayPortFromConfig(body)
	}
	return windowsEnterpriseGatewayPortFromConfig(nil)
}

func readWindowsEnterpriseBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

// windowsEnterpriseGatewayImage is the installed gateway executable, the
// only process allowed to hold the loopback port during a lifecycle run.
func windowsEnterpriseGatewayImage(input windowsEnterprisePrereqInput) (string, error) {
	root := strings.TrimSpace(input.InstallRoot)
	if root == "" {
		programFiles, err := windowsEnterpriseProgramFilesResolver()
		if err != nil {
			return "", err
		}
		root = filepath.Join(programFiles, "Cisco", "Cisco Secure Client", "DefenseClaw")
	}
	return filepath.Join(filepath.Clean(root), "bin", "defenseclaw-gateway.exe"), nil
}

func windowsEnterpriseProcessImage(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid process ID %d", pid)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func windowsEnterpriseBindAndConnect(addr string) (excluded, inUse bool, bindErr, connectErr error) {
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		switch {
		case errors.Is(err, windows.WSAEACCES):
			return true, false, err, nil
		case errors.Is(err, windows.WSAEADDRINUSE):
			return false, true, err, nil
		}
		return false, false, err, nil
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		if conn, err := listener.Accept(); err == nil {
			_ = conn.Close()
		}
	}()
	conn, err := net.DialTimeout("tcp4", addr, windowsEnterpriseLoopbackTimeout)
	if err != nil {
		_ = listener.Close()
		<-accepted
		return false, false, nil, err
	}
	_ = conn.Close()
	_ = listener.Close()
	<-accepted
	return false, false, nil, nil
}
