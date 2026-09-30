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
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// While another process holds the gateway API port (it binds loopback
// itself, or another account's wildcard listener makes Windows refuse the
// gateway's bind), the gateway keeps retrying and hooks fail closed. Its
// bind state is only on the API it cannot serve, so status and verify read
// the TCP listener table instead and name the holder, as the Linux and
// macOS lifecycles do.

// Seams for the listener table, the gateway service's process and a
// process's identity; tests replace them.
var (
	windowsEnterpriseAPIListeners    = daemon.Listeners
	windowsEnterpriseServicePID      = queryWindowsEnterpriseServicePID
	windowsEnterpriseProcessIdentity = describeWindowsEnterpriseProcess
)

// applyWindowsEnterpriseAPIPortHolders reports api_port_held when the
// gateway service runs but its API is not ready and processes other than the
// gateway listen where the API binds.
func applyWindowsEnterpriseAPIPortHolders(result *enterprisestatus.Result, report *windowsEnterpriseInstallerReport) {
	inspection := result.Action == "status" || result.Action == "verify"
	gatewayRunning := strings.TrimSpace(report.GatewayService) != "" && report.GatewayServiceState == "running"
	// A lifecycle run (a first install, for example) whose gateway never
	// became ready: its result named only the readiness booleans, and status
	// could not run on the rolled-back host to name the holder.
	lifecycleFailed := !inspection && !report.GatewayReady && (len(report.Errors) > 0 || strings.TrimSpace(report.Error) != "")
	if inspection && (!report.Installed || report.TransactionPending || report.GatewayReady || !gatewayRunning) {
		return
	}
	if !inspection && !lifecycleFailed {
		return
	}
	address := fmt.Sprintf("127.0.0.1:%d", config.DefaultGatewayAPIPort)
	listeners, err := windowsEnterpriseAPIListeners("127.0.0.1", config.DefaultGatewayAPIPort)
	if err != nil || len(listeners) == 0 {
		return
	}
	// Without the running gateway's own process ID a listener cannot be told
	// apart from the gateway itself. A gateway that is not running holds no
	// listener.
	gatewayPID := 0
	if strings.TrimSpace(report.GatewayService) != "" {
		gatewayPID = windowsEnterpriseServicePID(report.GatewayService)
	}
	if gatewayRunning && gatewayPID == 0 {
		return
	}
	var names []string
	for _, listener := range listeners {
		if listener.PID == gatewayPID {
			continue
		}
		holder := enterprisestatus.PortHolder{Address: listener.Address, PID: listener.PID}
		holder.Image, holder.Account = windowsEnterpriseProcessIdentity(listener.PID)
		result.APIPortHolders = append(result.APIPortHolders, holder)
		who := "a process this account cannot identify"
		if holder.Image != "" {
			who = holder.Image
			if holder.Account != "" {
				who += ", " + holder.Account
			}
		}
		names = append(names, fmt.Sprintf("pid %d (%s) listening on %s", holder.PID, who, holder.Address))
	}
	if len(names) == 0 {
		return
	}
	stop := "Stop that process"
	if len(names) > 1 {
		stop = "Stop those processes"
	}
	if !inspection {
		result.AddError("api_port_held", fmt.Sprintf(
			"the gateway API port %s is held by %s, not by the DefenseClaw gateway, so the gateway could not start. "+
				"%s, then run %s again",
			address, strings.Join(names, "; "), stop, result.Action))
		return
	}
	result.AddError("api_port_held", fmt.Sprintf(
		"the gateway API port %s is held by %s, not by the DefenseClaw gateway; hooks fail closed until the port is free. "+
			"%s: the gateway keeps retrying and takes the port back by itself",
		address, strings.Join(names, "; "), stop))
}

// queryWindowsEnterpriseServicePID returns the process ID of a running
// service, or 0 when it is not running or this account cannot query it.
func queryWindowsEnterpriseServicePID(name string) int {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return 0
	}
	return int(status.ProcessId)
}

// describeWindowsEnterpriseProcess returns a process's image path and
// account, each empty when this account cannot open the process.
func describeWindowsEnterpriseProcess(pid int) (string, string) {
	if pid <= 0 {
		return "", ""
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(process)
	image := ""
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err == nil {
		image = windows.UTF16ToString(buffer[:size])
	}
	account := ""
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			account = user.User.Sid.String()
			if name, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
				account = domain + `\` + name
			}
		}
	}
	return image, account
}
