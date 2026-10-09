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
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
func applyWindowsEnterpriseAPIPortHolders(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions, report *windowsEnterpriseInstallerReport) {
	inspection := result.Action == "status" || result.Action == "verify"
	gatewayRunning := strings.TrimSpace(report.GatewayService) != "" && report.GatewayServiceState == "running"
	// A lifecycle run (a first install, for example) whose gateway never
	// became ready: its result named only the readiness booleans, and status
	// could not run on the rolled-back host to name the holder.
	lifecycleFailed := !inspection && !report.GatewayReady && (len(report.Errors) > 0 || strings.TrimSpace(report.Error) != "")
	if inspection && (!report.Installed || report.TransactionPending || !gatewayRunning) {
		return
	}
	if !inspection && !lifecycleFailed {
		return
	}
	// An installer that refused its own module never started a gateway, so
	// the port is not why it failed (GAP-1658).
	if lifecycleFailed && windowsEnterpriseInstallerRefusedModule(report) {
		return
	}
	// The installed config is authoritative for the hook and gateway port.
	// If it cannot be read, a listener on the default port is not evidence
	// that it holds the gateway's configured port.
	portPath := ""
	if !report.Installed && opts != nil {
		portPath = strings.TrimSpace(opts.configPath)
	}
	port, err := windowsEnterpriseConfigAPIPort(portPath)
	if err != nil && !report.Installed && portPath == "" {
		// A failed first install may have removed its staged config. With no
		// supplied config it used the default, so retain port-holder advice.
		port, err = config.DefaultGatewayAPIPort, nil
	}
	if err != nil || port <= 0 {
		return
	}
	address := fmt.Sprintf("127.0.0.1:%d", port)
	listeners, err := windowsEnterpriseAPIListeners("127.0.0.1", port)
	if err != nil || len(listeners) == 0 {
		return
	}
	// Without the running gateway's own process ID a listener cannot be told
	// apart from the gateway itself. A gateway that is not running holds no
	// listener.
	gatewayService := strings.TrimSpace(report.GatewayService)
	if gatewayService == "" {
		// A lifecycle that failed before it read the deployment (an
		// installer that refused its module, GAP-1658) names no service;
		// the installed gateway service then still holds its own port.
		gatewayService = managed.StandaloneWindowsGatewaySvc
	}
	gatewayPID := windowsEnterpriseServicePID(gatewayService)
	if gatewayRunning && gatewayPID == 0 {
		return
	}
	// The readiness probe asks /health on the port, which any process
	// listening there answers: a standard user's listener answered 200, so
	// verify printed OK while every hook failed closed (GAP-1029). A ready
	// gateway holds its own listener; without it the port is held all the
	// same, and the probe's answer was the other process's.
	probeFooled := inspection && report.GatewayReady
	if probeFooled {
		for _, listener := range listeners {
			if listener.PID == gatewayPID {
				return
			}
		}
	}
	var names, perUser []string
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
		if windowsEnterprisePerUserGatewayHolder(holder.Image, holder.Account) {
			perUser = append(perUser, fmt.Sprintf("pid %d", holder.PID))
		}
	}
	if len(names) == 0 {
		return
	}
	if probeFooled {
		result.Readiness.Gateway = false
		result.Inspection.Local = "unknown"
		if result.Inspection.AIDefense == "ok" {
			result.Inspection.AIDefense = "unavailable:gateway_not_ready"
		}
	}
	stop := "Stop that process"
	if len(names) > 1 {
		stop = "Stop those processes"
	}
	if len(perUser) != 0 {
		// A per-user install's gateway: stopping it by hand does not keep it
		// stopped, and its data folder blocks the managed install next.
		hint := fmt.Sprintf("%s is a per-user DefenseClaw gateway: have that user run "+
			"`defenseclaw uninstall --all --binaries --yes`, which stops it and removes the per-user install",
			strings.Join(perUser, ", "))
		if len(perUser) == len(names) {
			stop = hint
		} else {
			stop = hint + ". " + stop
		}
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

// windowsEnterpriseInstallerRefusedModule reports a lifecycle the installer
// stopped before it imported its module: nothing ran.
func windowsEnterpriseInstallerRefusedModule(report *windowsEnterpriseInstallerReport) bool {
	for _, message := range append([]string{report.Error}, report.Errors...) {
		if strings.Contains(message, "installer rejected its module before import") {
			return true
		}
	}
	return false
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
