// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func ValidateBrokerServiceIdentity(config ServerConfig) error {
	if err := ValidateIdentityBinding(
		config.BrokerServiceName,
		config.GatewayServiceName,
		config.PipeName,
	); err != nil {
		return err
	}
	if err := requireLocalSystem(); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve CMID broker executable")
	}
	if err := managed.ValidateTrustedFilePath(executable, "CMID broker executable"); err != nil {
		return err
	}
	broker, err := queryService(config.BrokerServiceName, true)
	if err != nil {
		return errors.New("query configured CMID broker service")
	}
	if broker.pid != uint32(os.Getpid()) ||
		broker.state != windows.SERVICE_START_PENDING && broker.state != windows.SERVICE_RUNNING {
		return errors.New("CMID broker process is not the active configured service")
	}
	if !strings.EqualFold(broker.startName, "LocalSystem") &&
		!strings.EqualFold(broker.startName, `NT AUTHORITY\SYSTEM`) {
		return errors.New("CMID broker service is not configured as LocalSystem")
	}
	if broker.sidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		return errors.New("CMID broker service SID type is not unrestricted")
	}
	arguments, err := windows.DecomposeCommandLine(broker.binaryPath)
	if err != nil || len(arguments) == 0 || !sameExecutablePath(arguments[0], executable) {
		return errors.New("CMID broker executable does not match SCM configuration")
	}

	gateway, err := queryService(config.GatewayServiceName, true)
	if err != nil {
		return errors.New("query configured DefenseClaw gateway service")
	}
	expectedGatewayAccount := `NT SERVICE\` + config.GatewayServiceName
	if !strings.EqualFold(gateway.startName, expectedGatewayAccount) {
		return errors.New("DefenseClaw gateway service account is unexpected")
	}
	if _, err := managed.WindowsServiceAccountSID(expectedGatewayAccount); err != nil {
		return errors.New("DefenseClaw gateway virtual service SID is unavailable")
	}
	return nil
}

func authenticatePipeClient(pipe windows.Handle, gatewayServiceName string) (uint32, error) {
	var clientPID uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &clientPID); err != nil || clientPID == 0 {
		return clientPID, errors.New("CMID broker pipe client PID is unavailable")
	}
	gateway, err := queryService(gatewayServiceName, false)
	if err != nil {
		return clientPID, errors.New("DefenseClaw gateway status is unavailable")
	}
	if gateway.state != windows.SERVICE_RUNNING || gateway.pid == 0 || gateway.pid != clientPID {
		return clientPID, errors.New("CMID broker pipe client is not the active DefenseClaw gateway")
	}
	return clientPID, nil
}

func requireLocalSystem() error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil ||
		!user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("CMID broker must run as LocalSystem")
	}
	return nil
}

type serviceFacts struct {
	state      uint32
	pid        uint32
	startName  string
	binaryPath string
	sidType    uint32
}

func queryService(name string, includeConfig bool) (serviceFacts, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return serviceFacts{}, err
	}
	defer windows.CloseServiceHandle(manager)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return serviceFacts{}, err
	}
	access := uint32(windows.SERVICE_QUERY_STATUS)
	if includeConfig {
		access |= windows.SERVICE_QUERY_CONFIG
	}
	service, err := windows.OpenService(manager, namePtr, access)
	if err != nil {
		return serviceFacts{}, err
	}
	defer windows.CloseServiceHandle(service)

	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(
		service,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		&needed,
	); err != nil {
		return serviceFacts{}, err
	}
	facts := serviceFacts{state: status.CurrentState, pid: status.ProcessId}
	if !includeConfig {
		return facts, nil
	}

	configuration, err := queryServiceConfiguration(service)
	if err != nil {
		return serviceFacts{}, err
	}
	facts.startName = windows.UTF16PtrToString(configuration.ServiceStartName)
	facts.binaryPath = windows.UTF16PtrToString(configuration.BinaryPathName)
	buffer := make([]byte, unsafe.Sizeof(uint32(0)))
	if err := windows.QueryServiceConfig2(
		service,
		windows.SERVICE_CONFIG_SERVICE_SID_INFO,
		&buffer[0],
		uint32(len(buffer)),
		&needed,
	); err != nil {
		return serviceFacts{}, err
	}
	facts.sidType = *(*uint32)(unsafe.Pointer(&buffer[0]))
	return facts, nil
}

func queryServiceConfiguration(service windows.Handle) (*windows.QUERY_SERVICE_CONFIG, error) {
	var needed uint32
	_ = windows.QueryServiceConfig(service, nil, 0, &needed)
	if needed == 0 || needed > 64<<10 {
		return nil, fmt.Errorf("invalid service configuration size")
	}
	buffer := make([]byte, needed)
	configuration := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, configuration, needed, &needed); err != nil {
		return nil, err
	}
	return configuration, nil
}

func sameExecutablePath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil &&
		strings.EqualFold(filepath.Clean(leftAbsolute), filepath.Clean(rightAbsolute))
}
