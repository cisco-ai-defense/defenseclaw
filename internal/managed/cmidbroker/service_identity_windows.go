// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// windows.ImpersonateNamedPipeClient is not exported by x/sys/windows;
// bind it directly. Keeping the LazyProc at package scope avoids a
// runtime resolution on every connection. Use NewLazySystemDLL so the
// loader is restricted to %SystemRoot%\System32\ — defense in depth
// against a same-directory advapi32.dll planted next to the broker EXE
// or the current working directory being writable to a non-admin
// (KnownDLLs already covers most cases, but the system-only loader
// closes the residual gap).
var (
	modAdvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modAdvapi32.NewProc("ImpersonateNamedPipeClient")
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
	// Primary authentication: match the caller's token user SID to the
	// gateway's virtual service SID. PID is not stable across
	// re-use; between the peer's exit and SCM's next status refresh,
	// another process could inherit the gateway PID and pass a
	// PID-only check. Impersonation reads the token *of the actual
	// connected pipe endpoint*, which the kernel binds to the caller
	// at ConnectNamedPipe time.
	expectedAccount := `NT SERVICE\` + gatewayServiceName
	expectedSID, err := managed.WindowsServiceAccountSID(expectedAccount)
	if err != nil || expectedSID == nil {
		return clientPID, errors.New("DefenseClaw gateway virtual service SID is unavailable")
	}
	if err := verifyPipeClientTokenSID(pipe, expectedSID); err != nil {
		return clientPID, err
	}
	// Defense in depth: keep the PID/service-status check so a
	// non-Running gateway still fails, and so an unauthenticated caller
	// impersonating some other SYSTEM token cannot slip past — the
	// token check above already rejects that, but the double check is
	// cheap.
	gateway, err := queryService(gatewayServiceName, false)
	if err != nil {
		return clientPID, errors.New("DefenseClaw gateway status is unavailable")
	}
	if gateway.state != windows.SERVICE_RUNNING || gateway.pid == 0 || gateway.pid != clientPID {
		return clientPID, errors.New("CMID broker pipe client is not the active DefenseClaw gateway")
	}
	return clientPID, nil
}

// verifyPipeClientTokenSID impersonates the pipe client, reads its
// token user SID, and compares it against expected. The impersonation
// is scoped to this thread and reverted before return; if RevertToSelf
// fails, the goroutine's OS thread is retired so no privileged callback
// can ever run under the client's identity.
func verifyPipeClientTokenSID(pipe windows.Handle, expected *windows.SID) error {
	runtime.LockOSThread()
	unlock := runtime.UnlockOSThread
	// Impersonate the connected pipe client. Windows binds the
	// impersonation token to the current thread only.
	ret, _, errImpersonate := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if ret == 0 {
		unlock()
		return fmt.Errorf("CMID broker impersonate pipe client failed: %v", errImpersonate)
	}
	var revertOK bool
	defer func() {
		if !revertOK {
			// Retire this OS thread so no unrelated goroutine can
			// run with a leaked impersonation token.
			return
		}
		unlock()
	}()

	var threadToken windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY,
		true,
		&threadToken,
	); err != nil {
		if revertErr := windows.RevertToSelf(); revertErr == nil {
			revertOK = true
		}
		return fmt.Errorf("CMID broker open pipe-client thread token: %w", err)
	}
	// Defer the close immediately so every subsequent return path
	// releases the token handle exactly once. Capture the Close error
	// into a named return-adjacent local via a small closure so it can
	// be surfaced when the primary flow succeeded.
	var closeErr error
	closedByDefer := true
	defer func() {
		if closedByDefer {
			if err := threadToken.Close(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	}()
	tokenUser, err := threadToken.GetTokenUser()
	if err != nil || tokenUser == nil || tokenUser.User.Sid == nil {
		if revertErr := windows.RevertToSelf(); revertErr == nil {
			revertOK = true
		}
		if err == nil {
			err = errors.New("token user was nil")
		}
		return fmt.Errorf("CMID broker inspect pipe-client token user: %w", err)
	}
	sid := tokenUser.User.Sid
	if revertErr := windows.RevertToSelf(); revertErr != nil {
		return fmt.Errorf("CMID broker revert impersonation: %w", revertErr)
	}
	revertOK = true
	// Close the token explicitly on the success path so a Close error
	// can be surfaced (not silently discarded) before the SID mismatch
	// check runs — a Close failure indicates handle-leak / kernel-state
	// corruption that we want visible in the broker log rail.
	closedByDefer = false
	if err := threadToken.Close(); err != nil {
		return fmt.Errorf("CMID broker close pipe-client thread token: %w", err)
	}
	if !sid.Equals(expected) {
		return fmt.Errorf(
			"CMID broker pipe client token SID %s does not match gateway service SID %s",
			sid, expected,
		)
	}
	if closeErr != nil {
		return fmt.Errorf("CMID broker close pipe-client thread token: %w", closeErr)
	}
	return nil
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
