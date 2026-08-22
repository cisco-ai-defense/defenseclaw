// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var (
	version = "dev"
	commit  = "unknown"
)

const serviceStopTimeout = 30 * time.Second

func main() {
	options, err := parseBrokerOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: invalid service configuration")
		os.Exit(64)
	}
	if err := cmidbroker.ValidateIdentityBinding(
		options.serviceName,
		options.gatewayServiceName,
		options.pipeName,
	); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: service identity mismatch")
		os.Exit(64)
	}
	hosted, err := svc.IsWindowsService()
	if err != nil || !hosted {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: SCM service hosting is required")
		os.Exit(1)
	}
	handler := &brokerWindowsService{options: options}
	if err := svc.Run(options.serviceName, handler); err != nil {
		fmt.Fprintln(os.Stderr, "defenseclaw-cmid-broker: SCM service failed")
		os.Exit(1)
	}
}

type brokerWindowsService struct {
	options brokerOptions
}

func (service *brokerWindowsService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30_000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- runBroker(ctx, service.options, ready) }()

	checkpoint := uint32(1)
	startupTicker := time.NewTicker(time.Second)
	defer startupTicker.Stop()
	for {
		select {
		case err := <-result:
			if err != nil {
				return true, 1
			}
			return false, 0
		case <-ready:
			changes <- svc.Status{State: svc.Running, Accepts: accepted}
			return service.waitForStop(cancel, requests, changes, result)
		case <-startupTicker.C:
			checkpoint++
			changes <- svc.Status{State: svc.StartPending, CheckPoint: checkpoint, WaitHint: 30_000}
		case request := <-requests:
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown || request.Cmd == svc.PreShutdown {
				cancel()
				return false, 0
			}
		}
	}
}

func (service *brokerWindowsService) waitForStop(
	cancel context.CancelFunc,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
	result <-chan error,
) (bool, uint32) {
	current := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown,
	}
	var stopOnce sync.Once
	for {
		select {
		case err := <-result:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				stopOnce.Do(cancel)
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				stopOnce.Do(cancel)
				changes <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: uint32(serviceStopTimeout / time.Millisecond)}
				timer := time.NewTimer(serviceStopTimeout)
				select {
				case <-result:
					timer.Stop()
					return false, 0
				case <-timer.C:
					return true, 1
				}
			}
		}
	}
}

func runBroker(ctx context.Context, options brokerOptions, ready chan<- struct{}) error {
	serverConfig := cmidbroker.ServerConfig{
		PipeName:           options.pipeName,
		BrokerServiceName:  options.serviceName,
		GatewayServiceName: options.gatewayServiceName,
	}
	if err := cmidbroker.ValidateBrokerServiceIdentity(serverConfig); err != nil {
		return err
	}
	if err := validateBrokerPath(options.cmidLibraryPath, "CMID library", false); err != nil {
		return err
	}
	if err := validateBrokerPath(options.logPath, "broker log", true); err != nil {
		return err
	}
	key, err := cmidbroker.LoadAuthKey(options.authKeyPath, options.gatewayServiceName)
	if err != nil {
		return err
	}
	defer zeroBytes(key[:])

	logFile, err := openBrokerLog(options.logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags|log.LUTC)
	logger.Printf("stage=startup version=%s commit=%s protocol=%d", version, commit, cmidbroker.ProtocolVersion)
	defer logger.Print("stage=shutdown")

	if !cloudreg.Registered() {
		logger.Print("stage=provider-registration success=false")
		return errors.New("managed CMID provider is not registered")
	}
	provider, err := cloudreg.New(cloudreg.Config{LibPath: options.cmidLibraryPath})
	if err != nil || provider == nil {
		logger.Print("stage=provider-construction success=false")
		return errors.New("managed CMID provider construction failed")
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = provider.Refresh(refreshCtx)
	cancel()
	if err != nil {
		logger.Print("stage=provider-refresh success=false category=cmid_refresh_failed")
		return errors.New("managed CMID provider readiness failed")
	}

	server, err := cmidbroker.NewServer(serverConfig, provider, key[:], func(event cmidbroker.Event) {
		logger.Printf(
			"stage=%s operation=%s success=%t client_pid=%d duration_ms=%d",
			event.Stage,
			event.Operation,
			event.Success,
			event.ClientPID,
			event.Duration.Milliseconds(),
		)
	})
	if err != nil {
		return err
	}
	return server.ServeWithReady(ctx, ready)
}

func validateBrokerPath(path, label string, parentOnly bool) error {
	if err := validateLocalWindowsPath(path, label); err != nil {
		return err
	}
	if parentOnly {
		return managed.ValidateTrustedRuntimeDir(filepath.Dir(path), label+" directory")
	}
	return managed.ValidateTrustedFilePath(path, label)
}

func validateLocalWindowsPath(path, label string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be clean and absolute", label)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return fmt.Errorf("%s path is not on a trusted local NTFS volume", label)
	}
	return winpath.RejectReparseChain(filepath.Dir(path))
}

func openBrokerLog(path string) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, errors.New("broker log path is invalid")
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, errors.New("broker log is unavailable")
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("broker log has an unsafe file type")
	}
	file := os.NewFile(uintptr(handle), "cmid-broker.log")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("broker log is unavailable")
	}
	return file, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
