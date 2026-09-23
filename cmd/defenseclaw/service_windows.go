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

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

const (
	windowsServiceNameEnv = "DEFENSECLAW_WINDOWS_SERVICE_NAME"
	windowsServiceLogEnv  = "DEFENSECLAW_WINDOWS_SERVICE_LOG"

	defaultGatewayServiceName  = "DefenseClawGateway"
	defaultGuardianServiceName = "DefenseClawHookGuardian"

	windowsServiceStartSettle = 250 * time.Millisecond
)

var (
	isWindowsService        = svc.IsWindowsService
	runSCMService           = svc.Run
	terminateWindowsService = func(code uint32) { os.Exit(int(code)) }
	windowsServiceStopWait  = 30 * time.Second
	serviceNameRE           = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

type windowsServiceExecutor func(context.Context) int

// runWindowsService detects SCM hosting before Cobra interprets the process
// command line. The same signed gateway binary can therefore host either the
// long-running gateway (no arguments) or the enterprise hook watcher
// ("enterprise hooks watch ...") without an extra privileged wrapper binary.
func runWindowsService(execute windowsServiceExecutor) (bool, int) {
	name := strings.TrimSpace(os.Getenv(windowsServiceNameEnv))
	if name == "" {
		// Enterprise service hosting is an explicit installer-owned switch.
		// Ordinary Windows CLI and per-user gateway invocations must not even
		// consult the SCM detector, so adding enterprise support is a strict
		// no-op unless the protected service environment opts in.
		return false, 0
	}
	hosted, err := isWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: detect Windows service host: %v\n", err)
		return true, 1
	}
	if !hosted {
		return false, 0
	}

	if !validWindowsServiceName(name) {
		fmt.Fprintf(os.Stderr, "defenseclaw: invalid Windows service name %q\n", name)
		return true, 1
	}
	if execute == nil {
		fmt.Fprintln(os.Stderr, "defenseclaw: Windows service executor is unavailable")
		return true, 1
	}

	closeLog, err := redirectWindowsServiceOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: initialize Windows service log: %v\n", err)
		return true, 1
	}
	if closeLog != nil {
		defer closeLog()
	}

	handler := &defenseClawWindowsService{execute: execute}
	if err := runSCMService(name, handler); err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: run Windows service %s: %v\n", name, err)
		return true, 1
	}
	return true, 0
}

func validWindowsServiceName(name string) bool {
	return serviceNameRE.MatchString(name)
}

func redirectWindowsServiceOutput() (func(), error) {
	path := strings.TrimSpace(os.Getenv(windowsServiceLogEnv))
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must be an absolute path", windowsServiceLogEnv)
	}
	file, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	os.Stdout = file
	os.Stderr = file
	return func() { _ = file.Close() }, nil
}

type defenseClawWindowsService struct {
	execute windowsServiceExecutor
}

func (service *defenseClawWindowsService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown

	changes <- svc.Status{State: svc.StartPending, CheckPoint: 1, WaitHint: 30_000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan int, 1)
	go func() {
		result <- service.execute(ctx)
	}()

	// Catch deterministic configuration/startup failures before advertising a
	// running process. SCM "Running" means the command is alive; the
	// enterprise status/verify command separately authenticates application
	// health and never conflates process state with readiness.
	startTimer := time.NewTimer(windowsServiceStartSettle)
	defer startTimer.Stop()
	select {
	case code := <-result:
		return unexpectedWindowsServiceExit(code)
	case <-startTimer.C:
	}

	current := svc.Status{State: svc.Running, Accepts: accepted}
	changes <- current

	var stopOnce sync.Once
	stopRequested := false
	var stopTimer *time.Timer
	var stopDeadline <-chan time.Time
	defer func() {
		if stopTimer != nil {
			stopTimer.Stop()
		}
	}()
	for {
		select {
		case code := <-result:
			if stopRequested {
				// Executor cleanup errors after an accepted administrator stop
				// are diagnostics, not crash recovery signals. Reporting a
				// nonzero SERVICE_STOPPED status can race upgrade/uninstall.
				return false, 0
			}
			return unexpectedWindowsServiceExit(code)
		case <-stopDeadline:
			// Returning from Execute lets x/sys/svc report SERVICE_STOPPED and
			// then main exits the process, bounding servicing without asking
			// SCM recovery to undo an intentional administrator stop.
			return false, 0
		case request, ok := <-requests:
			if !ok {
				stopRequested = true
				stopOnce.Do(cancel)
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				stopRequested = true
				stopOnce.Do(func() {
					current = svc.Status{
						State:      svc.StopPending,
						CheckPoint: 1,
						WaitHint:   uint32(windowsServiceStopWait / time.Millisecond),
					}
					changes <- current
					cancel()
					stopTimer = time.NewTimer(windowsServiceStopWait)
					stopDeadline = stopTimer.C
				})
			}
		}
	}
}

func unexpectedWindowsServiceExit(code int) (bool, uint32) {
	exitCode := uint32(1)
	if code > 0 {
		exitCode = uint32(code)
	}
	// Do not return to x/sys/svc: that would send SERVICE_STOPPED and make
	// recovery depend on FailureActionsOnNonCrashFailures, whose first change
	// Microsoft documents as taking effect only after reboot. Process
	// termination is a base SCM failure and is recoverable immediately.
	terminateWindowsService(exitCode)
	// Production os.Exit never returns. This fallback makes the intent
	// observable in unit tests and still reports failure if a test seam returns.
	return true, exitCode
}
