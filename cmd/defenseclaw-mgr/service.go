// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
)

// serviceAction names the SCM operations `defenseclaw-mgr service` exposes.
var serviceActions = []string{"register", "unregister", "start", "stop", "status"}

func runService(args []string) (int, error) {
	if len(args) == 0 {
		return exitUsage, fmt.Errorf("service requires an action: one of %v", serviceActions)
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "register":
		return doServiceRegister(rest)
	case "unregister":
		return doServiceUnregister(rest)
	case "start":
		return doServiceStart(rest)
	case "stop":
		return doServiceStop(rest)
	case "status":
		return doServiceStatus(rest)
	default:
		return exitUsage, fmt.Errorf("unknown service action %q: one of %v", action, serviceActions)
	}
}

// The service_* handlers are follow-up work — they wrap golang.org/x/sys/windows/svc/mgr
// to create the DefenseClawGateway SCM entry with LocalSystem, delayed
// autostart, restart-on-failure recovery, and the pinned
// DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise env.
func doServiceRegister(_ []string) (int, error) {
	return exitRetryable, errors.New("service register not yet implemented")
}

func doServiceUnregister(_ []string) (int, error) {
	return exitRetryable, errors.New("service unregister not yet implemented")
}

func doServiceStart(_ []string) (int, error) {
	return exitRetryable, errors.New("service start not yet implemented")
}

func doServiceStop(_ []string) (int, error) {
	return exitRetryable, errors.New("service stop not yet implemented")
}

func doServiceStatus(_ []string) (int, error) {
	return exitRetryable, errors.New("service status not yet implemented")
}
