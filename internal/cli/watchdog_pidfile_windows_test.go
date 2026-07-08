// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"testing"
)

func TestVerifyWatchdogProcess_StartIdentity(t *testing.T) {
	identity := watchdogProcessStartIdentity(os.Getpid())
	if identity == "" {
		t.Fatal("current process has no Windows start identity")
	}
	if !verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity}) {
		t.Fatal("verifyWatchdogProcess rejected the matching Windows start identity")
	}
	if verifyWatchdogProcess(watchdogPIDInfo{PID: os.Getpid(), StartIdentity: identity + "-stale"}) {
		t.Fatal("verifyWatchdogProcess accepted a stale Windows start identity")
	}
}
