// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0059: a read that answered is never reported as "did not answer
// within ..." because its deadline is also ready when the wait looks. The
// hook holds the pass's goroutine until the read has answered and its
// deadline has passed, so both cases are ready at every wait (the old reader
// cancelled readCtx right after its answer, which made select pick the
// timeout at random: CI flakes of TestManagedGuardianOpenCodeHungAccountThenHealthyOne
// and TestManagedGuardianOpenCodeRecordWithoutImportDoneIsTheImportPass).
func TestOpenCodePortReadThatAnsweredIsNotATimeoutWhenItsDeadlineIsAlsoReady(t *testing.T) {
	previousCheck, previousRunner := enterpriseHookCheckHome, enterpriseHookWorkerRunner
	previousTimeout, previousHook := enterpriseHookOpenCodeReadTimeout, enterpriseHookOpenCodeReadBeforeWait
	t.Cleanup(func() {
		enterpriseHookCheckHome, enterpriseHookWorkerRunner = previousCheck, previousRunner
		enterpriseHookOpenCodeReadTimeout, enterpriseHookOpenCodeReadBeforeWait = previousTimeout, previousHook
	})
	const readTimeout = 20 * time.Millisecond
	enterpriseHookOpenCodeReadTimeout = readTimeout
	enterpriseHookCheckHome = func(string, int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomeAvailable}
	}
	var accounts []enterprisehooks.UnixEligibleAccount
	for uid := 2001; uid <= 2032; uid++ {
		accounts = append(accounts, enterprisehooks.UnixEligibleAccount{User: fmt.Sprintf("ent%d", uid), UID: uid, GID: uid, Home: t.TempDir()})
	}
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, _ enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{OpenCodeServicePort: &enterpriseHookWorkerOpenCodePortReport{Port: 20000 + account.UID}}, nil
	}
	// The hook waits until the answer is in the read's channel (not only
	// until the runner returned: on a loaded box the send can come later),
	// bounded, then until the deadline has passed.
	enterpriseHookOpenCodeReadBeforeWait = func(_ int, answered func() bool) {
		for wait := time.Now().Add(30 * time.Second); !answered() && time.Now().Before(wait); {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(3 * readTimeout)
	}
	var log strings.Builder
	ports, unknown := enterpriseHookReadOpenCodePortsAsUsers(context.Background(), &log, accounts)
	if len(unknown) != 0 {
		t.Fatalf("%d of %d reads that answered were reported unknown: %+v\n%s", len(unknown), len(accounts), unknown, log.String())
	}
	for _, account := range accounts {
		if ports[account.UID] != 20000+account.UID {
			t.Fatalf("uid %d: port %d, want %d (ports %v)\n%s", account.UID, ports[account.UID], 20000+account.UID, ports, log.String())
		}
	}
}
