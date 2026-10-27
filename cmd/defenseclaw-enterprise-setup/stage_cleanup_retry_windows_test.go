// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A staged file Windows still holds for a moment after the lifecycle child
// exits (its image, an antivirus scan) is removed once it is released; one
// that stays held, or any other error, still fails the cleanup.
func TestEnterpriseSetupStageCleanupWaitsForAHeldFile(t *testing.T) {
	previousRemove, previousWait := removeEnterpriseSetupStageFile, enterpriseSetupStageRemoveWait
	t.Cleanup(func() { removeEnterpriseSetupStageFile, enterpriseSetupStageRemoveWait = previousRemove, previousWait })
	enterpriseSetupStageRemoveWait = 2 * time.Second
	held := func(err error, times int) (*int, func(string) error) {
		calls := 0
		return &calls, func(string) error {
			calls++
			if calls <= times {
				return &os.PathError{Op: "remove", Path: "defenseclaw.exe", Err: err}
			}
			return nil
		}
	}
	for _, transient := range []error{windows.ERROR_SHARING_VIOLATION, windows.ERROR_ACCESS_DENIED} {
		calls, remove := held(transient, 3)
		removeEnterpriseSetupStageFile = remove
		if err := removeEnterpriseSetupStageEntry("defenseclaw.exe"); err != nil || *calls != 4 {
			t.Fatalf("%v: err=%v after %d removals; want the fourth to succeed", transient, err, *calls)
		}
	}
	enterpriseSetupStageRemoveWait = 200 * time.Millisecond
	calls, remove := held(windows.ERROR_SHARING_VIOLATION, 1<<30)
	removeEnterpriseSetupStageFile = remove
	started := time.Now()
	if err := removeEnterpriseSetupStageEntry("defenseclaw.exe"); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		time.Since(started) > 2*time.Second || *calls < 2 {
		t.Fatalf("a file that stays held: err=%v after %d removals in %s", err, *calls, time.Since(started))
	}
	calls, remove = held(windows.ERROR_DIR_NOT_EMPTY, 1<<30)
	removeEnterpriseSetupStageFile = remove
	if err := removeEnterpriseSetupStageEntry("stage"); !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) || *calls != 1 {
		t.Fatalf("another error is not retried: err=%v after %d removals", err, *calls)
	}
}
