// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sharedfiletest

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A poll that reads the file while an administrator saves it in place can
// see a torn file (GAP-1838); the watch does not keep that poll's failure,
// and it keeps every other one.
func TestWatchJudgesOnlyPollsNoAdministratorSaveOverlapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	admin := Admin{
		Path: path,
		Edit: func(data []byte) []byte { return append([]byte(nil), data...) },
		Kept: func([]byte) bool { return true },
	}
	waitPolls := func(watch *Watch, n int) {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if polls, _ := watch.Polls(); polls >= n || time.Now().After(deadline) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}

	t.Run("a failure while the administrator saves is not kept", func(t *testing.T) {
		var calls atomic.Int32
		watch := StartWatch(func() error {
			if calls.Add(1) == 1 {
				admin.Apply(t, Content) // the save lands during this poll's read
				return errors.New("torn read")
			}
			return nil
		})
		waitPolls(watch, 3)
		if err := watch.Stop(); err != nil {
			t.Fatalf("a poll that overlapped the administrator's save was judged: %v", err)
		}
		if _, torn := watch.Polls(); torn != 1 {
			t.Fatalf("torn polls = %d, want 1", torn)
		}
	})

	t.Run("any other failure is kept", func(t *testing.T) {
		admin.Apply(t, Content) // an earlier save does not hide a later failure
		var calls atomic.Int32
		watch := StartWatch(func() error {
			if calls.Add(1) == 2 {
				return errors.New("registration missing")
			}
			return nil
		})
		waitPolls(watch, 4)
		if err := watch.Stop(); err == nil {
			t.Fatal("a failure no administrator save overlapped was not kept")
		}
	})
}
