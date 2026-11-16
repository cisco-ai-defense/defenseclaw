// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winmutex

import (
	"errors"
	"testing"
	"time"
)

// Acquire waits for a held mutex instead of failing at once: it times out
// while the holder keeps it, and owns it once the holder releases, even when
// the release comes from another goroutine.
func TestAcquireWaitsForTheHolderAndTimesOut(t *testing.T) {
	name := testMutexName(t)
	release, abandoned, err := Acquire(name, nil, time.Second)
	if err != nil || abandoned {
		t.Fatalf("first acquire: abandoned=%v err=%v", abandoned, err)
	}
	if _, _, err := Acquire(name, nil, 100*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("acquire while held: err=%v, want ErrTimeout", err)
	}
	if _, err := TryAcquire(name, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("TryAcquire while held: err=%v, want ErrBusy", err)
	}
	waited := make(chan error, 1)
	go func() {
		next, _, err := Acquire(name, nil, 5*time.Second)
		if err == nil {
			err = next()
		}
		waited <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := <-waited; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}
