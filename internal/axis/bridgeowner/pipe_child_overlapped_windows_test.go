// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeowner

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"testing"
)

// Pure per-owner callbacks: no Windows API, pipe, process or child is created.
func TestOverlappedPipePendingCancellationRetainsPinnedStorageUntilTerminal(t *testing.T) {
	op := &windows.Overlapped{HEvent: 50}
	closed := 0
	pipe := &OverlappedPrivatePipe{serial: make(chan struct{}, 1), server: 10, client: 20, event: 50, operation: op, pending: true,
		cancel:      func(windows.Handle, *windows.Overlapped) error { return nil },
		result:      func(windows.Handle, *windows.Overlapped, *uint32, bool) error { return windows.ERROR_IO_INCOMPLETE },
		closeNative: func(windows.Handle) error { closed++; return nil }}
	pipe.pin.Pin(op)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pipe.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("pending completion ignored deadline")
	}
	if !pipe.pending || pipe.operation != op || pipe.event != 50 || closed != 0 {
		t.Fatal("pending native storage or handle was released")
	}
	pipe.result = func(_ windows.Handle, same *windows.Overlapped, _ *uint32, wait bool) error {
		if same != op || wait {
			t.Fatal("wrong pending operation or unbounded wait")
		}
		return windows.ERROR_OPERATION_ABORTED
	}
	if err := pipe.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pipe.pending || pipe.operation != nil || pipe.event != 0 || closed != 3 {
		t.Fatal("terminal completion did not release exact resources")
	}
}

func TestOverlappedPipeCloseUncertaintyNeverRetriesOrTransfers(t *testing.T) {
	closed := 0
	pipe := &OverlappedPrivatePipe{serial: make(chan struct{}, 1), server: 10, client: 20, event: 50, ready: true,
		closeNative: func(h windows.Handle) error {
			closed++
			if h == 50 {
				return errors.New("fixed fake close failure")
			}
			return nil
		}}
	if !errors.Is(pipe.Close(context.Background()), ErrCleanup) || !pipe.uncertain {
		t.Fatal("event close failure became success")
	}
	if _, err := pipe.Take(); !errors.Is(err, ErrClosed) {
		t.Fatal("uncertain construction transferred endpoints")
	}
	if !errors.Is(pipe.Close(context.Background()), ErrCleanup) || closed != 3 {
		t.Fatal("uncertain handle was retried or relabeled closed")
	}
}
