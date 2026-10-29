// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package mcpasuser

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

//go:noinline
func growPipeTestStack(depth int) byte {
	var frame [1024]byte
	frame[depth%len(frame)] = byte(depth)
	if depth == 0 {
		return frame[0]
	}
	return growPipeTestStack(depth-1) + frame[1]
}

// A pending ConnectNamedPipe keeps writing to its OVERLAPPED after the call
// returns. When the waiting goroutine's stack moves (here: it grows by about
// 256 KiB while the connect is pending), a stack-allocated OVERLAPPED is left
// behind: the kernel completes into freed memory and connectPipe reads a copy
// that still says pending (ERROR_IO_INCOMPLETE). The pinned heap OVERLAPPED
// completes normally.
func TestConnectPipeCompletesAfterTheWaitingStackMoves(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-mcpasuser-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	for round := 0; round < 5; round++ {
		pipe, err := createPipe(name, nil, round == 0)
		if err != nil {
			t.Fatal(err)
		}
		waiting := make(chan struct{})
		var once sync.Once
		previous := connectPipeWaiting
		connectPipeWaiting = func() {
			once.Do(func() {
				_ = growPipeTestStack(256)
				close(waiting)
			})
		}
		result := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		go func() { result <- connectPipe(ctx, pipe) }()
		select {
		case <-waiting:
		case err := <-result:
			t.Fatalf("round %d: connect returned before a client opened the pipe: %v", round, err)
		}
		pointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		client, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatalf("round %d: open the pipe as a client: %v", round, err)
		}
		err = <-result
		cancel()
		connectPipeWaiting = previous
		_ = windows.CloseHandle(client)
		_ = windows.CloseHandle(pipe)
		if err != nil {
			t.Fatalf("round %d: connect after the waiting stack moved: %v", round, err)
		}
	}
}

// Cancelling a pending connect returns only after the kernel is done with
// the OVERLAPPED.
func TestConnectPipeCancelReturnsTheContextError(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-mcpasuser-cancel-%d-%d`, os.Getpid(), time.Now().UnixNano())
	pipe, err := createPipe(name, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := connectPipe(ctx, pipe); err != context.DeadlineExceeded {
		t.Fatalf("connectPipe = %v, want %v", err, context.DeadlineExceeded)
	}
}
