// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeowner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsAnonymousPipeRefusesDeadlineContract(t *testing.T) {
	f := newFixture(t, time.Second)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	custody := &testCustody{}
	owner, err := New(ctx, f.binding, Pipes{w, f.owner.pipes.Output, f.owner.pipes.Diagnostics, custody}, Limits{time.Second, time.Second})
	if owner == nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("anonymous pipe accepted: %v", err)
	}
	if err := owner.Close(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if custody.calls.Load() != 1 {
		t.Fatal("accepted pipe failure lost custody")
	}
}

func TestWindowsDuplicatedPipeObjectRefusesBeforeOwnership(t *testing.T) {
	f := newFixture(t, time.Second)
	conn, err := f.owner.pipes.Output.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var duplicate windows.Handle
	var dupErr error
	if err := conn.Control(func(fd uintptr) {
		dupErr = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(fd), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS)
	}); err != nil {
		t.Fatal(err)
	}
	if dupErr != nil {
		t.Fatal(dupErr)
	}
	alias := os.NewFile(uintptr(duplicate), "duplicate-private-test")
	defer alias.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	custody := &testCustody{}
	owner, err := New(ctx, f.binding, Pipes{f.owner.pipes.Input, f.owner.pipes.Output, alias, custody}, Limits{time.Second, time.Second})
	if owner != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("duplicate kernel object accepted: %v", err)
	}
	if custody.calls.Load() != 0 {
		t.Fatal("duplicate refusal transferred resources")
	}
}
