// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"syscall"
	"testing"
)

func TestQuietClosedOutputPipe(t *testing.T) {
	closed := &fs.PathError{Op: "write", Path: "/dev/stdout", Err: syscall.EPIPE}
	if err := quietClosedOutputPipe(fmt.Errorf("export: %w", closed)); err != nil {
		t.Fatalf("closed pipe should end quietly, got %v", err)
	}
	other := errors.New("audit export: open db: no such file")
	if err := quietClosedOutputPipe(other); err != other {
		t.Fatalf("other errors must pass through, got %v", err)
	}
	if quietClosedOutputPipe(nil) != nil {
		t.Fatal("nil stays nil")
	}
	windowsClosed := &fs.PathError{Op: "write", Path: "/dev/stdout", Err: windowsErrorNoData}
	if got := isClosedOutputPipe(windowsClosed); got != (runtime.GOOS == "windows") {
		t.Fatalf("ERROR_NO_DATA closed-pipe detection = %v on %s", got, runtime.GOOS)
	}
}
