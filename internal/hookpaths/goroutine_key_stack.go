// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !((linux || darwin) && (amd64 || arm64))

package hookpaths

import (
	"bytes"
	"runtime"
	"strconv"
)

// goroutineKey names the calling goroutine where no register read of its g
// is built (goroutine_key_g.go): its goroutine number (goroutineID).
func goroutineKey() uint64 { return goroutineID() }

// goroutineID is the runtime's number of the calling goroutine (0: not
// read), from the first line of its stack: "goroutine N [...". Numbers are
// not reused while the process runs. It is a traceback of the whole stack.
func goroutineID() uint64 {
	var buf [64]byte
	line, ok := bytes.CutPrefix(buf[:runtime.Stack(buf[:], false)], []byte("goroutine "))
	if !ok {
		return 0
	}
	digits, _, _ := bytes.Cut(line, []byte(" "))
	id, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil {
		return 0
	}
	return id
}
