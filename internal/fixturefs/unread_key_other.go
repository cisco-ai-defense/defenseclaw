// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package fixturefs

import (
	"bytes"
	"runtime"
	"strconv"
)

// lockUnreadKey holds nothing: the key is the goroutine's own number.
func lockUnreadKey() (unlock func()) { return func() {} }

// unreadKey is the runtime's number of the calling goroutine (0: unknown,
// which no Unread registers, so such a goroutine reads as before).
func unreadKey() uint64 {
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
