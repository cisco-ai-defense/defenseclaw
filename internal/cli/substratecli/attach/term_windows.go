// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package attach

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// watch polls the console size every 500 ms: Windows has no SIGWINCH.
func (t *terminal) watch(stop <-chan struct{}) <-chan struct{} {
	return t.pollSize(stop, 500*time.Millisecond)
}

// enableVT turns on VT processing on the console output (the agent's screen
// is a VT stream) and VT input on the console input (arrow keys and the
// like reach the agent as escape sequences). It returns a func that puts
// the original modes back.
func enableVT(in, out *os.File) func() {
	var undo []func()
	set := func(f *os.File, flags uint32) {
		fd, ok := fdOf(f)
		if !ok {
			return
		}
		h := windows.Handle(fd)
		var mode uint32
		if windows.GetConsoleMode(h, &mode) != nil {
			return
		}
		if windows.SetConsoleMode(h, mode|flags) == nil {
			undo = append(undo, func() { _ = windows.SetConsoleMode(h, mode) })
		}
	}
	if out != nil {
		set(out, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
	}
	if in != nil {
		set(in, windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	}
	return func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
}
