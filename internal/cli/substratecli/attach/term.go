// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// fdOf returns f's descriptor (a handle on Windows) without File.Fd, which
// would switch a pollable file to blocking mode and break its deadlines.
func fdOf(f *os.File) (int, bool) {
	if f == nil {
		return 0, false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, false
	}
	var fd uintptr
	if rc.Control(func(x uintptr) { fd = x }) != nil {
		return 0, false
	}
	return int(fd), true
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fd, ok := fdOf(f)
	return ok && term.IsTerminal(fd)
}

// terminal owns the keyboard's mode. Nothing changes unless In is a
// terminal.
type terminal struct {
	in     *os.File
	out    *os.File
	inFd   int
	sizeFd int
	tty    bool
	sizeOK bool

	mu        sync.Mutex
	state     *term.State
	vtRestore func()
}

func newTerminal(in *os.File, out io.Writer) *terminal {
	t := &terminal{in: in}
	if fd, ok := fdOf(in); ok && term.IsTerminal(fd) {
		t.tty, t.inFd, t.sizeFd, t.sizeOK = true, fd, fd, true
	}
	if f, ok := out.(*os.File); ok {
		if fd, ok := fdOf(f); ok && term.IsTerminal(fd) {
			// The console size comes from the output handle on Windows.
			t.out, t.sizeFd, t.sizeOK = f, fd, true
		}
	}
	return t
}

// enableVT turns on VT sequences on a Windows console (a no-op elsewhere).
func (t *terminal) enableVT() {
	t.mu.Lock()
	defer t.mu.Unlock()
	var in *os.File
	if t.tty {
		in = t.in
	}
	if in != nil || t.out != nil {
		t.vtRestore = enableVT(in, t.out)
	}
}

func (t *terminal) raw() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.tty || t.state != nil {
		return nil
	}
	st, err := term.MakeRaw(t.inFd)
	if err != nil {
		return err
	}
	t.state = st
	return nil
}

func (t *terminal) restore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != nil {
		_ = term.Restore(t.inFd, t.state)
		t.state = nil
	}
}

func (t *terminal) close() {
	t.restore()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.vtRestore != nil {
		t.vtRestore()
		t.vtRestore = nil
	}
}

// guard is deferred by every goroutine of this package: a panic restores
// the terminal before it continues.
func (t *terminal) guard() {
	if r := recover(); r != nil {
		t.close()
		panic(r)
	}
}

func (t *terminal) size() (relay.Resize, bool) {
	if !t.sizeOK {
		return relay.Resize{}, false
	}
	c, r, err := term.GetSize(t.sizeFd)
	if err != nil || c <= 0 || r <= 0 {
		return relay.Resize{}, false
	}
	return relay.Resize{Cols: uint16(min(c, 1000)), Rows: uint16(min(r, 1000))}, true
}

// pollSize signals on the returned channel when the size changes, checking
// every interval (Windows has no SIGWINCH).
func (t *terminal) pollSize(stop <-chan struct{}, every time.Duration) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		defer t.guard()
		tick := time.NewTicker(every)
		defer tick.Stop()
		last, _ := t.size()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			if sz, ok := t.size(); ok && sz != last {
				last = sz
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch
}
