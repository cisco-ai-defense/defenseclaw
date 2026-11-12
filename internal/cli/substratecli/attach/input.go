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
)

// inputHub is the only reader of the keyboard. Each connection reads
// through its own inReader, which ends (EOF) when the connection does, so a
// connection that is gone never swallows a keystroke meant for the next.
type inputHub struct {
	f     *os.File
	ch    chan []byte
	quit  chan struct{}
	eof   chan struct{}
	done  chan struct{}
	once  sync.Once
	guard func()
}

func newInputHub(f *os.File, guard func()) *inputHub {
	h := &inputHub{f: f, ch: make(chan []byte), quit: make(chan struct{}), eof: make(chan struct{}), done: make(chan struct{}), guard: guard}
	go h.loop()
	return h
}

func (h *inputHub) loop() {
	defer close(h.done)
	defer h.guard()
	buf := make([]byte, 4096)
	for {
		n, err := h.f.Read(buf)
		if n > 0 {
			b := append([]byte(nil), buf[:n]...)
			select {
			case h.ch <- b:
			case <-h.quit:
				return
			}
		}
		if err != nil {
			select {
			case <-h.quit:
			default:
				close(h.eof)
			}
			return
		}
	}
}

// ended reports that the keyboard input ended (a pipe closed).
func (h *inputHub) ended() bool {
	select {
	case <-h.eof:
		return true
	default:
		return false
	}
}

// close stops the reader. A file with deadlines (a pipe) is interrupted at
// once; a blocking terminal read ends with the process.
func (h *inputHub) close() {
	h.once.Do(func() {
		close(h.quit)
		if h.f.SetReadDeadline(time.Now()) == nil {
			select {
			case <-h.done:
			case <-time.After(time.Second):
			}
			_ = h.f.SetReadDeadline(time.Time{})
		}
	})
}

func (h *inputHub) open() *inReader { return &inReader{h: h, stop: make(chan struct{})} }

type inReader struct {
	h       *inputHub
	stop    chan struct{}
	once    sync.Once
	pending []byte
}

func (r *inReader) Read(p []byte) (int, error) {
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	select {
	case <-r.stop:
		return 0, io.EOF
	case <-r.h.eof:
		return 0, io.EOF
	case b := <-r.h.ch:
		n := copy(p, b)
		r.pending = b[n:]
		return n, nil
	}
}

func (r *inReader) close() { r.once.Do(func() { close(r.stop) }) }
