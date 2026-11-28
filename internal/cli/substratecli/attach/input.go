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
	// gate, when set, holds the reader until it is closed: a reconnect
	// takes keys only once the relay has greeted it (GAP-0003); until
	// then the outage reader counts them as not sent.
	gate     chan struct{}
	gateOnce sync.Once
	// replay is input typed while disconnected that goes before the live
	// keys (B3.1); offer, in ask mode, is held until the person's next key:
	// Enter sends it, anything else drops it (decided reports which). Both
	// are set before the gate opens and zeroed once used.
	replay, offer []byte
	decided       func(sent bool)
}

// openGate lets the reader take keys.
func (r *inReader) openGate() {
	if r.gate != nil {
		r.gateOnce.Do(func() { close(r.gate) })
	}
}

// gated reports that the reader waits for the gate, so what is set before
// openGate is seen by Read.
func (r *inReader) gated() bool { return r.gate != nil }

// openGateReplay opens the gate with b sent first (ask false) or offered
// (ask true). It must be called before the gate opens, once.
func (r *inReader) openGateReplay(b []byte, ask bool, decided func(sent bool)) {
	if ask {
		r.offer, r.decided = b, decided
	} else {
		r.replay = b
	}
	r.openGate()
}

// next waits for the next chunk of live keys.
func (r *inReader) next() ([]byte, error) {
	select {
	case <-r.stop:
		return nil, io.EOF
	case <-r.h.eof:
		return nil, io.EOF
	case b := <-r.h.ch:
		return b, nil
	}
}

// answerOffer reads the person's answer to the offer: Enter sends the kept
// keys (the Enter itself is not sent), a lone Esc drops them, and any other
// key drops them and goes on to the agent.
func (r *inReader) answerOffer() error {
	b, err := r.next()
	if err != nil {
		zero(r.offer)
		r.offer = nil
		if r.decided != nil {
			r.decided(false)
		}
		return err
	}
	sent := len(b) > 0 && (b[0] == '\r' || b[0] == '\n')
	switch {
	case sent:
		r.replay, r.pending = r.offer, b[1:]
	case len(b) == 1 && b[0] == 0x1b:
		zero(r.offer)
	default:
		zero(r.offer)
		r.pending = b
	}
	r.offer = nil
	if r.decided != nil {
		r.decided(sent)
	}
	return nil
}

func (r *inReader) Read(p []byte) (int, error) {
	if r.gate != nil {
		select {
		case <-r.gate:
		case <-r.stop:
			return 0, io.EOF
		case <-r.h.eof:
			return 0, io.EOF
		}
	}
	if r.offer != nil {
		if err := r.answerOffer(); err != nil {
			return 0, err
		}
	}
	if len(r.replay) > 0 {
		n := copy(p, r.replay)
		zero(r.replay[:n])
		r.replay = r.replay[n:]
		return n, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	b, err := r.next()
	if err != nil {
		return 0, err
	}
	n := copy(p, b)
	r.pending = b[n:]
	return n, nil
}

func (r *inReader) close() { r.once.Do(func() { close(r.stop) }) }
