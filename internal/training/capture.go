// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"fmt"
	"os"
	"sync"
)

const captureBufferSize = 100

// Capturer wraps a Store with an async buffered channel so trace writes
// never block the request path.
type Capturer struct {
	store   *Store
	ch      chan TraceEntry
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewCapturer creates a new Capturer that asynchronously writes to the store.
func NewCapturer(store *Store) *Capturer {
	c := &Capturer{
		store:  store,
		ch:     make(chan TraceEntry, captureBufferSize),
		stopCh: make(chan struct{}),
	}
	go c.drain()
	return c
}

// Capture submits a trace entry for async writing. If the buffer is full,
// the entry is dropped (non-blocking).
func (c *Capturer) Capture(entry TraceEntry) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	select {
	case c.ch <- entry:
		// Successfully queued
	default:
		// Buffer full, drop entry (non-blocking behavior)
	}
}

// Stop signals the drain goroutine to finish and flush remaining entries.
func (c *Capturer) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()

	close(c.stopCh)
}

// drain runs in a goroutine and continuously writes entries from the channel
// to the store until Stop() is called.
func (c *Capturer) drain() {
	for {
		select {
		case <-c.stopCh:
			// Drain remaining entries before returning
			for {
				select {
				case entry := <-c.ch:
					c.write(entry)
				default:
					return
				}
			}
		case entry := <-c.ch:
			c.write(entry)
		}
	}
}

// write persists a single entry to the store and logs errors to stderr.
func (c *Capturer) write(entry TraceEntry) {
	if err := c.store.CaptureTrace(entry); err != nil {
		fmt.Fprintf(os.Stderr, "[training] capture write error: %v\n", err)
	}
}
