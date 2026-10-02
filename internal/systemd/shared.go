// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"net"
	"sync"
)

// sharedListener owns one inherited listening socket for the whole process.
//
// An activated socket must outlive any single consumer: the gateway restarts
// its API server in-process on configuration changes, and closing the only
// descriptor systemd handed over would leave the socket unit holding a
// listener nobody accepts from while the next server's own bind fails with
// "address in use". So the base listener is never closed; each consumer gets
// a view whose Close only detaches that consumer. Connections accepted while
// no view is attached wait in the kernel queue exactly as they do while the
// service is down, which is the point of socket activation.
type sharedListener struct {
	base  net.Listener
	conns chan acceptResult
	once  sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newSharedListener(base net.Listener) *sharedListener {
	return &sharedListener{base: base, conns: make(chan acceptResult)}
}

func (s *sharedListener) start() {
	s.once.Do(func() {
		go func() {
			for {
				conn, err := s.base.Accept()
				s.conns <- acceptResult{conn: conn, err: err}
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					// A permanent accept failure is delivered once to the
					// current view; later views observe the same failure.
					for {
						s.conns <- acceptResult{err: err}
					}
				}
			}
		}()
	})
}

// view returns a new consumer view of the shared listener.
func (s *sharedListener) view() net.Listener {
	s.start()
	return &listenerView{parent: s, done: make(chan struct{})}
}

type listenerView struct {
	parent    *sharedListener
	done      chan struct{}
	closeOnce sync.Once
}

func (v *listenerView) Accept() (net.Conn, error) {
	select {
	case <-v.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case result := <-v.parent.conns:
		return result.conn, result.err
	case <-v.done:
		return nil, net.ErrClosed
	}
}

// Close detaches this view. The inherited socket stays open for the next
// consumer and for systemd.
func (v *listenerView) Close() error {
	v.closeOnce.Do(func() { close(v.done) })
	return nil
}

func (v *listenerView) Addr() net.Addr { return v.parent.base.Addr() }
