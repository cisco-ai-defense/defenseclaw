// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// processListeners lets a successor graph generation serve the configured
// loopback address while the active generation still holds it. Each
// generation keeps its own HTTP server; the process binds the socket once and
// hands every new connection to the newest generation that is still open.
// When the last generation closes, the socket closes. Without it a reload
// that kept a Prometheus destination had to bind a port the process already
// held, so every observability edit (a redaction profile, a bucket, another
// destination) needed a gateway restart (GAP-2072).
var processListeners = &listenerSet{hubs: make(map[string]*listenerHub)}

type listenerSet struct {
	mu   sync.Mutex
	hubs map[string]*listenerHub
}

// errSharedListenerInUse refuses a second listener for one address in the
// same generation: two destinations of one plan cannot share a port.
var errSharedListenerInUse = errors.New("prometheus listen address already used by this generation")

// acquire returns a listener for address that this process shares across
// generations. listen binds the socket only when no generation holds it.
func (set *listenerSet) acquire(
	ctx context.Context,
	listen ListenFunc,
	address string,
	generation uint64,
) (net.Listener, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	hub := set.hubs[address]
	if hub != nil {
		hub.mu.Lock()
		for _, view := range hub.views {
			if view.generation == generation {
				hub.mu.Unlock()
				return nil, errSharedListenerInUse
			}
		}
		hub.mu.Unlock()
	}
	if hub == nil {
		base, err := listen(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		hub = &listenerHub{set: set, address: address, base: base, failed: make(chan struct{})}
		set.hubs[address] = hub
		go hub.acceptLoop()
	}
	view := &sharedListener{
		hub: hub, generation: generation, conns: make(chan net.Conn), done: make(chan struct{}),
	}
	hub.mu.Lock()
	hub.views = append(hub.views, view)
	hub.mu.Unlock()
	return view, nil
}

func (set *listenerSet) release(hub *listenerHub, view *sharedListener) {
	set.mu.Lock()
	defer set.mu.Unlock()
	hub.mu.Lock()
	for index, candidate := range hub.views {
		if candidate == view {
			hub.views = append(hub.views[:index:index], hub.views[index+1:]...)
			break
		}
	}
	last := len(hub.views) == 0
	if last {
		hub.closed = true
	}
	hub.mu.Unlock()
	if !last {
		return
	}
	if set.hubs[hub.address] == hub {
		delete(set.hubs, hub.address)
	}
	_ = hub.base.Close()
}

type listenerHub struct {
	set     *listenerSet
	address string
	base    net.Listener

	mu     sync.Mutex
	views  []*sharedListener
	closed bool

	failOnce sync.Once
	failed   chan struct{}
	failErr  error
}

func (hub *listenerHub) acceptLoop() {
	for {
		conn, err := hub.base.Accept()
		if err != nil {
			hub.mu.Lock()
			closed := hub.closed
			hub.mu.Unlock()
			if closed {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			hub.failOnce.Do(func() {
				hub.failErr = err
				close(hub.failed)
			})
			return
		}
		hub.deliver(conn)
	}
}

// deliver hands conn to the newest open generation, or closes it when none
// is left.
func (hub *listenerHub) deliver(conn net.Conn) {
	for {
		view := hub.newest()
		if view == nil {
			_ = conn.Close()
			return
		}
		select {
		case view.conns <- conn:
			return
		case <-view.done:
		}
	}
}

func (hub *listenerHub) newest() *sharedListener {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for index := len(hub.views) - 1; index >= 0; index-- {
		select {
		case <-hub.views[index].done:
		default:
			return hub.views[index]
		}
	}
	return nil
}

// sharedListener is one generation's view of the process socket. Close
// detaches only this generation.
type sharedListener struct {
	hub        *listenerHub
	generation uint64
	conns      chan net.Conn
	done       chan struct{}
	once       sync.Once
}

func (view *sharedListener) Accept() (net.Conn, error) {
	select {
	case <-view.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case conn := <-view.conns:
		select {
		case <-view.done:
			// Closed while the connection was handed over: give it to the
			// generation that serves now.
			go view.hub.deliver(conn)
			return nil, net.ErrClosed
		default:
			return conn, nil
		}
	case <-view.done:
		return nil, net.ErrClosed
	case <-view.hub.failed:
		return nil, view.hub.failErr
	}
}

func (view *sharedListener) Close() error {
	view.once.Do(func() {
		close(view.done)
		view.hub.set.release(view.hub, view)
	})
	return nil
}

func (view *sharedListener) Addr() net.Addr { return view.hub.base.Addr() }
