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

package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

// reclaimInterval is how often a full listener looks again for an idle
// connection to close.
const reclaimInterval = 50 * time.Millisecond

// connKey carries a request's *limitConn in its context.
type connKey struct{}

// limitListener bounds concurrent client connections and drops non-loopback
// peers, which can only appear if someone bypasses Listen. With every slot
// taken it closes the connection that has been idle longest to admit the
// next one, so idle keep-alive connections cannot keep new clients out.
type limitListener struct {
	net.Listener
	sem   chan struct{}
	conns *connTracker
	done  chan struct{}
	once  sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok && !addr.IP.IsLoopback() {
			_ = c.Close()
			continue
		}
		if !l.acquire() {
			_ = c.Close()
			return nil, net.ErrClosed
		}
		return &limitConn{Conn: c, tracker: l.conns, release: func() { <-l.sem }}, nil
	}
}

// acquire takes a connection slot. While none is free it closes the
// longest-idle connection, looking again as connections go idle, and
// otherwise waits for one to close.
func (l *limitListener) acquire() bool {
	select {
	case l.sem <- struct{}{}:
		return true
	default:
	}
	ticker := time.NewTicker(reclaimInterval)
	defer ticker.Stop()
	for {
		l.conns.reclaimIdle()
		select {
		case l.sem <- struct{}{}:
			return true
		case <-l.done:
			return false
		case <-ticker.C:
		}
	}
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// limitConn is an accepted client connection; it holds a connection slot
// until it is closed.
type limitConn struct {
	net.Conn
	tracker *connTracker
	once    sync.Once
	release func()

	// Guarded by tracker.mu.
	binding   string    // binding of the requests admitted on it
	idleSince time.Time // since when it waits between requests; zero in use
	closed    bool
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.tracker.forget(c)
		c.release()
	})
	return err
}

func (c *limitConn) CloseWrite() error { return closeWrite(c.Conn) }

// connTracker attributes client connections to bindings once a request on
// them is admitted, and records which ones are idle between keep-alive
// requests. It enforces the per-binding connection cap and picks the idle
// connections to close when a binding or the whole proxy is over its limit.
type connTracker struct {
	max int // per binding; <= 0 disables the cap

	mu        sync.Mutex
	idle      map[*limitConn]struct{}
	byBinding map[string]map[*limitConn]struct{}
}

func newConnTracker(maxPerBinding int) *connTracker {
	return &connTracker{
		max:       maxPerBinding,
		idle:      map[*limitConn]struct{}{},
		byBinding: map[string]map[*limitConn]struct{}{},
	}
}

// claim attributes c to binding. Over the binding's cap its longest-idle
// connections are closed; when none is idle, claim fails and c stays
// unattributed. It returns the binding's connection count.
func (t *connTracker) claim(c *limitConn, binding string) (int, bool) {
	t.mu.Lock()
	if c.closed || c.binding == binding {
		n := len(t.byBinding[binding])
		t.mu.Unlock()
		return n, true
	}
	t.detachLocked(c)
	set := t.byBinding[binding]
	if set == nil {
		set = map[*limitConn]struct{}{}
		t.byBinding[binding] = set
	}
	set[c] = struct{}{}
	c.binding = binding
	var victims []*limitConn
	if t.max > 0 && len(set) > t.max {
		idle := make([]*limitConn, 0, len(set))
		for o := range set {
			if !o.idleSince.IsZero() {
				idle = append(idle, o)
			}
		}
		slices.SortFunc(idle, func(a, b *limitConn) int { return a.idleSince.Compare(b.idleSince) })
		for _, o := range idle {
			if len(set) <= t.max {
				break
			}
			t.detachLocked(o)
			victims = append(victims, o)
		}
	}
	ok := t.max <= 0 || len(set) <= t.max
	if !ok {
		t.detachLocked(c)
	}
	n := len(t.byBinding[binding])
	t.mu.Unlock()
	for _, o := range victims {
		_ = o.Close()
	}
	return n, ok
}

// setIdle records c going idle between requests, or carrying one again. It
// reports that c should be closed now: a connection no request was admitted
// on has no business waiting for more.
func (t *connTracker) setIdle(c *limitConn, idle bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c.closed {
		return false
	}
	if !idle {
		c.idleSince = time.Time{}
		delete(t.idle, c)
		return false
	}
	if c.binding == "" {
		return true
	}
	c.idleSince = time.Now()
	t.idle[c] = struct{}{}
	return false
}

// reclaimIdle closes the connection that has been idle longest and reports
// whether there was one.
func (t *connTracker) reclaimIdle() bool {
	t.mu.Lock()
	var oldest *limitConn
	for c := range t.idle {
		if oldest == nil || c.idleSince.Before(oldest.idleSince) {
			oldest = c
		}
	}
	if oldest != nil {
		t.detachLocked(oldest)
	}
	t.mu.Unlock()
	if oldest == nil {
		return false
	}
	_ = oldest.Close()
	return true
}

func (t *connTracker) forget(c *limitConn) {
	t.mu.Lock()
	t.detachLocked(c)
	c.closed = true
	t.mu.Unlock()
}

// detachLocked drops c from its binding and from the idle set.
func (t *connTracker) detachLocked(c *limitConn) {
	if set := t.byBinding[c.binding]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(t.byBinding, c.binding)
		}
	}
	c.binding = ""
	c.idleSince = time.Time{}
	delete(t.idle, c)
}

// connState follows the HTTP server's view of each client connection.
func (p *Proxy) connState(c net.Conn, state http.ConnState) {
	lc, ok := c.(*limitConn)
	if !ok {
		return
	}
	switch state {
	case http.StateIdle:
		if p.conns.setIdle(lc, true) {
			_ = lc.Close()
		}
	case http.StateActive, http.StateHijacked:
		p.conns.setIdle(lc, false)
	}
}

// claimConn attributes the connection r arrived on to pr's binding,
// enforcing MaxConnsPerBinding. It returns a refusal reason when the
// binding already has too many connections and none of them is idle.
func (p *Proxy) claimConn(r *http.Request, pr Principal) (string, bool) {
	lc, _ := r.Context().Value(connKey{}).(*limitConn)
	if lc == nil {
		return "", true
	}
	if n, ok := p.conns.claim(lc, pr.BindingID); !ok {
		return fmt.Sprintf("This sandbox already has %d connections open to the egress proxy.", n), false
	}
	return "", true
}

func withConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}
