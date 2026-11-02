// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserPeerReadWait bounds the wait, at the deadline, for the read of the
// connected peer's process that started when the call connected.
var perUserPeerReadWait = 500 * time.Millisecond

// perUserPeerProcess is the process that owns the server end of a connected
// per-user gateway socket, and the gateway address it listens on.
type perUserPeerProcess struct {
	pid      int
	identity string
	server   *net.TCPAddr
}

// PerUserPeerRecord holds the process that owned the server end of the
// first connection a per-user request was sent on (`hook-post`). The kernel
// says which process holds that socket (Linux /proc, macOS lsof), so an
// agent cannot write it.
//
// Only a restart proof reads the record, and a proof needs a start of this
// account's gateway seen during the call or held at its deadline. So the
// read starts on demand, while the connection is still open: when hook-post
// first sees the start lock held after the call connected (Read), or when
// the proof waits for it. A call answered without a start reads nothing.
// The read walks every process of the account (Linux) or runs lsof (macOS);
// done on every call it was about a tenth of a 32-way hook burst's CPU and
// set its p95 (rel-1-0-6 GAP-0381). The holders of an open accepted socket
// change only when a holder closes it or hands a copy to another process;
// the gateway does neither while it serves the call, so the process read on
// demand is the process read at connect, and two holders stay no known peer.
type PerUserPeerRecord struct {
	once      sync.Once
	readOnce  sync.Once
	connected chan struct{}
	done      chan struct{}
	client    net.Addr
	server    net.Addr
	peer      perUserPeerProcess
	ok        bool
}

// NewPerUserPeerRecord returns an empty record for one request.
func NewPerUserPeerRecord() *PerUserPeerRecord {
	return &PerUserPeerRecord{connected: make(chan struct{}), done: make(chan struct{})}
}

// Connected closes when the transport has verified the socket that carries
// this request. A caller can observe a gateway restart only from that point
// onward, rather than from before the call was sent.
func (r *PerUserPeerRecord) Connected() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.connected
}

type perUserPeerRecordKey struct{}

// WithPerUserPeerRecord asks the per-user transport to read, into record,
// the process behind the first connection it proves.
func WithPerUserPeerRecord(ctx context.Context, record *PerUserPeerRecord) context.Context {
	if record == nil {
		return ctx
	}
	return context.WithValue(ctx, perUserPeerRecordKey{}, record)
}

// capture records the endpoints of the first proven connection, once. The
// process behind it is read only when Read or wait asks for it.
func (r *PerUserPeerRecord) capture(local, remote net.Addr) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.client, r.server = local, remote
		close(r.connected)
	})
}

// perUserConnectedPeerRead is the read of the process behind a connection
// (a seam for the on-demand test).
var perUserConnectedPeerRead = func(local, remote net.Addr) (perUserPeerProcess, bool) {
	client, okc := local.(*net.TCPAddr)
	server, oks := remote.(*net.TCPAddr)
	if !okc || !oks {
		return perUserPeerProcess{}, false
	}
	pid, ok := perUserConnectedPeerPID(client, server)
	if !ok || pid <= 0 {
		return perUserPeerProcess{}, false
	}
	identity, ok := procidentity.Of(pid)
	if !ok || identity == "" {
		return perUserPeerProcess{}, false
	}
	return perUserPeerProcess{pid: pid, identity: identity, server: server}, true
}

// Read starts, once, the background read of the process behind the
// connection the request was sent on. Before the request connected it does
// nothing: there is no connection to read yet.
func (r *PerUserPeerRecord) Read() {
	if r == nil || r.connected == nil {
		return
	}
	select {
	case <-r.connected:
	default:
		return
	}
	r.readOnce.Do(func() {
		go func() {
			defer close(r.done)
			r.peer, r.ok = perUserConnectedPeerRead(r.client, r.server)
		}()
	})
}

// wait starts the read (Read) and returns the peer once it is done, false
// when it is unknown or the read did not end within wait.
func (r *PerUserPeerRecord) wait(wait time.Duration) (perUserPeerProcess, bool) {
	if r == nil || r.done == nil {
		return perUserPeerProcess{}, false
	}
	r.Read()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-r.done:
		return r.peer, r.ok
	case <-timer.C:
		return perUserPeerProcess{}, false
	}
}
