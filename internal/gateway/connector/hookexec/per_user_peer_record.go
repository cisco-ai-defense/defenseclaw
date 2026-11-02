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
// agent cannot write it. Read in the background from the moment the
// connection's owner is proven, while the connection is open.
type PerUserPeerRecord struct {
	once      sync.Once
	connected chan struct{}
	done      chan struct{}
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

// capture starts the read of the connected peer once.
func (r *PerUserPeerRecord) capture(local, remote net.Addr) {
	if r == nil {
		return
	}
	r.once.Do(func() {
		close(r.connected)
		client, okc := local.(*net.TCPAddr)
		server, oks := remote.(*net.TCPAddr)
		go func() {
			defer close(r.done)
			if !okc || !oks {
				return
			}
			pid, ok := perUserConnectedPeerPID(client, server)
			if !ok || pid <= 0 {
				return
			}
			identity, ok := procidentity.Of(pid)
			if !ok || identity == "" {
				return
			}
			r.peer, r.ok = perUserPeerProcess{pid: pid, identity: identity, server: server}, true
		}()
	})
}

// wait returns the peer once its read is done, false when it is unknown or
// the read did not end within wait.
func (r *PerUserPeerRecord) wait(wait time.Duration) (perUserPeerProcess, bool) {
	if r == nil || r.done == nil {
		return perUserPeerProcess{}, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-r.done:
		return r.peer, r.ok
	case <-timer.C:
		return perUserPeerProcess{}, false
	}
}
