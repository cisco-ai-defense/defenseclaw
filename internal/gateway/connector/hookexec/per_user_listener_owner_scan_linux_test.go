// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A try with a connect deadline reads the owner of a connection that sat in
// the accept queue shortly before the deadline. A slow read (the record
// lookup of a busy host) is not cut by the deadline: the own frozen gateway
// of the account stays an outage and is not blamed on another process. A
// lookup that outlasts the grace has shown neither the own gateway nor another
// process, and nothing was sent: it is the same outage, and the outage mode of
// the account decides (errPerUserOwnerScanUnfinished).
func TestSlowOwnerReadOfTheOwnFrozenGatewayStaysAnOutage(t *testing.T) {
	addr := frozenListener(t)
	dataDir := recordGateway(t, os.Getpid(), nil)
	for _, tc := range []struct {
		name      string
		lookup    time.Duration
		firstRead bool // the first read of the record finds nothing
	}{
		{"prompt lookup", 0, false},
		{"first read finds no record", 0, true},
		{"lookup past the connect deadline", 1200 * time.Millisecond, false},
		{"lookup that outlasts the grace", ownerScanGrace + 600*time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads atomic.Int32
			homes := func() []string {
				time.Sleep(tc.lookup)
				if tc.firstRead && reads.Add(1) == 1 {
					return nil
				}
				return []string{dataDir}
			}
			tryCtx, release := connectBy(withPerUserGatewayHomes(context.Background(), homes), time.Now().Add(perUserConnectedWait), nil)
			defer release()
			_, err := PostPerUserHook(tryCtx, addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err == nil {
				t.Fatal("a frozen listener answered")
			}
			if !PerUserPostListenerUnanswered(err) || PerUserPostPeerUnverified(err) {
				t.Fatalf("an unanswered own listener was not an outage: %v", err)
			}
		})
	}
}

// A gateway that accepts the queued connection before the connect budget ends
// answers the call: the owner of the queue is not decided early, so its own
// answer (here a policy block) is the one the hook gets.
func TestGatewayAcceptingBeforeTheConnectBudgetEndsKeepsItsAnswer(t *testing.T) {
	for _, accept := range []time.Duration{500 * time.Millisecond, 2200 * time.Millisecond, 2450 * time.Millisecond} {
		t.Run(accept.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				time.Sleep(accept)
				_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"action":"block","raw_action":"block"}`))
				}))
			}()
			dataDir := recordGateway(t, os.Getpid(), nil)
			tryCtx, release := connectBy(WithPerUserGatewayDataDir(context.Background(), dataDir), time.Now().Add(perUserConnectedWait), nil)
			defer release()
			reply, err := PostPerUserHook(tryCtx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err != nil {
				t.Fatalf("a gateway that accepted after %s was treated as an outage: %v", accept, err)
			}
			if reply.Status != http.StatusOK || !strings.Contains(reply.Body, `"block"`) {
				t.Fatalf("the gateway answer was not kept: status=%d body=%q", reply.Status, reply.Body)
			}
		})
	}
}

// The first read of the record folder finds nothing, so the owner of the
// queued connection is read again, and the gateway accepts the connection
// while that read runs (still inside the connect budget). The listener is the
// own gateway, but the connection was accepted: its policy block is the
// answer, not an outage.
func TestGatewayAcceptingDuringTheOwnerReadKeepsItsAnswer(t *testing.T) {
	for _, accept := range []time.Duration{2800 * time.Millisecond, 2950 * time.Millisecond} {
		t.Run(accept.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			dataDir := recordGateway(t, os.Getpid(), nil)
			var handled atomic.Int32
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handled.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"block","raw_action":"block"}`))
			})}
			t.Cleanup(func() { _ = server.Close() })
			go func() {
				time.Sleep(accept)
				_ = server.Serve(listener)
			}()
			var reads atomic.Int32
			ctx := withPerUserGatewayHomes(context.Background(), func() []string {
				if reads.Add(1) == 1 {
					time.Sleep(300 * time.Millisecond)
					return nil
				}
				return []string{dataDir}
			})
			tryCtx, release := connectBy(ctx, time.Now().Add(perUserConnectedWait), nil)
			defer release()
			reply, err := PostPerUserHook(tryCtx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err != nil || reply.Status != http.StatusOK || !strings.Contains(reply.Body, `"block"`) || handled.Load() != 1 {
				t.Fatalf("the gateway answer was lost to the owner read: reads=%d handled=%d status=%d body=%q err=%v", reads.Load(), handled.Load(), reply.Status, reply.Body, err)
			}
		})
	}
}

// acceptWatchListener tells when the gateway has taken a connection.
type acceptWatchListener struct {
	net.Listener
	accepted   atomic.Int32
	acceptedCh chan struct{}
}

func (l *acceptWatchListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil && l.accepted.Add(1) == 1 {
		close(l.acceptedCh)
	}
	return conn, err
}

// The own gateway accepts the connection, and the peer check of that
// connection is still running (a busy procfs read) when the owner of the
// listener is found: the listener is the own gateway, but this connection was
// accepted. Its policy block is the answer, not an outage, however long the
// peer check takes inside the connect budget.
func TestGatewayAcceptedWhileThePeerCheckRunsKeepsItsAnswer(t *testing.T) {
	for _, peerDelay := range []time.Duration{50 * time.Millisecond, 300 * time.Millisecond} {
		t.Run(peerDelay.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			watched := &acceptWatchListener{Listener: listener, acceptedCh: make(chan struct{})}
			dataDir := recordGateway(t, os.Getpid(), nil)
			var handled atomic.Int32
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handled.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"action":"block","raw_action":"block"}`))
			})}
			t.Cleanup(func() { _ = server.Close() })
			go func() {
				time.Sleep(2600 * time.Millisecond)
				_ = server.Serve(watched)
			}()
			finished := make(chan struct{})
			previous := perUserConnectedPeer
			perUserConnectedPeer = func(client, peer *net.TCPAddr) error {
				defer close(finished)
				<-watched.acceptedCh
				time.Sleep(peerDelay)
				return previous(client, peer)
			}
			t.Cleanup(func() {
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
				}
				perUserConnectedPeer = previous
			})
			var reads atomic.Int32
			ctx := withPerUserGatewayHomes(context.Background(), func() []string {
				if reads.Add(1) == 1 {
					// The first read finds nothing and ends after the accept,
					// so the owner of the queue is read again.
					select {
					case <-watched.acceptedCh:
					case <-time.After(2 * time.Second):
					}
					return nil
				}
				return []string{dataDir}
			})
			tryCtx, release := connectBy(ctx, time.Now().Add(perUserConnectedWait), nil)
			defer release()
			reply, err := PostPerUserHook(tryCtx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err != nil || reply.Status != http.StatusOK || !strings.Contains(reply.Body, `"block"`) || handled.Load() != 1 {
				t.Fatalf("the accepted gateway answer was lost to the owner read: reads=%d accepted=%d handled=%d status=%d body=%q err=%v",
					reads.Load(), watched.accepted.Load(), handled.Load(), reply.Status, reply.Body, err)
			}
		})
	}
}

// The socket table lists a connection as queued only while the gateway has
// not accepted it.
func TestConnectionStillQueuedEndsWithTheAccept(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if !connectionStillQueued(conn) {
		t.Fatal("a connection nobody accepted was not listed as queued")
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	deadline := time.Now().Add(2 * time.Second)
	for connectionStillQueued(conn) {
		if time.Now().After(deadline) {
			t.Fatal("an accepted connection stayed listed as queued")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if connectionStillQueued(&net.TCPConn{}) {
		t.Fatal("a connection without endpoints was listed as queued")
	}
}
