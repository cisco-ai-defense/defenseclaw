// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// acceptCountListener tells when the gateway has taken a connection.
type acceptCountListener struct {
	net.Listener
	accepted atomic.Int32
	taken    chan struct{}
}

func (l *acceptCountListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil && l.accepted.Add(1) == 1 {
		close(l.taken)
	}
	return conn, err
}

// A gateway of the account accepts the queued connection just before the
// decision point and its peer check returns before the connect deadline, while
// the second read of the record folder (a busy host) is still running and
// outlasts ownerScanGrace. The peer proof is the result: the answer of the
// gateway, an ordinary allow as much as a policy block, is the one the hook
// gets, and the read of the owner does not hide it.
func TestSlowOwnerReadAfterTheAcceptedPeerProofKeepsTheGatewayAnswer(t *testing.T) {
	for _, action := range []string{"allow", "block"} {
		t.Run(action, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			watched := &acceptCountListener{Listener: listener, taken: make(chan struct{})}
			dataDir := recordGateway(t, os.Getpid(), nil)
			var handled atomic.Int32
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handled.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"action":%q,"raw_action":%q}`, action, action)
			})}
			t.Cleanup(func() { _ = server.Close() })
			go func() {
				time.Sleep(2600 * time.Millisecond)
				_ = server.Serve(watched)
			}()

			proved := make(chan struct{})
			previous := perUserConnectedPeer
			perUserConnectedPeer = func(client, peer *net.TCPAddr) error {
				defer close(proved)
				// A busy procfs read before the accepted tuple is checked.
				<-watched.taken
				time.Sleep(300 * time.Millisecond)
				return previous(client, peer)
			}
			t.Cleanup(func() {
				select {
				case <-proved:
				case <-time.After(2 * time.Second):
				}
				perUserConnectedPeer = previous
			})
			var reads atomic.Int32
			ctx := withPerUserGatewayHomes(context.Background(), func() []string {
				if reads.Add(1) == 1 {
					select {
					case <-watched.taken:
					case <-time.After(2 * time.Second):
					}
					return nil
				}
				// The read of the owner starts before the peer proof is
				// back and ends well after the grace.
				<-proved
				time.Sleep(ownerScanGrace + 500*time.Millisecond)
				return []string{dataDir}
			})
			tryCtx, release := connectBy(ctx, time.Now().Add(perUserConnectedWait), nil)
			defer release()
			reply, err := PostPerUserHook(tryCtx, listener.Addr().String(), "/api/v1/claude-code/hook", nil,
				[]byte(`{"tool_name":"Bash","tool_input":{"command":"echo hello"}}`))
			if err != nil || reply.Status != http.StatusOK || !strings.Contains(reply.Body, `"`+action+`"`) ||
				watched.accepted.Load() != 1 || handled.Load() != 1 {
				t.Fatalf("the gateway %s was lost to the owner read: reads=%d accepted=%d handled=%d status=%d body=%q err=%v",
					action, reads.Load(), watched.accepted.Load(), handled.Load(), reply.Status, reply.Body, err)
			}
		})
	}
}

// A try whose queued connection waits for the owner scan past ownerScanGrace
// ends with the outage of an unanswered listener, so the outage mode of the
// account decides the call: the default tiers let an ordinary call and the
// events that name no tool run with the outage warning, the strict tier
// blocks them, and a tool call that names a protected file, or a link to
// one, stays blocked in every tier. Nothing is refused as a foreign peer.
func TestOwnerScanOutlastingTheGraceFollowsTheOutageMode(t *testing.T) {
	err := fmt.Errorf("post: %w", errPerUserOwnerScanUnfinished)
	if !PerUserPostListenerUnanswered(err) || PerUserPostPeerUnverified(err) || PerUserPostOutage(err) || PerUserPostNoAnswer(err) {
		t.Fatalf("an owner scan the grace did not hold is not the unanswered listener: %v", err)
	}
	dataDir := recordGateway(t, os.Getpid(), nil)
	assertListenerOutageModeCells(t, "127.0.0.1:1", dataDir, func(*testing.T) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errPerUserOwnerScanUnfinished
		})}
	})
}
