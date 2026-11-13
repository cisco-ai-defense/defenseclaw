// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"net"
	"strings"
	"testing"
)

type fakePeerProcess struct {
	created uint64
	sid     string
	session uint32
	closed  *int
}

func (p fakePeerProcess) CreationTime() (uint64, error) { return p.created, nil }
func (p fakePeerProcess) Identity() (PeerIdentity, error) {
	return PeerIdentity{SID: p.sid, SessionID: p.session}, nil
}
func (p fakePeerProcess) Close() { *p.closed++ }

const (
	testGatewayPID  = uint32(900)
	testClientPID   = uint32(4242)
	testConnCreated = uint64(133_000_000_000_000_000)
)

var (
	testLo     = net.ParseIP("127.0.0.1")
	testServer = &net.TCPAddr{IP: testLo, Port: 18970}
	testClient = &net.TCPAddr{IP: testLo, Port: 51234}
	testRow    = tcpOwnerRow{State: mibTCPStateEstab, LocalIP: testLo, LocalPort: 51234, RemoteIP: testLo, RemotePort: 18970, PID: testClientPID, CreateTime: testConnCreated}
	testSrvRow = tcpOwnerRow{State: mibTCPStateEstab, LocalIP: testLo, LocalPort: 18970, RemoteIP: testLo, RemotePort: 51234, PID: testGatewayPID, CreateTime: testConnCreated}
)

// TestOwnerLookupVerifyRefusesAReusedPID: the table names the PID of the
// process that created the socket even after it exited; a process that got
// that PID later (another account) must not be taken as the caller
// (REVIEW-code-slice4 P1-1). The broker also answers only for the PID and
// creation time the request names and for connections its caller accepted.
func TestOwnerLookupVerifyRefusesAReusedPID(t *testing.T) {
	want := TCPConnOwner{PID: testClientPID, CreateTime: testConnCreated}
	cases := []struct {
		name        string
		first       []tcpOwnerRow
		second      []tcpOwnerRow
		created     uint64
		serverPID   uint32
		want        TCPConnOwner
		wantSID     string
		wantErr     error
		wantErrText string
	}{
		{name: "process started before the connection", created: testConnCreated - 10_000_000, wantSID: "S-1-5-21-1-2-3-1001"},
		{name: "process started in the same tick", created: testConnCreated, wantSID: "S-1-5-21-1-2-3-1001"},
		{name: "process started after the connection is a reused PID", created: testConnCreated + 1, wantErrText: "PID was reused"},
		{name: "no process creation time", created: 0, wantErrText: "no creation time"},
		{name: "request names no creation time", created: 1, want: TCPConnOwner{PID: testClientPID}, wantErr: ErrOwnerChanged},
		{name: "request names another PID", created: 1, want: TCPConnOwner{PID: 5151, CreateTime: testConnCreated}, wantErr: ErrOwnerChanged},
		{name: "request names another creation time", created: 1, want: TCPConnOwner{PID: testClientPID, CreateTime: testConnCreated - 5}, wantErr: ErrOwnerChanged},
		{name: "caller did not accept the connection", created: 1, serverPID: 777, wantErr: ErrNotAccepted},
		{name: "no server row", created: 1, first: []tcpOwnerRow{testRow}, wantErr: ErrPeerNotFound},
		{name: "owner changed between the reads", created: testConnCreated - 1, second: []tcpOwnerRow{testSrvRow, func() tcpOwnerRow { r := testRow; r.PID = 5151; return r }()}, wantErrText: "changed owner"},
		{name: "connection replaced between the reads", created: testConnCreated - 1, second: []tcpOwnerRow{testSrvRow, func() tcpOwnerRow { r := testRow; r.CreateTime = testConnCreated + 99; return r }()}, wantErrText: "changed owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reads, closed := 0, 0
			var opened uint32
			first := tc.first
			if first == nil {
				first = []tcpOwnerRow{testSrvRow, testRow}
			}
			l := ownerSIDLookup{
				rows: func() ([]tcpOwnerRow, error) {
					reads++
					if reads > 1 && tc.second != nil {
						return tc.second, nil
					}
					return first, nil
				},
				open: func(pid uint32) (peerProcess, error) {
					opened = pid
					return fakePeerProcess{created: tc.created, sid: "S-1-5-21-1-2-3-1001", session: 2, closed: &closed}, nil
				},
			}
			serverPID := tc.serverPID
			if serverPID == 0 {
				serverPID = testGatewayPID
			}
			w := tc.want
			if w == (TCPConnOwner{}) {
				w = want
			}
			got, err := l.verify(testServer, testClient, serverPID, w)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) || got.SID != "" {
					t.Fatalf("verify = %+v, %v; want %v", got, err, tc.wantErr)
				}
			case tc.wantErrText != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrText) || got.SID != "" {
					t.Fatalf("verify = %+v, %v; want an error naming %q", got, err, tc.wantErrText)
				}
			default:
				if err != nil || got.SID != tc.wantSID || got.SessionID != 2 {
					t.Fatalf("verify = %+v, %v; want %q in session 2", got, err, tc.wantSID)
				}
			}
			if opened != 0 && closed != 1 {
				t.Fatalf("the opened process was closed %d times", closed)
			}
			if (tc.wantErr != nil) && opened != 0 {
				t.Fatalf("process %d was opened for a refused request", opened)
			}
		})
	}
}

func TestOwnerLookupVerifyOpenFailureIsUnverified(t *testing.T) {
	denied := errors.New("access denied")
	l := ownerSIDLookup{
		rows: func() ([]tcpOwnerRow, error) { return []tcpOwnerRow{testSrvRow, testRow}, nil },
		open: func(uint32) (peerProcess, error) { return nil, denied },
	}
	if got, err := l.verify(testServer, testClient, testGatewayPID, TCPConnOwner{PID: testClientPID, CreateTime: testConnCreated}); !errors.Is(err, denied) || got.SID != "" {
		t.Fatalf("verify = %+v, %v; want the open error", got, err)
	}
}

func TestOwnerLookupClientOwner(t *testing.T) {
	l := ownerSIDLookup{rows: func() ([]tcpOwnerRow, error) { return []tcpOwnerRow{testSrvRow, testRow}, nil }}
	got, err := l.clientOwner(testServer, testClient)
	if err != nil || got != (TCPConnOwner{PID: testClientPID, CreateTime: testConnCreated}) {
		t.Fatalf("clientOwner = %+v, %v", got, err)
	}
	noTime := testRow
	noTime.CreateTime = 0
	l.rows = func() ([]tcpOwnerRow, error) { return []tcpOwnerRow{noTime}, nil }
	if _, err := l.clientOwner(testServer, testClient); err == nil {
		t.Fatal("a row without a creation time was accepted")
	}
	l.rows = func() ([]tcpOwnerRow, error) { return nil, nil }
	if _, err := l.clientOwner(testServer, testClient); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("clientOwner on an empty table = %v; want ErrPeerNotFound", err)
	}
}

func TestLoopbackTCPPeerFunctionsRefuseNonLoopback(t *testing.T) {
	ext := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	if _, err := LoopbackTCPClientOwner(testServer, ext); err == nil {
		t.Fatal("LoopbackTCPClientOwner accepted a non-loopback client")
	}
	if _, err := VerifyLoopbackTCPPeer(ext, testClient, 1, TCPConnOwner{PID: 1, CreateTime: 1}); err == nil {
		t.Fatal("VerifyLoopbackTCPPeer accepted a non-loopback server address")
	}
}
