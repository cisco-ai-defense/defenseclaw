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
	closed  *int
}

func (p fakePeerProcess) CreationTime() (uint64, error) { return p.created, nil }
func (p fakePeerProcess) UserSID() (string, error)      { return p.sid, nil }
func (p fakePeerProcess) Close()                        { *p.closed++ }

// TestOwnerSIDLookupRefusesAReusedPID: the table names the PID of the
// process that created the socket even after it exited; a process that got
// that PID later (another account) must not be taken as the caller
// (REVIEW-code-slice4 P1-1).
func TestOwnerSIDLookupRefusesAReusedPID(t *testing.T) {
	lo := net.ParseIP("127.0.0.1")
	server := &net.TCPAddr{IP: lo, Port: 18970}
	client := &net.TCPAddr{IP: lo, Port: 51234}
	const connCreated = uint64(133_000_000_000_000_000)
	row := tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo, LocalPort: 51234, RemoteIP: lo, RemotePort: 18970, PID: 4242, CreateTime: connCreated}

	cases := []struct {
		name        string
		first       tcpOwnerRow
		second      *tcpOwnerRow
		created     uint64
		wantSID     string
		wantErrText string
	}{
		{name: "process started before the connection", first: row, created: connCreated - 10_000_000, wantSID: "S-1-5-21-1-2-3-1001"},
		{name: "process started in the same tick", first: row, created: connCreated, wantSID: "S-1-5-21-1-2-3-1001"},
		{name: "process started after the connection is a reused PID", first: row, created: connCreated + 1, wantErrText: "PID was reused"},
		{name: "no connection creation time", first: func() tcpOwnerRow { r := row; r.CreateTime = 0; return r }(), created: 1, wantErrText: "no creation time"},
		{name: "no process creation time", first: row, created: 0, wantErrText: "no creation time"},
		{name: "owner changed between the reads", first: row, created: connCreated - 1, second: func() *tcpOwnerRow { r := row; r.PID = 5151; return &r }(), wantErrText: "changed owner"},
		{name: "connection replaced between the reads", first: row, created: connCreated - 1, second: func() *tcpOwnerRow { r := row; r.CreateTime = connCreated + 99; return &r }(), wantErrText: "changed owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reads, closed := 0, 0
			var opened uint32
			l := ownerSIDLookup{
				rows: func() ([]tcpOwnerRow, error) {
					reads++
					if reads > 1 && tc.second != nil {
						return []tcpOwnerRow{*tc.second}, nil
					}
					return []tcpOwnerRow{tc.first}, nil
				},
				open: func(pid uint32) (peerProcess, error) {
					opened = pid
					return fakePeerProcess{created: tc.created, sid: "S-1-5-21-1-2-3-1001", closed: &closed}, nil
				},
			}
			sid, err := l.lookup(server, client)
			if tc.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrText) || sid != "" {
					t.Fatalf("lookup = %q, %v; want an error naming %q", sid, err, tc.wantErrText)
				}
			} else if err != nil || sid != tc.wantSID {
				t.Fatalf("lookup = %q, %v; want %q", sid, err, tc.wantSID)
			}
			if opened != 0 && closed != 1 {
				t.Fatalf("the opened process was closed %d times", closed)
			}
		})
	}
}

func TestOwnerSIDLookupOpenFailureIsUnverified(t *testing.T) {
	lo := net.ParseIP("127.0.0.1")
	row := tcpOwnerRow{State: mibTCPStateEstab, LocalIP: lo, LocalPort: 51234, RemoteIP: lo, RemotePort: 18970, PID: 4242, CreateTime: 9}
	denied := errors.New("access denied")
	l := ownerSIDLookup{
		rows: func() ([]tcpOwnerRow, error) { return []tcpOwnerRow{row}, nil },
		open: func(uint32) (peerProcess, error) { return nil, denied },
	}
	if sid, err := l.lookup(&net.TCPAddr{IP: lo, Port: 18970}, &net.TCPAddr{IP: lo, Port: 51234}); !errors.Is(err, denied) || sid != "" {
		t.Fatalf("lookup = %q, %v; want the open error", sid, err)
	}
}
