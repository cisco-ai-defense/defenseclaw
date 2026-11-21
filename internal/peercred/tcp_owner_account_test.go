// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"strings"
	"testing"
)

// TestOwnerLookupAccountRefusesAReusedPID: the Secure Client caller account
// lookup (LoopbackTCPPeerAccount on Windows) applies the peer broker's
// PID-reuse rule (GAP-1131). The table keeps the PID of the process that
// created the client socket after it exits; a process that got the PID later
// (another account) must not be named, and an owner that changes between the
// table reads is refused.
func TestOwnerLookupAccountRefusesAReusedPID(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	otherPID := func() tcpOwnerRow { r := testRow; r.PID = 5151; return r }()
	replaced := func() tcpOwnerRow { r := testRow; r.CreateTime = testConnCreated + 99; return r }()
	noTime := func() tcpOwnerRow { r := testRow; r.CreateTime = 0; return r }()
	cases := []struct {
		name        string
		first       []tcpOwnerRow
		second      []tcpOwnerRow
		created     uint64
		wantSID     string
		wantErr     error
		wantErrText string
		wantOpen    bool
	}{
		{name: "process started before the connection", created: testConnCreated - 10_000_000, wantSID: sid, wantOpen: true},
		{name: "process started in the same tick", created: testConnCreated, wantSID: sid, wantOpen: true},
		{name: "the server end is this process and is not checked", first: []tcpOwnerRow{testRow}, created: testConnCreated - 1, wantSID: sid, wantOpen: true},
		{name: "process started after the connection is a reused PID", created: testConnCreated + 1, wantErrText: "PID was reused", wantOpen: true},
		{name: "no process creation time", created: 0, wantErrText: "no creation time", wantOpen: true},
		{name: "row without a creation time", first: []tcpOwnerRow{testSrvRow, noTime}, created: 1, wantErrText: "no creation time"},
		{name: "no client row", first: []tcpOwnerRow{testSrvRow}, created: 1, wantErr: ErrPeerNotFound},
		{name: "owner changed between the reads", created: testConnCreated - 1, second: []tcpOwnerRow{testSrvRow, otherPID}, wantErrText: "changed owner", wantOpen: true},
		{name: "connection replaced between the reads", created: testConnCreated - 1, second: []tcpOwnerRow{testSrvRow, replaced}, wantErrText: "changed owner", wantOpen: true},
		{name: "connection gone at the second read", created: testConnCreated - 1, second: []tcpOwnerRow{testSrvRow}, wantErr: ErrPeerNotFound, wantOpen: true},
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
					return fakePeerProcess{created: tc.created, sid: sid, closed: &closed}, nil
				},
			}
			got, err := l.account(testServer, testClient)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) || got.SID != "" {
					t.Fatalf("account = %+v, %v; want %v", got, err, tc.wantErr)
				}
			case tc.wantErrText != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrText) || got.SID != "" {
					t.Fatalf("account = %+v, %v; want an error naming %q", got, err, tc.wantErrText)
				}
			default:
				if err != nil || got.SID != tc.wantSID {
					t.Fatalf("account = %+v, %v; want %q", got, err, tc.wantSID)
				}
				if reads != 2 {
					t.Fatalf("the table was read %d times; want 2 (before and after the process read)", reads)
				}
			}
			if tc.wantOpen != (opened != 0) {
				t.Fatalf("opened PID %d; want opened=%v", opened, tc.wantOpen)
			}
			if opened != 0 && (opened != testClientPID || closed != 1) {
				t.Fatalf("opened PID %d closed %d times; want PID %d closed once", opened, closed, testClientPID)
			}
		})
	}
}

func TestOwnerLookupAccountOpenFailureIsUnverified(t *testing.T) {
	denied := errors.New("access denied")
	l := ownerSIDLookup{
		rows: func() ([]tcpOwnerRow, error) { return []tcpOwnerRow{testSrvRow, testRow}, nil },
		open: func(uint32) (peerProcess, error) { return nil, denied },
	}
	if got, err := l.account(testServer, testClient); !errors.Is(err, denied) || got.SID != "" {
		t.Fatalf("account = %+v, %v; want the open error", got, err)
	}
}
