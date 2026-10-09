// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func writeReviewUtmp(t *testing.T, path, host string, addr net.IP) {
	t.Helper()
	rec := make([]byte, utmpRecordSize)
	binary.NativeEndian.PutUint16(rec[0:2], utmpUserProcess)
	binary.NativeEndian.PutUint32(rec[4:8], 4200)
	copy(rec[utmpLineOffset:], "pts/1")
	copy(rec[utmpUserOffset:], "alice")
	copy(rec[utmpHostOffset:], host)
	if addr != nil {
		copy(rec[utmpAddrOffset:], addr.To4())
	}
	if err := os.WriteFile(path, rec, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReusedTTYReadsCurrentUtmpRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "utmp")
	old, oldSID := utmpSessionPath, utmpSessionID
	utmpSessionPath = path
	utmpSessionID = func(int) (int, error) { return 77, nil }
	t.Cleanup(func() { utmpSessionPath, utmpSessionID = old, oldSID })
	claim := useridentity.SessionFacts{TTY: "pts/1"}
	writeReviewUtmp(t, path, "first.example", net.ParseIP("192.0.2.10"))
	first, ok := verifyPeerSession(1001, 4201, "alice", claim)
	if !ok || first.ClientAddr != "192.0.2.10" {
		t.Fatalf("first session = %+v, verified %v", first, ok)
	}
	writeReviewUtmp(t, path, "second.example", net.ParseIP("192.0.2.11"))
	second, ok := verifyPeerSession(1001, 4201, "alice", claim)
	if !ok || second.ClientAddr != "192.0.2.11" {
		t.Fatalf("reused tty session = %+v, verified %v", second, ok)
	}
}

// A session owned by the same UID is not the peer process's session.
func TestLogindClaimMustMatchPeerPID(t *testing.T) {
	old := logindSessionLookup
	logindSessionLookup = func(uid, pid int, id string) (useridentity.SessionFacts, error) {
		if uid != 1001 || pid != 4200 || id != "other-session" {
			t.Fatalf("lookup received uid=%d pid=%d id=%q", uid, pid, id)
		}
		return useridentity.SessionFacts{}, errSessionNotOwned
	}
	t.Cleanup(func() { logindSessionLookup = old })
	if facts, ok := verifyPeerSession(1001, 4200, "alice", useridentity.SessionFacts{LogindSession: "other-session"}); ok {
		t.Fatalf("another session was verified: %+v", facts)
	}
}

// A successful lookup cannot attest a session that logind has since removed.
func TestEndedLogindSessionIsRechecked(t *testing.T) {
	old := logindSessionLookup
	calls := 0
	logindSessionLookup = func(int, int, string) (useridentity.SessionFacts, error) {
		calls++
		if calls == 1 {
			return useridentity.SessionFacts{LogindSession: "ssh-1", ClientAddr: "192.0.2.10", Assurance: useridentity.AssuranceVerified}, nil
		}
		return useridentity.SessionFacts{}, errSessionMissing
	}
	t.Cleanup(func() { logindSessionLookup = old })
	claim := useridentity.SessionFacts{LogindSession: "ssh-1"}
	if _, ok := verifyPeerSession(1001, 4200, "alice", claim); !ok {
		t.Fatal("active session was not verified")
	}
	if facts, ok := verifyPeerSession(1001, 4200, "alice", claim); ok || calls != 2 {
		t.Fatalf("ended session remained verified: %+v, calls=%d", facts, calls)
	}
}

// A temporary logind outage still permits a current utmp login on the TTY.
func TestLogindFailureFallsBackToUtmp(t *testing.T) {
	old := logindSessionLookup
	logindSessionLookup = func(int, int, string) (useridentity.SessionFacts, error) {
		return useridentity.SessionFacts{}, errors.New("bus unavailable")
	}
	t.Cleanup(func() { logindSessionLookup = old })
	path := filepath.Join(t.TempDir(), "utmp")
	oldPath, oldSID := utmpSessionPath, utmpSessionID
	utmpSessionPath = path
	utmpSessionID = func(int) (int, error) { return 77, nil }
	t.Cleanup(func() { utmpSessionPath, utmpSessionID = oldPath, oldSID })
	writeReviewUtmp(t, path, "ssh.example", net.ParseIP("192.0.2.21"))
	facts, ok := verifyPeerSession(1001, 4200, "alice", useridentity.SessionFacts{LogindSession: "ssh-1", TTY: "pts/1"})
	if !ok || facts.ClientAddr != "192.0.2.21" || facts.LogindSession != "" {
		t.Fatalf("utmp fallback = %+v, verified %v", facts, ok)
	}
}

// A same-account peer in another kernel session cannot borrow the login TTY.
func TestUtmpFallbackRequiresPeerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "utmp")
	oldPath, oldLookup, oldSID := utmpSessionPath, logindSessionLookup, utmpSessionID
	utmpSessionPath = path
	utmpSessionID = func(pid int) (int, error) { return pid, nil }
	logindSessionLookup = func(int, int, string) (useridentity.SessionFacts, error) {
		return useridentity.SessionFacts{}, errors.New("bus unavailable")
	}
	t.Cleanup(func() { utmpSessionPath, logindSessionLookup, utmpSessionID = oldPath, oldLookup, oldSID })
	writeReviewUtmp(t, path, "ssh.example", net.ParseIP("192.0.2.21"))
	claim := useridentity.SessionFacts{LogindSession: "ssh-1", TTY: "pts/1"}
	if facts, ok := verifyPeerSession(1001, 4201, "alice", claim); ok {
		t.Fatalf("another login session was verified: %+v", facts)
	}
	if facts, ok := verifyPeerSession(1001, 0, "alice", claim); ok {
		t.Fatalf("peer without a verified PID was verified: %+v", facts)
	}
}
