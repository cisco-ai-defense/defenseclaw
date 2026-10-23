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

// GAP-1254: utmp keeps 32 bytes of the user name, so a longer directory
// name is confirmed by its cut form when the login's session belongs to the
// peer's uid, and only then.
func TestUtmpFallbackConfirmsALongDirectoryName(t *testing.T) {
	const long = "dcad-very-long-account-name-0001@corp.example.com"
	path := filepath.Join(t.TempDir(), "utmp")
	rec := make([]byte, utmpRecordSize)
	binary.NativeEndian.PutUint16(rec[0:2], utmpUserProcess)
	binary.NativeEndian.PutUint32(rec[4:8], 4200)
	copy(rec[utmpLineOffset:], "pts/1")
	copy(rec[utmpUserOffset:utmpUserOffset+utmpUserSize], long)
	copy(rec[utmpAddrOffset:], net.ParseIP("192.0.2.30").To4())
	if err := os.WriteFile(path, rec, 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath, oldSID, oldOwner, oldLookup := utmpSessionPath, utmpSessionID, utmpProcessUID, logindSessionLookup
	utmpSessionPath = path
	utmpSessionID = func(int) (int, error) { return 77, nil }
	owner := 1001
	utmpProcessUID = func(pid int) (int, error) {
		if pid != 77 {
			return -1, errors.New("not the session leader")
		}
		return owner, nil
	}
	logindSessionLookup = func(int, int, string) (useridentity.SessionFacts, error) {
		return useridentity.SessionFacts{}, errors.New("bus unavailable")
	}
	t.Cleanup(func() {
		utmpSessionPath, utmpSessionID, utmpProcessUID, logindSessionLookup = oldPath, oldSID, oldOwner, oldLookup
	})
	claim := useridentity.SessionFacts{TTY: "pts/1"}
	facts, ok := verifyPeerSession(1001, 4201, long, claim)
	if !ok || facts.ClientAddr != "192.0.2.30" {
		t.Fatalf("long name session = %+v, verified %v", facts, ok)
	}
	owner = 1002
	if facts, ok := verifyPeerSession(1001, 4201, long, claim); ok {
		t.Fatalf("a cut name was confirmed for a session another uid leads: %+v", facts)
	}
	owner = 1001
	if facts, ok := verifyPeerSession(1001, 4201, long[:20], claim); ok {
		t.Fatalf("a shorter name matched a full utmp field: %+v", facts)
	}
}
