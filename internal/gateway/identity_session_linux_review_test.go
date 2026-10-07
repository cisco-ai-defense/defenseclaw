// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"encoding/binary"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"net"
	"os"
	"path/filepath"
	"testing"
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
	old := utmpSessionPath
	utmpSessionPath = path
	t.Cleanup(func() { utmpSessionPath = old })
	claim := useridentity.SessionFacts{TTY: "pts/1"}
	writeReviewUtmp(t, path, "first.example", net.ParseIP("192.0.2.10"))
	first, ok := verifyPeerSession(1001, "alice", claim)
	if !ok || first.ClientAddr != "192.0.2.10" {
		t.Fatalf("first session = %+v, verified %v", first, ok)
	}
	writeReviewUtmp(t, path, "second.example", net.ParseIP("192.0.2.11"))
	second, ok := verifyPeerSession(1001, "alice", claim)
	if !ok || second.ClientAddr != "192.0.2.11" {
		t.Fatalf("reused tty session = %+v, verified %v", second, ok)
	}
}
