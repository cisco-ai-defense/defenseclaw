// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"path/filepath"
	"testing"
)

func TestUtmpHostWithoutAddressDoesNotVerifySSH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "utmp")
	writeReviewUtmp(t, path, "203.0.113.9", nil)
	oldSID := utmpSessionID
	utmpSessionID = func(int) (int, error) { return 77, nil }
	t.Cleanup(func() { utmpSessionID = oldSID })
	facts, err := utmpSessionFactsFrom(path, "pts/1", "alice", 4201)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Kind == useridentity.SessionSSH || facts.ClientAddr != "" || facts.Assurance == useridentity.AssuranceVerified {
		t.Fatalf("host-only utmp was verified: %+v", facts)
	}
	old := utmpSessionPath
	utmpSessionPath = path
	t.Cleanup(func() { utmpSessionPath = old })
	if verified, ok := verifyPeerSession(1001, 0, "alice", useridentity.SessionFacts{TTY: "pts/1"}); ok {
		t.Fatalf("host-only utmp reached verified session context: %+v", verified)
	}
}
