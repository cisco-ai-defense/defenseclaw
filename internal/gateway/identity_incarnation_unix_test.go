// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review loop 3, finding 2: a macOS account's local node record names its
// incarnation by a digest that has no control bytes (the listed record
// joins its fields with NUL) and differs for every other record.
func TestAccountRecordTokenNamesTheRecord(t *testing.T) {
	if got := accountRecordToken(""); got != "" {
		t.Fatalf("no record: %q; want none", got)
	}
	a, b := accountRecordToken("501\x00GUID-A\x00/Users/alice\x0020"), accountRecordToken("501\x00GUID-B\x00/Users/alice\x0020")
	if a == "" || a == b || !strings.HasPrefix(a, "record:") || !validAccountToken(a) {
		t.Fatalf("record tokens %q and %q; want two valid, distinct record: tokens", a, b)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: "501", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{AccountRecord: a}}, false)
	if subject.accountToken != a {
		t.Fatalf("subject token %q; want the record's %q", subject.accountToken, a)
	}
}
