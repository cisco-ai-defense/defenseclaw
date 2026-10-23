// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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

// GAP-0653: a per-user gateway that is not root cannot show that SSSD holds
// no other account of its uid. Its own account's groups are its kernel
// credentials, so a group assignment decides as for proven groups; only an
// assignment that names an account is refused, naming the account holder.
func TestPerUserGatewayDecidesGroupsFromItsOwnCredentials(t *testing.T) {
	previous := processGroupIDs
	t.Cleanup(func() { processGroupIDs = previous })
	processGroupIDs = func() ([]int, error) { return []int{os.Getgid()}, nil }
	resolver, err := unixidentity.NewNSSResolver(context.Background())
	if err != nil {
		t.Skipf("no NSS resolver: %v", err)
	}
	uid := os.Getuid()
	facts, ok := processCredentialFacts(resolver, uid, time.Now())
	if !ok || !facts.HolderUnproven || len(facts.Groups) != 1 || len(facts.UnconfirmedGroups) != 0 {
		t.Fatalf("facts = %+v, %v; want the gateway's own named group, holder unproven", facts, ok)
	}
	if _, ok := processCredentialFacts(resolver, uid+1, time.Now()); ok {
		t.Fatal("another uid must not get the gateway's own credentials")
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: strconv.Itoa(uid), IDKind: useridentity.KindPOSIXUID,
		UserName: "t7ar-u1", Directory: facts, Source: subjectSourceProcessOwner}, true)
	p := identityTestPlatforms[0]
	byGroup := func(group string) config.ProfileAssignment {
		return config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{group}}}
	}
	if got := identityTestSet(t, p, "watch", byGroup(facts.Groups[0])).match(&subject, profileSubjectProcessOwner, "claudecode", ""); got.Refused != "" || got.Name != "strict" {
		t.Fatalf("member: %+v; want strict, not refused", got)
	}
	if got := identityTestSet(t, p, "watch", byGroup("dc-r104-id-strict")).match(&subject, profileSubjectProcessOwner, "claudecode", ""); got.Refused != "" || got.Name != "watch" {
		t.Fatalf("not a member: %+v; want watch, not refused", got)
	}
	byName := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"t7ar-u1"}}}
	got := identityTestSet(t, p, "watch", byName).match(&subject, profileSubjectProcessOwner, "claudecode", "")
	if !strings.Contains(got.Refused, "account holder is unconfirmed") || !slices.Equal(got.Unproven, []string{"account:unknown"}) {
		t.Fatalf("users entry: %+v; want a refusal naming the account holder only", got)
	}
}
