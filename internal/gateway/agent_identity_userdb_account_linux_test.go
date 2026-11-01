// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// userdbAccountFixture is recreatedAccountFixture with a systemd-userdb
// account ("nss:systemd") behind sss in the passwd line, as on cap-erhel3
// (passwd: files sss systemd): the non-root gateway cannot show that SSSD
// holds no account of the uid, so it names the account's incarnation only
// through the guardian's current identity record of the uid.
func userdbAccountFixture(t *testing.T) *recreatedAccountFixture {
	t.Helper()
	f := newRecreatedAccountFixture(t)
	previousGuardian := managedHookPeerGuardianIncarnation
	t.Cleanup(func() { managedHookPeerGuardianIncarnation = previousGuardian })
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
	managedHookPeerGuardianIncarnation = func(account unixidentity.Account) (string, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if account.UID != f.uid || f.recordProof == "" {
			return "", false
		}
		return "nss:systemd", true
	}
	managedHookPeerHomeProof = func(uid int, name, incarnation string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		if uid != f.uid || name != "alice" || incarnation != "nss:systemd" {
			return ""
		}
		return normalizeHomeProof(f.recordProof)
	}
	return f
}

// rel-1-0-5 GAP-0022 (cap-erhel3, 55654a8ada and 5e9965c636): a userdb
// account ran its first Codex turn before the guardian's first record of it,
// was deleted and created again under the same name, uid and home path, and
// the new account's first turn, after the guardian's record proved the new
// home, ran under the earlier holder's agent identity (sessions_seen 1 -> 2).
// The new account derives its own agent identity, which it keeps.
func TestRecreatedUserdbAccountBehindSSSDDerivesItsOwnAgentIdentity(t *testing.T) {
	f := userdbAccountFixture(t)
	f.guardian("")
	old := f.hook("s-old")
	f.mu.Lock()
	f.now = f.now.Add(time.Minute)
	created := f.now.UnixNano()
	f.mu.Unlock()
	f.guardian("home:66308:2000:" + strconv.FormatInt(created, 10))
	recreated := f.hook("s-new")
	if recreated.ID == old.ID {
		t.Fatalf("the recreated userdb account derived the earlier holder's agent identity %s", old.ID)
	}
	if got := f.hook("s-new-2").ID; got != recreated.ID {
		t.Fatalf("the recreated userdb account's next turn has agent identity %s, want %s", got, recreated.ID)
	}
}

// Control: the userdb account whose home existed before its first turn
// keeps its agent identity once the guardian's record names it.
func TestUserdbAccountBehindSSSDKeepsItsAgentIdentityWhenTheGuardianNamesIt(t *testing.T) {
	f := userdbAccountFixture(t)
	f.guardian("")
	before := f.hook("s-1")
	f.guardian("home:66308:1000:" + strconv.FormatInt(f.now.Add(-time.Hour).UnixNano(), 10))
	if got := f.hook("s-2").ID; got != before.ID {
		t.Fatalf("the guardian's first record moved the userdb account's agent identity to %s, want %s", got, before.ID)
	}
}

// The non-root gateway takes the guardian's recorded SSSD miss for a
// systemd-userdb account as it does for an /etc/passwd one: its facts
// resolve, and its account incarnation is the recorded one. A record of an
// SSSD account (sss, a SID) gives no such proof.
func TestGuardianRecordNamesAUserdbAccountBehindSSSD(t *testing.T) {
	write, _ := unixFactsSpool(t)
	fake := &peerNSSReviewFake{account: unixidentity.Account{UID: 6001, Name: "pod-udb"},
		recordedFacts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}}
	installPeerNSSReviewFake(t, fake, true)
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
	managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { return "nss:systemd", true }
	write(enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: "nss:systemd",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal}})
	facts, err := resolveNSSPeerFacts(unixFactsUID)
	if err != nil || fake.recordedCalls != 1 || !facts.GuardianRecord {
		t.Fatalf("userdb account facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
	}
	if got, known := peerAccountIncarnation(fake.account); !known || got != "nss:systemd" {
		t.Fatalf("userdb account incarnation = %q, %v; want nss:systemd", got, known)
	}
	for _, incarnation := range []string{"sss", "sid:S-1-5-21-1-2-3-1105"} {
		managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { return incarnation, true }
		write(enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: incarnation,
			Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal}})
		if got, known := peerAccountIncarnation(fake.account); known {
			t.Fatalf("a %s record named the incarnation %q", incarnation, got)
		}
	}
}
