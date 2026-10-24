// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

var errPeerNeedsRoot = errors.New("SSSD's absence proof needs root")

type peerNSSReviewFake struct {
	account       unixidentity.Account
	recordedFacts useridentity.DirectoryFacts
	recordedErr   error
	groupNames    []string
	recordedCalls int
}

func (f *peerNSSReviewFake) LookupUID(int) (unixidentity.Account, error) {
	return f.account, nil
}

func (f *peerNSSReviewFake) DirectoryFactsForUID(int, time.Time) (useridentity.DirectoryFacts, error) {
	return useridentity.DirectoryFacts{}, errPeerNeedsRoot
}

func (f *peerNSSReviewFake) DirectoryFactsForRecordedUnsharedUID(int, time.Time) (useridentity.DirectoryFacts, error) {
	f.recordedCalls++
	return f.recordedFacts, f.recordedErr
}

func (f *peerNSSReviewFake) GroupNames([]int) ([]string, []string, error) {
	return f.groupNames, nil, nil
}

func installPeerNSSReviewFake(t *testing.T, fake *peerNSSReviewFake, service bool) {
	t.Helper()
	oldFactory, oldNeedsRoot := newPeerNSSResolver, peerUnsharedUIDNeedsRoot
	oldIncarnation, oldGroups := managedHookPeerAccountIncarnation, processGroupIDs
	oldRecordedIncarnation := managedHookPeerRecordedAccountIncarnation
	oldService, oldDomains := managedServiceHosted.Load(), observedGroupDomains
	t.Cleanup(func() {
		newPeerNSSResolver, peerUnsharedUIDNeedsRoot = oldFactory, oldNeedsRoot
		managedHookPeerAccountIncarnation, processGroupIDs = oldIncarnation, oldGroups
		managedHookPeerRecordedAccountIncarnation = oldRecordedIncarnation
		setManagedServiceHosted(oldService)
		observedGroupDomains = oldDomains
	})
	newPeerNSSResolver = func(context.Context) (peerNSSResolver, error) { return fake, nil }
	peerUnsharedUIDNeedsRoot = func(err error) bool { return errors.Is(err, errPeerNeedsRoot) }
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "sid:current", true }
	processGroupIDs = func() ([]int, error) { return []int{os.Getgid()}, nil }
	setManagedServiceHosted(service)
	observedGroupDomains = &boundedNameSet{max: 16}
}

// The unixidentity test configures "passwd: sss files" and proves that its
// ordinary owner lookup needs root while its recorded lookup finds files.
// Here the gateway must use that recorded proof for the incarnation check
// and the facts retry, then decide the managed local user's assignments.
func TestResolveNSSPeerFactsUsesSSSDFirstGuardianRecord(t *testing.T) {
	write, _ := unixFactsSpool(t)
	fake := &peerNSSReviewFake{account: unixidentity.Account{UID: 6001, Name: "local-user"},
		recordedFacts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Groups: []string{"local-strict"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}}
	installPeerNSSReviewFake(t, fake, true)
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
	managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
	write(enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: "files",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal}})

	facts, err := resolveNSSPeerFacts(unixFactsUID)
	if err != nil || fake.recordedCalls != 1 || facts.Source != useridentity.SourceNSSFiles || !facts.GuardianRecord {
		t.Fatalf("recorded SSSD-first local facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: unixFactsUID, IDKind: useridentity.KindPOSIXUID,
		UserName: fake.account.Name, Directory: facts, Source: subjectSourcePeerCredentials}, true)
	set := identityTestSet(t, identityTestPlatforms[0], "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Groups: []string{"local-strict"}}},
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{fake.account.Name}}})
	if got := set.match(&subject, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Refused != "" {
		t.Fatalf("managed local assignment = %+v; want strict without refusal", got)
	}
	// If the SSSD lookup now finds an account, the recorded miss cannot
	// authorize reuse of the local facts.
	fake.recordedErr = &unixidentity.SharedUIDError{UID: 6001, Accounts: []string{"local", "sss"}}
	if facts, err := resolveNSSPeerFacts(unixFactsUID); err == nil || !facts.ResolvedAt.IsZero() {
		t.Fatalf("new SSSD holder facts = %+v, %v; want refusal", facts, err)
	}
}

func reviewPeerDecision(t *testing.T, uid int, name string, facts useridentity.DirectoryFacts, match config.ProfileMatch) profileDecision {
	t.Helper()
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: strconv.Itoa(uid), IDKind: useridentity.KindPOSIXUID,
		UserName: name, Directory: facts, Source: subjectSourcePeerCredentials}, true)
	set := identityTestSet(t, identityTestPlatforms[0], "watch", config.ProfileAssignment{Profile: "strict", Match: match})
	return set.match(&subject, profileSubjectVerified, "codex", "")
}

// The real NSS resolver's root-only error and recorded-proof behavior are
// tested in unixidentity. This test pins the gateway wiring for each mode.
func TestResolveNSSPeerFactsUsesOnlyAvailableUnsharedUIDProof(t *testing.T) {
	t.Run("per-user credentials decide groups but not account names", func(t *testing.T) {
		unixFactsSpool(t)
		uid := os.Getuid()
		fake := &peerNSSReviewFake{account: unixidentity.Account{UID: uid, Name: "dcad-strict"},
			groupNames: []string{"dc-ml@corp.example"}}
		installPeerNSSReviewFake(t, fake, false)
		facts, err := resolveNSSPeerFacts(strconv.Itoa(uid))
		if err != nil || facts.Source != useridentity.SourceProcessCredentials || !facts.HolderUnproven ||
			!slices.Equal(facts.Groups, fake.groupNames) || fake.recordedCalls != 0 {
			t.Fatalf("per-user facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
		}
		for _, tc := range []struct {
			group, want string
		}{
			{group: "dc-ml@corp.example", want: "strict"},
			{group: "not-a-member", want: "watch"},
		} {
			got := reviewPeerDecision(t, uid, fake.account.Name, facts, config.ProfileMatch{Groups: []string{tc.group}})
			if got.Name != tc.want || got.Refused != "" {
				t.Fatalf("group %s: %+v; want %s without refusal", tc.group, got, tc.want)
			}
		}
		got := reviewPeerDecision(t, uid, fake.account.Name, facts, config.ProfileMatch{Users: []string{fake.account.Name}})
		if !slices.Equal(got.Unproven, []string{"account:unknown"}) || !strings.Contains(got.Refused, "account holder is unconfirmed") {
			t.Fatalf("users entry = %+v; want only account:unknown", got)
		}
		if !slices.Contains(observedGroupDomains.list(), "corp.example") {
			t.Fatalf("qualified process group domain was not observed: %v", observedGroupDomains.list())
		}
	})

	t.Run("managed current same incarnation", func(t *testing.T) {
		write, _ := unixFactsSpool(t)
		fake := &peerNSSReviewFake{account: unixidentity.Account{UID: 6001, Name: "dcad-strict"},
			recordedFacts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
				Groups: []string{"dc-ml@corp.example"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}}
		installPeerNSSReviewFake(t, fake, true)
		managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
		managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
		write(enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: "files",
			Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal,
				UPN: "dcad-strict@corp.example"}})
		facts, err := resolveNSSPeerFacts(unixFactsUID)
		if err != nil || fake.recordedCalls != 1 || facts.Directory != useridentity.DirectoryLocal ||
			facts.UPN != "dcad-strict@corp.example" || !facts.GuardianRecord || facts.SpoolSeenAt.IsZero() {
			t.Fatalf("managed facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
		}
		if got := reviewPeerDecision(t, 6001, fake.account.Name, facts,
			config.ProfileMatch{Groups: []string{"dc-ml@corp.example"}}); got.Name != "strict" || got.Refused != "" {
			t.Fatalf("proven managed group = %+v", got)
		}
	})

	for _, tc := range []struct {
		name, incarnation string
		stale             bool
	}{
		{name: "no guardian record"},
		{name: "stale guardian record", incarnation: "sid:current", stale: true},
		{name: "another incarnation", incarnation: "sid:previous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write, _ := unixFactsSpool(t)
			fake := &peerNSSReviewFake{account: unixidentity.Account{UID: 6001, Name: "dcad-strict"}}
			installPeerNSSReviewFake(t, fake, true)
			if tc.incarnation != "" {
				record := enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: tc.incarnation}
				if tc.stale {
					record.UpdatedAt = time.Now().Add(-identitySpoolMaxAge - time.Second)
				}
				write(record)
			}
			facts, err := resolveNSSPeerFacts(unixFactsUID)
			if !errors.Is(err, errPeerNeedsRoot) || !facts.ResolvedAt.IsZero() || fake.recordedCalls != 0 {
				t.Fatalf("unproven managed facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
			}
			for _, check := range []struct {
				match config.ProfileMatch
				fact  string
			}{
				{match: config.ProfileMatch{Groups: []string{"dc-ml@corp.example"}}, fact: "groups:unknown"},
				{match: config.ProfileMatch{Users: []string{fake.account.Name}}, fact: "account:unknown"},
			} {
				got := reviewPeerDecision(t, 6001, fake.account.Name, facts, check.match)
				if !slices.Contains(got.Unproven, check.fact) || got.Refused == "" {
					t.Fatalf("%s refusal = %+v; want named missing fact", check.fact, got)
				}
			}
		})
	}

	t.Run("service account cannot borrow its own process credentials", func(t *testing.T) {
		unixFactsSpool(t)
		uid := os.Getuid()
		fake := &peerNSSReviewFake{account: unixidentity.Account{UID: uid, Name: "dcad-strict"},
			groupNames: []string{"dc-ml@corp.example"}}
		installPeerNSSReviewFake(t, fake, true)
		facts, err := resolveNSSPeerFacts(strconv.Itoa(uid))
		if !errors.Is(err, errPeerNeedsRoot) || !facts.ResolvedAt.IsZero() || fake.recordedCalls != 0 {
			t.Fatalf("service account facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
		}
	})

	t.Run("record cannot excuse a shared uid", func(t *testing.T) {
		write, _ := unixFactsSpool(t)
		fake := &peerNSSReviewFake{account: unixidentity.Account{UID: 6001, Name: "dcad-strict"},
			recordedErr: &unixidentity.SharedUIDError{UID: 6001, Accounts: []string{"local", "sss"}}}
		installPeerNSSReviewFake(t, fake, true)
		managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
		managedHookPeerRecordedAccountIncarnation = func(unixidentity.Account) (string, bool) { return "files", true }
		write(enterprisehooks.IdentitySpoolRecord{User: fake.account.Name, AccountIncarnation: "files",
			Facts: useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal}})
		facts, err := resolveNSSPeerFacts(unixFactsUID)
		var shared *unixidentity.SharedUIDError
		if !errors.As(err, &shared) || !facts.ResolvedAt.IsZero() || fake.recordedCalls != 1 {
			t.Fatalf("shared uid facts = %+v, %v; recorded calls = %d", facts, err, fake.recordedCalls)
		}
	})
}
