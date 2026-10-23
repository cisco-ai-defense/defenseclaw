// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

var errW27SSSDNeedsRoot = errors.New("SSSD absence needs root")

// managedLocalNSS models a service-account lookup: NSS finds the local uid,
// but a non-root gateway cannot prove that SSSD has no second holder. The
// recorded lookup still checks whether SSSD has acquired that uid meanwhile.
type managedLocalNSS struct {
	holderInSSSD  bool
	recordedCalls int
}

func (*managedLocalNSS) LookupUID(uid int) (unixidentity.Account, error) {
	return unixidentity.Account{Name: "t7ar-u1", UID: uid, GID: 49202}, nil
}

func (nss *managedLocalNSS) DirectoryFactsForUID(uid int, _ time.Time) (useridentity.DirectoryFacts, error) {
	if nss.holderInSSSD {
		return useridentity.DirectoryFacts{}, &unixidentity.SharedUIDError{UID: uid, Accounts: []string{"t7ar-u1", "SSSD account"}}
	}
	return useridentity.DirectoryFacts{}, errW27SSSDNeedsRoot
}

func (nss *managedLocalNSS) DirectoryFactsForRecordedUnsharedUID(uid int, now time.Time) (useridentity.DirectoryFacts, error) {
	nss.recordedCalls++
	return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
		Groups: []string{"49202"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: now}, nil
}

func (*managedLocalNSS) GroupNames([]int) ([]string, []string, error) {
	return nil, nil, nil
}

// GAP-0677: a managed service-account gateway needs the guardian's current
// record of root's proof before it can place a fresh local uid on its group
// profile. No record or a different incarnation must refuse with both missing
// facts named. A newly shared uid remains an error even with the record.
func TestManagedLocalAccountRecoversWhenGuardianRecordsUnsharedUID(t *testing.T) {
	const uid, gid = 49201, "49202"
	key := strconv.Itoa(uid)
	previousResolver, previousRootProof := newPeerNSSResolver, peerUnsharedUIDNeedsRoot
	previousIncarnation, previousRecordedIncarnation := managedHookPeerAccountIncarnation, managedHookPeerRecordedAccountIncarnation
	previousValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	previousService := managedServiceHosted.Load()
	t.Cleanup(func() {
		newPeerNSSResolver, peerUnsharedUIDNeedsRoot = previousResolver, previousRootProof
		managedHookPeerAccountIncarnation, managedHookPeerRecordedAccountIncarnation = previousIncarnation, previousRecordedIncarnation
		validateManagedGuardianAuthorization = previousValidate
		setIdentitySpoolDir(previousDir)
		setManagedServiceHosted(previousService)
	})
	setManagedServiceHosted(true)
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
	managedHookPeerRecordedAccountIncarnation = func(account unixidentity.Account) (string, bool) {
		return "files", account.Name == "t7ar-u1" && account.UID == uid
	}
	peerUnsharedUIDNeedsRoot = func(err error) bool { return errors.Is(err, errW27SSSDNeedsRoot) }
	set := identityTestSet(t, identityTestPlatforms[0], "watch",
		config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{`.\t7ar-u1`}, Groups: []string{gid}}})
	hookCfg := r2BridgeConfig(config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{
		Users: []string{`.\t7ar-u1`}, Groups: []string{gid},
	}})
	hookCfg.Guardrail.Connector = "codex"
	hookAPI := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, hookCfg)

	for _, tc := range []struct {
		name, recordIncarnation string
		sssdHolds               bool
		wantRecorded            int
	}{
		{name: "current guardian record", recordIncarnation: "files", wantRecorded: 1},
		{name: "no guardian record"},
		{name: "record of prior incarnation", recordIncarnation: "prior", wantRecorded: 0},
		{name: "SSSD also holds the uid", recordIncarnation: "files", sssdHolds: true, wantRecorded: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setIdentitySpoolDir(dir)
			writeRecord := func(incarnation string) {
				t.Helper()
				data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
					Key: key, User: "t7ar-u1", UpdatedAt: time.Now().UTC(), AccountIncarnation: incarnation,
					Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.recordIncarnation != "" {
				writeRecord(tc.recordIncarnation)
			}
			nss := &managedLocalNSS{holderInSSSD: tc.sssdHolds}
			newPeerNSSResolver = func(context.Context) (peerNSSResolver, error) { return nss, nil }
			check := func(wantRecorded int, wantSuccess, wantShared bool) {
				t.Helper()
				facts, err := resolveNSSPeerFacts(key)
				if nss.recordedCalls != wantRecorded {
					t.Fatalf("recorded lookup calls = %d, want %d", nss.recordedCalls, wantRecorded)
				}
				var shared *unixidentity.SharedUIDError
				if wantShared != errors.As(err, &shared) {
					t.Fatalf("facts = %+v, err = %v; shared uid = %t", facts, err, wantShared)
				}
				if wantSuccess && (err != nil || facts.Directory != useridentity.DirectoryLocal ||
					!facts.GuardianRecord || !slices.Contains(facts.Groups, gid)) {
					t.Fatalf("facts = %+v, err = %v; want the confirmed local account and gid", facts, err)
				}
				if !wantSuccess && !wantShared && !errors.Is(err, errW27SSSDNeedsRoot) {
					t.Fatalf("facts = %+v, err = %v; want the missing root-only proof", facts, err)
				}
				if err != nil {
					facts = useridentity.DirectoryFacts{}
				}
				subject := profileSubjectFromVerified(VerifiedSubject{UserID: key, IDKind: useridentity.KindPOSIXUID,
					UserName: "t7ar-u1", Directory: facts, Source: subjectSourcePeerCredentials}, true)
				if err != nil {
					subject.LookupError = err.Error()
				}
				decision := set.match(&subject, profileSubjectVerified, "codex", "")
				if wantSuccess {
					if decision.Name != "strict" || decision.Refused != "" {
						t.Fatalf("group assignment selected %+v; want strict without refusal", decision)
					}
					// Drive the managed Codex handler from the same kernel-verified
					// peer facts, so a matching group must reach a real hook answer.
					ctx := withVerifiedSubject(t.Context(), VerifiedSubject{UserID: key,
						IDKind: useridentity.KindPOSIXUID, UserName: "t7ar-u1", Directory: facts,
						Source: subjectSourcePeerCredentials})
					ctx = withManagedHookPeer(ctx, managedHookPeer{UID: uid, Name: "t7ar-u1"})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook",
						strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"echo ok"}}`)).WithContext(ctx)
					req.Header.Set("X-DefenseClaw-Hook-Event", "PreToolUse")
					req.Header.Set("X-DefenseClaw-Hook-Contract", defaultTestCodexHookContract)
					recorder := httptest.NewRecorder()
					hookAPI.handleAgentHook("codex").ServeHTTP(recorder, req)
					var answer struct {
						Action string `json:"action"`
						Mode   string `json:"mode"`
					}
					if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil ||
						answer.Action != "allow" || answer.Mode != "action" {
						t.Fatalf("managed Codex hook: status=%d answer=%s; want strict action allow", recorder.Code, recorder.Body.String())
					}
					return
				}
				accountReason := "account holder is unconfirmed"
				if wantShared {
					accountReason = "account holder is ambiguous"
				}
				for _, text := range []string{accountReason, "group membership is unconfirmed",
					"profile explain --user " + key} {
					if !strings.Contains(decision.Refused, text) {
						t.Fatalf("refusal %q does not name %q", decision.Refused, text)
					}
				}
			}
			check(tc.wantRecorded, tc.recordIncarnation == "files" && !tc.sssdHolds, tc.sssdHolds)
			if tc.name == "no guardian record" {
				// The first guardian pass publishes the proof. A fresh account
				// then recovers on its next lookup without waiting for SSSD root.
				writeRecord("files")
				check(1, true, false)
			}
		})
	}
}
