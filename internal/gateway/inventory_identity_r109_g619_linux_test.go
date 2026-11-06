// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Every lifecycle signal takes the same resolved identity attributes as the
// account's identity observation. The inventory record keeps the full NSS
// spelling for the holder check and emits the short user display name.
func TestGAP0619PerUserLifecycleRecordsShareVerifiedIdentity(t *testing.T) {
	const uid = "700004"
	const account = "alice@corp.example"
	const principal = "alice@corp.example"
	previousFacts, previousPrincipal := identityFactsEnabled.Load(), userPrincipalCollectionEnabled.Load()
	setIdentityFactsEnabled(true)
	SetUserPrincipalCollectionEnabled(true)
	oldDirectory, oldName := managedHookPeerDirectory, userScopedIdentityName
	managedHookPeerDirectory = func(id int, _ bool) (useridentity.DirectoryFacts, bool) {
		if id != 700004 {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSDInfoPipe,
			Principal: principal, UPN: principal, Domain: "corp.example",
			Groups: []string{"domain-users"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, true
	}
	userScopedIdentityName = func(id string) string {
		if id == uid {
			return account
		}
		return ""
	}
	identityObservedState.Lock()
	delete(identityObservedState.last, uid)
	identityObservedState.Unlock()
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		SetUserPrincipalCollectionEnabled(previousPrincipal)
		managedHookPeerDirectory, userScopedIdentityName = oldDirectory, oldName
		identityObservedState.Lock()
		delete(identityObservedState.last, uid)
		identityObservedState.Unlock()
	})
	capture := &endpointInventoryCapture{}
	facts, _ := managedHookPeerDirectory(700004, true)
	observeIdentity(t.Context(), capture, VerifiedSubject{
		UserID: uid, IDKind: useridentity.KindPOSIXUID, UserName: "alice", Directory: facts,
	}, useridentity.SessionFacts{})
	adapter := &aiDiscoveryV8Adapter{runtime: capture}
	summary := inventory.AIDiscoverySummary{ScanID: "scan-identity", Source: "scheduled"}
	for _, state := range []string{inventory.AIStateNew, inventory.AIStateChanged, inventory.AIStateSeen, inventory.AIStateGone} {
		_, err := adapter.emitSignalLog(t.Context(), summary, inventory.AISignal{
			SignalID: "skill-identity", SignatureID: "claudecode", Category: inventory.SignalSkill,
			Confidence: .9, State: state, UserID: uid, UserName: account,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	records := capture.snapshot()
	if len(records) != 5 {
		t.Fatalf("records = %d; want identity observation and four lifecycle records", len(records))
	}
	identity := canonicalBody(t, records[0])
	for _, record := range records[1:] {
		body := canonicalBody(t, record)
		for _, key := range []string{"defenseclaw.user.principal", "defenseclaw.user.domain", "defenseclaw.user.principal.assurance"} {
			if body[key] != identity[key] || body[key] == nil {
				t.Errorf("%s %s = %v; identity.observed = %v", record.EventName(), key, body[key], identity[key])
			}
		}
		if body["defenseclaw.user.name"] != "alice" || body["user.id"] != uid {
			t.Errorf("%s display identity = %v", record.EventName(), body)
		}
	}
	SetUserPrincipalCollectionEnabled(false)
	_, err := adapter.emitSignalLog(t.Context(), summary, inventory.AISignal{
		SignalID: "skill-identity", SignatureID: "claudecode", Category: inventory.SignalSkill,
		Confidence: .9, State: inventory.AIStateGone, UserID: uid, UserName: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	if body := canonicalBody(t, capture.snapshot()[5]); body["defenseclaw.user.principal"] != nil {
		t.Errorf("principal collection disabled: %v", body)
	}
}
