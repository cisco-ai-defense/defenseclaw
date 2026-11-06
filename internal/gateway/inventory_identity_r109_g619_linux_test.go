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

func TestReviewG619IDEPluginQualifiedAndReusedNameMutants(t *testing.T) {
	const uid = "700004"
	previousFacts, previousPrincipal := identityFactsEnabled.Load(), userPrincipalCollectionEnabled.Load()
	oldDirectory, oldName := managedHookPeerDirectory, userScopedIdentityName
	setIdentityFactsEnabled(true)
	SetUserPrincipalCollectionEnabled(true)
	managedHookPeerDirectory = func(id int, _ bool) (useridentity.DirectoryFacts, bool) {
		if id != 700004 {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
			Source: useridentity.SourceSSSDInfoPipe, Principal: "alice@corp.example", UPN: "alice@corp.example",
			Domain: "corp.example", Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}, true
	}
	userScopedIdentityName = func(id string) string {
		if id == uid {
			return "alice@corp.example"
		}
		return ""
	}
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		SetUserPrincipalCollectionEnabled(previousPrincipal)
		managedHookPeerDirectory, userScopedIdentityName = oldDirectory, oldName
	})
	capture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: capture}
	summary := inventory.AIDiscoverySummary{ScanID: "review-ide", Source: "scheduled"}
	for _, item := range []struct {
		name, state   string
		wantPrincipal bool
	}{
		{"alice@corp.example", inventory.AIStateNew, true},
		{"ALICE@CORP.EXAMPLE", inventory.AIStateGone, true},
		{"alice@other.example", inventory.AIStateGone, false},
		{"alice", inventory.AIStateGone, false},
	} {
		err := adapter.emitIDEPluginLog(t.Context(), summary, inventory.IDEPlugin{
			PluginID: "anthropic.claude-code", Product: "vscode", Enabled: "enabled", IsAI: true,
			UserID: uid, UserName: item.name, State: item.state,
		})
		if err != nil {
			t.Fatal(err)
		}
		body := canonicalBody(t, capture.snapshot()[len(capture.snapshot())-1])
		principal := body["defenseclaw.user.principal"]
		if (principal != nil) != item.wantPrincipal {
			t.Errorf("name=%q state=%q principal=%v, want present=%v", item.name, item.state, principal, item.wantPrincipal)
		}
	}
}

func TestReviewG619BackslashQualifiedPOSIXPluginKeepsDisplayAndPrincipal(t *testing.T) {
	const uid = "700005"
	previousFacts, previousPrincipal := identityFactsEnabled.Load(), userPrincipalCollectionEnabled.Load()
	oldDirectory, oldName := managedHookPeerDirectory, userScopedIdentityName
	setIdentityFactsEnabled(true)
	SetUserPrincipalCollectionEnabled(true)
	managedHookPeerDirectory = func(id int, _ bool) (useridentity.DirectoryFacts, bool) {
		if id != 700005 {
			return useridentity.DirectoryFacts{}, false
		}
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
			Source: useridentity.SourceWinbind, Principal: "alice@corp.example", UPN: "alice@corp.example",
			Domain: "corp.example", Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}, true
	}
	userScopedIdentityName = func(id string) string {
		if id == uid {
			return `CORP\alice`
		}
		return ""
	}
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		SetUserPrincipalCollectionEnabled(previousPrincipal)
		managedHookPeerDirectory, userScopedIdentityName = oldDirectory, oldName
	})
	capture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: capture}
	err := adapter.emitIDEPluginLog(t.Context(), inventory.AIDiscoverySummary{ScanID: "review-ide", Source: "scheduled"},
		inventory.IDEPlugin{PluginID: "anthropic.claude-code", Product: "vscode", Enabled: "enabled", IsAI: true,
			UserID: uid, UserName: `CORP\alice`, State: inventory.AIStateNew})
	if err != nil {
		t.Fatal(err)
	}
	body := canonicalBody(t, capture.snapshot()[0])
	if body["defenseclaw.user.principal"] != "alice@corp.example" || body["defenseclaw.user.name"] != "alice" {
		t.Errorf("backslash-qualified POSIX plugin lost identity fields: principal=%v name=%v", body["defenseclaw.user.principal"], body["defenseclaw.user.name"])
	}
	setIdentityFactsEnabled(false)
	err = adapter.emitIDEPluginLog(t.Context(), inventory.AIDiscoverySummary{ScanID: "review-ide", Source: "scheduled"},
		inventory.IDEPlugin{PluginID: "anthropic.claude-code", Product: "vscode", Enabled: "enabled", IsAI: true,
			UserID: uid, UserName: `CORP\alice`, State: inventory.AIStateGone})
	if err != nil {
		t.Fatal(err)
	}
	if body := canonicalBody(t, capture.snapshot()[1]); body["defenseclaw.user.name"] != nil || body["defenseclaw.user.principal"] != nil {
		t.Errorf("identity collection disabled: name=%v principal=%v", body["defenseclaw.user.name"], body["defenseclaw.user.principal"])
	}
}
