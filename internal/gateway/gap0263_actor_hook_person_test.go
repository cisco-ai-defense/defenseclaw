// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// substrate-1 GAP-0263 (journey J02): the hook rows of a launcher actor named
// the gateway pod's own account (user.id 65532, id_kind posix_uid, name
// nonroot) and carried the person only as extra.substrate_person, an
// issuer#subject string with no assurance. They name the person the gateway
// verified: user.id the OIDC subject, id_kind oidc_subject, and the directory
// facts at assurance verified from identity source oidc. Each actor's rows
// name its own person; an actor with no bound person names nobody.
func TestGAP0263ActorHookRowsNameTheVerifiedPerson(t *testing.T) {
	prev := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	installCorrelationHMACForTest(t)
	installDefaultProfileConnector(t, "claudecode")
	f := newSubstrateFixture(t)
	f.api.store, f.api.logger = testStoreAndV8Logger(t)
	r := chartReplica{f}
	r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls"))

	events, err := f.api.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Action != "connector-hook" {
			continue
		}
		rows++
		if id, kind := ev.Structured[auditUserIDKey], ev.Structured[auditUserIDKindKey]; id != "alice" || kind != substrateSubjectIDKind {
			t.Fatalf("actor hook row names user.id %v id_kind %v, want the verified person alice as %s", id, kind, substrateSubjectIDKind)
		}
		if name := ev.Structured[auditUserNameKey]; name == "nonroot" {
			t.Fatalf("actor hook row names the gateway pod's account %v", name)
		}
	}
	if rows == 0 {
		t.Fatal("no connector-hook audit row")
	}

	// The records' user and its identity facts, as the listener builds the
	// hook request's context.
	ctxFor := func(reg registry.Registration) context.Context {
		if err := reg.Validate(); err != nil {
			t.Fatal(err)
		}
		ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID, "actor/"+reg.Atespace+"/"+reg.Name, reg.Key))
		ctx = sandboxauth.WithRequest(ctx, sandboxauth.Binding{ID: reg.Key, SandboxID: reg.UID, Connector: "claudecode",
			Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}}, nil)
		ctx = contextWithSubstratePerson(ctx, reg)
		return f.api.attachSubstrateSubject(ctx, reg)
	}
	aliceReg := registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Connector: "claudecode", Person: ownerOf(alice)}
	user := resolveHookUserIdentity(ctxFor(aliceReg), "claudecode", nil)
	if user.ID != "alice" || user.IDKind != substrateSubjectIDKind || user.Identity == nil {
		t.Fatalf("hook user %+v", user)
	}
	// The name is the bare name, as on the host's verified path; the
	// email-shaped principal is only the directory fact below.
	if user.Name != "alice" {
		t.Fatalf("hook user name %q, want the bare name alice", user.Name)
	}
	if d := user.Identity.Directory; d.Assurance != useridentity.AssuranceVerified || d.Source != substrateIdentitySourceOIDC || d.Principal != "alice@example.com" {
		t.Fatalf("directory facts %+v: want principal alice@example.com, assurance verified, source oidc", d)
	}
	bobReg := aliceReg
	bobReg.Name, bobReg.UID, bobReg.Person = "bob-1", subUID2, ownerOf(bob)
	if user := resolveHookUserIdentity(ctxFor(bobReg), "claudecode", nil); user.ID != "bob" || user.Name != "bob" || user.Identity == nil || user.Identity.Directory.Principal != "bob@example.com" {
		t.Fatalf("bob's actor names %+v", user)
	}
	attributed := registry.Registration{Atespace: "other", Name: "x-1", UID: subUID2, Connector: "claudecode", Attributed: true}
	if user := resolveHookUserIdentity(ctxFor(attributed), "claudecode", nil); user.ID != "" || user.Name != "" || user.IDKind != "" {
		t.Fatalf("an actor with no person names %+v", user)
	}
}
