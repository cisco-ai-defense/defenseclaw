// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// rel-1-0-10 GAP-0933: the model.usage log carried only the numeric uid, so
// the routing dashboard listed 1001 where other events carried the account
// name. The log now carries defenseclaw.user.name next to the id, and keeps
// the id alone when no name resolved.
func TestModelUsageLogCarriesTheAccountName(t *testing.T) {
	envelope := observability.FamilyEnvelopeInput{
		Source: observability.SourceConnector, Connector: "claudecode", Action: "model_usage", Phase: "model",
		Provenance: observability.FamilyProvenanceInput{Producer: modelUsageV8Producer, BinaryVersion: "test", ConfigGeneration: 1,
			ConfigDigest: "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	rec := modelusage.Record{
		Facts: modelusage.CallFacts{
			RequestID: "r", Connector: "claudecode", APIFamily: modelusage.FamilyMessages, CallRole: modelusage.RoleAgent,
			SelectedProvider: "anthropic", SelectedModel: "m", Subject: "1001", SubjectKind: "posix_uid", IdentityVerified: true, SubjectName: "fixture-user",
		},
		Outcome: "completed", EndedAt: time.Now(),
	}
	in := buildModelUsageLogInput(envelope, rec)
	if id, _ := in.UserID.Get(); id != "1001" {
		t.Fatalf("user id = %q", id)
	}
	if name, ok := in.DefenseClawUserName.Get(); !ok || name != "fixture-user" {
		t.Fatalf("user name = %q, %v", name, ok)
	}
	rec.Facts.SubjectName = ""
	if _, ok := buildModelUsageLogInput(envelope, rec).DefenseClawUserName.Get(); ok {
		t.Fatal("no resolved name must leave the name absent (the uid stays)")
	}
	rec.Facts.SubjectName, rec.Facts.IdentityVerified = "fixture-user", false
	if _, ok := buildModelUsageLogInput(envelope, rec).DefenseClawUserName.Get(); ok {
		t.Fatal("an unverified caller must not carry a name")
	}
}

func TestUsageIdentityTakesTheVerifiedAccountName(t *testing.T) {
	ctx := context.WithValue(context.Background(), verifiedSubjectContextKey{}, VerifiedSubject{UserID: "1001", UserName: "fixture-user", Source: subjectSourcePeerCredentials})
	var f modelusage.CallFacts
	usageIdentity(ctx, &f)
	if f.Subject != "1001" || f.SubjectName != "fixture-user" || !f.IdentityVerified {
		t.Fatalf("facts = %+v", f)
	}
}
