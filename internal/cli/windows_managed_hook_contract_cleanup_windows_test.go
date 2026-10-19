// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestManagedHookContractCleanupIdentitySurvivesCrashProgressPrefixes(t *testing.T) {
	receipt := windowsManagedHookContractCleanupReceipt{
		SchemaVersion:          windowsManagedHookContractCleanupReceiptSchema,
		Phase:                  windowsManagedHookContractCleanupPrepared,
		ScopeSHA256:            "1111111111111111111111111111111111111111111111111111111111111111",
		ManifestSHA256:         "2222222222222222222222222222222222222222222222222222222222222222",
		ManifestFingerprint:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		DeploymentGenerationID: "44444444444444444444444444444444",
		GatewayServiceName:     "DefenseClawGateway",
		Claims: []connector.WindowsManagedHookContractCleanupClaim{{
			SchemaVersion:      connector.WindowsManagedHookContractCleanupClaimSchema,
			Connector:          "codex",
			SID:                "S-1-5-21-1-2-3-1001",
			DataDir:            `C:\Users\fixture\.defenseclaw`,
			GatewayServiceName: "DefenseClawGateway",
			EntryPresent:       true,
			EntrySHA256:        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
		}},
	}
	identity, err := windowsManagedHookContractCleanupIdentitySHA256(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.IdentitySHA256 = identity
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		t.Fatalf("validate prepared receipt: %v", err)
	}

	// A crash immediately after the durable mutation barrier must leave a
	// receipt that retains the same immutable purge-intent binding.
	receipt.Claims[0].ApplicationStarted = true
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		t.Fatalf("validate mutation-barrier crash prefix: %v", err)
	}
	if progressed, err := windowsManagedHookContractCleanupIdentitySHA256(receipt); err != nil {
		t.Fatal(err)
	} else if progressed != identity {
		t.Fatalf("mutation barrier changed immutable identity: got %s want %s", progressed, identity)
	}

	// The completion marker and final phase are also one-way progress, not new
	// authority, and therefore remain resumable under the original intent.
	receipt.Claims[0].Completed = true
	receipt.Phase = windowsManagedHookContractCleanupFinalized
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		t.Fatalf("validate finalized crash prefix: %v", err)
	}
	if progressed, err := windowsManagedHookContractCleanupIdentitySHA256(receipt); err != nil {
		t.Fatal(err)
	} else if progressed != identity {
		t.Fatalf("finalization changed immutable identity: got %s want %s", progressed, identity)
	}

	receipt.Claims[0].EntrySHA256 =
		"sha256:6666666666666666666666666666666666666666666666666666666666666666"
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err == nil {
		t.Fatal("immutable connector claim mutation was accepted")
	}
}

func TestManagedHookContractCleanupCapturedEntryAlreadyAbsentRequiresBarrier(t *testing.T) {
	claim := connector.WindowsManagedHookContractCleanupClaim{
		SchemaVersion:      connector.WindowsManagedHookContractCleanupClaimSchema,
		Connector:          "codex",
		SID:                "S-1-5-21-1-2-3-1001",
		DataDir:            `C:\Users\fixture\.defenseclaw`,
		GatewayServiceName: "DefenseClawGateway",
		EntryPresent:       true,
		EntrySHA256:        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
	}
	completeWindowsManagedHookContractCleanupClaim(
		&claim,
		connector.WindowsManagedHookContractCleanupResult{AlreadyAbsent: true},
	)
	if claim.ApplicationStarted || !claim.Completed {
		t.Fatalf("pre-barrier absence fabricated cleanup authority: %+v", claim)
	}
	receipt := windowsManagedHookContractCleanupReceipt{
		SchemaVersion:          windowsManagedHookContractCleanupReceiptSchema,
		Phase:                  windowsManagedHookContractCleanupPrepared,
		ScopeSHA256:            "1111111111111111111111111111111111111111111111111111111111111111",
		ManifestSHA256:         "2222222222222222222222222222222222222222222222222222222222222222",
		ManifestFingerprint:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		DeploymentGenerationID: "44444444444444444444444444444444",
		GatewayServiceName:     "DefenseClawGateway",
		Claims:                 []connector.WindowsManagedHookContractCleanupClaim{claim},
	}
	identity, err := windowsManagedHookContractCleanupIdentitySHA256(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.IdentitySHA256 = identity
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err == nil {
		t.Fatal("pre-barrier completed absence could be persisted")
	}

	claim.Completed = false
	claim.ApplicationStarted = true
	completeWindowsManagedHookContractCleanupClaim(
		&claim,
		connector.WindowsManagedHookContractCleanupResult{AlreadyAbsent: true},
	)
	if !claim.ApplicationStarted || !claim.Completed {
		t.Fatalf("post-barrier absence did not complete: %+v", claim)
	}
	receipt.Claims[0] = claim
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		t.Fatalf("post-barrier completed absence was rejected: %v", err)
	}
}

// GAP-0029: native prepare resumes only this deployment's prepared receipt.
// A prepared receipt that an earlier, removed deployment left at the
// scope-stable path is replaced, so it no longer fails every later uninstall.
// A same-generation mismatch, or a receipt for another scope or gateway
// service, still refuses.
func TestManagedHookContractCleanupPrepareReusesOnlyThisDeploymentsReceipt(t *testing.T) {
	const scope = "1111111111111111111111111111111111111111111111111111111111111111"
	identity := windowsManagedHooksTeardownJournal{
		ManifestSHA256:         "2222222222222222222222222222222222222222222222222222222222222222",
		ManifestFingerprint:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		DeploymentGenerationID: "44444444444444444444444444444444",
		GatewayServiceName:     "DefenseClawGateway",
		Targets: []windowsManagedHooksTeardownTarget{{
			Connector: "codex",
			SID:       "S-1-5-21-1-2-3-1001",
			DataDir:   `C:\Users\fixture\.defenseclaw`,
		}},
	}
	receipt := func(mutate func(*windowsManagedHookContractCleanupReceipt)) windowsManagedHookContractCleanupReceipt {
		r := windowsManagedHookContractCleanupReceipt{
			SchemaVersion:          windowsManagedHookContractCleanupReceiptSchema,
			Phase:                  windowsManagedHookContractCleanupPrepared,
			ScopeSHA256:            scope,
			ManifestSHA256:         identity.ManifestSHA256,
			ManifestFingerprint:    identity.ManifestFingerprint,
			DeploymentGenerationID: identity.DeploymentGenerationID,
			GatewayServiceName:     identity.GatewayServiceName,
			Claims: []connector.WindowsManagedHookContractCleanupClaim{{
				SchemaVersion:      connector.WindowsManagedHookContractCleanupClaimSchema,
				Connector:          "codex",
				SID:                "S-1-5-21-1-2-3-1001",
				DataDir:            `C:\Users\fixture\.defenseclaw`,
				GatewayServiceName: "DefenseClawGateway",
			}},
		}
		if mutate != nil {
			mutate(&r)
		}
		identitySHA256, err := windowsManagedHookContractCleanupIdentitySHA256(r)
		if err != nil {
			t.Fatal(err)
		}
		r.IdentitySHA256 = identitySHA256
		return r
	}
	otherGeneration := func(r *windowsManagedHookContractCleanupReceipt) {
		r.DeploymentGenerationID = "c3d039e5f86f49baae75aa3261797cf7"
		r.ManifestSHA256 = "2026be56e484c4c8d82d601a3a804b414db7c34a2501e4d5e727145bbceeedfb"
	}
	for _, tc := range []struct {
		name    string
		receipt windowsManagedHookContractCleanupReceipt
		reuse   bool
		refuse  bool
	}{
		{name: "this deployment's prepared receipt is resumed", receipt: receipt(nil), reuse: true},
		{name: "a finalized predecessor is replaced", receipt: receipt(func(r *windowsManagedHookContractCleanupReceipt) {
			otherGeneration(r)
			r.Phase = windowsManagedHookContractCleanupFinalized
		})},
		{name: "a removed deployment's prepared receipt is replaced", receipt: receipt(otherGeneration)},
		{name: "same generation with other claims refuses", receipt: receipt(func(r *windowsManagedHookContractCleanupReceipt) {
			r.Claims[0].SID = "S-1-5-21-1-2-3-1002"
		}), refuse: true},
		{name: "same generation with another manifest refuses", receipt: receipt(func(r *windowsManagedHookContractCleanupReceipt) {
			r.ManifestSHA256 = "5555555555555555555555555555555555555555555555555555555555555555"
		}), refuse: true},
		{name: "another scope refuses", receipt: receipt(func(r *windowsManagedHookContractCleanupReceipt) {
			otherGeneration(r)
			r.ScopeSHA256 = "6666666666666666666666666666666666666666666666666666666666666666"
		}), refuse: true},
		{name: "another gateway service refuses", receipt: receipt(func(r *windowsManagedHookContractCleanupReceipt) {
			otherGeneration(r)
			r.GatewayServiceName = "DefenseClawGatewayOther"
			r.Claims[0].GatewayServiceName = "DefenseClawGatewayOther"
		}), refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reuse, err := windowsManagedHookContractCleanupPrepareReuses(tc.receipt, identity, scope)
			if tc.refuse != (err != nil) || reuse != tc.reuse {
				t.Fatalf("reuse=%v err=%v, want reuse=%v refuse=%v", reuse, err, tc.reuse, tc.refuse)
			}
		})
	}
}
