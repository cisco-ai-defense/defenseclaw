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
