// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func sha256HexForTest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// TestSecureClientStoreKeepsImpliedEvidenceAndReceiptExpiry: on a Secure
// Client store the R5 trims keep main's rows. The source evidence an edge
// from a semantic event implies is stored (PutRelationshipEvidence), and
// settling a call leaves its start's receipt at its own expiry
// (SettleReceipt). Either gate dropped fails here (S8 R5 re-check P3-1).
func TestSecureClientStoreKeepsImpliedEvidenceAndReceiptExpiry(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	at := time.Now().UTC()
	expires := at.Add(7 * 24 * time.Hour)
	receipt := &CorrelationReceiptClaim{
		SourceKeyDigest: sha256HexForTest("sc-start"), FingerprintSHA256: sha256HexForTest("sc-bytes"),
		ReceivedAt: at, ExpiresAt: expires,
	}
	start := seedImpliedEvidenceGraph(t, repo, instance, at, "sc", receipt)

	var implied int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_relationship_evidence AS evidence
		JOIN correlation_relationships AS relationship USING (relationship_id)
		WHERE relationship.from_kind = 'semantic_event' AND evidence.semantic_event_id = ?
		AND evidence.evidence_role = 'source' AND evidence.evidence_record_id IS NULL`,
		string(start.SemanticEventID)).Scan(&implied); err != nil {
		t.Fatal(err)
	}
	// Two edges from the start event: to its session and to its trace.
	if implied != 2 {
		t.Fatalf("stored implied source evidence rows = %d, want 2 on a Secure Client store", implied)
	}

	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		receivedAt: at.Add(time.Second), eventName: "tool.completed",
		mutate: func(tx *CorrelationTx, _ CorrelationEvent) {
			if err := tx.SettleReceipt(t.Context(), instance.ConnectorInstanceID, receipt.SourceKeyDigest,
				start.SemanticEventID, at.Add(time.Hour)); err != nil {
				t.Error(err)
			}
		},
	})
	var expiry int64
	if err := store.db.QueryRow(`SELECT expires_time_unix_nano FROM correlation_receipts
		WHERE connector_instance_id = ? AND source_key_digest = ? AND semantic_event_id = ?`,
		string(instance.ConnectorInstanceID), receipt.SourceKeyDigest, string(start.SemanticEventID)).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(0, expiry).UTC(); got.Before(expires.Add(-time.Second)) {
		t.Fatalf("Secure Client receipt expiry = %v after the settle, want its own %v", got, expires)
	}
}
