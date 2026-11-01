// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// rel-1-0-6 GAP-0381: in an observe-mode burst every hook call queued on the
// store's one connection to read its connector instance again (a
// transaction for an unchanged row), and calls whose ledger missed its share
// of the answer window failed right there ("begin connector instance
// resolution: context deadline exceeded") and lost their join IDs. An
// instance this store resolved needs no connection while nothing would
// change; a custody promotion, a new profile version and an explicit upsert
// still go to the table.
func TestAResolvedConnectorInstanceResolvesWhileTheStoreConnectionIsBusy(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "claudecode", ConnectorCustodyHookOnly)

	// Another call holds the store's one connection (MaxOpenConns 1).
	held, err := store.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	busyResolve := func(profile string, custody ConnectorExportCustody) (ConnectorInstance, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		return repo.ResolveConnectorInstance(ctx, "claudecode", profile, custody)
	}
	for i := range 20 {
		resolved, err := busyResolve("claudecode-profile-v1", ConnectorCustodyHookOnly)
		if err != nil {
			t.Fatalf("resolution %d of an unchanged instance waited for the busy connection: %v", i, err)
		}
		if !sameConnectorInstance(resolved, instance) {
			t.Fatalf("resolved %+v, want the stored %+v", resolved, instance)
		}
	}
	// A call that would change the row still needs the table.
	if _, err := busyResolve("claudecode-profile-v2", ConnectorCustodyHookOnly); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a new profile version resolved without the table: err=%v", err)
	}
	if _, err := busyResolve("claudecode-profile-v1", ConnectorCustodyDefenseClaw); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a custody promotion resolved without the table: err=%v", err)
	}
	if err := held.Rollback(); err != nil {
		t.Fatal(err)
	}

	promoted, err := repo.ResolveConnectorInstance(t.Context(), "claudecode", "claudecode-profile-v2", ConnectorCustodyDefenseClaw)
	if err != nil || promoted.ExportCustody != ConnectorCustodyDefenseClaw || promoted.ProfileVersion != "claudecode-profile-v2" {
		t.Fatalf("promotion = %+v, %v", promoted, err)
	}
	// An explicit upsert is what the next resolution returns.
	promoted.ExportCustody = ConnectorCustodyExternal
	promoted.UpdatedAt = time.Now().UTC().Add(time.Second)
	if _, err := repo.UpsertConnectorInstance(t.Context(), promoted); err != nil {
		t.Fatal(err)
	}
	resolved, err := repo.ResolveConnectorInstance(t.Context(), "claudecode", "claudecode-profile-v2", ConnectorCustodyHookOnly)
	if err != nil || resolved.ExportCustody != ConnectorCustodyExternal {
		t.Fatalf("after an explicit upsert resolved %+v, %v; want custody external", resolved, err)
	}
	stored, err := repo.GetConnectorInstance(t.Context(), resolved.ConnectorInstanceID)
	if err != nil || !sameConnectorInstance(stored, resolved) {
		t.Fatalf("resolved %+v, table %+v (%v)", resolved, stored, err)
	}
}

func sameConnectorInstance(a, b ConnectorInstance) bool {
	return a.ConnectorInstanceID == b.ConnectorInstanceID && a.Connector == b.Connector &&
		a.ExportCustody == b.ExportCustody && a.ProfileVersion == b.ProfileVersion &&
		a.ManagedConfigDigest == b.ManagedConfigDigest && a.Default == b.Default &&
		a.CreatedAt.Equal(b.CreatedAt) && a.UpdatedAt.Equal(b.UpdatedAt)
}
