// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func stubGatewayAuditOpen(t *testing.T, failures int) (*int, func() (*audit.Store, error)) {
	t.Helper()
	attempts := 0
	originalBudget, originalInitial, originalMax :=
		gatewayAuditOpenBudget, gatewayAuditOpenInitialDelay, gatewayAuditOpenMaxDelay
	gatewayAuditOpenBudget = time.Second
	gatewayAuditOpenInitialDelay = time.Millisecond
	gatewayAuditOpenMaxDelay = 2 * time.Millisecond
	t.Cleanup(func() {
		gatewayAuditOpenBudget, gatewayAuditOpenInitialDelay, gatewayAuditOpenMaxDelay =
			originalBudget, originalInitial, originalMax
	})
	return &attempts, func() (*audit.Store, error) {
		attempts++
		if attempts <= failures {
			return nil, errors.New("access is denied")
		}
		return &audit.Store{}, nil
	}
}

func TestOpenGatewayAuditStoreWaitsForRepairInManagedMode(t *testing.T) {
	attempts, attempt := stubGatewayAuditOpen(t, 3)
	store, err := openAuditStoreWaitingForRepair(context.Background(), "managed_enterprise", "audit.db", attempt)
	if err != nil || store == nil {
		t.Fatalf("open = %v, %v; want the store once the guardian repaired it", store, err)
	}
	if *attempts != 4 {
		t.Fatalf("attempts = %d, want 4", *attempts)
	}
}

func TestOpenGatewayAuditStoreFailsFastOutsideManagedMode(t *testing.T) {
	attempts, attempt := stubGatewayAuditOpen(t, 3)
	if _, err := openAuditStoreWaitingForRepair(context.Background(), "", "audit.db", attempt); err == nil {
		t.Fatal("unmanaged open succeeded after a failure")
	}
	if *attempts != 1 {
		t.Fatalf("attempts = %d, want 1", *attempts)
	}
}

func TestOpenGatewayAuditStoreStopsWhenCancelled(t *testing.T) {
	_, attempt := stubGatewayAuditOpen(t, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openAuditStoreWaitingForRepair(ctx, "managed_enterprise", "audit.db", attempt); err == nil {
		t.Fatal("cancelled open succeeded")
	}
}
