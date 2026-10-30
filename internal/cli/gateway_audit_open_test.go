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

func stubGatewayAuditOpen(t *testing.T, failures int) *int {
	t.Helper()
	attempts := 0
	originalAttempt := gatewayAuditOpenAttempt
	originalBudget, originalInitial, originalMax :=
		gatewayAuditOpenBudget, gatewayAuditOpenInitialDelay, gatewayAuditOpenMaxDelay
	gatewayAuditOpenBudget = time.Second
	gatewayAuditOpenInitialDelay = time.Millisecond
	gatewayAuditOpenMaxDelay = 2 * time.Millisecond
	gatewayAuditOpenAttempt = func(string, string) (*audit.Store, error) {
		attempts++
		if attempts <= failures {
			return nil, errors.New("access is denied")
		}
		return &audit.Store{}, nil
	}
	t.Cleanup(func() {
		gatewayAuditOpenAttempt = originalAttempt
		gatewayAuditOpenBudget, gatewayAuditOpenInitialDelay, gatewayAuditOpenMaxDelay =
			originalBudget, originalInitial, originalMax
	})
	return &attempts
}

func TestOpenGatewayAuditStoreWaitsForRepairInManagedMode(t *testing.T) {
	attempts := stubGatewayAuditOpen(t, 3)
	store, err := openGatewayAuditStore(context.Background(), "managed_enterprise", "audit.db")
	if err != nil || store == nil {
		t.Fatalf("open = %v, %v; want the store once the guardian repaired it", store, err)
	}
	if *attempts != 4 {
		t.Fatalf("attempts = %d, want 4", *attempts)
	}
}

func TestOpenGatewayAuditStoreFailsFastOutsideManagedMode(t *testing.T) {
	attempts := stubGatewayAuditOpen(t, 3)
	if _, err := openGatewayAuditStore(context.Background(), "", "audit.db"); err == nil {
		t.Fatal("unmanaged open succeeded after a failure")
	}
	if *attempts != 1 {
		t.Fatalf("attempts = %d, want 1", *attempts)
	}
}

func TestOpenGatewayAuditStoreStopsWhenCancelled(t *testing.T) {
	stubGatewayAuditOpen(t, 1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openGatewayAuditStore(ctx, "managed_enterprise", "audit.db"); err == nil {
		t.Fatal("cancelled open succeeded")
	}
}
