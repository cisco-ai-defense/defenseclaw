// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// GAP-0448: helm leaves a rollback the pre-rollback hook refused as a
// pending-rollback revision, and every later helm upgrade fails until it is
// cleared. The refusal names the recovery with this release and namespace.
func TestGAP0448RefusedRollbackNamesTheRecovery(t *testing.T) {
	ctx := context.Background()
	plan := testPlan()
	kube := newFakeKube()
	kube.cms["defenseclaw-system/defenseclaw-store-state"] = &ConfigMap{Data: StoreState{SchemaVersion: 2, WrittenByVersion: "dev"}.Data()}
	_, err := PreRollback(ctx, plan, kube)
	var rs *ErrRollbackSchema
	if !errors.As(err, &rs) {
		t.Fatalf("rollback across a schema change: %v", err)
	}
	for _, want := range []string{
		"No backup is recorded",
		"pending-rollback",
		"helm -n defenseclaw-system rollback dc N",
		"helm -n defenseclaw-system history dc",
		"deployed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	// A rollback the store allows says nothing about recovery.
	plan.StoreSchema = 2
	if _, err := PreRollback(ctx, plan, kube); err != nil {
		t.Fatalf("same schema: %v", err)
	}
}
