// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"strings"
	"testing"
)

// GAP-0917: a store-state ConfigMap that does not parse fails the pre-rollback
// hook on every run, so a recovery that only says "helm rollback" runs into the
// same failure. The text names the ConfigMap repair first, and the repair makes
// the hook pass.
func TestGAP0917UnparsableStoreStateNamesTheConfigMapRepairFirst(t *testing.T) {
	ctx := context.Background()
	plan := testPlan()
	kube := newFakeKube()
	cm := &ConfigMap{Data: map[string]string{StoreStateSchemaKey: "not-a-number"}}
	kube.cms["defenseclaw-system/defenseclaw-store-state"] = cm

	_, err := PreRollback(ctx, plan, kube)
	if err == nil {
		t.Fatal("the pre-rollback hook passed on an unparsable store state")
	}
	msg := err.Error()
	repair := strings.Index(msg, "kubectl -n defenseclaw-system edit configmap defenseclaw-store-state")
	rollback := strings.Index(msg, "helm -n defenseclaw-system rollback dc N")
	if repair < 0 || rollback < 0 || repair > rollback {
		t.Errorf("the ConfigMap repair must come before the helm rollback: %v", err)
	}
	for _, want := range []string{"schema_version", "kubectl -n defenseclaw-system delete configmap defenseclaw-store-state", "pending-rollback"} {
		if !strings.Contains(msg, want) {
			t.Errorf("recovery lacks %q: %v", want, err)
		}
	}

	// The repair it names clears the failure.
	cm.Data[StoreStateSchemaKey] = "1"
	if _, err := PreRollback(ctx, plan, kube); err != nil {
		t.Fatalf("after the repair: %v", err)
	}
}
