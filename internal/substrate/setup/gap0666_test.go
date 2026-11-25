// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// failingGet makes the store-state read fail like an unreachable API server.
type failingGet struct {
	KubeAPI
	err error
}

func (f failingGet) GetConfigMap(context.Context, string, string) (*ConfigMap, error) {
	return nil, f.err
}

// GAP-0666: helm writes the pending-rollback revision before the hook runs,
// so every failed pre-rollback hook leaves it, not only the schema refusal.
// A store-state read that fails (kube error) or a store state that does not
// parse names the same recovery, and keeps its own cause.
func TestGAP0666EveryFailedPreRollbackNamesTheRecovery(t *testing.T) {
	ctx := context.Background()
	plan := testPlan()
	wantRecovery := []string{"pending-rollback", "helm -n defenseclaw-system rollback dc N", "helm -n defenseclaw-system history dc"}

	bad := newFakeKube()
	bad.cms["defenseclaw-system/defenseclaw-store-state"] = &ConfigMap{Data: map[string]string{StoreStateSchemaKey: "not-a-number"}}
	cause := errors.New("connection refused")
	for _, tc := range []struct {
		name  string
		kube  KubeAPI
		cause string
	}{
		{"kube error", failingGet{KubeAPI: newFakeKube(), err: cause}, "connection refused"},
		{"unparsable store state", bad, "is not a schema version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PreRollback(ctx, plan, tc.kube)
			if err == nil {
				t.Fatal("the pre-rollback hook passed")
			}
			for _, want := range append([]string{tc.cause}, wantRecovery...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("failed hook lacks %q: %v", want, err)
				}
			}
		})
	}
	if _, err := PreRollback(ctx, plan, newFakeKube()); err != nil {
		t.Fatalf("a fresh store refused: %v", err)
	}
	if err := errors.Unwrap(func() error { _, e := PreRollback(ctx, plan, failingGet{KubeAPI: newFakeKube(), err: cause}); return e }()); !errors.Is(err, cause) {
		t.Errorf("the kube error is not kept as the cause: %v", err)
	}
}
