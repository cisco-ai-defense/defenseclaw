// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestRuntimeAlertAcknowledgementRejectsMismatchedLocalGeneration(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)

	lease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	componentValue, ok := lease.Component(LocalLogComponentName)
	if !ok {
		lease.Release()
		t.Fatal("active graph has no local component")
	}
	component, ok := componentValue.(*localLogComponent)
	if !ok {
		lease.Release()
		t.Fatal("active graph local component has an unexpected type")
	}
	component.digest = "mismatched-local-generation"
	lease.Release()

	_, applyErr := runtime.ApplyAlertAcknowledgement(
		t.Context(),
		audit.AlertAcknowledgementCommand{},
	)
	var runtimeErr *Error
	if !errors.As(applyErr, &runtimeErr) || runtimeErr.Code() != ErrorComponentUnavailable {
		t.Fatalf("mismatched local generation error=%v", applyErr)
	}
}
