// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"reflect"
	"testing"
)

// TestMergeEnvelopeCoversEveryField keeps MergeEnvelope in step with the
// struct: a field added without a merge rule would silently drop from
// every merged envelope.
func TestMergeEnvelopeCoversEveryField(t *testing.T) {
	var overlay CorrelationEnvelope
	v := reflect.ValueOf(&overlay).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() != reflect.String {
			t.Fatalf("field %s is not a string; extend this test", v.Type().Field(i).Name)
		}
		v.Field(i).SetString("overlay-" + v.Type().Field(i).Name)
	}
	merged := MergeEnvelope(CorrelationEnvelope{}, overlay)
	if merged != overlay {
		t.Fatalf("MergeEnvelope dropped fields:\n got %+v\nwant %+v", merged, overlay)
	}
	base := CorrelationEnvelope{SandboxID: "sbx-base", SandboxName: "dc-base"}
	merged = MergeEnvelope(base, overlay)
	if merged.SandboxID != "sbx-base" || merged.SandboxName != "dc-base" {
		t.Fatalf("base sandbox identity must win: %+v", merged)
	}
}

func TestSandboxEnvelopeRoundTripsThroughContext(t *testing.T) {
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{SandboxID: "sbx-1", SandboxName: "dc-claude-app"})
	got := EnvelopeFromContext(ctx)
	if got.SandboxID != "sbx-1" || got.SandboxName != "dc-claude-app" {
		t.Fatalf("envelope = %+v", got)
	}
}
