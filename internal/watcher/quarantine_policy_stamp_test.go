// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// p0 GAP-1000: a quarantine names the policy generation of the admission
// decision that ordered it; without a decision on ctx the audit logger
// falls back to the live stamp.
func TestQuarantineAuditNamesTheDecisionPolicy(t *testing.T) {
	evt := InstallEvent{Type: InstallSkill, Name: "risky", Path: "/skills/risky"}
	if input := quarantineAppliedInput(context.Background(), evt, "/quarantine/risky"); input.PolicyStamped {
		t.Fatalf("no decision on ctx: input = %+v, want the live stamp", input)
	}
	ctx := withDecisionPolicy(context.Background(), AdmissionPolicySnapshot{
		Digest: observability.Present("sha256:decision"), Generation: observability.Present(int64(7)),
	})
	input := quarantineAppliedInput(ctx, evt, "/quarantine/risky")
	digest, _ := input.PolicyDigest.Get()
	generation, _ := input.PolicyGeneration.Get()
	if !input.PolicyStamped || digest != "sha256:decision" || generation != 7 {
		t.Fatalf("input stamp = %v %q %d, want the decision's sha256:decision / 7", input.PolicyStamped, digest, generation)
	}
}
