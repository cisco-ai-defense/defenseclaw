// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "testing"

// release105Digest is the kernel_policy digest of 1.0.1 to 1.0.5. 1.0.6
// adds kernel.ssh_authorized_keys_write, so the digest changes (#1172).
const release105Digest = "sha256:08b71155b713"

// An administrator who pushes the 1.0.5 and 1.0.6 digests before the
// upgrade keeps enforcement across it; the 1.0.5 digest alone goes stale
// (monitor until the new digest is added), as the docs say.
func TestPreAckedUpgradeKeepsEnforcement(t *testing.T) {
	if Digest() == release105Digest {
		t.Fatal("the authorized keys control must change the kernel_policy digest")
	}
	preAcked := Intent{Mode: ModeEnforce, EnforceAcks: []string{release105Digest, Digest()}}
	if !preAcked.Approves() || preAcked.Approval() != ApprovalApproved {
		t.Fatalf("pre-acked list %v: approves=%v approval=%s", preAcked.EnforceAcks, preAcked.Approves(), preAcked.Approval())
	}
	oldOnly := Intent{Mode: ModeEnforce, EnforceAcks: []string{release105Digest}}
	if oldOnly.Approves() || oldOnly.Approval() != ApprovalStale {
		t.Fatalf("1.0.5 ack alone: approves=%v approval=%s, want stale", oldOnly.Approves(), oldOnly.Approval())
	}
}
