// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPolicyStampReadsOneAppliedGeneration(t *testing.T) {
	old := &Generation{Config: &config.Config{}, Digest: "digest-old", N: 7}
	newer := &Generation{Config: &config.Config{}, Digest: "digest-new", N: 8}
	loads := 0
	digest, generation := policyStampFromLoad(func() *Generation {
		loads++
		if loads == 1 {
			return old
		}
		return newer
	})
	gotDigest, hasDigest := digest.Get()
	gotGeneration, hasGeneration := generation.Get()
	if loads != 1 || !hasDigest || !hasGeneration ||
		gotDigest != old.Digest || gotGeneration != int64(old.N) {
		t.Fatalf("policy stamp split generations: loads=%d digest=%v generation=%v", loads, digest, generation)
	}
}
