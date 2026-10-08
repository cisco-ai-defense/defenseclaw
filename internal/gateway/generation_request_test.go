// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPinnedGenerationDecidesARequestWhileReloadsPublish(t *testing.T) {
	// GAP-0455: a reload published the next generation's digest before the
	// enforcement components switched packs, so a record could carry one
	// generation's digest for a decision another generation's rules made.
	resetConnectorRuleCategories(t) // an earlier test may have registered codex rules
	before := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(before) })
	generations := [2]*Generation{
		{N: 1, Config: &config.Config{}, Digest: "sha256:a", activeRules: &compiledRulePackCategories{}},
		{N: 2, Config: &config.Config{}, Digest: "sha256:b", activeRules: &compiledRulePackCategories{}},
	}
	liveGeneration.Store(generations[0])
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				liveGeneration.Store(generations[i%2])
			}
		}
	}()
	defer func() { close(stop); <-done }()

	for i := 0; i < 5000; i++ {
		ctx := withPinnedGeneration(context.Background(), currentGeneration())
		rules := snapshotRulePackGenerationFor(ctx, "codex")
		digest, _ := policyDigestV8(ctx).Get()
		want := generations[0]
		if digest == generations[1].Digest {
			want = generations[1]
		}
		if rules != want.activeRules {
			t.Fatalf("request %d stamped %s but scanned with another generation's rules", i, digest)
		}
		if requestPolicyConfig(ctx) != want.Config {
			t.Fatalf("request %d stamped %s but decided with another generation's configuration", i, digest)
		}
	}
}
