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

package pipeline

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestNewLocalProjectionBindingCapturesCompiledGraph(t *testing.T) {
	source := &config.ObservabilityV8Source{
		RedactionProfiles: map[string]config.ObservabilityV8RedactionProfileSource{
			"local-content": {
				Extends: redactionProfileSourceName(redaction.ProfileSensitive),
				FieldClasses: map[config.ObservabilityV8FieldClass]config.ObservabilityV8FieldMode{
					config.ObservabilityV8FieldContent: config.ObservabilityV8ModeWhole,
				},
			},
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketDiagnostic: {RedactionProfile: "local-content"},
		},
	}
	plan, _ := mustPlanEvaluator(t, source)
	engine := mustEngine(t)
	binding, err := NewLocalProjectionBinding(plan, engine)
	if err != nil {
		t.Fatal(err)
	}
	if binding.GraphDigest() != plan.Digest() {
		t.Fatalf("binding digest = %q, want %q", binding.GraphDigest(), plan.Digest())
	}

	// Source mutation cannot change the already-compiled binding.
	source.Buckets[observability.BucketDiagnostic] = config.ObservabilityV8BucketPolicySource{
		RedactionProfile: string(redaction.ProfileStrict),
	}
	if binding.GraphDigest() != plan.Digest() {
		t.Fatal("source mutation changed the graph binding")
	}
}

func TestNewLocalProjectionBindingRejectsInvalidDependencies(t *testing.T) {
	plan, _ := mustPlanEvaluator(t, nil)
	if _, err := NewLocalProjectionBinding(nil, mustEngine(t)); err == nil {
		t.Fatal("nil plan was accepted")
	}
	if _, err := NewLocalProjectionBinding(plan, nil); err == nil {
		t.Fatal("nil engine was accepted")
	}
	if _, err := NewLocalProjectionBinding(&config.ObservabilityV8Plan{}, mustEngine(t)); err == nil {
		t.Fatal("plan without a compiled digest was accepted")
	}
}

func redactionProfileSourceName(name redaction.ProfileName) string { return string(name) }
