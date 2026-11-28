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

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// TestB1SubstrateSecretChangeTyped: a Substrate secret change is one typed
// log.substrate.secret.changed record (M-OBS-1) with the name, operation,
// host and owner pseudonym, never the value; an unknown operation and a
// nameless change are refused.
func TestB1SubstrateSecretChangeTyped(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
	key := "hmac-sha256:" + strings.Repeat("ab", 32)
	if err := recorder.RecordSubstrateSecretChange(context.Background(), SubstrateSecretChangeEvent{
		Name: "gl-work", Operation: SubstrateSecretBindingAdded, Host: "Git.Corp.Example", SubjectKey: key,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	metadata, record := onlySandboxRecord(t, runtime)
	assertRecordMatchesRuntimeContract(t, record)
	if got := string(metadata.Identity().Name); got != observability.TelemetryEventSubstrateSecretChanged {
		t.Fatalf("event name %q", got)
	}
	assertSandboxFields(t, sandboxBody(t, record), map[string]any{
		"defenseclaw.secret.name":                "gl-work",
		"defenseclaw.substrate.secret.operation": "binding_added",
		"defenseclaw.network.target_ref":         "git.corp.example:443",
		"defenseclaw.subject.key":                key,
	})
	for _, bad := range []SubstrateSecretChangeEvent{
		{Name: "gl-work", Operation: "rotated"},
		{Name: " ", Operation: SubstrateSecretSet},
	} {
		if err := recorder.RecordSubstrateSecretChange(context.Background(), bad); err == nil {
			t.Fatalf("%+v recorded, want refused", bad)
		}
	}
	if _, records := runtime.snapshot(); len(records) != 1 {
		t.Fatalf("records=%d after refusals, want 1", len(records))
	}
}
