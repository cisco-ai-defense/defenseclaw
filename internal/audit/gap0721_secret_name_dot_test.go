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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// GAP-0721: substrate.secrets[].name accepts a DNS-1123 subdomain (dots,
// up to 253 bytes); defenseclaw.secret.name must take every name the
// configuration accepts, or the change record of a dotted name is refused.
func TestGAP0721DottedSecretNameIsRecorded(t *testing.T) {
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60)
	for _, name := range []string{"github.work", "npm.corp-1.example", long} {
		cfg := config.SubstrateConfig{Secrets: []config.SubstrateSecret{{Name: name}}}
		if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "secrets[0].name") {
			t.Fatalf("%q: config refuses the name: %v", name, err)
		}
		harness := newSandboxHarness(t)
		_, recorder := harness.bind(t, router.AdmissionOrdinary)
		if err := recorder.RecordSubstrateSecretChange(context.Background(), SubstrateSecretChangeEvent{
			Name: name, Operation: SubstrateSecretSet,
		}); err != nil {
			t.Errorf("%q: the change record is refused: %v", name, err)
		}
	}
}
