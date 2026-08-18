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
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// NewLocalProjectionBinding converts one compiled plan and exact redaction
// engine into the sealed audit binding used by mandatory local persistence.
// The complete resolved profile values are snapshotted, not merely their
// route-selectable names.
func NewLocalProjectionBinding(
	plan *config.ObservabilityV8Plan,
	engine *redaction.Engine,
) (*audit.TrustedLocalProjectionBinding, error) {
	if plan == nil || engine == nil || plan.Digest() == "" {
		return nil, fmt.Errorf("observability local projection binding dependencies are invalid")
	}
	catalog, err := plan.RedactionProfileCatalog()
	if err != nil {
		return nil, fmt.Errorf("observability local projection binding catalog is invalid")
	}
	profiles := make(map[observability.Bucket]redaction.Profile, len(observability.Buckets()))
	for _, bucket := range observability.Buckets() {
		name, resolveErr := plan.ResolveLocalRedactionProfile(bucket)
		if resolveErr != nil {
			return nil, fmt.Errorf("observability local projection binding is incomplete")
		}
		profile, ok := catalog.Resolve(name)
		if !ok {
			return nil, fmt.Errorf("observability local projection binding profile is unavailable")
		}
		profiles[bucket] = profile
	}
	binding, err := audit.NewTrustedLocalProjectionBinding(plan.Digest(), engine, profiles)
	if err != nil {
		return nil, fmt.Errorf("observability local projection binding is invalid")
	}
	return binding, nil
}
