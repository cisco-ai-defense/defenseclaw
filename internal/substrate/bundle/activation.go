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

package bundle

import (
	"context"
	"errors"
	"fmt"
)

// Activated reports whether the bundle state is a managed gateway's
// activated config (GAP-0135, the second source after the chart-mounted
// file): at least one stage has an active bundle, and every stage's active
// bundle verifies now against the anchors and the boot config (signature,
// key status, tenant, version floor, the policy over Base). A stage that
// no longer verifies refuses the start, since a managed policy must never
// loosen by itself (D8); no bundle at all is not an activation.
func (s *Store) Activated(ctx context.Context) error {
	snap, problems, err := s.Load(ctx)
	if err != nil {
		return fmt.Errorf("substrate activation: bundle state: %w", err)
	}
	if len(problems) > 0 {
		p := problems[0]
		return fmt.Errorf("substrate activation: the active bundle of stage %s does not verify (%s): %s", p.Stage, p.Code, p.Error)
	}
	if snap.For("") != nil {
		return nil // stage all
	}
	for _, a := range snap.Atespaces {
		if snap.For(a) != nil {
			return nil
		}
	}
	return errors.New("substrate activation: no signed bundle is applied")
}
