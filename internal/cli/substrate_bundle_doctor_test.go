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

package cli

import (
	"context"
	"strings"
	"testing"
)

// GAP-0429: the gateway doctor (what `defenseclaw substrate doctor` shows
// an administrator) fails when a stage's bundle no longer verifies against
// the anchors the gateway reads, and names the stage, the code and the fix.
func TestSubstrateBundleDoctorCheck(t *testing.T) {
	c := newBundleCluster(t)
	if got := substrateBundleCheck(context.Background(), c.store, false); got.Status != "pass" {
		t.Fatalf("verified bundle: %+v", got)
	}
	c.rotateAnchors(t)
	got := substrateBundleCheck(context.Background(), c.store, false)
	if got.Status != "fail" || !strings.Contains(got.Detail, "stage s-eng (signature_invalid)") ||
		!strings.Contains(got.Detail, "fall back to config.yaml") || !strings.Contains(got.Fix, "bundle apply") {
		t.Fatalf("rotated anchors: %+v", got)
	}
	if got := substrateBundleCheck(context.Background(), c.store, true); !strings.Contains(got.Detail, "deny-only") {
		t.Errorf("managed: %+v", got)
	}
}
