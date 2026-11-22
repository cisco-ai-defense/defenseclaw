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

package extproc

import (
	"context"
	"testing"
)

// TestAdminServiceRefused is GAP-0066: the admin listener is never reached
// through egress, in any spelling, even when listed as a DefenseClaw host.
func TestAdminServiceRefused(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.DefenseClawHosts = append(c.DefenseClawHosts, "defenseclaw-admin.defenseclaw-system.svc")
	})
	for _, host := range []string{"defenseclaw-admin.defenseclaw-system.svc.cluster.local", "defenseclaw-admin.defenseclaw-system.svc",
		"defenseclaw-admin.defenseclaw-system", "defenseclaw-admin", "DefenseClaw-Admin.defenseclaw-system.svc.", "defenseclaw-admin:8443"} {
		v := h.eng.DecideHeaders(context.Background(), req("eng-web", "POST", host, "/api/v1/substrate/callout/verdict"))
		if v.Allow || v.Category != CategoryInternalHost {
			t.Errorf("%s: %+v", host, v)
		}
	}
	if v := h.eng.DecideHeaders(context.Background(), req("eng-web", "POST", "defenseclaw-actor.defenseclaw-system.svc", "/api/v1/substrate/hook/claude-code")); !v.Allow || !v.OwnHost {
		t.Errorf("actor listener: %+v", v)
	}
}
