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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// TestActorListenerAnswersVerifyProbes: verify's actor_service_routes check
// (GAP-0209) asks the actor Service for fleet.ActorListenerProbes without a
// token and counts every answer but 404 as a served route. On the real
// actor listener exactly the actor routes answer (401), so the check passes
// on a correct gateway and fails on one that serves anything else.
func TestActorListenerAnswersVerifyProbes(t *testing.T) {
	f := newSubstrateFixture(t)
	served := 0
	for _, path := range fleet.ActorListenerProbes {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		f.actor.ServeHTTP(rec, req)
		if got, want := rec.Code != http.StatusNotFound, fleet.ActorRouteAllowed(path); got != want {
			t.Errorf("GET %s without a token: %d; verify would count it served=%v, want %v", path, rec.Code, got, want)
		}
		if rec.Code != http.StatusNotFound {
			served++
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("GET %s without a token: %d, want 401", path, rec.Code)
			}
		}
	}
	if served == 0 {
		t.Fatal("no probe reached an actor route")
	}
}
