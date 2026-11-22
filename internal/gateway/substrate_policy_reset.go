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
	"encoding/json"
	"io"
	"net/http"
)

// SubstratePolicyReset asks the controller to clear an actor's
// policy_conflict (controller.RequestReset); by names the admin.
type SubstratePolicyReset func(ctx context.Context, atespace, actor, by, reason string) error

// substratePolicyReset is POST /api/v1/substrate/actors/{atespace}/{name}/policy/reset
// (admins only): it records an audited request; the controller writes
// DefenseClaw's policy again on its next pass and drift handling starts
// over. `defenseclaw substrate policy reset <actor>` calls it.
func (a *APIServer) substratePolicyReset(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.PolicyReset == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "policy_reset_unavailable")
			return
		}
		caller, ok := substrateCallerFrom(r.Context())
		if !ok || !caller.admin {
			writeSubstrateJSONError(w, http.StatusForbidden, "admin_only")
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
		if err == nil && len(raw) > 0 && json.Unmarshal(raw, &body) != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "invalid_body")
			return
		}
		by := caller.person.Principal
		if by == "" {
			by = caller.person.ID()
		}
		atespace, name := r.PathValue("atespace"), r.PathValue("name")
		if err := st.cfg.PolicyReset(r.Context(), atespace, name, by, body.Reason); err != nil {
			writeSubstrateJSONError(w, http.StatusBadGateway, "policy_reset_failed")
			return
		}
		writeSubstrateJSON(w, http.StatusAccepted, map[string]string{"status": "requested", "atespace": atespace, "actor": name, "by": by})
	}
}
