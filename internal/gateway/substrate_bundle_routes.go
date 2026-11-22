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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// SubstrateBundles is the signed policy bundle store of the cluster
// (internal/substrate/bundle.Store through an adapter): the admin listener
// applies, rolls back and shows bundles for administrators only.
type SubstrateBundles interface {
	Apply(ctx context.Context, archive []byte, stage string, atespaces []string) (receipt any, err error)
	Rollback(ctx context.Context, stage string) (receipt any, err error)
	Status(ctx context.Context) (any, error)
}

// SubstrateBundleApplyRequest is the body of POST /api/v1/substrate/bundle.
// The admin listener takes JSON only (CSRF gate), so the archive is
// base64.
type SubstrateBundleApplyRequest struct {
	Name      string   `json:"name,omitempty"`
	Bundle    []byte   `json:"bundle"`
	Stage     string   `json:"stage,omitempty"`
	Atespaces []string `json:"atespaces,omitempty"`
}

// substrateBundleStage is the stage of an apply that names none: all for no
// atespaces; otherwise one stage per atespace set, so the same set always
// lands in the same stage.
func substrateBundleStage(stage string, atespaces []string) string {
	if stage = strings.TrimSpace(stage); stage != "" {
		return stage
	}
	if len(atespaces) == 0 {
		return "all"
	}
	set := slices.Clone(atespaces)
	slices.Sort(set)
	sum := sha256.Sum256([]byte(strings.Join(slices.Compact(set), ",")))
	return "s-" + hex.EncodeToString(sum[:5])
}

func substrateBundleAdmin(w http.ResponseWriter, r *http.Request, st *substrateState) bool {
	if st.cfg.Bundles == nil {
		writeSubstrateJSONError(w, http.StatusNotImplemented, "bundles_off")
		return false
	}
	if c, ok := substrateCallerFrom(r.Context()); !ok || !c.admin {
		writeSubstrateJSONError(w, http.StatusForbidden, "admin_only")
		return false
	}
	return true
}

func writeSubstrateBundleResult(w http.ResponseWriter, receipt any, err error) {
	if err == nil {
		writeSubstrateJSON(w, http.StatusOK, receipt)
		return
	}
	if code := enterprisebundle.CodeOf(err); code != "" {
		writeSubstrateJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "bundle refused", "reason": string(code), "detail": err.Error(), "receipt": receipt})
		return
	}
	writeSubstrateJSONError(w, http.StatusServiceUnavailable, "bundle_store_unavailable")
}

func (a *APIServer) substrateBundleApply(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !substrateBundleAdmin(w, r, st) {
			return
		}
		var req SubstrateBundleApplyRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || len(req.Bundle) == 0 {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		rc, err := st.cfg.Bundles.Apply(r.Context(), req.Bundle, substrateBundleStage(req.Stage, req.Atespaces), req.Atespaces)
		writeSubstrateBundleResult(w, rc, err)
	}
}

func (a *APIServer) substrateBundleRollback(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !substrateBundleAdmin(w, r, st) {
			return
		}
		var req struct {
			Stage string `json:"stage"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Stage) == "" {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_request")
			return
		}
		rc, err := st.cfg.Bundles.Rollback(r.Context(), strings.TrimSpace(req.Stage))
		writeSubstrateBundleResult(w, rc, err)
	}
}

func (a *APIServer) substrateBundleStatus(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !substrateBundleAdmin(w, r, st) {
			return
		}
		s, err := st.cfg.Bundles.Status(r.Context())
		if err != nil {
			writeSubstrateBundleResult(w, nil, err)
			return
		}
		writeSubstrateJSON(w, http.StatusOK, s)
	}
}
