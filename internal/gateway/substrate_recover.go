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
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// SubstrateActorRecoverer brings a crashed actor back: the launcher's undo
// of an actor whose worker went away (GAP-0410). Actions that cannot do it
// leave the route answering 501.
type SubstrateActorRecoverer interface {
	Recover(ctx context.Context, atespace, name string) error
}

// ErrSubstrateNotCrashed is a recover of an actor that is not CRASHED.
var ErrSubstrateNotCrashed = errors.New("the actor has not crashed")

// errSubstrateNoRevert is a control API client without RevertActor.
var errSubstrateNoRevert = errors.New("the control API client cannot revert actors")

// Recover reverts a CRASHED actor to its last durable snapshot (SUSPENDED,
// as kubectl ate revert actor does) and resumes it with its policy, so the
// person's agent runs again from the state it last saved.
func (s *SubstrateATEActions) Recover(ctx context.Context, atespace, name string) error {
	rv, ok := s.Client.(ateapi.Reverter)
	if !ok {
		return errSubstrateNoRevert
	}
	ref := ateapi.Ref(atespace, name)
	a, err := s.Client.GetActor(ctx, ref)
	if err != nil {
		return err
	}
	if a.GetStatus().GetState() != ateapi.ActorStateCrashed {
		return fmt.Errorf("%w (it is %s)", ErrSubstrateNotCrashed, a.GetStatus().GetState())
	}
	if _, err := rv.RevertActor(ctx, ref); err != nil {
		return fmt.Errorf("revert: %w", err)
	}
	return s.Resume(ctx, atespace, name)
}

// substrateRecoverActor is POST .../actors/{atespace}/{name}/recover: the
// owner (or an administrator) brings a crashed actor back.
func (a *APIServer) substrateRecoverActor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, ok := st.cfg.Actions.(SubstrateActorRecoverer)
		if st.cfg.Actions == nil || !ok {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "recover_unavailable")
			return
		}
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		a.substrateAuditAdminTarget(st, r, reg, "recover", "HIGH")
		err := rec.Recover(r.Context(), reg.Atespace, reg.Name)
		switch {
		case errors.Is(err, ErrSubstrateNotCrashed):
			writeSubstrateJSONError(w, http.StatusConflict, "not_crashed")
			return
		case errors.Is(err, ErrSubstrateNoWorker):
			w.Header().Set("Retry-After", "30")
			writeSubstrateJSONError(w, http.StatusServiceUnavailable, "no_worker")
			return
		case errors.Is(err, errSubstrateNoRevert):
			writeSubstrateJSONError(w, http.StatusNotImplemented, "recover_unavailable")
			return
		case err != nil:
			fmt.Fprintf(os.Stderr, "[substrate] recover of %s/%s failed: %v\n", reg.Atespace, reg.Name, err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "recover_failed")
			return
		}
		if inv, ok := st.cfg.Actors.(interface{ Invalidate(string, string) }); ok {
			inv.Invalidate(reg.Atespace, reg.Name)
		}
		fmt.Fprintf(os.Stderr, "[substrate] actor %s/%s recovered from a crash to its last snapshot\n", reg.Atespace, reg.Name)
		v := substrateActorView(reg)
		v["state"] = "running"
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}
