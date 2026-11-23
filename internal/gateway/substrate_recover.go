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
		// GAP-0861: the relay of a recovered actor lost its key, so its
		// next certificate request has no proof; recover is the owner's or
		// an administrator's way to let it through in refuse mode
		// (defenseclaw substrate recover, GAP-0930). The record is cleared
		// first, also for an actor that has not crashed (a relay that
		// restarted inside a running actor, or an emergency CA rotation);
		// recover's mark keeps any certificate issued before it from
		// renewing (GAP-0928).
		cleared := false
		if st.cfg.RelayCerts != nil {
			row := map[string]any{"atespace": reg.Atespace, "actor": reg.Name, "actor_uid": reg.UID}
			if cerr := st.cfg.RelayCerts.ClearRelayCert(r.Context(), reg.Atespace, reg.UID); cerr != nil {
				a.substrateRelayCertAudit(st, r, "HIGH", "recover of "+reg.Atespace+"/"+reg.Name+": the relay certificate record was not cleared",
					"substrate.relay.cert_record_cleared", row, map[string]any{"relay_cert_record": "unavailable", "error": cerr.Error()})
				fmt.Fprintf(os.Stderr, "[substrate] recover of %s/%s: the relay certificate record was not cleared: %v\n", reg.Atespace, reg.Name, cerr)
				writeSubstrateJSONError(w, http.StatusServiceUnavailable, "relay_cert_record_unavailable")
				return
			}
			cleared = true
			a.substrateRelayCertAudit(st, r, "HIGH", "recover of "+reg.Atespace+"/"+reg.Name+" cleared the relay certificate record: the relay's next request without proof gets a first certificate, and no certificate issued before renews",
				"substrate.relay.cert_record_cleared", row, map[string]any{"relay_cert_record": "cleared"})
		}
		err := rec.Recover(r.Context(), reg.Atespace, reg.Name)
		switch {
		case errors.Is(err, ErrSubstrateNotCrashed):
			// The CLI reads relay_cert_record to say what recover did to a
			// running agent.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": http.StatusText(http.StatusConflict), "reason": "not_crashed", "relay_cert_record_cleared": cleared})
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
		v := st.actorView(reg)
		v["state"] = "running"
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}
