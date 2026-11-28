// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// substrateWorkspaceEvent is POST .../actors/{atespace}/{name}/workspace-event:
// the owner's launcher reports a checkpoint it took or an undo it ran with
// git inside the actor, which the controller never sees, so the leader's
// chain state can follow it (substrate-1:GAP-0476). Only the agent's own
// person reports one, as for a session (checkpoint and undo run through
// one). The body: event (checkpoint or undo), checkpoint (the commit) and,
// for an undo, removed and restored (path digests of the files it
// reverted). The answer: forgotten (chain events changed) and
// checkpoint_known. 501 chain_unavailable without the leader's chain
// state; 502 chain_report_failed when the leader refused or did not answer
// (an older leader knows neither event).
func (a *APIServer) substrateWorkspaceEvent(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if st.cfg.Chains == nil {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "chain_unavailable")
			return
		}
		reg, status, reason := a.substrateFindSession(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		var in struct {
			Event      string   `json:"event"`
			Checkpoint string   `json:"checkpoint"`
			Removed    []string `json:"removed,omitempty"`
			Restored   []string `json:"restored,omitempty"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_workspace_event")
			return
		}
		ev := chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: reg.Atespace, UID: reg.UID}, Checkpoint: in.Checkpoint}
		switch in.Event {
		case "checkpoint":
			if len(in.Removed)+len(in.Restored) > 0 {
				writeSubstrateJSONError(w, http.StatusBadRequest, "bad_workspace_event")
				return
			}
			ev.Event = chainstate.LifecycleCheckpointed
		case "undo":
			ev.Event, ev.Removed, ev.Restored = chainstate.LifecycleUndone, in.Removed, in.Restored
		default:
			writeSubstrateJSONError(w, http.StatusBadRequest, "bad_workspace_event")
			return
		}
		res, err := st.cfg.Chains.Lifecycle(r.Context(), ev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[substrate] %s report of %s/%s to the chain state failed: %v\n", in.Event, reg.Atespace, reg.Name, err)
			writeSubstrateJSONError(w, http.StatusBadGateway, "chain_report_failed")
			return
		}
		writeSubstrateJSON(w, http.StatusOK, map[string]any{"forgotten": res.Forgotten, "checkpoint_known": !res.CheckpointUnknown})
	}
}
