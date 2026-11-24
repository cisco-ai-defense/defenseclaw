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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// SubstrateActorRecoverer brings a crashed actor back: the launcher's undo
// of an actor whose worker went away (GAP-0410). Actions that cannot do it
// leave the route answering 501.
type SubstrateActorRecoverer interface {
	Recover(ctx context.Context, atespace, name string) (SubstrateRecovery, error)
}

// SubstrateRecovery is the snapshot a recovered actor came back from.
type SubstrateRecovery struct {
	// FromTemplate: the actor had no snapshot of its own in durable
	// storage, so the revert took it back to its template's (golden)
	// snapshot, owned by a tag. The folder copied into it and its restore
	// points are gone (GAP-0410). False when no snapshot is listed at all:
	// that is not evidence of a loss.
	FromTemplate bool
	// Generation is the snapshot generation it came back from.
	Generation int32
}

// SubstrateActorSnapshotter keeps a running actor's state in the cluster's
// durable snapshot storage, so a crash recovery returns to it and not to
// the template's snapshot (GAP-0410): the launcher's checkpoint calls it
// after it saves a restore point in the actor.
type SubstrateActorSnapshotter interface {
	Snapshot(ctx context.Context, atespace, name string) (SubstrateKept, error)
}

// SubstrateKept is a snapshot Snapshot stored.
type SubstrateKept struct {
	Generation int32
	// Running: the actor was resumed after the snapshot. When false it
	// stays SUSPENDED at that snapshot, and the next connect starts it.
	Running bool
	// NoWorker: the resume found no room in the pool.
	NoWorker bool
}

// substrateSnapshotTimeout bounds a snapshot (the durable suspend and the
// resume after it). It runs detached from the request, so a launcher that
// stops waiting never leaves the agent suspended.
const substrateSnapshotTimeout = 5 * time.Minute

var (
	// ErrSubstrateNotCrashed is a recover of an actor that is not CRASHED.
	ErrSubstrateNotCrashed = errors.New("the actor has not crashed")
	// ErrSubstrateNotRunning is a snapshot of an actor that is not RUNNING.
	ErrSubstrateNotRunning = errors.New("the actor is not running")
	// errSubstrateNoRevert is a control API client without RevertActor.
	errSubstrateNoRevert = errors.New("the control API client cannot revert actors")
	// errSubstrateNoDurableSuspend is a control API client without a
	// synchronous suspend.
	errSubstrateNoDurableSuspend = errors.New("the control API client cannot store a snapshot durably")
	// errSubstrateKeptNotResumed is a snapshot that was stored, then the
	// actor could not be started again.
	errSubstrateKeptNotResumed = errors.New("the snapshot is stored but the actor did not start again")
)

// Recover reverts a CRASHED actor to its last durable snapshot (SUSPENDED,
// as kubectl ate revert actor does) and resumes it with its policy, so the
// person's agent runs again from the state it last saved. The result says
// whether that was a snapshot of its own or only the template's.
func (s *SubstrateATEActions) Recover(ctx context.Context, atespace, name string) (SubstrateRecovery, error) {
	rv, ok := s.Client.(ateapi.Reverter)
	if !ok {
		return SubstrateRecovery{}, errSubstrateNoRevert
	}
	ref := ateapi.Ref(atespace, name)
	a, err := s.Client.GetActor(ctx, ref)
	if err != nil {
		return SubstrateRecovery{}, err
	}
	if a.GetStatus().GetState() != ateapi.ActorStateCrashed {
		return SubstrateRecovery{}, fmt.Errorf("%w (it is %s)", ErrSubstrateNotCrashed, a.GetStatus().GetState())
	}
	ra, err := rv.RevertActor(ctx, ref)
	if err != nil {
		return SubstrateRecovery{}, fmt.Errorf("revert: %w", err)
	}
	if ra.GetStatus() == nil {
		if ra, err = s.Client.GetActor(ctx, ref); err != nil {
			return SubstrateRecovery{}, err
		}
	}
	// A revert drops a newest snapshot that was never uploaded, so the
	// newest one left is the one the actor resumes from.
	h := newestSnapshot(ra.GetStatus())
	rec := SubstrateRecovery{FromTemplate: h != nil && h.GetOwner() == ateapi.SnapshotOwnerTag, Generation: h.GetGeneration()}
	return rec, s.Resume(ctx, atespace, name)
}

// Snapshot suspends a RUNNING actor with synchronous durability (the call
// returns once the snapshot is in object storage), then resumes it. A
// memory snapshot resumes where it left off; the agent pauses for the
// seconds the upload takes.
func (s *SubstrateATEActions) Snapshot(ctx context.Context, atespace, name string) (SubstrateKept, error) {
	ds, ok := s.Client.(ateapi.DurableSuspender)
	if !ok {
		return SubstrateKept{}, errSubstrateNoDurableSuspend
	}
	ref := ateapi.Ref(atespace, name)
	a, err := s.Client.GetActor(ctx, ref)
	if err != nil {
		return SubstrateKept{}, err
	}
	if st := a.GetStatus().GetState(); st != ateapi.ActorStateRunning {
		return SubstrateKept{}, fmt.Errorf("%w (it is %s)", ErrSubstrateNotRunning, st)
	}
	before := newestSnapshot(a.GetStatus()).GetGeneration()
	sa, err := ds.SuspendActorDurable(ctx, ref)
	if err != nil {
		return s.snapshotFailed(ctx, atespace, name, before, err)
	}
	h := newestSnapshot(sa.GetStatus())
	if h.GetGeneration() <= before || h.GetOwner() != ateapi.SnapshotOwnerActor || h.GetDurableSnapshot().GetState() != ateapi.SnapshotStorageCompleted {
		// Someone else suspended it first (the idle controller, an
		// asynchronous snapshot): it is SUSPENDED by their decision and
		// the call returned it as it was. Leave it so.
		return SubstrateKept{}, fmt.Errorf("%w (suspended meanwhile, at generation %d)", ErrSubstrateNotRunning, h.GetGeneration())
	}
	kept := SubstrateKept{Generation: h.GetGeneration()}
	if err := s.Resume(ctx, atespace, name); err != nil {
		kept.NoWorker = errors.Is(err, ErrSubstrateNoWorker)
		return kept, fmt.Errorf("%w: %w", errSubstrateKeptNotResumed, err)
	}
	kept.Running = true
	return kept, nil
}

// snapshotFailed handles a durable suspend that returned err: the suspend
// may have taken effect before the upload failed, the bound ran out or the
// gateway lost the call. It re-reads the actor and, when it is SUSPENDED at
// a generation newer than before (this call's own snapshot), starts it
// again, so an unattended task does not stall until someone connects
// (GAP-0649). The answer is always an error: nothing durable is known.
func (s *SubstrateATEActions) snapshotFailed(ctx context.Context, atespace, name string, before int32, err error) (SubstrateKept, error) {
	// ctx may be the one that ran out: give the re-read and the resume a
	// bound of their own.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), substrateSnapshotRecheckTimeout)
	defer cancel()
	a, gerr := s.Client.GetActor(rctx, ateapi.Ref(atespace, name))
	if gerr != nil {
		return SubstrateKept{}, fmt.Errorf("suspend: %w (and the actor could not be read again: %v; it may be suspended)", err, gerr)
	}
	h := newestSnapshot(a.GetStatus())
	// Only an actor-owned snapshot can be this call's (a tag's is a
	// template's); its state is left as it is otherwise.
	if a.GetStatus().GetState() != ateapi.ActorStateSuspended || h.GetGeneration() <= before || h.GetOwner() != ateapi.SnapshotOwnerActor {
		return SubstrateKept{Running: a.GetStatus().GetState() == ateapi.ActorStateRunning}, fmt.Errorf("suspend: %w", err)
	}
	kept := SubstrateKept{Generation: h.GetGeneration()}
	if rerr := s.Resume(rctx, atespace, name); rerr != nil {
		kept.NoWorker = errors.Is(rerr, ErrSubstrateNoWorker)
		return kept, fmt.Errorf("suspend: %w (it is suspended at generation %d and did not start again: %v)", err, kept.Generation, rerr)
	}
	kept.Running = true
	fmt.Fprintf(os.Stderr, "[substrate] actor %s/%s: durable suspend failed (%v); it was suspended at generation %d and is running again\n", atespace, name, err, kept.Generation)
	return kept, fmt.Errorf("suspend: %w", err)
}

// substrateSnapshotRecheckTimeout bounds the re-read and resume after a
// failed durable suspend.
const substrateSnapshotRecheckTimeout = time.Minute

// newestSnapshot is the highest generation in s, nil for none.
func newestSnapshot(s *ateapi.ActorStatus) *ateapi.Snapshot {
	var h *ateapi.Snapshot
	for _, sn := range s.GetSnapshots() {
		if h == nil || sn.GetGeneration() > h.GetGeneration() {
			h = sn
		}
	}
	return h
}

// substrateRecoverActor is POST .../actors/{atespace}/{name}/recover: the
// owner (or an administrator) brings a crashed actor back. The answer's
// recovered_from is "snapshot" (its own last snapshot) or "template" (it
// had none, so its folder is gone); absent when no snapshot is listed.
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
		// Detached like a snapshot: a launcher that stops waiting must
		// not leave the actor reverted but not started.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), substrateSnapshotTimeout)
		defer cancel()
		res, err := rec.Recover(ctx, reg.Atespace, reg.Name)
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
		from := "snapshot"
		if res.FromTemplate {
			from = "template"
		}
		fmt.Fprintf(os.Stderr, "[substrate] actor %s/%s recovered from a crash to snapshot generation %d (%s)\n", reg.Atespace, reg.Name, res.Generation, from)
		v := st.actorView(reg)
		v["state"] = "running"
		if res.Generation > 0 {
			// No snapshot listed: say nothing; the launcher's undo
			// finds out from the folder.
			v["recovered_from"] = from
		}
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}

// substrateSnapshotActor is POST .../actors/{atespace}/{name}/snapshot: the
// owner (or an administrator) has the cluster store the running actor's
// state durably, so a crash recovery returns to it (GAP-0410).
func (a *APIServer) substrateSnapshotActor(st *substrateState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sn, ok := st.cfg.Actions.(SubstrateActorSnapshotter)
		if st.cfg.Actions == nil || !ok {
			writeSubstrateJSONError(w, http.StatusNotImplemented, "snapshot_unavailable")
			return
		}
		reg, status, reason := a.substrateFind(st, r, r.PathValue("atespace"), r.PathValue("name"))
		if status != http.StatusOK {
			writeSubstrateJSONError(w, status, reason)
			return
		}
		a.substrateAuditAdminTarget(st, r, reg, "snapshot", "MEDIUM")
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), substrateSnapshotTimeout)
		defer cancel()
		kept, err := sn.Snapshot(ctx, reg.Atespace, reg.Name)
		switch {
		case errors.Is(err, ErrSubstrateNotRunning):
			writeSubstrateJSONError(w, http.StatusConflict, "not_running")
			return
		case errors.Is(err, errSubstrateNoDurableSuspend):
			writeSubstrateJSONError(w, http.StatusNotImplemented, "snapshot_unavailable")
			return
		case errors.Is(err, errSubstrateKeptNotResumed):
			// Stored; the next connect starts it.
			fmt.Fprintf(os.Stderr, "[substrate] actor %s/%s: snapshot generation %d stored, resume failed: %v\n", reg.Atespace, reg.Name, kept.Generation, err)
		case err != nil:
			fmt.Fprintf(os.Stderr, "[substrate] snapshot of %s/%s failed: %v\n", reg.Atespace, reg.Name, err)
			if inv, ok := st.cfg.Actors.(interface{ Invalidate(string, string) }); ok {
				inv.Invalidate(reg.Atespace, reg.Name)
			}
			// A suspend that took effect and could not be undone leaves
			// the actor suspended: say so (GAP-0649).
			reason := "snapshot_failed"
			if !kept.Running {
				reason = "snapshot_failed_may_be_suspended"
			}
			writeSubstrateJSONError(w, http.StatusBadGateway, reason)
			return
		}
		if inv, ok := st.cfg.Actors.(interface{ Invalidate(string, string) }); ok {
			inv.Invalidate(reg.Atespace, reg.Name)
		}
		v := st.actorView(reg)
		v["state"] = "running"
		if !kept.Running {
			v["state"] = "suspended"
			v["resume_error"] = "resume_failed"
			if kept.NoWorker {
				v["resume_error"] = "no_worker"
			}
		}
		v["snapshot_generation"] = kept.Generation
		writeSubstrateJSON(w, http.StatusOK, v)
	}
}
