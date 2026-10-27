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

package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The guest inventory. Every sandbox DefenseClaw holds a record of lives on
// the gateway place its record names (recordPlace: the registration,
// endpoint, workspace and compute driver it was created on, or last found
// on). Its state is what that place says of it, and only that place: the
// connected gateway's lookups when it is that place, else a read of the
// place itself (proveGuests). One account of it (unprotectedKind) serves
// the status, which the doctor, the managed verify and the package
// upgrade read, the run refusal and the view. A guest whose session may run
// a legacy supervisor, or a contained one, that its place cannot vouch for
// is unknown: reported, and no new sandbox runs, until its place says.
// DefenseClaw stops none of them.

// guestRead is what the latest read of a guest at the place its record
// names said (proveGuests).
type guestRead struct {
	// place is the recordPlace the read was of: a read stands only while
	// the record names that place.
	place string
	at    time.Time
	// phase is the phase found there, gone that the place has no sandbox
	// of the guest's identity (not found, or another sandbox under its
	// name), err why the place could not be read.
	phase audit.SandboxPhase
	gone  bool
	err   string
	// word is the box's word count (box.word) when the read began: a
	// lookup of its place or a phase given since outranks it.
	word uint64
}

// found is the phase the read proves: phaseMissing for a guest gone.
func (r guestRead) found() audit.SandboxPhase {
	if r.gone {
		return phaseMissing
	}
	return r.phase
}

// proofFresh is how long a read of a guest's place stands before the next
// account reads it again.
const proofFresh = 30 * time.Second

// recordPlace names where rec's sandbox lives: the gateway registration,
// endpoint and workspace its record names, and the compute driver it was
// created on.
func recordPlace(rec record) string {
	return gatewayPlace(rec.Gateway, rec.GatewayEndpoint, rec.GatewayWorkspace) + " on " + string(recordDriver(rec))
}

// mayBeUnprotected reports a record whose guest DefenseClaw cannot show
// protected while it runs: one whose session may run the supervisor of an
// OpenShell release older than openshell.SupportedMin (every record of
// DefenseClaw 1.0.3 or older among them), and a contained one.
func mayBeUnprotected(rec record) bool {
	return !openshell.RunsSandboxes(rec.SessionRelease) || rec.Contained != ""
}

// atConnectedPlace reports whether b's place is here, the gateway
// DefenseClaw is connected to or was last (nil before any: a box then has
// no state but what its place's reads gave).
func atConnectedPlace(b *box, here *Gateway) bool {
	return here == nil || gatewayMismatch(b.rec, here) == ""
}

// provenPhase is the phase of b that its own place proves, and whether one
// does. A guest its place proved gone (box.gone) is missing on whichever
// gateway DefenseClaw is connected to. Otherwise it is the newest word of
// that place: at the connected place a read of the place no lookup or
// phase has come after (one taken while DefenseClaw was connected
// elsewhere, whose word the phase cached before the switch does not
// outrank), else its lookups' phase; elsewhere only such a read proves
// anything (one a lookup or phase of that place came after is stale, and
// is read again: proveGuests), and the phase returned unproven is the last
// known one: the last word of its place (record.PlacePhase) when that word
// is that it holds no compute, which a read of the place that failed since
// or a daemon restart does not take back (GAP-1176), else the box's phase.
// The caller holds m.mu.
func provenPhase(b *box, here *Gateway) (audit.SandboxPhase, bool) {
	if b.gone {
		return phaseMissing, true
	}
	r := b.read
	read := !r.at.IsZero() && r.err == "" && r.place == recordPlace(b.rec)
	if atConnectedPlace(b, here) {
		switch {
		case read && r.word == b.word:
			return r.found(), true
		case b.phase != "":
			return b.phase, true
		}
		return releasedWord(b), false
	}
	if read && r.word == b.word {
		return r.found(), true
	}
	if w := releasedWord(b); w != "" {
		return w, false
	}
	return b.phase, false
}

// releasedWord is the last word of b's own place (record.PlacePhase) when
// it is that b holds no compute there (stopped, deleted, missing), else "":
// a guest last said running, or never said anything of, stays held while
// its place cannot be read. The caller holds m.mu.
func releasedWord(b *box) audit.SandboxPhase {
	w := audit.SandboxPhase(b.rec.PlacePhase)
	if w == "" || b.rec.PlacePhaseOf != recordPlace(b.rec) || holdsCompute(w, b.rec.Driver, b.rec.PhaseReason) {
		return ""
	}
	return w
}

// proveGuests reads, at the place its record names, every guest that may
// be unprotected (mayBeUnprotected) whose account its place does not prove
// otherwise (provenPhase): one at the connected place that no lookup has
// found since the daemon started, and one that lives elsewhere, whose own
// gateway is opened for it (Options.GatewayAt). A read stands for
// proofFresh, until its place says something newer (box.word). A place
// that cannot be read leaves the guest unproven. A read
// that found the guest gone proves it gone for good (box.gone), and a guest
// so proven is not read again. A read that a lookup of its place or a phase
// came after while it ran is dropped: the place said something newer.
func (m *Manager) proveGuests(ctx context.Context) {
	m.proveMu.Lock()
	defer m.proveMu.Unlock()
	here := m.lastGw.Load()
	now := m.now()
	type guest struct {
		b     *box
		rec   record
		place string
		word  uint64
	}
	var local []guest
	away := map[string][]guest{}
	m.mu.Lock()
	for _, b := range m.boxes {
		if b.deleted || b.retained || b.creating || b.gone || !mayBeUnprotected(b.rec) {
			continue
		}
		g := guest{b: b, rec: b.rec, place: recordPlace(b.rec), word: b.word}
		if r := b.read; r.place == g.place && r.word == b.word && !r.at.IsZero() && now.Sub(r.at) < proofFresh {
			continue
		}
		if atConnectedPlace(b, here) {
			if _, proven := provenPhase(b, here); !proven {
				local = append(local, g)
			}
			continue
		}
		away[g.place] = append(away[g.place], g)
	}
	m.mu.Unlock()
	reads := map[*box]guestRead{}
	if len(local) > 0 {
		rctx, cancel := context.WithTimeout(ctx, otherGatewayTimeout)
		gw, err := m.gateway(rctx)
		for _, g := range local {
			switch {
			case err != nil:
				reads[g.b] = guestRead{place: g.place, at: now, err: truncate(err.Error(), 200), word: g.word}
			case gatewayMismatch(g.rec, gw) == "":
				reads[g.b] = m.readGuest(rctx, gw, g.b, g.rec, g.place, g.word)
			}
		}
		cancel()
	}
	for place, guests := range away {
		pctx, cancel := context.WithTimeout(ctx, otherGatewayTimeout)
		gw, done, err := m.openPlace(pctx, guests[0].rec, here)
		for _, g := range guests {
			if err != nil {
				reads[g.b] = guestRead{place: place, at: now, err: truncate(err.Error(), 200), word: g.word}
				continue
			}
			reads[g.b] = m.readGuest(pctx, gw, g.b, g.rec, place, g.word)
		}
		if done != nil {
			done()
		}
		cancel()
	}
	var said []*box
	var names []string
	m.mu.Lock()
	for b, r := range reads {
		if recordPlace(b.rec) != r.place || b.word != r.word {
			continue // the record moved meanwhile, or its place said something since
		}
		b.read = r
		b.gone = b.gone || r.gone
		if r.err == "" && (b.rec.PlacePhase != string(r.found()) || b.rec.PlacePhaseOf != r.place) {
			b.rec.PlacePhase, b.rec.PlacePhaseOf = string(r.found()), r.place
			said, names = append(said, b), append(names, b.rec.Name)
		}
	}
	m.mu.Unlock()
	for i, b := range said {
		if err := m.saveRecord(b); err != nil {
			m.logf("sandbox %s: keeping what its gateway said of it: %v", names[i], err)
		}
	}
}

// readGuest asks gw, the gateway of place, what it holds of b's sandbox
// (rec is b's record and word its word count, as read).
func (m *Manager) readGuest(ctx context.Context, gw *Gateway, b *box, rec record, place string, word uint64) guestRead {
	r := guestRead{place: place, at: m.now(), word: word}
	sb, err := gw.Client.GetSandbox(ctx, rec.Name)
	switch {
	case openshell.IsNotFound(err):
		r.gone = true
	case err != nil:
		r.err = truncate(err.Error(), 200)
	case !m.sameSandbox(b, sb):
		r.gone = true // another sandbox has its name there
	default:
		r.phase = auditPhase(sb.Status.Phase)
	}
	return r
}

// openPlace connects to the gateway rec's place names when it is not here
// (the connected gateway): its registration, which must still point at the
// endpoint rec names and run the compute driver rec's sandbox was created
// on, or nothing proves its sandbox gone. The returned func closes it.
func (m *Manager) openPlace(ctx context.Context, rec record, here *Gateway) (*Gateway, func(), error) {
	if here != nil && samePlace(rec, here) {
		return nil, nil, fmt.Errorf("that gateway runs the %s compute driver now, which does not see a %s sandbox", here.Driver.Name, recordDriver(rec))
	}
	if m.opts.GatewayAt == nil || rec.Gateway == "" {
		return nil, nil, errors.New("DefenseClaw is connected to another gateway")
	}
	gw, err := m.opts.GatewayAt(ctx, rec.Gateway, rec.GatewayWorkspace)
	if err != nil {
		return nil, nil, err
	}
	done := func() {
		if gw.Close != nil {
			_ = gw.Close()
		}
	}
	switch {
	case rec.GatewayEndpoint != "" && gw.Endpoint != rec.GatewayEndpoint:
		done()
		return nil, nil, fmt.Errorf("its registration %s now points at %s", rec.Gateway, gw.Endpoint)
	case gw.Driver.Name != recordDriver(rec):
		done()
		return nil, nil, fmt.Errorf("that gateway runs the %s compute driver now, which does not see a %s sandbox", gw.Driver.Name, recordDriver(rec))
	}
	return gw, done, nil
}

// heardLocked counts a word of b's own place about b, a lookup of it or a
// phase given while DefenseClaw is connected to it (here, as in
// atConnectedPlace): a read taken before no longer outranks the box's
// lookups (provenPhase). A phase given while DefenseClaw is connected
// elsewhere is not its place's word. The caller holds m.mu.
func heardLocked(b *box, here *Gateway) {
	if atConnectedPlace(b, here) {
		b.word++
	}
}

// unknownWhy says what DefenseClaw cannot see of the unknown guest b
// (unprotectedKind sandboxapi.UnprotectedUnknown), why, and what its user
// does about it; here is unprotectedKind's. The caller holds m.mu.
func unknownWhy(b *box, here *Gateway) string {
	what := "its session may run the supervisor of an OpenShell release older than " + openshell.SupportedMin +
		", whose network broker can let its connections bypass sandbox policy (NVIDIA/OpenShell#4494)"
	if b.rec.Contained != "" {
		what = "DefenseClaw had to stop it (" + b.rec.Contained + ") but could not sync its MicroVM's disk first, so it may still run contained"
	}
	failed := ""
	if r := b.read; r.place == recordPlace(b.rec) && r.err != "" {
		failed = " (" + r.err + ")"
	}
	if atConnectedPlace(b, here) {
		return what + ", and the OpenShell gateway has not said whether it runs since the sandbox daemon started" + failed +
			": run the command again once the gateway answers"
	}
	return what + ", and it lives on " + gatewayMismatch(b.rec, here) + ", which DefenseClaw could not read" + failed +
		": connect DefenseClaw to that gateway (openshell.gateway) or start it, so DefenseClaw sees the sandbox and you can stop it there; " +
		"if it no longer exists, `defenseclaw sandbox delete " + b.rec.Name + "` releases DefenseClaw's side"
}

// unknownUnprotected opens every account of an unknown guest.
const unknownUnprotected = sandboxapi.UnknownUnprotected
