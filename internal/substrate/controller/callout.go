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

package controller

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// The egress callout slot (GAP-0505). Substrate has one additional egress
// callout; an ate-setup deploy that names another one replaces DefenseClaw's
// without telling DefenseClaw. Every EgressPolicy DefenseClaw writes allows
// hosts whose final decision is the callout's (ask hosts, URL rules, egress
// feeds, secret and DLP scans, MCP and body inspection), so with another
// callout in the slot those hosts are simply open. The controller reads the
// slot from atenet-egress's live config every calloutCheckEvery, records a
// change (EventCalloutReplaced, EventCalloutRestored) and applies the fail
// mode: closed (the default; always on a managed install and for unattended
// actors, D8) gives every managed actor only the DefenseClaw rule
// (render.DenyOnly) until DefenseClaw's callout is back; open leaves the
// policies and the alert says what does not run.

// CalloutReader reads who holds the egress callout slot now
// (setup.EgressCalloutReader).
type CalloutReader interface {
	ReadCalloutSlot(ctx context.Context) (setup.CalloutSlot, error)
}

// calloutCheckEvery bounds the slot reads: one ConfigMap GET per interval
// per controller, so a replacement is acted on within it plus one pass.
const calloutCheckEvery = 5 * time.Second

// CalloutChecks are the DefenseClaw checks that run only in its egress
// callout: off while another callout holds the slot. The EgressPolicy
// (default deny, the allow list, credential injection on bound hosts) and
// the kit's hooks keep working.
var CalloutChecks = []string{"ask hosts", "URL rules", "egress feeds", "secret and DLP scans", "body and MCP inspection", "tool chains at egress"}

// Callout fail modes (CalloutStatus.FailMode).
const (
	CalloutFailClosed = "closed"
	CalloutFailOpen   = "open"
	// CalloutOff is substrate.extproc.enabled: false, an install that
	// runs without the DefenseClaw callout on purpose.
	CalloutOff = "off"
)

// CalloutFailModeFromConfig is the fail mode of a callout replacement:
// substrate.extproc.failure_mode, closed on a managed install (D8).
func CalloutFailModeFromConfig(cfg *config.Config) string {
	sub := cfg.Substrate
	if sub.Extproc.Enabled != nil && !*sub.Extproc.Enabled {
		return CalloutOff
	}
	managed := strings.EqualFold(strings.TrimSpace(cfg.DeploymentMode), string(config.DeploymentModeManagedEnterprise))
	if !managed && strings.EqualFold(strings.TrimSpace(sub.Extproc.FailureMode), config.SubstrateFailOpen) {
		return CalloutFailOpen
	}
	return CalloutFailClosed
}

// CalloutStatus is the slot as the controller last read it.
type CalloutStatus struct {
	// Known is false until one read worked.
	Known bool
	// Ours: the DefenseClaw callout holds the slot. Holder names the
	// callout that does, NS/SVC:PORT ("" when none is registered).
	Ours   bool
	Holder string
	// Err is the last read's error ("" when it worked); the last known
	// state stays in force meanwhile.
	Err string
	// FailMode is CalloutFailClosed, CalloutFailOpen or CalloutOff.
	FailMode string
	// Since is when the slot last changed (or was first read).
	Since time.Time
}

type calloutWatch struct {
	mu     sync.Mutex
	reader CalloutReader
	at     time.Time
	known  bool
	slot   setup.CalloutSlot
	since  time.Time
	err    string
	warned bool
}

// SetCallout sets the slot reader before Run (the CLI wiring). Without one
// the slot is not checked.
func (c *Controller) SetCallout(r CalloutReader) {
	c.callout.mu.Lock()
	c.callout.reader = r
	c.callout.mu.Unlock()
}

// CalloutStatus reads the slot when the last read is older than
// calloutCheckEvery and returns it; false when no reader is set.
func (c *Controller) CalloutStatus(ctx context.Context) (CalloutStatus, bool) {
	c.checkCallout(ctx)
	w := &c.callout
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader == nil {
		return CalloutStatus{}, false
	}
	return CalloutStatus{Known: w.known, Ours: w.slot.Ours, Holder: w.slot.Holder, Err: w.err,
		FailMode: c.live().CalloutFailMode(), Since: w.since}, true
}

// CalloutFailMode is the fail mode in force ("" is closed).
func (lv *Live) CalloutFailMode() string {
	if lv.CalloutMode == "" {
		return CalloutFailClosed
	}
	return lv.CalloutMode
}

// checkCallout reads the slot at most every calloutCheckEvery and records a
// change once. A failed read keeps the last known state (a replacement
// already seen stays in force) and warns once until a read works again.
func (c *Controller) checkCallout(ctx context.Context) {
	w := &c.callout
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader == nil {
		return
	}
	now := c.o.Now()
	if !w.at.IsZero() && now.Sub(w.at) < calloutCheckEvery {
		return
	}
	w.at = now
	slot, err := w.reader.ReadCalloutSlot(ctx)
	if err != nil {
		w.err = err.Error()
		if !w.warned {
			w.warned = true
			c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
				Message: "cannot read which egress callout Substrate uses (" + w.err + "): another callout replacing DefenseClaw's is not " +
					"detected until it reads again, and the last known state stays in force",
				Detail: map[string]any{"configmap": setup.EgressConfigMap}})
		}
		return
	}
	w.err, w.warned = "", false
	prev, wasKnown := w.slot, w.known
	w.slot, w.known = slot, true
	switch {
	case !slot.Ours && (!wasKnown || prev.Ours || prev.Holder != slot.Holder):
		w.since = now
		c.emitCalloutReplaced(slot)
	case slot.Ours && wasKnown && !prev.Ours:
		w.since = now
		c.emit(Event{Type: EventCalloutRestored, Severity: SeverityInfo,
			Message: "the DefenseClaw callout holds Substrate's egress callout again: every actor's policy is rendered in full again on this pass",
			Detail:  map[string]any{"holder": slot.Holder, "previous_holder": prev.Holder}})
	case !wasKnown:
		w.since = now
	}
}

func (c *Controller) emitCalloutReplaced(slot setup.CalloutSlot) {
	mode := c.live().CalloutFailMode()
	what := "no egress callout is registered"
	if slot.Holder != "" {
		what = "egress goes to another callout (" + slot.Holder + ")"
	}
	off := strings.Join(CalloutChecks, ", ")
	ev := Event{Type: EventCalloutReplaced, Severity: SeverityAlert,
		Detail: map[string]any{"holder": slot.Holder, "failure_mode": mode, "checks_off": CalloutChecks}}
	switch mode {
	case CalloutOff:
		ev.Severity = SeverityWarn
		ev.Message = "Substrate's egress callout is not DefenseClaw's: " + what + ". substrate.extproc.enabled is false, so actor policies stay as they are; " +
			"these checks do not run: " + off
	case CalloutFailOpen:
		ev.Message = "Substrate's egress callout is not DefenseClaw's: " + what + ". Fail open (substrate.extproc.failure_mode: open): actors keep their " +
			"egress policies without these checks: " + off + "; unattended actors keep only the DefenseClaw rule. Register the DefenseClaw callout again: " +
			"defenseclaw substrate setup, then ate-setup deploy"
	default:
		ev.Message = "Substrate's egress callout is not DefenseClaw's: " + what + ". Fail closed: every managed actor keeps only the DefenseClaw rule " +
			"(no other egress) until the DefenseClaw callout is registered again (defenseclaw substrate setup, then ate-setup deploy); " +
			"without it these checks do not run: " + off
	}
	c.emit(ev)
}

// calloutDenyOnly is why an actor keeps only the DefenseClaw rule because
// another callout holds the slot, "" when it does not: a replacement seen,
// the DefenseClaw callout expected, and the fail mode closed for the actor
// (open never applies to unattended actors, D8).
func (c *Controller) calloutDenyOnly(lv *Live, reg Registration) string {
	w := &c.callout
	w.mu.Lock()
	reader, known, slot := w.reader, w.known, w.slot
	w.mu.Unlock()
	if reader == nil || !known || slot.Ours {
		return ""
	}
	switch lv.CalloutFailMode() {
	case CalloutOff:
		return ""
	case CalloutFailOpen:
		if !reg.Task {
			return ""
		}
	}
	if slot.Holder == "" {
		return "callout_replaced: no egress callout is registered, so DefenseClaw's egress checks do not run (fail closed)"
	}
	return "callout_replaced: egress goes to another callout (" + slot.Holder + "), not DefenseClaw's (fail closed)"
}
