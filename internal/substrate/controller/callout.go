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
//
// Only the controller's ServiceAccount may get the atenet-egress ConfigMap.
// It publishes each read to the leader (SetCalloutPublisher); the gateway's
// create path and /info read that (LeaderCallout), and a report older than
// CalloutStaleAfter is unknown. Unknown is never the DefenseClaw callout:
// doctor says it cannot verify the egress callout.

// CalloutReader reads who holds the egress callout slot now
// (setup.EgressCalloutReader).
type CalloutReader interface {
	ReadCalloutSlot(ctx context.Context) (setup.CalloutSlot, error)
}

// calloutCheckEvery bounds the slot reads: one ConfigMap GET per interval
// per controller, so a replacement is acted on within it plus one pass.
const calloutCheckEvery = 5 * time.Second

// CalloutStaleAfter is how old the controller's last published read may be
// before a gateway calls the slot unknown: three read intervals.
const CalloutStaleAfter = 3 * calloutCheckEvery

// calloutPublishWait bounds one publish to the leader.
const calloutPublishWait = 3 * time.Second

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
	// Known is true only when the last read worked: false until one did,
	// and false again while reads fail (forbidden, no ConfigMap). An
	// unknown slot is never Ours.
	Known bool
	// Ours: the DefenseClaw callout holds the slot. Holder names the
	// callout that does, NS/SVC:PORT ("" when none is registered). Both
	// are empty when the slot is not Known.
	Ours   bool
	Holder string
	// Err is the last read's error ("" when it worked). A replacement
	// already seen stays in force for the policies meanwhile.
	Err string
	// FailMode is CalloutFailClosed, CalloutFailOpen or CalloutOff.
	FailMode string
	// Since is when the slot last changed (or was first read).
	Since time.Time
	// At is when the slot was last read (zero before the first read).
	At time.Time
}

// CalloutPublisher takes each slot read the controller makes (the leader,
// LeaderCalloutPublisher), so that the gateway, which may not read the slot,
// sees it.
type CalloutPublisher interface {
	PublishCallout(ctx context.Context, st CalloutStatus) error
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
	// pub gets every read; pubWarned: one warning per run of failures.
	pub       CalloutPublisher
	pubWarned bool
}

// SetCallout sets the slot reader before Run (the CLI wiring). Without one
// the slot is not checked.
func (c *Controller) SetCallout(r CalloutReader) {
	c.callout.mu.Lock()
	c.callout.reader = r
	c.callout.mu.Unlock()
}

// SetCalloutPublisher sends every slot read to p (the controller's leader
// client) before Run.
func (c *Controller) SetCalloutPublisher(p CalloutPublisher) {
	c.callout.mu.Lock()
	c.callout.pub = p
	c.callout.mu.Unlock()
}

// CalloutStatus reads the slot when the last read is older than
// calloutCheckEvery and returns it; false when no reader is set.
func (c *Controller) CalloutStatus(ctx context.Context) (CalloutStatus, bool) {
	c.checkCallout(ctx)
	return c.calloutStatusNow()
}

// calloutStatusNow is the slot as last read. A failed last read is unknown,
// whatever an earlier read showed: what cannot be read is never reported as
// the DefenseClaw callout.
func (c *Controller) calloutStatusNow() (CalloutStatus, bool) {
	w := &c.callout
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader == nil {
		return CalloutStatus{}, false
	}
	st := CalloutStatus{Err: w.err, FailMode: c.live().CalloutFailMode(), Since: w.since, At: w.at}
	if w.known && w.err == "" {
		st.Known, st.Ours, st.Holder = true, w.slot.Ours, w.slot.Holder
	}
	return st, true
}

// watchCallout keeps reading (and so publishing) the slot every
// calloutCheckEvery while a pass runs long, so that the gateway's view
// does not go stale behind a slow pass.
func (c *Controller) watchCallout(ctx context.Context) {
	t := time.NewTicker(calloutCheckEvery / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.checkCallout(ctx)
		}
	}
}

// calloutPublishes reports that the slot is read and published (Run starts
// watchCallout).
func (c *Controller) calloutPublishes() bool {
	c.callout.mu.Lock()
	defer c.callout.mu.Unlock()
	return c.callout.reader != nil && c.callout.pub != nil
}

// publishCallout sends the slot as last read to the publisher. A failure
// warns once until a publish works again; the gateway then calls the slot
// unknown once the last report is CalloutStaleAfter old.
func (c *Controller) publishCallout(ctx context.Context) {
	w := &c.callout
	w.mu.Lock()
	pub := w.pub
	w.mu.Unlock()
	if pub == nil {
		return
	}
	st, ok := c.calloutStatusNow()
	if !ok {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, calloutPublishWait)
	err := pub.PublishCallout(pctx, st)
	cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		w.pubWarned = false
		return
	}
	if !w.pubWarned && ctx.Err() == nil {
		w.pubWarned = true
		c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
			Message: "cannot tell the leader which egress callout Substrate uses (" + err.Error() + "): the gateway cannot verify the egress " +
				"callout until a report reaches the leader"})
	}
}

// CalloutFailMode is the fail mode in force ("" is closed).
func (lv *Live) CalloutFailMode() string {
	if lv.CalloutMode == "" {
		return CalloutFailClosed
	}
	return lv.CalloutMode
}

// checkCallout reads the slot at most every calloutCheckEvery, records a
// change once and publishes the read.
func (c *Controller) checkCallout(ctx context.Context) {
	if c.readCallout(ctx) {
		c.publishCallout(ctx)
	}
}

// readCallout reads the slot unless the last read is younger than
// calloutCheckEvery; true when it read. A failed read makes the slot
// unknown (CalloutStatus), keeps a replacement already seen in force for
// the policies, and warns once until a read works again.
func (c *Controller) readCallout(ctx context.Context) bool {
	w := &c.callout
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader == nil {
		return false
	}
	now := c.o.Now()
	if !w.at.IsZero() && now.Sub(w.at) < calloutCheckEvery {
		return false
	}
	w.at = now
	slot, err := w.reader.ReadCalloutSlot(ctx)
	if err != nil {
		w.err = err.Error()
		if !w.warned {
			w.warned = true
			c.emit(Event{Type: EventWarning, Severity: SeverityWarn,
				Message: "cannot verify the egress callout: cannot read which egress callout Substrate uses (" + w.err + "); another callout " +
					"replacing DefenseClaw's is not detected until it reads again, and a replacement already seen stays in force",
				Detail: map[string]any{"configmap": setup.EgressConfigMap}})
		}
		return true
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
	return true
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
