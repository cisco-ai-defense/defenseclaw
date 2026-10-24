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
	"net/http"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A managed computer's sandbox daemon has no telemetry destination: no
// config file, no exporter, no audit store. Its manager's sandbox records
// went to no recorder at all, so a managed host never reported a phase
// change (log.sandbox.lifecycle) or an egress decision (log.egress.*), and
// the fleet's Sandboxes board stayed empty for them (GAP-0003).
//
// daemonRelayTelemetry is the daemon manager's recorder: it relays the
// lifecycle, egress and otherwise uncounted ask decisions through POST
// sandbox/events, which records
// them with its own recorder, stamped with the registration's sandbox,
// profile and person as it verified them from the hook-socket peer
// (emitSandboxTelemetryClaim). The daemon names no person: a record only
// says which of the caller's own sandboxes it describes.
//
// Producers record on the egress proxy's and the lifecycle's paths, so a
// record is only queued; one goroutine, started on demand and gone when the
// queue is empty, posts the queue every daemonTelemetryFlushEvery, one batch
// per registration. A record of a sandbox whose registration the daemon
// does not hold yet (the phases of a create before its bind) waits for it,
// at most daemonTelemetryWaitFor.
type daemonRelayTelemetry struct {
	relay sandboxrelay.Client
	// registration is the registration of a sandbox of the daemon, by name.
	registration func(sandbox string) (string, bool)
	logf         func(string, ...any)
	now          func() time.Time
	flushEvery   time.Duration

	mu      sync.Mutex
	pending []daemonTelemetryRecord
	running bool
	// dropped counts the records lost to a full queue, a refused batch or
	// a registration that never came; failing is a streak of failed posts.
	dropped int64
	failing bool
}

// daemonTelemetryRecord is one queued record: the sandbox it describes,
// its registration once known, and the event to post.
type daemonTelemetryRecord struct {
	sandbox, registration string
	queued                time.Time
	ev                    sandboxrelay.Event
}

const (
	// daemonTelemetryFlushEvery paces the posts: the events route allows
	// each account a few batches a second (sandboxBudgetEvents).
	daemonTelemetryFlushEvery = 2 * time.Second
	// daemonTelemetryMaxPending bounds the queue; the oldest go first.
	daemonTelemetryMaxPending = 2048
	// daemonTelemetryBatch bounds one batch, the route's telemetry batch
	// limit, under its byte limit (a record is well under 1 KiB).
	daemonTelemetryBatch = sandboxrelay.MaxTelemetryBatchRecords
	// daemonTelemetryWaitFor is how long a record waits for its sandbox's
	// registration.
	daemonTelemetryWaitFor = 10 * time.Minute
	// daemonTelemetryPostTimeout bounds one post.
	daemonTelemetryPostTimeout = 10 * time.Second
)

func newDaemonRelayTelemetry(relay sandboxrelay.Client, registration func(string) (string, bool), logf func(string, ...any)) *daemonRelayTelemetry {
	return &daemonRelayTelemetry{relay: relay, registration: registration, logf: logf, now: time.Now, flushEvery: daemonTelemetryFlushEvery}
}

// sandboxTelemetryClaim is the payload of a sandbox_lifecycle or
// sandbox_egress record. Every field is the daemon's claim about one of the
// caller's own sandboxes: the managed gateway takes the sandbox, its
// registration, profile, policy and person from the registration and the
// peer, bounds the severity (sandboxClaimSeverity) and strips control
// characters from the text (sandboxClaimPayload), and the recorder bounds
// each value as on any other host. The image digest, network profile and
// policy revision are not sent: no registration vouches for them, so the
// gateway would not record them (an older daemon's are ignored).
type sandboxTelemetryClaim struct {
	Sandbox   string `json:"sandbox"`
	SandboxID string `json:"sandbox_id,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Pack      string `json:"pack,omitempty"`
	Severity  string `json:"severity,omitempty"`

	// The lifecycle record's.
	PreviousPhase string                 `json:"previous_phase,omitempty"`
	Trigger       string                 `json:"trigger,omitempty"`
	ExitCode      *int32                 `json:"exit_code,omitempty"`
	Condition     *sandboxConditionClaim `json:"condition,omitempty"`

	// The egress record's.
	Source         string `json:"source,omitempty"`
	End            string `json:"end,omitempty"`
	TimedOut       bool   `json:"timed_out,omitempty"`
	Terminated     bool   `json:"terminated,omitempty"`
	BytesUp        int64  `json:"bytes_up,omitempty"`
	BytesDown      int64  `json:"bytes_down,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
	PID            int    `json:"pid,omitempty"`
	Executable     string `json:"executable,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	Scheme         string `json:"scheme,omitempty"`
	Path           string `json:"path,omitempty"`
	ResolvedIP     string `json:"resolved_ip,omitempty"`
	Blocked        bool   `json:"blocked,omitempty"`
	DecisionCode   string `json:"decision_code,omitempty"`
	Reason         string `json:"reason,omitempty"`
	PolicyOutcome  string `json:"policy_outcome,omitempty"`
}

// sandboxConditionClaim is a lifecycle record's OpenShell condition.
type sandboxConditionClaim struct {
	Type    string `json:"type,omitempty"`
	Status  string `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// claimOf is the claim part of a record's sandbox identity.
func claimOf(id audit.SandboxIdentity) sandboxTelemetryClaim {
	return sandboxTelemetryClaim{Sandbox: id.Name, SandboxID: id.ID, Phase: string(id.Phase), Pack: id.Pack}
}

func lifecycleClaim(e audit.SandboxLifecycleEvent) sandboxTelemetryClaim {
	c := claimOf(e.Sandbox)
	c.PreviousPhase, c.Trigger, c.ExitCode, c.Severity = string(e.PreviousPhase), string(e.Trigger), e.ExitCode, e.Severity
	if e.Condition != nil {
		c.Condition = &sandboxConditionClaim{Type: e.Condition.Type, Status: e.Condition.Status, Reason: e.Condition.Reason, Message: e.Condition.Message}
	}
	return c
}

func egressClaim(e audit.SandboxEgressEvent) sandboxTelemetryClaim {
	c := claimOf(e.Sandbox)
	c.Severity, c.Source, c.End, c.TimedOut, c.Terminated = e.Severity, string(e.Source), string(e.End), e.TimedOut, e.Terminated
	c.BytesUp, c.BytesDown, c.DurationMS, c.PID, c.Executable = e.BytesUp, e.BytesDown, e.Duration.Milliseconds(), e.PID, e.Executable
	c.ConversationID, c.Host, c.Port, c.Scheme, c.Path, c.ResolvedIP = e.ConversationID, e.Host, e.Port, e.Scheme, e.Path, e.ResolvedIP
	c.Blocked, c.DecisionCode, c.Reason, c.PolicyOutcome = e.Blocked, e.DecisionCode, e.Reason, e.PolicyOutcome
	return c
}

// RecordSandboxLifecycle queues a phase change for the managed gateway.
func (t *daemonRelayTelemetry) RecordSandboxLifecycle(_ context.Context, e audit.SandboxLifecycleEvent) error {
	t.queue(sandboxrelay.EventSandboxLifecycle, e.Timestamp, lifecycleClaim(e))
	return nil
}

// RecordSandboxEgress queues an egress decision or connection end for the
// managed gateway.
func (t *daemonRelayTelemetry) RecordSandboxEgress(_ context.Context, e audit.SandboxEgressEvent) error {
	t.queue(sandboxrelay.EventSandboxEgress, e.Timestamp, egressClaim(e))
	return nil
}

func (t *daemonRelayTelemetry) RecordManagedAskDecision(_ context.Context, e audit.SandboxAskDecidedEvent) error {
	if e.Result != audit.SandboxApprovalDenied {
		return nil
	}
	outcome := "rejected"
	if e.Reason == sandboxAskReasonFloorDenied {
		outcome = sandboxAskReasonFloorDenied
	}
	c := claimOf(e.Sandbox)
	c.ApprovalID, c.Outcome, c.Host, c.Port = e.ApprovalID, outcome, e.Host, e.Port
	t.queue(sandboxrelay.EventSandboxAskDecision, e.Timestamp, c)
	return nil
}

// Other approvals already reach the gateway's decisions route. The remaining
// sandbox records have no managed route and stay in the daemon's feed.
func (*daemonRelayTelemetry) RecordSandboxApproval(context.Context, audit.SandboxApprovalEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxPolicy(context.Context, audit.SandboxPolicyEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxHealth(context.Context, audit.SandboxHealthEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxFinding(context.Context, audit.SandboxFindingEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxWorkspace(context.Context, audit.SandboxWorkspaceEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxActivity(context.Context, audit.SandboxActivityEvent) error {
	return nil
}
func (*daemonRelayTelemetry) RecordSandboxProcess(context.Context, audit.SandboxProcessEvent) error {
	return nil
}

// queue adds one record. Its registration is looked up now, while the
// daemon still holds it (a delete drops it right after the deleted phase),
// or at the post that follows the create's bind.
func (t *daemonRelayTelemetry) queue(kind string, at time.Time, claim sandboxTelemetryClaim) {
	if t == nil || t.relay == nil || claim.Sandbox == "" {
		return
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return
	}
	if at.IsZero() {
		at = t.now()
	}
	rec := daemonTelemetryRecord{sandbox: claim.Sandbox, queued: t.now(), ev: sandboxrelay.Event{Kind: kind, Time: at.UTC(), Payload: raw}}
	rec.registration, _ = t.registration(claim.Sandbox)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = append(t.pending, rec)
	if over := len(t.pending) - daemonTelemetryMaxPending; over > 0 {
		t.pending = t.pending[over:]
		t.dropped += int64(over)
	}
	if !t.running {
		t.running = true
		go t.drain()
	}
}

// drain posts the queue every flushEvery until it is empty.
func (t *daemonRelayTelemetry) drain() {
	for {
		time.Sleep(t.flushEvery)
		if !t.flush(context.Background()) {
			return
		}
	}
}

// flush posts what is queued, one batch per registration, and reports
// whether records remain (those of a gateway out of reach, and those still
// waiting for their registration). When none remain the drain ends.
func (t *daemonRelayTelemetry) flush(ctx context.Context) bool {
	t.mu.Lock()
	records := t.pending
	t.pending = nil
	t.mu.Unlock()

	var order []string
	batches := map[string][]daemonTelemetryRecord{}
	var waiting []daemonTelemetryRecord
	now := t.now()
	for _, rec := range records {
		if rec.registration == "" {
			rec.registration, _ = t.registration(rec.sandbox)
		}
		if rec.registration == "" {
			if now.Sub(rec.queued) < daemonTelemetryWaitFor {
				waiting = append(waiting, rec)
			} else {
				t.drop(1)
			}
			continue
		}
		if _, ok := batches[rec.registration]; !ok {
			order = append(order, rec.registration)
		}
		batches[rec.registration] = append(batches[rec.registration], rec)
	}
	var retry []daemonTelemetryRecord
	// A gateway out of reach or over budget takes no other registration's
	// batch either: the first such answer ends the pass, and the rest waits
	// for the next one.
	stopped := false
	for _, registration := range order {
		list := batches[registration]
		for len(list) > 0 && !stopped {
			n := min(len(list), daemonTelemetryBatch)
			chunk := list[:n]
			list = list[n:]
			events := make([]sandboxrelay.Event, len(chunk))
			for i, rec := range chunk {
				events[i] = rec.ev
			}
			postCtx, cancel := context.WithTimeout(ctx, daemonTelemetryPostTimeout)
			err := t.relay.Events(postCtx, sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: registration, Events: events})
			cancel()
			if err == nil {
				t.recovered()
				continue
			}
			if daemonTelemetryRetryable(err) {
				t.failed(len(chunk), err, true)
				retry = append(retry, chunk...)
				stopped = true
				break
			}
			t.failed(len(chunk), err, false)
			t.drop(len(chunk))
		}
		retry = append(retry, list...)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	left := append(append(retry, waiting...), t.pending...)
	if over := len(left) - daemonTelemetryMaxPending; over > 0 {
		left = left[over:]
		t.dropped += int64(over)
	}
	t.pending = left
	if len(t.pending) == 0 {
		t.running = false
		return false
	}
	return true
}

// daemonTelemetryRetryable reports a post worth trying again: a gateway out
// of reach, a busy one (the events budget) or one not ready yet.
func daemonTelemetryRetryable(err error) bool {
	if errors.Is(err, sandboxrelay.ErrGatewayUnreachable) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var relayErr *sandboxrelay.Error
	if errors.As(err, &relayErr) {
		return relayErr.Status == http.StatusTooManyRequests || relayErr.Status == http.StatusServiceUnavailable
	}
	return false
}

func (t *daemonRelayTelemetry) drop(n int) {
	t.mu.Lock()
	t.dropped += int64(n)
	t.mu.Unlock()
}

// failed logs the first failed post of a streak; kept says the records are
// tried again.
func (t *daemonRelayTelemetry) failed(n int, err error, kept bool) {
	t.mu.Lock()
	first := !t.failing
	t.failing = true
	dropped := t.dropped
	t.mu.Unlock()
	if !first || t.logf == nil {
		return
	}
	what := "dropped"
	if kept {
		what = "kept for the next try"
	}
	t.logf("report %d sandbox telemetry record(s) to the managed gateway: %v (%s; %d dropped since the daemon started)", n, err, what, dropped)
}

func (t *daemonRelayTelemetry) recovered() {
	t.mu.Lock()
	was := t.failing
	t.failing = false
	t.mu.Unlock()
	if was && t.logf != nil {
		t.logf("the managed gateway takes sandbox telemetry records again")
	}
}
