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

package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// The gateway's half of item 1: the events of the host's own Tetragon
// policies that the sensor helper forwarded (plane.KindPolicyEvent). The
// lineage gate decides what becomes a record: an event below an AI agent is
// attributed to the agent, its user and the managed hook decision of its
// tool call, the way the host plane attributes DefenseClaw's own events; the
// rest is counted per policy and never exported one by one. None of it is
// scored: a noisy customer policy cannot inflate DefenseClaw's findings.

const (
	// maxCustomerRecordsPerPoll bounds the attributed records one poll
	// carries (and one snapshot exports); the rest is counted.
	maxCustomerRecordsPerPoll = 256
	// maxCustomerRecent bounds the latest attributed records the runtime
	// API serves.
	maxCustomerRecent = 100
	// maxCustomerCounted bounds the policies counted by name; the rest
	// count in the totals only.
	maxCustomerCounted = 256
	// maxCustomerBlocks bounds the recent denials kept for the developer
	// notice, and customerBlockWindow how long one is kept.
	maxCustomerBlocks = 256
)

// CustomerKernelEvent is one event of the host's own Tetragon policy below an
// AI agent: what the policy did, to which target, in which process, and the
// agent, user and hook decision it is attributed to.
type CustomerKernelEvent struct {
	At time.Time
	// Policy is the customer policy's name; HookType kprobe or lsm,
	// Function the hooked symbol, Action the policy action, PolicyMode
	// enforce, monitor or unknown.
	Policy, HookType, Function, Action, PolicyMode string
	Outcome                                        plane.KernelOutcome
	// Target is the path or the peer the hook concerned (content class).
	Target  string
	Tags    []string
	Message string
	// Count is how many identical events this record stands for.
	Count int
	// The process.
	PID     int
	ExecID  string
	Process string
	Exe     string
	Cmdline string
	UID     *int
	AUID    *int
	User    string
	// The attribution: the agent, its session root and connector, the
	// tool-call process the event came from (0 when the agent itself did
	// it), and why no kernel control can anchor the root, for a heuristic or
	// IDE-hosted one.
	AgentName         string
	RootPID           int
	SessionRootPID    int
	ToolPID           int
	Connector         string
	NotEnforcedReason string
	// Hook is the hook join of the tool call; nil when it does not apply
	// (not a managed host, or the agent root acting itself).
	Hook *HookJoin
}

// CustomerPolicyCounts are the gateway's counts of one customer policy's
// forwarded events: every one it received (Seen), the ones below an AI agent
// (Attributed) and the rest (Gated). Container and Self count the ones the
// helper should have kept back (it counts its own).
type CustomerPolicyCounts struct {
	Seen, Attributed, Gated, Container, Self int64
}

func (c *CustomerPolicyCounts) add(other CustomerPolicyCounts) {
	c.Seen += other.Seen
	c.Attributed += other.Attributed
	c.Gated += other.Gated
	c.Container += other.Container
	c.Self += other.Self
}

// customerPlane is the host plane's record of customer policy events. The
// host plane's mutex guards it.
type customerPlane struct {
	records []CustomerKernelEvent
	dropped int64
	recent  []CustomerKernelEvent
	counts  map[string]*CustomerPolicyCounts
	total   CustomerPolicyCounts
}

// count adds one event's fate to its policy and the totals.
func (c *customerPlane) count(policy string, delta CustomerPolicyCounts) {
	c.total.add(delta)
	if c.counts == nil {
		c.counts = map[string]*CustomerPolicyCounts{}
	}
	counts := c.counts[policy]
	if counts == nil {
		if len(c.counts) >= maxCustomerCounted {
			return
		}
		counts = &CustomerPolicyCounts{}
		c.counts[policy] = counts
	}
	counts.add(delta)
}

// handleCustomer attributes one event of a customer policy, or gates it.
func (h *hostPlane) handleCustomer(event plane.Event) {
	n := int64(max(event.Count, 1))
	switch {
	case event.ContainerID != "":
		h.mu.Lock()
		h.customer.count(event.Policy, CustomerPolicyCounts{Seen: n, Container: n})
		h.mu.Unlock()
		return
	case event.Self || event.Hook == plane.HookVerified:
		h.mu.Lock()
		h.customer.count(event.Policy, CustomerPolicyCounts{Seen: n, Self: n})
		h.mu.Unlock()
		return
	}
	lineage, attributed := h.tracker.Lineage(event.PID, event.ExecID)
	h.mu.Lock()
	defer h.mu.Unlock()
	if !attributed {
		// The lineage gate: the user's own shell, a cron job, a service.
		h.customer.count(event.Policy, CustomerPolicyCounts{Seen: n, Gated: n})
		return
	}
	h.customer.count(event.Policy, CustomerPolicyCounts{Seen: n, Attributed: n})
	record := customerRecord(event, lineage)
	if h.hooks != nil && lineage.Depth > 0 {
		if join, ok := h.joins.get(toolKey(lineage.Child.PID, lineage.Child.ExecID)); ok {
			copied := join
			copied.RuleIDs = append([]string(nil), join.RuleIDs...)
			record.Hook = &copied
		} else {
			// A tool call no managed hook decision covered.
			record.Hook = &HookJoin{}
		}
	}
	if len(h.customer.records) < maxCustomerRecordsPerPoll {
		h.customer.records = append(h.customer.records, record)
	} else {
		h.customer.dropped++
	}
	h.customer.recent = append(h.customer.recent, record)
	if len(h.customer.recent) > maxCustomerRecent {
		h.customer.recent = h.customer.recent[len(h.customer.recent)-maxCustomerRecent:]
	}
	if record.Outcome == plane.OutcomeBlocked {
		h.noteBlockLocked(kernelBlockOf(record))
	}
}

func customerRecord(event plane.Event, lineage agentchain.Lineage) CustomerKernelEvent {
	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	record := CustomerKernelEvent{
		At: at, Policy: event.Policy, HookType: event.KernelHookType, Function: event.KernelFunction,
		Action: event.KernelAction, PolicyMode: event.PolicyMode, Outcome: event.Outcome, Target: event.Target,
		Tags: append([]string(nil), event.PolicyTags...), Message: event.PolicyMessage, Count: max(event.Count, 1),
		PID: event.PID, ExecID: event.ExecID, Process: event.Name, Exe: event.Exe, Cmdline: event.Cmdline,
		UID: copyIntPtr(event.UID), AUID: copyIntPtr(event.AUID), User: event.User,
		AgentName: lineage.AgentName, RootPID: lineage.RootPID, SessionRootPID: lineage.SessionRoot.PID,
		Connector:         firstNonEmptyString(lineage.SessionRoot.Agent.Connector, lineage.Root.Agent.Connector),
		NotEnforcedReason: lineage.Root.Agent.ObserveOnly,
	}
	if lineage.Depth > 0 {
		record.ToolPID = lineage.Child.PID
	}
	return record
}

// drainCustomer hands over the attributed records since the last drain and
// how many did not fit.
func (h *hostPlane) drainCustomer() ([]CustomerKernelEvent, int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	records, dropped := h.customer.records, h.customer.dropped
	h.customer.records, h.customer.dropped = nil, 0
	return records, dropped
}

// customerSnapshot returns the latest attributed records, oldest first, the
// per-policy counts by name and the totals.
func (h *hostPlane) customerSnapshot() ([]CustomerKernelEvent, map[string]CustomerPolicyCounts, CustomerPolicyCounts) {
	h.mu.Lock()
	defer h.mu.Unlock()
	recent := make([]CustomerKernelEvent, len(h.customer.recent))
	copy(recent, h.customer.recent)
	counts := make(map[string]CustomerPolicyCounts, len(h.customer.counts))
	for name, value := range h.customer.counts {
		counts[name] = *value
	}
	return recent, counts, h.customer.total
}

// mergeCustomer is the backend's customer view: the helper's policies and
// counts from kernel_status, with the gateway's attributed and gated counts
// beside them; a policy only the gateway counted is added (at most
// plane's 64).
func mergeCustomer(backend *plane.Backend, kernel *KernelState, gateway map[string]CustomerPolicyCounts, total CustomerPolicyCounts) {
	if backend == nil {
		return
	}
	const maxPolicies = 64
	seen := map[string]bool{}
	if kernel != nil {
		for _, policy := range kernel.Status.CustomerPolicies {
			if len(backend.CustomerPolicies) == maxPolicies {
				break
			}
			counted := gateway[policy.Name]
			backend.CustomerPolicies = append(backend.CustomerPolicies, plane.CustomerPolicy{
				Name: policy.Name, Mode: policy.Mode, State: policy.State,
				CustomerEvents: plane.CustomerEvents{
					Seen: policy.Seen, Forwarded: policy.Forwarded, Dropped: policy.Dropped, Container: policy.Container,
					Capped: policy.Capped, Attributed: counted.Attributed, Gated: counted.Gated,
				},
			})
			seen[policy.Name] = true
		}
		if events := kernel.Status.CustomerEvents; events != nil {
			backend.CustomerEvents.Seen, backend.CustomerEvents.Forwarded = events.Seen, events.Forwarded
			backend.CustomerEvents.Dropped, backend.CustomerEvents.Container = events.Dropped, events.Container
			backend.CustomerEvents.Capped = events.Capped
		}
	}
	names := make([]string, 0, len(gateway))
	for name := range gateway {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if len(backend.CustomerPolicies) == maxPolicies {
			break
		}
		counted := gateway[name]
		backend.CustomerPolicies = append(backend.CustomerPolicies, plane.CustomerPolicy{
			Name: name, CustomerEvents: plane.CustomerEvents{Attributed: counted.Attributed, Gated: counted.Gated},
		})
	}
	backend.CustomerEvents.Attributed, backend.CustomerEvents.Gated = total.Attributed, total.Gated
}

// KernelBlock is a denial the kernel returned to a process below an AI agent:
// a DefenseClaw kernel control's or a customer policy's. The gateway's
// post-tool hook answer tells the agent about it (kernel_block_notice.go).
type KernelBlock struct {
	// ID is stable for the denial, so it is told once.
	ID    string
	At    time.Time
	Owner string // plane.PolicyOwnerDefenseClaw or plane.PolicyOwnerCustomer
	// Control and RuleID name a DefenseClaw control; Policy and Function a
	// customer policy and its hook, Action that policy's action (override,
	// sigkill or notify_enforcer).
	Control, RuleID          string
	Policy, Function, Action string
	// Process is the executable basename and Target the path (or peer) the
	// call concerned.
	Process, Target string
	UID             *int
	// RootPID and SessionRootPID are the agent's; SessionID and
	// ToolInvocationID the hook decision joined to the tool call, if any.
	RootPID, SessionRootPID     int
	Connector                   string
	SessionID, ToolInvocationID string
}

// kernelBlockWindow is how long a denial is kept for the notice.
const kernelBlockWindow = 5 * time.Minute

func kernelBlockOf(record CustomerKernelEvent) KernelBlock {
	block := KernelBlock{
		At: record.At, Owner: plane.PolicyOwnerCustomer, Policy: record.Policy, Function: record.Function, Action: record.Action,
		Process: record.Process, Target: record.Target, UID: copyIntPtr(record.UID),
		RootPID: record.RootPID, SessionRootPID: record.SessionRootPID, Connector: record.Connector,
	}
	if record.Hook != nil && record.Hook.Seen {
		block.SessionID, block.ToolInvocationID = record.Hook.SessionID, record.Hook.ToolInvocationID
	}
	block.ID = kernelBlockID(block.Owner, record.Policy, record.ExecID, record.PID, record.Target, record.At)
	return block
}

// kernelBlockID is a content-free id: the parts are hashed.
func kernelBlockID(owner, policy, execID string, pid int, target string, at time.Time) string {
	sum := sha256.New()
	for _, part := range []string{owner, policy, execID, strconv.Itoa(pid), target, strconv.FormatInt(at.UnixNano(), 10)} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	return "kblock-" + hex.EncodeToString(sum.Sum(nil))[:24]
}

// noteBlockLocked keeps an attributed denial for the notice. The host
// plane's mutex is held.
func (h *hostPlane) noteBlockLocked(block KernelBlock) {
	cutoff := block.At.Add(-kernelBlockWindow)
	kept := h.blocks[:0]
	for _, old := range h.blocks {
		if old.At.After(cutoff) {
			kept = append(kept, old)
		}
	}
	h.blocks = append(kept, block)
	if len(h.blocks) > maxCustomerBlocks {
		h.blocks = h.blocks[len(h.blocks)-maxCustomerBlocks:]
	}
}

// recentBlocks returns the denials at or after since, oldest first.
func (h *hostPlane) recentBlocks(since time.Time) []KernelBlock {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []KernelBlock
	for _, block := range h.blocks {
		if !block.At.Before(since) {
			block.UID = copyIntPtr(block.UID)
			out = append(out, block)
		}
	}
	return out
}
