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

package tetragon

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// Events of the host's own Tetragon policies (item 1 of the Tetragon UX
// spec, section 5.4).
//
// The helper's event session already asks for every kprobe and LSM event,
// the customer's included. A policy is DefenseClaw's only when this helper
// recorded loading it; every other policy is the customer's, whatever its
// name. Their events are mapped to a typed, bounded plane.KindPolicyEvent:
// the policy, the hook, the action, the mode, the outcome, one target (a
// path or a peer), the policy's tags and message, and the process facts the
// helper forwards for DefenseClaw's own events. Nothing else of the raw
// event crosses: no string, byte or integer argument, no data, no stack
// trace, no return value. DefenseClaw never adds, changes or deletes one of
// these policies; it only reads their events.
//
// Volume is bounded here, before the broker: container processes and
// DefenseClaw's own processes are counted and never forwarded, repeats of
// the same policy, process, function, action and target within a minute
// are folded into one record with a count, and each policy may forward
// CustomerPolicyRate events a second (burst CustomerPolicyBurst) within a
// host budget of CustomerHostRate. What is over the budget is counted per
// policy and raises tetragon_customer_events_capped for the hour.

// Bounds of a forwarded event of a customer policy.
const (
	MaxPolicyNameBytes    = 253
	MaxKernelFunctionByte = 128
	MaxPolicyTags         = 8
	MaxPolicyTagBytes     = 64
	MaxPolicyMessageBytes = 256
	MaxTargetBytes        = 1024
	// MaxCustomerPolicies bounds the published policy list.
	MaxCustomerPolicies = 64
	// MaxCustomerSensors bounds the sensors kept per listed policy.
	MaxCustomerSensors = 8
)

// Volume budget of the events of customer policies.
const (
	CustomerPolicyRate  = 20
	CustomerPolicyBurst = 100
	CustomerHostRate    = 200
	CustomerHostBurst   = 200
	// CustomerFoldWindow is how long repeats fold into one record.
	CustomerFoldWindow = time.Minute
	// maxFolds bounds the fold table; past it an event is not folded.
	maxFolds = 4096
	// maxBudgets bounds the per-policy budgets; past it a policy shares
	// the host budget only.
	maxBudgets = 256
	// sweepEvery is how often expired folds are flushed.
	sweepEvery = time.Second
)

// CustomerEvents is the customer_events setting: AgentEvents forwards the
// events (the gateway keeps those below an AI agent), OffEvents forwards
// none and keeps the counts and the policy list.
const (
	AgentEvents = "agent"
	OffEvents   = "off"
)

// customerActions names Tetragon's actions as an event of a customer policy
// carries them; any other value is "other".
var customerActions = map[pb.KprobeAction]string{
	pb.KprobeAction_KPROBE_ACTION_POST:                        "post",
	pb.KprobeAction_KPROBE_ACTION_FOLLOWFD:                    "followfd",
	pb.KprobeAction_KPROBE_ACTION_SIGKILL:                     "sigkill",
	pb.KprobeAction_KPROBE_ACTION_UNFOLLOWFD:                  "unfollowfd",
	pb.KprobeAction_KPROBE_ACTION_OVERRIDE:                    "override",
	pb.KprobeAction_KPROBE_ACTION_COPYFD:                      "copyfd",
	pb.KprobeAction_KPROBE_ACTION_GETURL:                      "geturl",
	pb.KprobeAction_KPROBE_ACTION_DNSLOOKUP:                   "dnslookup",
	pb.KprobeAction_KPROBE_ACTION_NOPOST:                      "nopost",
	pb.KprobeAction_KPROBE_ACTION_SIGNAL:                      "signal",
	pb.KprobeAction_KPROBE_ACTION_TRACKSOCK:                   "tracksock",
	pb.KprobeAction_KPROBE_ACTION_UNTRACKSOCK:                 "untracksock",
	pb.KprobeAction_KPROBE_ACTION_NOTIFYENFORCER:              "notify_enforcer",
	pb.KprobeAction_KPROBE_ACTION_CLEANUPENFORCERNOTIFICATION: "cleanup_enforcer_notification",
	pb.KprobeAction_KPROBE_ACTION_SET:                         "set",
}

// ActionOther is the action of an event whose action Tetragon did not name.
const ActionOther = "other"

// CustomerActionNames lists every action name an event can carry, sorted
// (the telemetry enum).
func CustomerActionNames() []string {
	names := []string{ActionOther}
	for _, name := range customerActions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// customerAction is an event's action, lower case, without its prefix.
func customerAction(action pb.KprobeAction) string {
	if name, ok := customerActions[action]; ok {
		return name
	}
	return ActionOther
}

// customerMode is a policy's mode as an event of it carries it: enforce,
// monitor (monitor and monitor_only) or unknown.
func customerMode(listed string) string {
	switch listed {
	case "enforce":
		return "enforce"
	case "monitor", "monitor_only":
		return "monitor"
	}
	return "unknown"
}

// customerOutcome is what an event of a customer policy says happened: an
// override, a sigkill or an enforcer notification denied the call when the
// policy enforces and would have otherwise; anything else is observed.
func customerOutcome(action, mode string) plane.KernelOutcome {
	switch action {
	case "override", "sigkill", "notify_enforcer":
		if mode == "enforce" {
			return plane.OutcomeBlocked
		}
		return plane.OutcomeWouldBlock
	}
	return plane.OutcomeObserved
}

// customerTarget is what the hook concerned: the first file, path or binprm
// argument's path, else the first socket argument's peer. No other argument
// is read.
func customerTarget(args []*pb.KprobeArgument) string {
	for _, arg := range args {
		var file string
		switch {
		case arg.GetFileArg() != nil:
			file = arg.GetFileArg().GetPath()
		case arg.GetPathArg() != nil:
			file = arg.GetPathArg().GetPath()
		case arg.GetLinuxBinprmArg() != nil:
			file = arg.GetLinuxBinprmArg().GetPath()
		}
		if file = boundedText(file, MaxTargetBytes); file != "" {
			return file
		}
	}
	if peer, ok := connectPeer(args); ok {
		return peer
	}
	return ""
}

// boundedText trims value, drops control characters and cuts it to max
// bytes on a rune boundary.
func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		value = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, value)
	}
	return redaction.TruncateUTF8(value, max)
}

// customerTags are a policy's tags, bounded.
func customerTags(tags []string) []string {
	var out []string
	for _, tag := range tags {
		if len(out) == MaxPolicyTags {
			break
		}
		if tag = boundedText(tag, MaxPolicyTagBytes); tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// customerFate is what happened to one event of a customer policy.
type customerFate int

const (
	fateForwarded customerFate = iota
	fateFolded
	fateContainer
	fateSelf
	fateCapped
	fateWithheld
)

// CustomerListing is one customer policy as ListTracingPolicies reported it.
type CustomerListing struct {
	Name, Mode, State, Error string
	Sensors                  []string
	// Actions are Tetragon's own action counters for the policy, the
	// non-zero ones (post, override, monitor_override, ...).
	Actions map[string]int64
}

// customerListing reads one status.
func customerListing(status *pb.TracingPolicyStatus) CustomerListing {
	listing := CustomerListing{
		Name:  boundedText(status.GetName(), MaxPolicyNameBytes),
		Mode:  PolicyMode(status.GetMode()),
		State: PolicyState(status.GetState()),
		Error: boundedText(status.GetError(), 256),
	}
	for _, sensor := range status.GetSensors() {
		if len(listing.Sensors) == MaxCustomerSensors {
			break
		}
		if sensor = boundedText(sensor, 128); sensor != "" {
			listing.Sensors = append(listing.Sensors, sensor)
		}
	}
	if counters := status.GetStats().GetActionCounters(); counters != nil {
		for name, value := range map[string]uint64{
			"post": counters.GetPost(), "signal": counters.GetSignal(), "monitor_signal": counters.GetMonitorSignal(),
			"override": counters.GetOverride(), "monitor_override": counters.GetMonitorOverride(),
			"notify_enforcer": counters.GetNotifyEnforcer(), "monitor_notify_enforcer": counters.GetMonitorNotifyEnforcer(),
			"set": counters.GetSet(), "monitor_set": counters.GetMonitorSet(),
		} {
			if value > 0 {
				if listing.Actions == nil {
					listing.Actions = map[string]int64{}
				}
				listing.Actions[name] = int64(min(value, uint64(1<<63-1)))
			}
		}
	}
	return listing
}

// CustomerCounts count the events of customer policies in the helper.
type CustomerCounts struct {
	// Seen is every event received; Forwarded the ones the gateway got
	// (repeats folded into a forwarded record included); Container those of
	// container processes; Self, Capped and Withheld the ones not
	// forwarded: DefenseClaw's own processes, over the volume budget,
	// customer_events off. Blocked are the events, of every process, whose
	// outcome is blocked (customerOutcome): the BLOCKED count status shows,
	// in the same terms as the forwarded records.
	Seen, Forwarded, Container, Self, Capped, Withheld, Blocked int64
	// CappedLastHour is how many were over the budget in the last hour.
	CappedLastHour int64
	// LastEvent is when the latest event was received.
	LastEvent time.Time
}

// Dropped is every event received and not forwarded, containers apart.
func (c CustomerCounts) Dropped() int64 { return c.Self + c.Capped + c.Withheld }

// CustomerPolicyStatus is one customer policy: its latest listing (Listed
// false when Tetragon did not list it, for a policy that had events) and
// its counts.
type CustomerPolicyStatus struct {
	CustomerListing
	Listed bool
	CustomerCounts
}

// CustomerLedger keeps the latest listing of the host's own policies and the
// counts of their events, for the helper's published state. One per helper,
// shared by every event session; safe for concurrent use.
type CustomerLedger struct {
	mu       sync.Mutex
	listed   map[string]CustomerListing
	listedAt time.Time
	counts   map[string]*customerTally
	total    CustomerCounts
}

type customerTally struct {
	CustomerCounts
	// capped counts the over-budget events per minute (Unix minute).
	capped map[int64]int64
}

// NewCustomerLedger returns an empty ledger.
func NewCustomerLedger() *CustomerLedger {
	return &CustomerLedger{listed: map[string]CustomerListing{}, counts: map[string]*customerTally{}}
}

// maxTallies bounds the policies counted; the rest count in the total.
const maxTallies = 256

// setListed replaces the listing.
func (l *CustomerLedger) setListed(listings []CustomerListing, at time.Time) {
	if l == nil {
		return
	}
	listed := make(map[string]CustomerListing, len(listings))
	for _, listing := range listings {
		listed[listing.Name] = listing
	}
	l.mu.Lock()
	l.listed, l.listedAt = listed, at
	l.mu.Unlock()
}

// count records n events of policy with one fate.
func (l *CustomerLedger) count(policy string, fate customerFate, n int64, at time.Time) {
	if l == nil || n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tally := l.counts[policy]
	if tally == nil && len(l.counts) < maxTallies {
		tally = &customerTally{}
		l.counts[policy] = tally
	}
	apply := func(c *CustomerCounts) {
		switch fate {
		case fateForwarded:
			c.Forwarded += n
		case fateContainer:
			c.Container += n
		case fateSelf:
			c.Self += n
		case fateCapped:
			c.Capped += n
		case fateWithheld:
			c.Withheld += n
		}
	}
	apply(&l.total)
	if tally != nil {
		apply(&tally.CustomerCounts)
		if fate == fateCapped {
			if tally.capped == nil {
				tally.capped = map[int64]int64{}
			}
			tally.capped[at.Unix()/60] += n
		}
	}
}

// seen records the arrival of one event, and whether it was a denial.
func (l *CustomerLedger) seen(policy string, at time.Time, blocked bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	note := func(c *CustomerCounts) {
		c.Seen++
		if blocked {
			c.Blocked++
		}
		if at.After(c.LastEvent) {
			c.LastEvent = at
		}
	}
	note(&l.total)
	tally := l.counts[policy]
	if tally == nil && len(l.counts) < maxTallies {
		tally = &customerTally{}
		l.counts[policy] = tally
	}
	if tally != nil {
		note(&tally.CustomerCounts)
	}
}

// Snapshot returns the customer policies, listed ones first by name and then
// those Tetragon no longer lists but that had events, at most
// MaxCustomerPolicies, and the totals of every customer policy.
func (l *CustomerLedger) Snapshot(now time.Time) ([]CustomerPolicyStatus, CustomerCounts) {
	if l == nil {
		return nil, CustomerCounts{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	hour := now.Add(-time.Hour).Unix() / 60
	var total int64
	statuses := make([]CustomerPolicyStatus, 0, len(l.listed))
	seen := map[string]bool{}
	add := func(name string, listing CustomerListing, listed bool) {
		status := CustomerPolicyStatus{CustomerListing: listing, Listed: listed}
		status.Name = name
		if tally := l.counts[name]; tally != nil {
			status.CustomerCounts = tally.CustomerCounts
			for minute, n := range tally.capped {
				if minute <= hour {
					delete(tally.capped, minute)
					continue
				}
				status.CappedLastHour += n
			}
			total += status.CappedLastHour
		}
		status.Sensors = append([]string(nil), listing.Sensors...)
		if len(listing.Actions) > 0 {
			status.Actions = make(map[string]int64, len(listing.Actions))
			for key, value := range listing.Actions {
				status.Actions[key] = value
			}
		}
		statuses = append(statuses, status)
		seen[name] = true
	}
	names := make([]string, 0, len(l.listed))
	for name := range l.listed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		add(name, l.listed[name], true)
	}
	var unlisted []string
	for name, tally := range l.counts {
		if !seen[name] && tally.Seen > 0 {
			unlisted = append(unlisted, name)
		}
	}
	sort.Strings(unlisted)
	for _, name := range unlisted {
		add(name, CustomerListing{}, false)
	}
	if len(statuses) > MaxCustomerPolicies {
		statuses = statuses[:MaxCustomerPolicies]
	}
	out := l.total
	out.CappedLastHour = total
	return statuses, out
}

// customerGate folds repeats and applies the volume budget of one event
// session. Not safe for concurrent use: the mapper owns it.
type customerGate struct {
	folds     map[foldKey]*fold
	order     []foldKey
	budgets   map[string]*rate.Limiter
	host      *rate.Limiter
	lastSweep time.Time
}

type foldKey struct {
	policy, execID, function, action, target string
}

type fold struct {
	first time.Time
	// pending repeats since the record that opened the window, and the
	// latest of them (the folded record carries its facts).
	pending int
	last    plane.Event
}

func newCustomerGate() *customerGate {
	return &customerGate{
		folds:   map[foldKey]*fold{},
		budgets: map[string]*rate.Limiter{},
		host:    rate.NewLimiter(CustomerHostRate, CustomerHostBurst),
	}
}

func keyOf(event plane.Event) foldKey {
	execID := event.ExecID
	if execID == "" {
		execID = "pid:" + strconv.Itoa(event.PID)
	}
	return foldKey{policy: event.Policy, execID: execID, function: event.KernelFunction, action: event.KernelAction, target: event.Target}
}

// fold returns the records to forward for one event: none when it folds
// into the record that opened its window, else the event with a count of 1,
// after the folded repeats of a window that just closed.
func (g *customerGate) fold(event plane.Event, at time.Time) []plane.Event {
	key := keyOf(event)
	entry := g.folds[key]
	if entry != nil && at.Sub(entry.first) < CustomerFoldWindow {
		entry.pending++
		entry.last = event
		return nil
	}
	event.Count = 1
	if entry != nil {
		var out []plane.Event
		if entry.pending > 0 {
			folded := entry.last
			folded.Count = entry.pending
			out = append(out, folded)
		}
		entry.first, entry.pending, entry.last = at, 0, plane.Event{}
		return append(out, event)
	}
	if len(g.folds) < maxFolds {
		g.folds[key] = &fold{first: at}
		g.order = append(g.order, key)
	}
	return []plane.Event{event}
}

// sweep returns the folded records whose window is over, and forgets the
// windows that closed with no repeat. all flushes every pending repeat.
func (g *customerGate) sweep(now time.Time, all bool) []plane.Event {
	if !all && now.Sub(g.lastSweep) < sweepEvery {
		return nil
	}
	g.lastSweep = now
	var out []plane.Event
	kept := g.order[:0]
	for _, key := range g.order {
		entry := g.folds[key]
		if entry == nil {
			continue
		}
		if !all && now.Sub(entry.first) < CustomerFoldWindow {
			kept = append(kept, key)
			continue
		}
		if entry.pending > 0 {
			folded := entry.last
			folded.Count = entry.pending
			out = append(out, folded)
		}
		delete(g.folds, key)
	}
	g.order = kept
	return out
}

// allow applies the per-policy and host budgets to one record.
func (g *customerGate) allow(policy string, at time.Time) bool {
	budget := g.budgets[policy]
	if budget == nil && len(g.budgets) < maxBudgets {
		budget = rate.NewLimiter(CustomerPolicyRate, CustomerPolicyBurst)
		g.budgets[policy] = budget
	}
	if budget != nil && !budget.AllowN(at, 1) {
		return false
	}
	return g.host.AllowN(at, 1)
}
