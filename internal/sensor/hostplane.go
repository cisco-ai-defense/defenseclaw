// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// maxKernelEventsPerPoll bounds the kernel control outcomes one poll
	// carries. An agent looping on a denied read must not grow a snapshot
	// without limit; the rest is counted.
	maxKernelEventsPerPoll = 512

	// hookRingSize and hookRingWindow bound the managed hook decisions kept
	// for joining: Claude Code's approval prompt alone delays a tool's exec
	// by 15-20 s after its PreToolUse decision.
	hookRingSize   = 4096
	hookRingWindow = 120 * time.Second
	// hookUntimedWindow is how long a decision for a tool that runs no shell
	// command (a search tool spawning rg) can match a process by time alone.
	hookUntimedWindow = 10 * time.Second
	// hookClockSkew lets a decision stamped by the gateway slightly after
	// the kernel stamped the exec still match it.
	hookClockSkew = 2 * time.Second

	// maxToolJoins bounds the joins kept for tool-call processes.
	maxToolJoins = 8192
)

// hostPlane consumes the kernel event stream, attributes each observation to
// the agent responsible for it, and accumulates per-agent sessions.
//
// The lineage gate lives here and nowhere else: an observation whose process
// has no AI agent above it is discarded before it can become a signal. That is
// the difference between this and a mediocre EDR, and it is also the primary
// false-positive control -- these tactics are far too ordinary on a developer
// machine to report without an actor attached.
type hostPlane struct {
	source     plane.Source
	tracker    *agentchain.Tracker
	indicators tactics.IndicatorSet
	window     time.Duration
	minStages  int
	// hooks holds the managed hook decisions tool-call processes are joined
	// against; nil where decisions are not joined (not a managed host).
	hooks *hookRing

	mu       sync.Mutex
	sessions map[int]*agentchain.Session
	// meta is the per-session detail the scored session does not carry,
	// keyed like sessions.
	meta map[int]*sessionMeta
	// joins are the hook joins of tool-call processes (an agent's direct
	// children), which their descendants' activity inherits.
	joins toolJoins
	// kernelEvents are the kernel control outcomes since the last drain.
	kernelEvents  []KernelEvent
	kernelDropped int64
	// gated counts observations discarded for having no agent above them. It
	// is the denominator that makes the lineage gate auditable rather than
	// invisible.
	gated int64
	// classified counts observations that became a tactic.
	classified int64
	running    bool
	started    bool
	coverage   plane.Coverage

	// handled counts every event consumed; containerEvents those from
	// container processes, routed to that count and never joined to a host
	// session; ownEvents DefenseClaw's own processes (gateway, helper,
	// verified hooks), kept in the lineage and never scored; hookUnexpected
	// the processes started under a verified hook that are not its tools.
	handled         atomic.Int64
	containerEvents atomic.Int64
	ownEvents       atomic.Int64
	hookUnexpected  atomic.Int64
}

// sessionMeta is what one agent session's records say beyond the score.
type sessionMeta struct {
	root       agentchain.ProcessFacts
	activities map[tactics.Tactic]*RuntimeActivity
}

func newHostPlane(
	source plane.Source, tracker *agentchain.Tracker,
	indicators tactics.IndicatorSet, window time.Duration, minStages int,
) *hostPlane {
	return &hostPlane{
		source: source, tracker: tracker, indicators: indicators,
		window: window, minStages: minStages,
		sessions: make(map[int]*agentchain.Session),
		meta:     make(map[int]*sessionMeta),
		joins:    newToolJoins(maxToolJoins),
	}
}

// start begins consumption. A source that cannot start is reported to the
// caller rather than retried silently: the capability layer has already said
// the plane should work here, so a failure is a fact an operator needs.
func (h *hostPlane) start(ctx context.Context) error {
	if err := h.source.Start(ctx); err != nil {
		return err
	}
	h.mu.Lock()
	h.running = true
	h.started = true
	h.coverage = h.source.Coverage()
	h.mu.Unlock()

	go h.consume(ctx)
	return nil
}

func (h *hostPlane) consume(ctx context.Context) {
	defer func() {
		h.mu.Lock()
		h.running = false
		h.mu.Unlock()
	}()
	events := h.source.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			h.handle(event)
		}
	}
}

func (h *hostPlane) handle(event plane.Event) {
	defer h.handled.Add(1)
	if event.ContainerID != "" {
		// A container process (a devcontainer, a docker run on a managed
		// host): counted, and never joined to a host agent session. Its
		// processes are not the host agent's, whatever their names say, and
		// no host process descends from them.
		h.containerEvents.Add(1)
		return
	}
	// Every exec teaches the tracker, whether or not it classifies. Lineage is
	// built from the whole process tree; discarding non-agent execs would break
	// attribution for the agent -> sh -> cat chain this exists to follow.
	switch event.Kind {
	case plane.KindExec:
		h.tracker.ObserveExecEvent(agentchain.ExecObservation{
			PID: event.PID, PPID: event.PPID, ResponsiblePID: event.ResponsiblePID,
			Name: event.Name, Exe: event.Exe, Cmdline: event.Cmdline, User: event.User,
			UID: event.UID, AUID: event.AUID,
			ExecID: event.ExecID, ParentExecID: event.ParentExecID, StartNS: event.StartNS,
		})
		if event.Hook == plane.HookUnexpected {
			h.hookUnexpected.Add(1)
		}
		if h.hooks != nil && event.Hook == "" && !event.Self {
			h.joinToolCall(event)
		}
	case plane.KindExit:
		h.tracker.ObserveExitEvent(event.PID, event.ExecID)
		return
	}
	if event.Self || event.Hook == plane.HookVerified {
		// DefenseClaw's own gateway, helper and verified hooks stay in the
		// lineage, so what they start is attributed through them, and are
		// excluded from scoring. Counted, never hidden.
		h.ownEvents.Add(1)
		return
	}

	var (
		lineage    agentchain.Lineage
		attributed bool
		looked     bool
	)
	if event.Outcome == plane.OutcomeWouldBlock || event.Outcome == plane.OutcomeBlocked {
		// A kernel control's verdict is recorded whatever the gateway's own
		// lineage says: the helper's anchors decided the scope, and a denial
		// happened either way.
		lineage, attributed = h.tracker.Lineage(event.PID, event.ExecID)
		looked = true
		h.recordKernelEvent(event, lineage, attributed)
	}

	match, ok := tactics.Classify(tactics.Observation{
		Kind:    string(event.Kind),
		PID:     event.PID,
		Name:    event.Name,
		Cmdline: commandWordCmdline(event.Cmdline),
		Path:    event.Path,
		Detail:  event.Detail,
	}, h.indicators)
	if !ok {
		return
	}

	if !looked {
		lineage, attributed = h.tracker.Lineage(event.PID, event.ExecID)
	}
	if !attributed {
		// The lineage gate. A developer running sudo produces nothing here.
		h.mu.Lock()
		h.gated++
		h.mu.Unlock()
		return
	}

	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.classified++
	session, exists := h.sessions[lineage.RootPID]
	if !exists {
		session = agentchain.NewSession(lineage.RootPID, lineage.AgentName, at)
		h.sessions[lineage.RootPID] = session
	}
	session.Record(agentchain.Observation{
		Tactic:     match.Tactic,
		SignalID:   match.SignalID,
		Title:      match.Title,
		Detail:     match.Detail,
		PID:        event.PID,
		Confidence: match.Confidence,
		At:         at,
	})
	h.noteActivityLocked(lineage, match.Tactic, event)
}

// noteActivityLocked folds one observation into its session's per-tactic
// detail.
func (h *hostPlane) noteActivityLocked(lineage agentchain.Lineage, tactic tactics.Tactic, event plane.Event) {
	meta := h.meta[lineage.RootPID]
	if meta == nil {
		meta = &sessionMeta{activities: make(map[tactics.Tactic]*RuntimeActivity)}
		h.meta[lineage.RootPID] = meta
	}
	meta.root = lineage.Root
	activity := meta.activities[tactic]
	if activity == nil {
		activity = &RuntimeActivity{Tactic: tactic}
		meta.activities[tactic] = activity
	}
	if event.Source != "" {
		activity.Source = event.Source
	}
	if event.UID != nil {
		activity.UID, activity.AUID = copyIntPtr(event.UID), copyIntPtr(event.AUID)
	}
	if event.User != "" {
		activity.User = event.User
	}
	if outcomeRank(event.Outcome) > outcomeRank(activity.Outcome) {
		activity.Outcome, activity.Control = event.Outcome, event.Control
	}
	if h.hooks == nil || lineage.Depth == 0 {
		return
	}
	join, ok := h.joins.get(toolKey(lineage.Child.PID, lineage.Child.ExecID))
	if !ok {
		return
	}
	switch {
	case activity.Hook == nil || (activity.Hook.Seen && join.Seen):
		// The latest joined decision.
		activity.Hook = &join
	case !join.Seen:
		// Any observation outside a hook decision keeps the tactic marked:
		// agent activity without a hook decision is the record worth having.
		activity.Hook = &HookJoin{}
	}
}

// outcomeRank orders kernel outcomes by how much the kernel did.
func outcomeRank(outcome plane.KernelOutcome) int {
	switch outcome {
	case plane.OutcomeBlocked:
		return 3
	case plane.OutcomeWouldBlock:
		return 2
	case plane.OutcomeObserved:
		return 1
	}
	return 0
}

func copyIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

// recordKernelEvent keeps one kernel control outcome for the next poll.
func (h *hostPlane) recordKernelEvent(event plane.Event, lineage agentchain.Lineage, attributed bool) {
	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	record := KernelEvent{
		At: at, Outcome: event.Outcome, Control: event.Control,
		RuleID: KernelControlRuleID(event.Control), Policy: event.Policy,
		Kind: event.Kind, Path: event.Path, PID: event.PID, ExecID: event.ExecID,
		Process: event.Name, Exe: event.Exe, UID: copyIntPtr(event.UID), AUID: copyIntPtr(event.AUID),
		User: event.User,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if attributed {
		record.AgentName, record.RootPID = lineage.AgentName, lineage.RootPID
		record.Connector = firstNonEmptyString(lineage.SessionRoot.Agent.Connector, lineage.Root.Agent.Connector)
		if h.hooks != nil && lineage.Depth > 0 {
			if join, ok := h.joins.get(toolKey(lineage.Child.PID, lineage.Child.ExecID)); ok {
				record.Hook = &join
			}
		}
	}
	if len(h.kernelEvents) >= maxKernelEventsPerPoll {
		h.kernelDropped++
		return
	}
	h.kernelEvents = append(h.kernelEvents, record)
}

// drainKernelEvents hands over the kernel outcomes since the last drain.
func (h *hostPlane) drainKernelEvents() ([]KernelEvent, int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	events, dropped := h.kernelEvents, h.kernelDropped
	h.kernelEvents, h.kernelDropped = nil, 0
	return events, dropped
}

// joinToolCall labels a process an agent started directly -- a tool call's
// shell -- with the managed hook decision that covered it, at exec time: the
// decision is recorded before the hook answers, so it is already there when
// the tool runs. Its descendants inherit the label.
func (h *hostPlane) joinToolCall(event plane.Event) {
	if isHookLauncher(event.Cmdline) {
		// The vendor's launcher of a DefenseClaw hook is not a tool call.
		return
	}
	lineage, ok := h.tracker.Lineage(event.PID, event.ExecID)
	if !ok || lineage.Depth != 1 {
		return
	}
	at := event.At
	if at.IsZero() {
		at = time.Now()
	}
	uid := copyIntPtr(event.UID)
	if uid == nil {
		uid = lineage.SessionRoot.UID
	}
	join := h.hooks.join(hookExec{
		RootPID:   lineage.SessionRoot.PID,
		Connector: firstNonEmptyString(lineage.SessionRoot.Agent.Connector, lineage.Root.Agent.Connector),
		UID:       uid,
		At:        at,
		Hashes:    shellCommandHashes(event.Cmdline),
	}, func(peerPID int) (int, bool) {
		peer, ok := h.tracker.Lineage(peerPID, "")
		if !ok {
			return 0, false
		}
		return peer.SessionRoot.PID, true
	})
	h.mu.Lock()
	h.joins.put(toolKey(event.PID, event.ExecID), join, at)
	h.mu.Unlock()
}

// commandWordCmdline is a command line with its program named as a shell
// command names it. Tetragon reports argv[0] as the resolved binary
// (/usr/bin/sudo), and the classifier's command patterns are anchored on the
// command word (sudo -i), so an unreduced path would hide every one of them.
func commandWordCmdline(cmdline string) string {
	trimmed := strings.TrimLeft(cmdline, " \t")
	end := strings.IndexAny(trimmed, " \t")
	if end < 0 {
		end = len(trimmed)
	}
	first := trimmed[:end]
	if !strings.ContainsAny(first, `/\`) {
		return cmdline
	}
	return tactics.BaseName(first) + trimmed[end:]
}

// isHookLauncher reports a command line that runs a DefenseClaw hook.
func isHookLauncher(cmdline string) bool {
	return strings.Contains(cmdline, "defenseclaw-hook ") || strings.Contains(cmdline, "/.defenseclaw/hooks/")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// hostFinding is one agent session, scored.
type hostFinding struct {
	RootPID    int
	AgentName  string
	Score      int
	Signals    []scoring.Signal
	Stages     []tactics.Tactic
	FirstSeen  time.Time
	LastSeen   time.Time
	Root       agentchain.ProcessFacts
	Activities []RuntimeActivity
}

// harvest expires stale observations and returns the sessions that currently
// score at or above the floor.
//
// Expiry runs on every harvest rather than on a timer, so a chain is a chain
// within its window rather than over the lifetime of a long-running agent, and
// a session that has gone quiet decays out instead of scoring forever.
func (h *hostPlane) harvest(now time.Time, minRisk int) []hostFinding {
	cutoff := now.Add(-h.window)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.joins.expire(now.Add(-h.window - hookRingWindow))

	findings := make([]hostFinding, 0, len(h.sessions))
	for rootPID, session := range h.sessions {
		session.Expire(cutoff)
		if len(session.Observations()) == 0 {
			delete(h.sessions, rootPID)
			delete(h.meta, rootPID)
			continue
		}
		stages := session.TacticsSeen()
		meta := h.meta[rootPID]
		activities := make([]RuntimeActivity, 0, len(stages))
		present := make(map[tactics.Tactic]bool, len(stages))
		for _, tactic := range stages {
			present[tactic] = true
			activity := RuntimeActivity{Tactic: tactic}
			if meta != nil && meta.activities[tactic] != nil {
				activity = copyActivity(*meta.activities[tactic])
			}
			activities = append(activities, activity)
		}
		var root agentchain.ProcessFacts
		if meta != nil {
			root = meta.root
			for tactic := range meta.activities {
				if !present[tactic] {
					delete(meta.activities, tactic)
				}
			}
		}
		score, signals := session.Score(h.minStages)
		if score < minRisk {
			continue
		}
		findings = append(findings, hostFinding{
			RootPID: rootPID, AgentName: session.AgentName,
			Score: score, Signals: signals, Stages: stages,
			FirstSeen: session.FirstSeen, LastSeen: session.LastSeen,
			Root: root, Activities: activities,
		})
	}
	return findings
}

func copyActivity(activity RuntimeActivity) RuntimeActivity {
	activity.UID, activity.AUID = copyIntPtr(activity.UID), copyIntPtr(activity.AUID)
	if activity.Hook != nil {
		join := *activity.Hook
		activity.Hook = &join
	}
	return activity
}

// stats reports what the gate did, so the lineage filter is auditable. The
// coverage is the source's current one: the managed helper's Tetragon
// backend can fall back to cn_proc and come back while the stream runs.
func (h *hostPlane) stats() (classified, gated int64, running bool, coverage plane.Coverage) {
	h.mu.Lock()
	classified, gated, running, coverage = h.classified, h.gated, h.running, h.coverage
	started := h.started
	h.mu.Unlock()
	if started {
		coverage = h.source.Coverage()
	}
	return classified, gated, running, coverage
}

func (h *hostPlane) close() error {
	if h.source == nil {
		return nil
	}
	return h.source.Close()
}

// HookDecision is one managed hook decision, as the gateway's hook socket
// recorded it, for joining the processes of the tool call it covered.
type HookDecision struct {
	// Connector is the decision's connector ("claudecode").
	Connector        string
	SessionID        string
	ToolInvocationID string
	// CommandHash is HookCommandHash of the tool call's shell command; ""
	// for a tool that runs no command.
	CommandHash string
	// PeerPID and PeerUID are the hook process's kernel credentials
	// (SO_PEERCRED), never anything the caller sent.
	PeerPID int
	PeerUID int
	At      time.Time
}

// hookExec is a tool-call process as the join sees it.
type hookExec struct {
	// RootPID is the session root of the agent that started it.
	RootPID   int
	Connector string
	UID       *int
	At        time.Time
	// Hashes are the hashes of the shell commands its command line may be
	// running (shellCommandHashes).
	Hashes []string
}

// hookRing is a bounded ring of managed hook decisions.
type hookRing struct {
	mu      sync.Mutex
	entries []hookEntry
	next    int
	window  time.Duration
}

type hookEntry struct {
	HookDecision
	valid bool
	// used marks a command decision already joined to its process.
	used bool
}

func newHookRing(capacity int, window time.Duration) *hookRing {
	return &hookRing{entries: make([]hookEntry, capacity), window: window}
}

func (r *hookRing) record(decision HookDecision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[r.next] = hookEntry{HookDecision: decision, valid: true}
	r.next = (r.next + 1) % len(r.entries)
}

// join matches a tool-call process to the oldest decision it can belong to:
// exact when its shell command hashes equal a decision's of the same agent
// (or, when the decision's hook process is not in the lineage table, of the
// same user and connector), temporal when only the agent and the time agree.
// A command decision joins one process; a decision for a tool that runs no
// command (a search spawning rg) can label several, within a short window.
// rootOf resolves a hook process pid to its agent's session root.
func (r *hookRing) join(exec hookExec, rootOf func(pid int) (int, bool)) HookJoin {
	r.mu.Lock()
	defer r.mu.Unlock()
	roots := map[int][2]int{}
	resolve := func(pid int) (int, bool) {
		if cached, ok := roots[pid]; ok {
			return cached[0], cached[1] == 1
		}
		root, known := rootOf(pid)
		flag := 0
		if known {
			flag = 1
		}
		roots[pid] = [2]int{root, flag}
		return root, known
	}
	var exact, timed *hookEntry
	for step := 1; step <= len(r.entries); step++ {
		entry := &r.entries[(r.next-step+len(r.entries))%len(r.entries)]
		if !entry.valid {
			break
		}
		age := exec.At.Sub(entry.At)
		if age > r.window {
			// Newest first: everything older is out of the window too.
			break
		}
		if age < -hookClockSkew || entry.used {
			continue
		}
		root, known := resolve(entry.PeerPID)
		sameRoot := known && root == exec.RootPID
		sameUser := !known && exec.UID != nil && *exec.UID == entry.PeerUID &&
			exec.Connector != "" && exec.Connector == entry.Connector
		if entry.CommandHash != "" && containsString(exec.Hashes, entry.CommandHash) && (sameRoot || sameUser) {
			exact = entry
		}
		if sameRoot && (entry.CommandHash != "" || age <= hookUntimedWindow) {
			timed = entry
		}
	}
	picked, confidence := exact, HookJoinExact
	if picked == nil {
		picked, confidence = timed, HookJoinTemporal
	}
	if picked == nil {
		return HookJoin{}
	}
	if picked.CommandHash != "" {
		picked.used = true
	}
	return HookJoin{
		Seen: true, Confidence: confidence, Connector: picked.Connector,
		SessionID: picked.SessionID, ToolInvocationID: picked.ToolInvocationID,
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// toolJoins is a bounded map of the hook joins of tool-call processes.
type toolJoins struct {
	limit   int
	entries map[string]toolJoin
	order   []string
}

type toolJoin struct {
	join HookJoin
	at   time.Time
}

func newToolJoins(limit int) toolJoins {
	return toolJoins{limit: limit, entries: make(map[string]toolJoin)}
}

func toolKey(pid int, execID string) string {
	if execID != "" {
		return execID
	}
	return "pid:" + strconv.Itoa(pid)
}

// put records a join. toolJoins has no lock of its own: the host plane's
// mutex guards it.
func (j *toolJoins) put(key string, join HookJoin, at time.Time) {
	if _, exists := j.entries[key]; !exists {
		j.order = append(j.order, key)
	}
	j.entries[key] = toolJoin{join: join, at: at}
	for len(j.order) > j.limit {
		delete(j.entries, j.order[0])
		j.order = j.order[1:]
	}
}

func (j *toolJoins) get(key string) (HookJoin, bool) {
	entry, ok := j.entries[key]
	return entry.join, ok
}

// expire drops joins recorded before cutoff.
func (j *toolJoins) expire(cutoff time.Time) {
	kept := j.order[:0]
	for _, key := range j.order {
		entry, ok := j.entries[key]
		if !ok {
			continue
		}
		if entry.at.Before(cutoff) {
			delete(j.entries, key)
			continue
		}
		kept = append(kept, key)
	}
	j.order = kept
}

// HookCommandHash is the join hash of a hook decision's shell command: the
// command split into words, each passed through the command-line redaction
// the sensor helper applies to every kernel-sourced command line (the quotes
// a word starts or ends with set aside, as the helper does), joined with
// single spaces and hashed. "" for an empty command.
func HookCommandHash(command string) string {
	words := strings.Fields(command)
	if len(words) == 0 {
		return ""
	}
	// A leading shell word stands in for the program the helper saw first
	// (bash -c ...), so argv[0]-dependent rules decide the same way.
	argv := append(append(make([]string, 0, len(words)+1), "sh"), words...)
	return commandDigest(strings.Join(redaction.CommandArgs(argv)[1:], " "))
}

// HookArgvCommand is the shell command an argv-shaped tool input runs: the
// script of a `sh -c` form, else the words joined.
func HookArgvCommand(argv []string) string {
	if len(argv) >= 3 && isShellName(tactics.BaseName(argv[0])) && isShellCommandFlag(argv[1]) {
		return argv[2]
	}
	return strings.Join(argv, " ")
}

func commandDigest(normalized string) string {
	if normalized == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(digest[:16])
}

// shellCommandHashes are the hashes of the shell commands a tool-call
// process may be running, read from its forwarded command line (already
// redacted by the helper): the script of `bash -c` / `bash -lc` (Codex), the
// argument of an `eval '...'` inside it (Claude Code), and the program with
// its arguments (a tool that ran one directly).
func shellCommandHashes(cmdline string) []string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return nil
	}
	var candidates []string
	if isShellName(tactics.BaseName(strings.Trim(fields[0], `"'`))) {
		for index := 1; index < len(fields); index++ {
			field := fields[index]
			if !isShellCommandFlag(field) {
				if strings.HasPrefix(field, "-") {
					continue
				}
				break
			}
			rest := fields[index+1:]
			for len(rest) > 0 && isShellOption(rest[0]) {
				rest = rest[1:]
			}
			script := strings.Join(rest, " ")
			// Tetragon wraps an argument that holds a space in double quotes.
			if len(script) >= 2 && strings.HasPrefix(script, `"`) && strings.HasSuffix(script, `"`) {
				script = script[1 : len(script)-1]
			}
			candidates = append(candidates, script)
			if inner, ok := evalArgument(script); ok {
				candidates = append(candidates, inner)
			}
			break
		}
	}
	candidates = append(candidates, strings.Join(append([]string{tactics.BaseName(fields[0])}, fields[1:]...), " "))
	hashes := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if hash := commandDigest(strings.Join(strings.Fields(candidate), " ")); hash != "" {
			hashes = append(hashes, hash)
		}
	}
	return hashes
}

// evalArgument is the shell word that follows the first `eval` in a script.
func evalArgument(script string) (string, bool) {
	for offset := 0; offset < len(script); {
		index := strings.Index(script[offset:], "eval ")
		if index < 0 {
			return "", false
		}
		at := offset + index
		if at == 0 || strings.ContainsRune(" \t;&|(", rune(script[at-1])) {
			return shellWord(strings.TrimLeft(script[at+len("eval "):], " \t"))
		}
		offset = at + len("eval ")
	}
	return "", false
}

// shellWord reads one POSIX shell word: quoted runs are unquoted, and the
// word ends at unquoted white space. false for an unterminated quote (a
// command line cut at its length bound).
func shellWord(text string) (string, bool) {
	var word strings.Builder
	for index := 0; index < len(text); {
		switch char := text[index]; {
		case char == '\'':
			end := strings.IndexByte(text[index+1:], '\'')
			if end < 0 {
				return "", false
			}
			word.WriteString(text[index+1 : index+1+end])
			index += end + 2
		case char == '"':
			closed := false
			cursor := index + 1
			for cursor < len(text) {
				if text[cursor] == '\\' && cursor+1 < len(text) {
					word.WriteByte(text[cursor+1])
					cursor += 2
					continue
				}
				if text[cursor] == '"' {
					closed = true
					break
				}
				word.WriteByte(text[cursor])
				cursor++
			}
			if !closed {
				return "", false
			}
			index = cursor + 1
		case char == '\\' && index+1 < len(text):
			word.WriteByte(text[index+1])
			index += 2
		case char == ' ' || char == '\t':
			return word.String(), word.Len() > 0
		default:
			word.WriteByte(char)
			index++
		}
	}
	return word.String(), word.Len() > 0
}

func isShellName(name string) bool {
	switch strings.ToLower(name) {
	case "sh", "bash", "zsh", "dash", "ksh":
		return true
	}
	return false
}

// isShellCommandFlag is -c, alone or in a cluster (-lc, -ic, -ec).
func isShellCommandFlag(flag string) bool {
	if len(flag) < 2 || flag[0] != '-' || flag[1] == '-' {
		return false
	}
	for _, char := range flag[1:] {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') {
			return false
		}
	}
	return strings.ContainsRune(flag[1:], 'c')
}

// isShellOption is a short option a shell takes after -c and before the
// script (bash -c -l "...").
func isShellOption(word string) bool {
	return word == "-l" || word == "-i" || word == "--login" || word == "-e" || word == "-x"
}
