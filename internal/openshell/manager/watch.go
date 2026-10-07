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
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// watchRetry paces restarting a watch that ended with an error.
const watchRetry = 10 * time.Second

// startWatch runs the sandbox's watcher unless one is running already or
// the manager is not running.
func (m *Manager) startWatch(b *box) {
	runCtx := m.running()
	if runCtx == nil {
		return
	}
	m.mu.Lock()
	if b.watchCancel != nil || b.deleted {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(runCtx)
	done := make(chan struct{})
	b.watchCancel, b.watchDone = cancel, done
	name := b.rec.Name
	m.mu.Unlock()
	go func() {
		defer close(done)
		defer func() {
			m.mu.Lock()
			if b.watchDone == done {
				b.watchCancel, b.watchDone = nil, nil
			}
			m.mu.Unlock()
			cancel()
		}()
		m.watchLoop(ctx, b, name)
	}()
}

func (m *Manager) stopWatch(b *box) {
	m.stopGuard(b)
	m.stopObserve(b)
	m.mu.Lock()
	cancel, done := b.watchCancel, b.watchDone
	b.watchCancel, b.watchDone = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (m *Manager) stopWatchers() {
	m.mu.Lock()
	boxes := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		boxes = append(boxes, b)
	}
	m.mu.Unlock()
	for _, b := range boxes {
		m.stopWatch(b)
	}
}

func (m *Manager) watchLoop(ctx context.Context, b *box, name string) {
	for ctx.Err() == nil {
		gw, gone, err := m.connection(ctx)
		dropped := false
		if err == nil {
			m.mu.Lock()
			cursor := b.rec.Cursor
			m.mu.Unlock()
			dropped, err = m.watchOn(ctx, gw, gone, b, name, cursor)
		}
		if ctx.Err() != nil {
			return
		}
		if dropped {
			// The connection the stream ran on was dropped (and closed): a
			// watch on it would retry on a dead connection for good.
			// Follow the next one at once; connection paces the redials.
			continue
		}
		if errors.Is(err, stream.ErrSandboxNotFound) {
			// Deleted outside DefenseClaw: reconcile releases what it held.
			go m.reconcileOne(context.WithoutCancel(ctx), name)
			return
		}
		if err != nil {
			m.logf("%s: watch %s: %v", gatewaylog.ErrCodeOpenShellWatchFailed, name, err)
		}
		t := time.NewTimer(watchRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// watchOn runs one watch on gw until it ends, ctx ends or gw's connection
// is dropped (gone closes), which dropped reports.
func (m *Manager) watchOn(ctx context.Context, gw *Gateway, gone <-chan struct{}, b *box, name, cursor string) (dropped bool, err error) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-gone:
			cancel()
		case <-wctx.Done():
		}
	}()
	err = m.opts.Watch(wctx, gw, name, cursor, func(c string) error { return m.saveCursor(b, c) },
		func(ev stream.Event) { m.handleEvent(ctx, b, ev) })
	select {
	case <-gone:
		return true, err
	default:
		return false, err
	}
}

func (m *Manager) saveCursor(b *box, cursor string) error {
	m.mu.Lock()
	if b.deleted || b.rec.Cursor == cursor {
		m.mu.Unlock()
		return nil
	}
	b.rec.Cursor = cursor
	m.mu.Unlock()
	return m.saveRecord(b)
}

// handleEvent maps one WatchSandbox event onto telemetry, the feed and
// triage.
func (m *Manager) handleEvent(ctx context.Context, b *box, ev stream.Event) {
	switch ev.Kind {
	case stream.KindStatus:
		m.statusEvent(ctx, b, ev.Status)
	case stream.KindLog:
		if ev.Log != nil && ev.Log.OCSF != nil {
			m.ocsfEvent(ctx, b, *ev.Log.OCSF, ev.Time)
		}
	case stream.KindDraft:
		// Off the receive loop: a pass resolves the destinations the
		// agent's proposals name, which can take up to triagePassBudget,
		// and a receiver that lags that long has its events dropped by
		// OpenShell.
		m.triageNow(b)
	case stream.KindGap:
		m.mu.Lock()
		id, deleted := b.identity(), b.deleted
		m.mu.Unlock()
		if deleted || ev.Gap == nil {
			// A deleted sandbox's stream has nothing left to report.
			return
		}
		m.tel.RecordSandboxHealth(ctx, gapHealth(id, ev.Gap.Reason, m.now()))
	case stream.KindWarning:
		m.streamWarning(ctx, b, ev.Warning)
	case stream.KindConnected:
		// A reconnect may have missed a draft notification.
		m.triageNow(b)
	}
}

// gapHealth is the degraded health record of events lost on a sandbox's
// stream, in words (GAP-0137). A cursor out of range is what a gateway
// restart (an upgrade, setup installing OpenShell) or a trimmed event log
// leaves: MEDIUM, no alert. A cursor the gateway could not have issued (a
// different gateway, a damaged state file) stays HIGH.
func gapHealth(id audit.SandboxIdentity, reason string, at time.Time) audit.SandboxHealthEvent {
	ev := audit.SandboxHealthEvent{Sandbox: id, State: audit.SandboxHealthDegraded,
		ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellWatchFailed), Timestamp: at}
	switch reason {
	case stream.GapCursorOutOfRange:
		ev.Severity = "MEDIUM"
		ev.ErrorSummary = "the OpenShell gateway restarted or trimmed its event log: this sandbox's events up to the reconnect at " +
			at.UTC().Format("15:04:05") + " UTC may be missing (" + reason + ")"
	case stream.GapCursorRejected:
		ev.ErrorSummary = "the OpenShell gateway does not know where this sandbox's events left off (a different gateway, " +
			"or a damaged sandbox record): its events up to the reconnect at " + at.UTC().Format("15:04:05") + " UTC may be missing (" + reason + ")"
	default:
		ev.ErrorSummary = "sandbox events were lost: " + reason
	}
	return ev
}

// streamWarning reports a warning of the sandbox's stream: OpenShell's
// (it dropped messages for a lagging receiver, say: the sandbox's events
// are incomplete) as degraded health, the watcher's own (a cursor it could
// not save) in the log.
func (m *Manager) streamWarning(ctx context.Context, b *box, w *stream.Warning) {
	if w == nil {
		return
	}
	m.mu.Lock()
	id := b.identity()
	m.mu.Unlock()
	msg := truncate(sandboxapi.DisplayText(w.Message), 400)
	if w.Local {
		m.logf("sandbox %s: watch: %s", id.Name, msg)
		return
	}
	m.logf("%s: sandbox %s: OpenShell warned on its event stream: %s", gatewaylog.ErrCodeOpenShellWatchFailed, id.Name, msg)
	m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{Sandbox: id, State: audit.SandboxHealthDegraded,
		ErrorCode:    errorToken(gatewaylog.ErrCodeOpenShellWatchFailed),
		ErrorSummary: truncate("OpenShell warned on the sandbox's event stream (its events may be incomplete): "+msg, 512), Timestamp: m.now()})
}

func (m *Manager) statusEvent(ctx context.Context, b *box, st *stream.Status) {
	if st == nil {
		return
	}
	m.mu.Lock()
	if b.rec.ID != "" && st.ID != "" && st.ID != b.rec.ID {
		// The stream follows a name: this is another sandbox that took it,
		// whose phase is not this one's.
		name := b.rec.Name
		m.mu.Unlock()
		go m.reconcileOne(context.WithoutCancel(ctx), name)
		return
	}
	if b.sb != nil {
		b.sb.Status.Phase = st.Phase
		b.sb.Status.CurrentPolicyVersion = st.PolicyVersion
		b.sb.Status.ExitCode = st.ExitCode
	}
	if b.rec.ID == "" && st.ID != "" {
		b.rec.ID = st.ID
	}
	creating := b.creating
	m.mu.Unlock()
	if creating {
		return
	}
	// A failing condition explains the phase.
	var cond *audit.SandboxCondition
	for _, c := range st.Conditions {
		if !strings.EqualFold(c.Status, "true") {
			cond = &audit.SandboxCondition{Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message}
			break
		}
	}
	phase := auditPhase(st.Phase)
	if phase == audit.SandboxPhaseUnknown {
		return
	}
	m.lifecycle(ctx, b, phase, audit.SandboxTriggerWatch, false, cond, st.ExitCode)
}

// ocsfEvent handles one OpenShell OCSF record.
func (m *Manager) ocsfEvent(ctx context.Context, b *box, r ocsf.Record, at time.Time) {
	if at.IsZero() {
		at = m.now()
	}
	m.mu.Lock()
	id := b.identity()
	name, harnessName, hostname := b.rec.Name, b.rec.Harness, b.rec.Hostname
	m.mu.Unlock()
	// A record from before this daemon started is OpenShell's stream
	// replaying what it recorded while DefenseClaw was down: it lands on
	// the feed after newer events, so the feed marks it.
	replayed := at.Before(m.startedAt)
	switch r.Class {
	case ocsf.ClassConfig:
		if settingsReload(r) {
			m.noteSettingsReload(b, at)
		}
		m.noteSyntheticAddress(b, r.Message)
	case ocsf.ClassNetwork, ocsf.ClassHTTP:
		host := m.namedHost(b, triage.NormalizeHost(r.Host), r.Port)
		if host == openshellHostAlias {
			m.hostAliasEvent(ctx, b, r, at, harnessName)
			return
		}
		if host == "" {
			return
		}
		// The harness's own background request around the proxy is refused
		// as expected and is none of the agent's doing: it is audited, but
		// neither counted as a blocked site nor shown on the feed, where
		// triage's rejection of its proposal explains it once, and it is no
		// sign of work (the Codex TUI makes it at start, before any prompt).
		fetch := r.Denied() && harnessFetchDenial(harnessName, r, host)
		// A refused name lookup (dnsRefusal) is no blocked request: the
		// connection that follows it is, and it is denied and counted on
		// its own. Nor is a connection to the sandbox's own host name
		// (ownHostName), which reaches nothing, or one OpenShell closed
		// because the policy changed under it (policyReloadCut), which the
		// policy still allows: the client connects again. They are
		// audited, but neither counted nor shown on the feed.
		quiet := fetch || (r.Denied() && (dnsRefusal(r) || ownHostName(host, hostname) || policyReloadCut(r)))
		ofHarness := harnessActivity(harnessName, r.Binary)
		if !fetch {
			m.markWork(b, at, ofHarness, m.harnessModelCall(b, r, host, ofHarness))
		} else if ofHarness {
			m.markActive(b, at)
		}
		if !r.Denied() && !r.Allowed() {
			return
		}
		ev := audit.SandboxEgressEvent{
			Sandbox: id, Source: audit.SandboxEgressSourceOpenShell, Host: host, Port: r.Port, Path: r.Path,
			Blocked: r.Denied(), Reason: truncate(openshellReason(r, host), 512), PolicyOutcome: truncate(r.Policy, 256),
			Timestamp: at, Executable: r.Binary, PID: ocsfPID(r),
		}
		if !quiet {
			m.observeDestination(ctx, b, destinationSighting{host: host, port: r.Port, at: at, denied: r.Denied(), rule: r.Policy,
				binary: r.Binary, pid: ocsfPID(r), turn: r.Allowed() && r.Class == ocsf.ClassHTTP && modelRequestOf(r) == modelTurn})
		}
		if r.Denied() {
			ev.DecisionCode = "SANDBOX_EGRESS_OPENSHELL_DENIED"
			switch {
			case fetch:
				ev.DecisionCode, ev.Severity = audit.SandboxEgressCodeHarnessFetch, "INFO"
			case dnsRefusal(r):
				// The connection that follows is the refusal that counts
				// (and the alert); the lookup alone is audited at INFO.
				ev.DecisionCode, ev.Severity = audit.SandboxEgressCodeLookupRefused, "INFO"
			case policyReloadCut(r):
				// The end of a connection the policy still allows, not a
				// refusal: no block, no alert, no blocked count (GAP-0138).
				ev.Blocked, ev.End, ev.Terminated = false, audit.SandboxEgressFailed, true
				ev.DecisionCode = "SANDBOX_EGRESS_TERMINATED"
				ev.Reason = truncate("OpenShell closed it when the sandbox policy changed; the client connects again ("+
					firstNonEmpty(r.Reason, r.Message)+")", 512)
			}
			// OpenShell drafts a proposal for the denied destination a few
			// seconds later; OpenShell 0.1.1 does not always announce it
			// on the stream. A lookup draws none.
			if fetch || !quiet {
				m.scheduleTriage(b)
			}
		} else {
			ev.DecisionCode = "SANDBOX_EGRESS_ALLOWED"
		}
		if r.Class == ocsf.ClassHTTP {
			ev.Scheme = schemeOf(r.URL)
		}
		if !m.connectionRequest(b, r, host, at) {
			m.tel.RecordSandboxEgress(ctx, ev)
		}
		if r.Denied() && !quiet {
			m.publishEgress(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Host: host, Port: r.Port,
				Source: sandboxapi.SourceOpenShell, Reason: r.Reason, Message: "✗ " + host + " (direct connection denied by OpenShell)",
				Replayed: replayed})
		}
	case ocsf.ClassProcess:
		if harnessActivity(harnessName, r.Binary) {
			m.markActive(b, at)
		}
		m.processEvent(ctx, id, r, at)
		m.observeOCSFProcess(ctx, b, r, at)
	case ocsf.ClassSSH:
		m.sshEvent(ctx, id, r, at)
	case ocsf.ClassAPI:
		m.inferenceEvent(ctx, b, id, r, at)
	case ocsf.ClassFinding:
		severity := ocsfSeverity(r.Severity)
		ev := audit.SandboxFindingEvent{
			Sandbox: id, Kind: audit.SandboxFindingOCSF, Severity: severity, Title: truncate(firstNonEmpty(r.Title, "OpenShell finding"), 256),
			Description: truncate(r.Message, 1024), Evidence: truncate(r.Raw, 1024), TargetRef: firstNonEmpty(r.Host, r.Binary),
			Timestamp: at,
		}
		if c, err := parseConfidence(r.Confidence); err == nil {
			ev.Confidence = c
		}
		m.tel.RecordSandboxFinding(ctx, ev)
		m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: severity,
			Host: r.Host, Message: firstNonEmpty(r.Title, r.Message), Replayed: replayed})
	}
}

// l7Window bounds how long after OpenShell allowed a connection the first
// request it inspected on it may come; maxOpenConns bounds the connections
// a sandbox has awaiting one.
const (
	l7Window     = 5 * time.Second
	maxOpenConns = 256
)

// openConns are OpenShell's allowed connections to one host and port whose
// first inspected request has not come yet.
type openConns struct {
	at      time.Time
	pending int
}

// connectionRequest reports an allowed OpenShell HTTP record that is the
// first request on a connection whose NET record was already recorded.
// OpenShell reports an allowed connection (NET, naming the process) and
// then each HTTP request it inspects on it, so recording both made one
// plain request two egress records (GAP-0093). Each later request on the
// connection is a record of its own, and so is every denied one. It notes
// an allowed NET open and returns false for it.
func (m *Manager) connectionRequest(b *box, r ocsf.Record, host string, at time.Time) bool {
	open := r.Class == ocsf.ClassNetwork && strings.EqualFold(r.Activity, "OPEN")
	if !r.Allowed() || (!open && r.Class != ocsf.ClassHTTP) {
		return false
	}
	key := host + ":" + strconv.Itoa(r.Port)
	m.mu.Lock()
	defer m.mu.Unlock()
	o := b.opens[key]
	if !open {
		if o == nil || o.pending == 0 || at.Sub(o.at) > l7Window {
			return false
		}
		o.pending--
		return true
	}
	if o == nil {
		if len(b.opens) >= maxOpenConns {
			for k, v := range b.opens {
				if at.Sub(v.at) > l7Window {
					delete(b.opens, k)
				}
			}
			if len(b.opens) >= maxOpenConns {
				return false
			}
		}
		if b.opens == nil {
			b.opens = map[string]*openConns{}
		}
		o = &openConns{}
		b.opens[key] = o
	} else if at.Sub(o.at) > l7Window {
		o.pending = 0
	}
	o.at = at
	o.pending++
	return false
}

// openshellReason is the audit reason of an OpenShell record: for a denial
// the words the activity feed shows for OpenShell's reason token and host
// (a cloud metadata or link-local host by name, GAP-0147), with the token
// after them, and for SSH what to do instead; otherwise OpenShell's reason
// or message (GAP-0134).
func openshellReason(r ocsf.Record, host string) string {
	token := firstNonEmpty(r.Reason, r.Message)
	if !r.Denied() || token == "" {
		return token
	}
	if r.Port == 22 {
		return sandboxapi.SSHBlockedText(host) + " (" + token + ")"
	}
	if text, ok := sandboxapi.LookupBlockedText(r.Reason, host); ok {
		return text + " (" + token + ")"
	}
	return token
}

// dnsRefusal reports OpenShell's refusal of a name lookup ("NET:REFUSE …
// DENIED <name> [reason:policy_dns_ineligible]": no port, no process).
// OpenShell answers it with a staged address and judges the connection
// that follows, which it reports as a denial of its own.
func dnsRefusal(r ocsf.Record) bool {
	return r.Class == ocsf.ClassNetwork && strings.EqualFold(r.Activity, "REFUSE") && r.Port == 0 && r.Binary == ""
}

// syntheticPrefix is where OpenShell's policy DNS takes the addresses it
// hands out for names (policy.go lists it among the reserved ranges).
var syntheticPrefix = netip.MustParsePrefix("198.18.0.0/15")

// maxSyntheticNames bounds the names one sandbox's synthetic addresses map.
const maxSyntheticNames = 512

// syntheticMapping is OpenShell's record of a synthetic address it handed
// out: "Policy DNS mapped <name> resolved=… synthetic=<addr> …" or "Policy
// DNS staged unapproved name <name> synthetic=<addr> …".
var syntheticMapping = regexp.MustCompile(`^Policy DNS (?:mapped|staged unapproved name) (\S+) (?:\S+ )*?synthetic=(\S+)`)

// mappingPorts is the port list of a "Policy DNS mapped" record: the ports
// the name's transparent mapping covers ("ports=38821,38871,38872").
var mappingPorts = regexp.MustCompile(`(?:^| )ports=([0-9,]+)(?: |$)`)

// maxMappedPorts bounds the host alias ports a record keeps.
const maxMappedPorts = 64

// hostAliasRecord is what OpenShell's policy DNS last reported of the host
// alias in a sandbox: its synthetic address and the ports its transparent
// mapping covers. It is kept on the record because a restarted daemon's
// watch resumes past that report, and a later connection to the address
// names only the address.
type hostAliasRecord struct {
	Addr  string `json:"addr"`
	Ports []int  `json:"ports,omitempty"`
}

// noteSyntheticAddress keeps the name behind a synthetic address OpenShell
// reports (syntheticMapping), so a later record of a connection to the
// address names the destination (namedHost). The host alias's address and
// mapped ports also go on the record.
func (m *Manager) noteSyntheticAddress(b *box, msg string) {
	msg = strings.TrimSpace(msg)
	sub := syntheticMapping.FindStringSubmatch(msg)
	if sub == nil {
		return
	}
	name := triage.NormalizeHost(sub[1])
	addr, err := netip.ParseAddr(sub[2])
	if err != nil || name == "" || !syntheticPrefix.Contains(addr.Unmap()) {
		return
	}
	key := addr.Unmap().String()
	var alias *hostAliasRecord
	if name == openshellHostAlias && strings.HasPrefix(msg, "Policy DNS mapped ") {
		alias = &hostAliasRecord{Addr: key}
		if p := mappingPorts.FindStringSubmatch(msg); p != nil {
			for _, f := range strings.Split(p[1], ",") {
				if port, err := strconv.Atoi(f); err == nil && port > 0 && port < 65536 && len(alias.Ports) < maxMappedPorts &&
					!slices.Contains(alias.Ports, port) {
					alias.Ports = append(alias.Ports, port)
				}
			}
			slices.Sort(alias.Ports)
		}
	}
	m.mu.Lock()
	if b.synthetic == nil || len(b.synthetic) >= maxSyntheticNames {
		b.synthetic = map[string]string{}
	}
	b.synthetic[key] = name
	changed := alias != nil && !b.deleted && (b.rec.HostAlias == nil || b.rec.HostAlias.Addr != alias.Addr ||
		!slices.Equal(b.rec.HostAlias.Ports, alias.Ports))
	if changed {
		b.rec.HostAlias = alias
	}
	recName := b.rec.Name
	m.mu.Unlock()
	if changed {
		if err := m.saveRecord(b); err != nil {
			m.logf("sandbox %s: record the host alias mapping: %v", recName, err)
		}
	}
}

// namedHost is the destination name behind a synthetic address OpenShell
// reported (noteSyntheticAddress), else host as recorded. A synthetic
// address DefenseClaw has seen no mapping record for since it started is
// the host alias when the record names the host alias's address, or when
// port is one only the host alias's mapping covers (hostAliasPortLocked).
func (m *Manager) namedHost(b *box, host string, port int) string {
	addr, err := netip.ParseAddr(host)
	if err != nil || !syntheticPrefix.Contains(addr.Unmap()) {
		return host
	}
	key := addr.Unmap().String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if name := b.synthetic[key]; name != "" {
		return name
	}
	if (b.rec.HostAlias != nil && b.rec.HostAlias.Addr == key) || m.hostAliasPortLocked(b, port) {
		return openshellHostAlias
	}
	return host
}

// hostAliasPortLocked reports a port only the host alias's mapping serves in
// b: DefenseClaw's own listeners, the host ports the run declared, and the
// ports OpenShell last reported the mapping covers. Callers hold
// Manager.mu.
func (m *Manager) hostAliasPortLocked(b *box, port int) bool {
	if port <= 0 {
		return false
	}
	if port == m.opts.IngressPort || port == m.opts.EgressPort || slices.Contains(b.rec.Flags.HostPorts, port) {
		return true
	}
	return b.rec.HostAlias != nil && slices.Contains(b.rec.HostAlias.Ports, port)
}

const openshellHostAlias = "host.openshell.internal"

// ownHostName reports the workload's own host name: the one the workload
// check read in the sandbox (recorded), or the one Docker gives a
// sandbox's container, the first 12 hex digits of its ID (a MicroVM's is
// the sandbox's name). Tools look it up to find their own address: git
// does when it has no identity, to make up an e-mail address. OpenShell's
// DNS refuses it like every single-label name, and nothing is reached by
// it, so its refusal is no blocked site.
func ownHostName(host, recorded string) bool {
	// A single label only: a name with a dot is a site, whatever the
	// sandbox calls itself.
	if recorded != "" && !strings.Contains(recorded, ".") && strings.EqualFold(host, recorded) {
		return true
	}
	if len(host) != 12 {
		return false
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// hostAliasEvent handles OpenShell's record of a connection to the host.
// Relays to DefenseClaw's own listeners are reported by those listeners,
// except what only OpenShell sees of the hooks: a connection or request to
// the ingress it refused, or one that never became an authenticated
// request. None of them is a blocked site: this install's own ports never
// reach the feed's blocks or the blocked counts. The harness reaching any
// other host port (a local model endpoint, a --host-port service) is its
// work; a denied connection to one is hostPortDenied's.
func (m *Manager) hostAliasEvent(ctx context.Context, b *box, r ocsf.Record, at time.Time, harnessName string) {
	switch r.Port {
	case m.opts.IngressPort:
		outcome := hookConnAllowed
		switch {
		case !r.Denied():
		case policyReloadCut(r):
			outcome = hookConnReloadCut
		case mappingDenial(r):
			outcome = hookConnMappingDenied
		default:
			outcome = hookConnRefused
		}
		m.observeHookConnection(ctx, b, outcome, at)
	case m.opts.EgressPort:
		// A connection to the egress proxy is the harness's activity when
		// its own binary made it (the proxy cannot tell); it is no model
		// call, which goes around the proxy.
		m.markWork(b, at, harnessActivity(harnessName, r.Binary), noModelCall)
		if r.Allowed() && r.Binary != "" {
			m.mu.Lock()
			b.proxyOpens = append(b.proxyOpens, proxyOpen{binary: r.Binary, pid: ocsfPID(r), at: m.now()})
			if n := len(b.proxyOpens); n > maxProxyOpens {
				b.proxyOpens = slices.Delete(b.proxyOpens, 0, n-maxProxyOpens)
			}
			m.mu.Unlock()
		}
	case 0:
	default:
		ofHarness := harnessActivity(harnessName, r.Binary)
		req := noModelCall
		if r.Allowed() {
			req = m.harnessRequest(b, r, openshellHostAlias, ofHarness)
		}
		m.markWork(b, at, ofHarness, req)
		switch {
		case r.Denied():
			m.hostPortDenied(ctx, b, r, at)
		case r.Allowed():
			m.hostPortAllowed(ctx, b, r, at)
		}
	}
}

// mappingDenial reports OpenShell's denial of a connection to a synthetic
// address that its transparent mapping does not cover for the port
// ("transparent_tcp_mapping_denied"): the port is not open, or the mapping
// was republished under the connection (a policy or provider reload).
func mappingDenial(r ocsf.Record) bool {
	return strings.EqualFold(strings.TrimSpace(r.Reason), "transparent_tcp_mapping_denied")
}

// harnessFetchDenial reports an OpenShell denial of one of the sandbox
// harness's own background requests (harness.Spec.DirectFetches): the
// destination is the fetch's, and the actor is a binary under the harness's
// root-owned install root, or none (the DNS refusal before the connection
// names no binary). Binary is display text the workload could choose, which
// can at worst hide such a denial from the feed; the audit record stays.
func harnessFetchDenial(harnessName string, r ocsf.Record, host string) bool {
	for _, f := range harnessFetches(harnessName) {
		if host != triage.NormalizeHost(f.Host) || (r.Port != 0 && r.Port != f.Port) {
			continue
		}
		if r.Binary == "" || (strings.HasPrefix(r.Binary, f.BinaryRoot+"/") && !strings.Contains(r.Binary, "/../")) {
			return true
		}
	}
	return false
}

// settingsReload reports OpenShell's record of reloading the sandbox's
// settings: its settings poll saw the policy or the provider environment
// change ("CONFIG:DETECTED [INFO] Settings poll: config change detected
// [old_revision:… new_revision:… policy_changed:false
// provider_env_changed:true]"). A reload drops the transparent mappings of
// the names the sandbox looked up; the next lookup maps them again.
func settingsReload(r ocsf.Record) bool {
	return strings.EqualFold(r.Activity, "DETECTED") &&
		(strings.EqualFold(r.Context["policy_changed"], "true") || strings.EqualFold(r.Context["provider_env_changed"], "true"))
}

// policyReloadCut reports a connection OpenShell closed because the
// sandbox policy changed while it was open ("L7 tunnel closed before
// inspection because policy changed: policy generation is stale"): every
// policy reload closes the open connections, those the policy still allows
// included, so it is no refusal. The hooks retry once, and a session whose
// requests then never authenticate is still flagged after hookAttemptGrace.
func policyReloadCut(r ocsf.Record) bool {
	reason := strings.ToLower(r.Reason)
	return strings.Contains(reason, "policy changed") || strings.Contains(reason, "policy generation is stale")
}

// markWork records network activity of the sandbox's workload: when the
// harness's own binary made it (harnessActivity) it keeps the hooks'
// silence check going, and when it is a model call of the harness
// (harnessModelCall) it starts the session's reachability window. A call
// the request's path shows (modelTurn) starts it at once; a connection to
// the model endpoint, which shows no path (modelConnection), only after
// harnessStartupGrace; a request for the model list (modelListing) never.
// Other traffic (the harness's start-up and onboarding requests, tools,
// `sandbox exec` commands) is no sign that hooks are overdue, and neither
// is a record from before the session (replayed after a watch resumed).
func (m *Manager) markWork(b *box, at time.Time, ofHarness bool, req modelRequest) {
	// A layer-7 record names no binary: one on the harness's own model
	// connection (harnessRequest) is the harness at work too. A harness
	// keeps that connection open for many turns, so its NET records alone
	// are a handful a session, and hooks switched off went unnoticed.
	if ofHarness || req != noModelCall {
		m.markActive(b, at)
	}
	if req != modelTurn && req != modelConnection {
		return
	}
	m.mu.Lock()
	switch {
	case req == modelTurn && !at.Before(b.started):
		m.noteWorkLocked(b)
	case req == modelConnection && !at.Before(b.started.Add(harnessStartupGrace)):
		m.noteWorkLocked(b)
	}
	m.mu.Unlock()
}

// providerRulePrefix starts the names of the rules OpenShell adds for the
// providers attached to a sandbox (policy.go), the only rules that carry
// credentials: the harness's model provider and --credential bindings.
const providerRulePrefix = "_provider_"

// modelRequest is what an OCSF record tells of a request of the sandbox's
// harness to its model.
type modelRequest int

const (
	// noModelCall: no request of the harness to its model.
	noModelCall modelRequest = iota
	// modelConnection: a connection to the model endpoint (a NET record,
	// which carries no path), or a request whose path names neither a
	// model call nor the model list. Within harnessStartupGrace of the
	// session's start it is taken for the harness's start-up.
	modelConnection
	// modelListing: a request for the model list or one model's metadata
	// (GET /v1/models), which a harness makes on its own: the Codex TUI
	// asks for the list as it opens, before any prompt.
	modelListing
	// modelTurn: a model call (POST /v1/messages, /v1/chat/completions,
	// /v1/responses, Bedrock's invoke and converse), which a harness makes
	// only for a prompt, also within harnessStartupGrace.
	modelTurn
)

// harnessModelCall reports what an OCSF record of a connection or request
// to host says of a model call of the sandbox's harness: one OpenShell
// allowed under a provider rule, which the harness made (harnessRequest).
// A harness reaches its model only after a prompt, which fires its hooks;
// the requests it makes on its own before one (update checks, telemetry,
// onboarding) go elsewhere, except for the model list, which the request's
// path tells apart (modelRequestOf).
func (m *Manager) harnessModelCall(b *box, r ocsf.Record, host string, ofHarness bool) modelRequest {
	if !r.Allowed() || !strings.HasPrefix(r.Policy, providerRulePrefix) {
		return noModelCall
	}
	return m.harnessRequest(b, r, host, ofHarness)
}

// harnessRequest reports what an allowed record of a connection or request
// to host is when the harness made it (modelRequestOf), and noModelCall
// when it did not. A record that names a binary is the harness's when its
// own binary made it (ofHarness). Layer-7 records name none: one is the
// harness's when the last connection OpenShell allowed to the same host
// and port was, the connection it rides on (a harness keeps its
// connection to its model open from the model list to the prompts after
// it). Callers run on b's watch, which gets its records in order.
func (m *Manager) harnessRequest(b *box, r ocsf.Record, host string, ofHarness bool) modelRequest {
	dest := net.JoinHostPort(host, strconv.Itoa(r.Port))
	m.mu.Lock()
	if r.Binary != "" {
		if b.reach.modelConns == nil {
			b.reach.modelConns = map[string]bool{}
		}
		b.reach.modelConns[dest] = ofHarness
	} else {
		ofHarness = b.reach.modelConns[dest]
	}
	m.mu.Unlock()
	if !ofHarness {
		return noModelCall
	}
	return modelRequestOf(r)
}

// modelTurnPaths end the paths of model calls: Anthropic's Messages,
// OpenAI's Chat Completions, Completions and Responses, Bedrock's
// InvokeModel and Converse, streaming or not, and Gemini's
// generateContent.
var modelTurnPaths = []string{"/messages", "/completions", "/responses", "/invoke", "/invoke-with-response-stream",
	"/converse", "/converse-stream", ":generateContent", ":streamGenerateContent"}

// modelListSegments name the collections a model list or one model's
// metadata is read from: /v1/models and /v1/models/{id} (Anthropic,
// OpenAI and the servers compatible with them, Gemini), and Bedrock's
// foundation models and inference profiles.
var modelListSegments = []string{"models", "foundation-models", "inference-profiles"}

// modelRequestOf is the kind of request a record of the harness to its
// model shows: a POST to a model call's path (modelTurnPaths) is a turn,
// a GET or HEAD of the model list or of one model (modelListSegments, or
// Ollama's /api/tags) a listing, and a record without a path, or with one
// that names neither, a connection. A GET of a model call's path is no
// turn: the Responses API's WebSocket opens with one, which a harness may
// open before any prompt.
func modelRequestOf(r ocsf.Record) modelRequest {
	p, _, _ := strings.Cut(r.Path, "?")
	p = strings.TrimRight(p, "/")
	if p == "" {
		return modelConnection
	}
	switch strings.ToUpper(r.Method) {
	case "POST":
		for _, suffix := range modelTurnPaths {
			if strings.HasSuffix(p, suffix) {
				return modelTurn
			}
		}
	case "GET", "HEAD":
		segments := strings.Split(p, "/")
		n := len(segments)
		if p == "/api/tags" || slices.Contains(modelListSegments, segments[n-1]) ||
			n > 1 && slices.Contains(modelListSegments, segments[n-2]) {
			return modelListing
		}
	}
	return modelConnection
}

// harnessActivity reports an OCSF event of the harness itself: its binary
// lies under the harness's install root in the overlay image. Only that
// counts toward hook silence: commands run through `sandbox exec` (the
// CLI's probe, a copy-mode upload or pull, the user's own) never pass the
// harness's hooks, and would raise hook_silence on a sandbox whose
// session is over. A harness whose hooks were disabled still reaches its
// model, so its own network events keep the check alive. The binary is
// what the workload reports; a process claiming the harness's path can
// only raise the alarm, never silence it.
func harnessActivity(harnessName, binary string) bool {
	spec, ok := harness.Get(harnessName)
	if !ok || binary == "" {
		return false
	}
	return strings.HasPrefix(path.Clean(binary), spec.InstallRoot()+"/")
}

func (m *Manager) markActive(b *box, at time.Time) {
	m.mu.Lock()
	b.noteActiveLocked(at)
	m.mu.Unlock()
}

func ocsfSeverity(s ocsf.Severity) string {
	switch s {
	case ocsf.SeverityLow:
		return "LOW"
	case ocsf.SeverityMedium:
		return "MEDIUM"
	case ocsf.SeverityHigh:
		return "HIGH"
	case ocsf.SeverityCritical, ocsf.SeverityFatal:
		return "CRITICAL"
	default:
		return "INFO"
	}
}

func schemeOf(raw string) string {
	switch {
	case strings.HasPrefix(raw, "https://"):
		return "https"
	case strings.HasPrefix(raw, "http://"):
		return "http"
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parseConfidence(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f <= 0 || f > 1 {
		return 0, errors.New("no confidence")
	}
	return f, nil
}
