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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
)

// Destinations: what each sandbox reaches, or tries to reach, on the
// network, and what kind of destination each host is. Two boundaries see a
// sandbox's traffic: the DefenseClaw egress proxy (its web egress, which
// egress.Counter counts per binding and the proxy's events name with their
// category) and OpenShell's own (the direct connections, the model
// endpoint's among them, which its OCSF NET and HTTP records name with the
// binary and the policy rule). Their observations are merged per host into
// one table per sandbox, kept across daemon restarts and stops in
// <data_dir>/sandboxes/<name>/destinations.json (written within
// destinationFlushEvery of a change and when the sandbox stops; a delete
// removes it).
//
// A host is told apart in this order: one OpenShell allowed under a
// provider rule is the sandbox's model provider, or the endpoint of one of
// its --credential bindings (credential); a catalogued AI provider
// (internal/sensor/catalog) whose signature is the harness's own connector
// is its vendor's; any other catalogued AI provider is shadow AI, and so is
// a host shaped like an inference endpoint the catalog does not know; any
// other is blocked when it was only ever refused, else takes the category
// the proxy allowed it under (a feed's, such as package_registry), else is
// other. A shadow AI host
// raises one shadow_ai finding per provider per session: LOW while the
// sandbox was only refused it, MEDIUM once it reached it (a refusal first
// and a contact later raise both).

const (
	destinationsFile      = "destinations.json"
	destinationsMaxBytes  = 4 << 20
	destinationFlushEvery = time.Minute
	maxDestinationPorts   = 8
	maxDestinationBins    = 4
	maxDestinationModels  = 32
	maxDestinationText    = 256
)

// Shadow AI severities a session reported for a provider.
const (
	shadowNone = iota
	shadowRefused
	shadowReached
)

// ProcessLookup resolves a sandbox process to its lineage: the process
// first, then its parent and theirs. Manager.Lineage, the opt-in process
// tree (observe.process_tree, processes.go), implements it: a sandbox whose
// tree is off has destinations without lineage.
type ProcessLookup interface {
	Lineage(sandboxName string, pid int) []ProcessRef
}

// ProcessRef is one process of a lineage, as the process index saw it in
// the sandbox. Exe and Comm are what the workload reports.
type ProcessRef struct {
	PID, PPID int
	Exe, Comm string
	Start     time.Time
}

// lineage is pid's lineage in the sandbox, nil without a process index.
func (m *Manager) lineage(sandbox string, pid int) []sandboxapi.DestinationProcess {
	if m.procs == nil || pid <= 0 {
		return nil
	}
	refs := m.procs.Lineage(sandbox, pid)
	if len(refs) == 0 {
		return nil
	}
	out := make([]sandboxapi.DestinationProcess, 0, len(refs))
	for _, p := range refs {
		out = append(out, sandboxapi.DestinationProcess{PID: p.PID, PPID: p.PPID,
			Exe: sandboxapi.DisplayText(truncate(p.Exe, maxDestinationText)), Comm: sandboxapi.DisplayText(truncate(p.Comm, maxDestinationText)),
			Start: p.Start})
	}
	return out
}

// destTable is one sandbox's destinations. Manager.destMu guards it.
type destTable struct {
	rows   map[string]*destRow
	models map[string]*sandboxapi.ModelUse
	// dropped counts the rows evicted, or refused, over
	// sandboxapi.MaxDestinations.
	dropped int
	dirty   bool
	// shadow is what this session (shadowSession) reported of each shadow
	// AI provider (shadowRefused, shadowReached).
	shadowSession int
	shadow        map[string]int
}

// destRow is one host of a table. The proxy's counts are its counter's: Proxy
// holds what earlier daemon runs (and counters reset since) counted, live
// the counter's last snapshot in this run.
type destRow struct {
	Host      string    `json:"host"`
	Ports     []int     `json:"ports,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Reached marks a host either boundary let the sandbox reach.
	Reached     bool     `json:"reached,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	Connections int64    `json:"connections,omitempty"`
	Refused     int64    `json:"refused,omitempty"`
	ModelTurns  int64    `json:"model_turns,omitempty"`
	Rule        string   `json:"rule,omitempty"`
	// ProviderRule marks a host OpenShell allowed under a provider rule of
	// the sandbox's model provider, CredentialRule under one of a
	// --credential binding (its endpoint).
	ProviderRule   bool `json:"provider_rule,omitempty"`
	CredentialRule bool `json:"credential_rule,omitempty"`
	// Category is the egress category of the proxy's last allowed request
	// (a feed's, such as package_registry), Refusal that of its last
	// refusal (not_allowlisted, paste_site, ...).
	Category string   `json:"category,omitempty"`
	Refusal  string   `json:"refusal,omitempty"`
	Binaries []string `json:"binaries,omitempty"`
	PID      int      `json:"pid,omitempty"`
	Proxy    counts   `json:"proxy,omitzero"`

	live counts
	// proxyAt are when the proxy's requests to the host came that no
	// program is named for yet (attributeProxied).
	proxyAt []time.Time
	// hit is the catalog's provider of the host, when it has one.
	hit *catalog.Provider
}

// counts are a destination's egress proxy counts.
type counts struct {
	BytesUp   int64 `json:"bytes_up,omitempty"`
	BytesDown int64 `json:"bytes_down,omitempty"`
	Tunnels   int64 `json:"tunnels,omitempty"`
	Blocked   int64 `json:"blocked,omitempty"`
}

func (c counts) add(o counts) counts {
	return counts{c.BytesUp + o.BytesUp, c.BytesDown + o.BytesDown, c.Tunnels + o.Tunnels, c.Blocked + o.Blocked}
}

// total is the row's proxy counts, this run's included.
func (r *destRow) total() counts { return r.Proxy.add(r.live) }

// contacted reports a host either boundary let the sandbox reach.
func (r *destRow) contacted() bool {
	return r.Reached || r.Connections > 0 || r.total().Tunnels > 0
}

// destinationSighting is one boundary's observation of a destination.
type destinationSighting struct {
	host string
	port int
	at   time.Time
	// proxy marks the DefenseClaw proxy's (else OpenShell's).
	proxy  bool
	denied bool
	// rule is OpenShell's policy rule (allowed records), category the
	// proxy decision's.
	rule, category string
	binary         string
	pid            int
	// turn marks a model call among OpenShell's requests.
	turn bool
	// credential marks a host one of the sandbox's --credential bindings
	// names (and its model provider does not).
	credential bool
}

// destinationInfo is what classifying and reporting a sandbox's
// destinations needs of its box.
type destinationInfo struct {
	name, harness, bindingID string
	session                  int
	id                       audit.SandboxIdentity
	gone                     bool
	// credentialHosts are the endpoints of the sandbox's --credential
	// bindings that are not also its model provider's.
	credentialHosts []string
}

func (m *Manager) destinationInfo(b *box) destinationInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := destinationInfo{name: b.rec.Name, harness: b.rec.Harness, bindingID: b.rec.BindingID, session: b.rec.Sessions,
		id: b.identity(), gone: b.deleted || b.retained}
	var modelHosts []string
	for _, ep := range b.rec.ProviderEndpoints {
		if ep.Role == roleLLM {
			modelHosts = append(modelHosts, ep.Host)
		}
	}
	for _, ep := range b.rec.ProviderEndpoints {
		if ep.Role == roleCredential && !slices.Contains(modelHosts, ep.Host) {
			info.credentialHosts = append(info.credentialHosts, ep.Host)
		}
	}
	return info
}

// destinationCatalog is the shared AI provider catalog; nil (logged once)
// when it cannot be built, which leaves every host unclassified as AI.
func (m *Manager) destinationCatalog() *catalog.Catalog {
	m.catalogOnce.Do(func() {
		c, err := catalog.Shared()
		if err != nil {
			m.logf("the AI provider catalog is unavailable, so sandbox destinations are not classified as AI: %v", err)
		}
		m.catalog = c
	})
	return m.catalog
}

// tableLocked returns name's table, making an empty one; nil once a delete
// dropped it (dropDestinations), until the sandbox is forgotten. Callers
// hold destMu.
func (m *Manager) tableLocked(name string) *destTable {
	t, ok := m.dests[name]
	if !ok {
		t = &destTable{rows: map[string]*destRow{}, models: map[string]*sandboxapi.ModelUse{}, shadow: map[string]int{}}
		m.dests[name] = t
	}
	return t
}

// row returns host's row, adding it (at; at the cap in place of another,
// evictable); nil when there is no room.
func (t *destTable) row(m *Manager, host string, at time.Time, harnessName string) *destRow {
	if r := t.rows[host]; r != nil {
		return r
	}
	r := &destRow{Host: host, FirstSeen: at, LastSeen: at}
	r.lookup(m.destinationCatalog())
	if len(t.rows) >= sandboxapi.MaxDestinations {
		t.dropped++
		victim := t.evictable(harnessName, r.hit != nil)
		if victim == nil {
			return nil
		}
		delete(t.rows, victim.Host)
	}
	t.rows[host] = r
	return r
}

// evictable is the row a new one takes the place of at the cap: the least
// recently seen that is no AI destination, else, for a catalogued AI
// provider, the least recently seen unknown_ai row. A workload can make up
// any number of inference-shaped names, but not catalogued providers, so a
// table full of made-up names still records (and reports) a real one.
func (t *destTable) evictable(harnessName string, catalogued bool) *destRow {
	var oldest, oldestUnknown *destRow
	for _, r := range t.rows {
		switch kind, _, _ := r.classify(harnessName); {
		case !isAIKind(kind):
			if oldest == nil || r.LastSeen.Before(oldest.LastSeen) {
				oldest = r
			}
		case catalogued && kind == sandboxapi.DestinationUnknownAI:
			if oldestUnknown == nil || r.LastSeen.Before(oldestUnknown.LastSeen) {
				oldestUnknown = r
			}
		}
	}
	if oldest != nil {
		return oldest
	}
	return oldestUnknown
}

func (r *destRow) lookup(c *catalog.Catalog) {
	if c == nil {
		return
	}
	if p, ok := c.Lookup(r.Host); ok {
		r.hit = &p
	}
}

// note folds a sighting into the row.
func (r *destRow) note(s destinationSighting) {
	if s.at.After(r.LastSeen) {
		r.LastSeen = s.at
	}
	if s.at.Before(r.FirstSeen) {
		r.FirstSeen = s.at
	}
	source := sandboxapi.SourceOpenShell
	if s.proxy {
		source = sandboxapi.SourceProxy
	}
	if !slices.Contains(r.Sources, source) {
		r.Sources = append(r.Sources, source)
		slices.Sort(r.Sources)
	}
	if s.port > 0 && s.port < 65536 && !slices.Contains(r.Ports, s.port) && len(r.Ports) < maxDestinationPorts {
		r.Ports = append(r.Ports, s.port)
		slices.Sort(r.Ports)
	}
	if !s.denied {
		r.Reached = true
	}
	switch {
	case s.proxy && s.denied:
		// The counter counts the proxy's tunnels and refusals.
		r.Refusal = truncate(s.category, 64)
	case s.proxy:
		r.Category = truncate(s.category, 64)
	case s.denied:
		r.Refused++
	default:
		r.Connections++
		if s.turn {
			r.ModelTurns++
		}
		if s.rule != "" {
			r.Rule = truncate(s.rule, maxDestinationText)
			if strings.HasPrefix(s.rule, providerRulePrefix) {
				r.CredentialRule = r.CredentialRule || s.credential
				r.ProviderRule = r.ProviderRule || !s.credential
			}
		}
	}
	r.addActor(s.binary, s.pid)
}

// addActor records the program (and its pid, 0 when unknown) that reached
// the row's host, the most recent last.
func (r *destRow) addActor(binary string, pid int) {
	if binary != "" {
		bin := truncate(binary, maxDestinationText)
		r.Binaries = slices.DeleteFunc(r.Binaries, func(b string) bool { return b == bin })
		r.Binaries = append(r.Binaries, bin)
		if len(r.Binaries) > maxDestinationBins {
			r.Binaries = r.Binaries[len(r.Binaries)-maxDestinationBins:]
		}
	}
	if pid > 0 {
		r.PID = pid
	}
}

// proxyOpen is OpenShell's record of a connection to the egress proxy: the
// program that opened it, as the workload reports it, and when the record
// came.
type proxyOpen struct {
	binary string
	pid    int
	at     time.Time
}

// Pairing a request of the egress proxy with the connection it came on:
// the proxy sees neither the program nor its socket, and OpenShell's
// record of the connection names no destination. proxyOpenWindow bounds
// how far apart the two come; maxProxyOpens and maxProxyRequests bound
// what a sandbox keeps of each.
const (
	proxyOpenWindow  = 5 * time.Second
	maxProxyOpens    = 256
	maxProxyRequests = 16
)

// proxyActor is the program that opened the proxy connection a request
// that came at `at` rode on: the one program OpenShell's records of proxy
// connections around then name. Records of two programs then leave it
// unknown rather than guessed.
func proxyActor(opens []proxyOpen, at time.Time) (binary string, pid int, ok bool) {
	for _, o := range opens {
		if o.at.Before(at.Add(-proxyOpenWindow)) || o.at.After(at.Add(proxyOpenWindow)) {
			continue
		}
		switch {
		case binary == "":
			binary, pid = o.binary, o.pid
		case o.binary != binary:
			return "", 0, false
		case o.pid != pid:
			pid = 0
		}
	}
	return binary, pid, binary != ""
}

// attributeProxied names the program of each of the row's proxied
// requests (proxyActor) once the window around it is over, so every
// OpenShell record that could pair with it is in; it reports whether it
// named one. A request it cannot pair is forgotten.
func (r *destRow) attributeProxied(opens []proxyOpen, now time.Time) bool {
	named := false
	kept := r.proxyAt[:0]
	for _, at := range r.proxyAt {
		if now.Before(at.Add(proxyOpenWindow)) {
			kept = append(kept, at)
			continue
		}
		if bin, pid, ok := proxyActor(opens, at); ok {
			r.addActor(bin, pid)
			named = true
		}
	}
	r.proxyAt = kept
	return named
}

// classify says what the row's host is (see the comment at the top): its
// kind, and the AI provider and its vendor when it is one.
func (r *destRow) classify(harnessName string) (kind, provider, vendor string) {
	switch hit := r.hit; {
	case r.ProviderRule:
		provider = strings.TrimPrefix(r.Rule, providerRulePrefix)
		if hit != nil {
			provider, vendor = catalogProviderName(hit), hit.Vendor
		}
		return sandboxapi.DestinationModelProvider, provider, vendor
	case r.CredentialRule:
		if hit != nil {
			provider, vendor = catalogProviderName(hit), hit.Vendor
		}
		return sandboxapi.DestinationCredential, provider, vendor
	case harnessFetchHost(harnessName, r.Host, 0):
		// The harness's own background request (OpenCode's model
		// catalog), which an open pack lets through: its vendor's, no
		// shadow AI.
		if spec, ok := harness.Get(harnessName); ok {
			provider = spec.DisplayName
		}
		return sandboxapi.DestinationHarnessVendor, provider, ""
	case hit != nil && hit.SupportedConnector != "" && hit.SupportedConnector == harnessName:
		return sandboxapi.DestinationHarnessVendor, hit.DisplayName, hit.Vendor
	case hit != nil:
		return sandboxapi.DestinationOtherAI, catalogProviderName(hit), hit.Vendor
	case catalog.InferenceShaped(r.Host):
		return sandboxapi.DestinationUnknownAI, "", ""
	case !r.contacted():
		return sandboxapi.DestinationBlocked, "", ""
	case r.Category != "":
		return r.Category, "", ""
	default:
		return sandboxapi.DestinationOther, "", ""
	}
}

// catalogProviderName is how a catalogued AI provider is named: by its
// vendor when the signature is a connector's, whose hosts are the vendor's
// API (api.openai.com is OpenAI's, not the Codex agent's), else by the
// signature's name.
func catalogProviderName(p *catalog.Provider) string {
	if p.SupportedConnector != "" && p.Vendor != "" {
		return p.Vendor
	}
	return p.DisplayName
}

// shadowKey is the provider a shadow AI host is reported under: the
// catalog's signature, else the host.
func (r *destRow) shadowKey() string {
	if r.hit != nil && r.hit.ID != "" {
		return r.hit.ID
	}
	return r.Host
}

func isAIKind(kind string) bool {
	return kind == sandboxapi.DestinationModelProvider || kind == sandboxapi.DestinationHarnessVendor || sandboxapi.ShadowAIKind(kind)
}

// observeDestination folds one boundary's sighting into the sandbox's
// destinations and reports shadow AI.
func (m *Manager) observeDestination(ctx context.Context, b *box, s destinationSighting) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.host)), ".")
	if b == nil || host == "" || len(host) > 253 {
		return
	}
	info := m.destinationInfo(b)
	if info.gone {
		return
	}
	s.credential = slices.Contains(info.credentialHosts, host)
	m.destMu.Lock()
	t := m.tableLocked(info.name)
	var r *destRow
	if t != nil {
		r = t.row(m, host, s.at, info.harness)
	}
	if r == nil {
		m.destMu.Unlock()
		return
	}
	r.note(s)
	if s.proxy && s.binary == "" {
		r.proxyAt = append(r.proxyAt, m.now())
		if n := len(r.proxyAt); n > maxProxyRequests {
			r.proxyAt = slices.Delete(r.proxyAt, 0, n-maxProxyRequests)
		}
	}
	t.dirty = true
	kind, provider, _ := r.classify(info.harness)
	level := shadowRefused
	if !s.denied {
		level = shadowReached
	}
	report := false
	if sandboxapi.ShadowAIKind(kind) {
		if t.shadowSession != info.session {
			t.shadowSession, t.shadow = info.session, map[string]int{}
		}
		if key := r.shadowKey(); t.shadow[key] < level {
			t.shadow[key], report = level, true
		}
	}
	port, binary := s.port, r.lastBinary()
	m.destMu.Unlock()
	if report {
		m.shadowAI(ctx, info, host, port, kind, provider, binary, level == shadowReached, s.at)
	}
}

func (r *destRow) lastBinary() string {
	if len(r.Binaries) == 0 {
		return ""
	}
	return r.Binaries[len(r.Binaries)-1]
}

// shadowAI records and shows a shadow AI destination of the sandbox. The
// host and binary come from the sandbox (a CONNECT target, an OCSF record),
// so the finding's title, description and evidence show them made safe for
// a terminal; the raw host is only checked for the block command, and the
// target reference keeps it only when it is an identifier.
func (m *Manager) shadowAI(ctx context.Context, info destinationInfo, host string, port int, kind, provider, binary string, reached bool, at time.Time) {
	shown := sandboxapi.DisplayText(host)
	what := "an AI API of " + firstNonEmpty(provider, shown)
	if kind == sandboxapi.DestinationUnknownAI {
		what = "a host that looks like an AI inference endpoint the AI provider catalog does not know"
	}
	severity, title, did := "LOW", "Shadow AI: the sandbox tried to reach "+firstNonEmpty(provider, shown), "tried to reach"
	if reached {
		severity, title, did = "MEDIUM", "Shadow AI: the sandbox reached "+firstNonEmpty(provider, shown), "reached"
	}
	remediation := shadowRemediation(info.name, host, reached)
	evidence := fmt.Sprintf("host=%s kind=%s", sandboxapi.HostPort(shown, port), kind)
	if provider != "" {
		evidence += " provider=" + provider
	}
	if binary != "" {
		evidence += " binary=" + sandboxapi.DisplayText(binary)
	}
	m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
		Sandbox: info.id, Kind: audit.SandboxFindingShadowAI, Severity: severity, Title: truncate(title, 256),
		Description: truncate(fmt.Sprintf("%s %s %s, %s, which is neither its model provider nor its harness's vendor.",
			info.name, did, shown, what), 1024),
		Evidence: truncate(evidence, 512), TargetRef: host, Timestamp: at, Remediation: remediation,
	})
	m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: info.name, Host: host, Port: port,
		Severity: severity, Reason: sandboxapi.ReasonShadowAI,
		Message: truncate("⚠ shadow AI: "+did+" "+sandboxapi.HostPort(shown, port)+" ("+firstNonEmpty(provider, "unknown AI endpoint")+")", 300)})
}

// shadowRemediation is a shadow AI finding's remediation for sandbox name.
// The host comes from the sandbox (a CONNECT target, an OCSF record), so it
// goes into the block command a user copies only as a host name or an IP
// address in canonical form, which a shell reads literally; any other
// spelling is shown made safe for a terminal, without the command.
func shadowRemediation(name, host string, reached bool) string {
	shown, look := sandboxapi.DisplayText(host), " (`defenseclaw sandbox destinations "+name+"`); "
	if !reached {
		return "Check what in the sandbox tries to call " + shown + look + "the policy refused it, so nothing reached it."
	}
	check := "Check what in the sandbox calls " + shown + look + "if it is not expected, "
	if p, err := config.ParseOpenShellEgressPattern(host); err == nil && !p.Wildcard &&
		(!p.Prefix.IsValid() || p.Prefix.IsSingleIP()) && p.String() == host {
		return check + "block it: defenseclaw sandbox policy block " + host + "."
	}
	return check + "add it to openshell.egress.block."
}

// observeInference counts a model call OpenShell's inference route
// reported.
func (m *Manager) observeInference(b *box, provider, model string, failed bool, at time.Time) {
	info := m.destinationInfo(b)
	if info.gone || (provider == "" && model == "") {
		return
	}
	provider, model = truncate(provider, maxDestinationText), truncate(model, maxDestinationText)
	m.destMu.Lock()
	defer m.destMu.Unlock()
	t := m.tableLocked(info.name)
	if t == nil {
		return
	}
	key := provider + "\x00" + model
	u := t.models[key]
	if u == nil {
		if len(t.models) >= maxDestinationModels {
			return
		}
		u = &sandboxapi.ModelUse{Provider: provider, Model: model}
		t.models[key] = u
	}
	u.Calls++
	if failed {
		u.Failed++
	}
	if at.After(u.LastSeen) {
		u.LastSeen = at
	}
	t.dirty = true
}

// touchDestinations marks a sandbox's table changed: the proxy counted
// more for it.
func (m *Manager) touchDestinations(name string) {
	m.destMu.Lock()
	if t := m.dests[name]; t != nil {
		t.dirty = true
	}
	m.destMu.Unlock()
}

// proxyStats is the egress proxy counter's view of a binding, by host.
func (m *Manager) proxyStats(bindingID string) map[string]egress.DestinationStats {
	m.mu.Lock()
	proxy := m.proxy
	m.mu.Unlock()
	if proxy == nil || proxy.Counter() == nil || bindingID == "" {
		return nil
	}
	out := map[string]egress.DestinationStats{}
	for _, d := range proxy.Counter().DestinationsFor(bindingID) {
		out[strings.ToLower(d.Host)] = d
	}
	return out
}

// mergeLiveLocked takes the proxy counter's current counts into t: a host
// the counter counted that t lacks gets a row, and a count that went down
// (the counter forgot or evicted it) is kept in the row's Proxy first.
// Callers hold destMu.
func (m *Manager) mergeLiveLocked(t *destTable, live map[string]egress.DestinationStats, harnessName string) {
	for host, d := range live {
		if !d.Contacted && harnessFetchHost(harnessName, host, 0) {
			continue
		}
		r := t.rows[host]
		if r == nil {
			if r = t.row(m, host, d.FirstSeen, harnessName); r == nil {
				continue
			}
			r.Sources = []string{sandboxapi.SourceProxy}
			t.dirty = true
		}
		now := counts{BytesUp: d.BytesUp, BytesDown: d.BytesDown, Tunnels: d.Tunnels, Blocked: d.Blocked}
		if now.BytesUp < r.live.BytesUp || now.BytesDown < r.live.BytesDown || now.Tunnels < r.live.Tunnels || now.Blocked < r.live.Blocked {
			r.Proxy = r.Proxy.add(r.live)
		}
		r.live = now
		if d.LastSeen.After(r.LastSeen) {
			r.LastSeen = d.LastSeen
		}
	}
}

// Destinations returns a sandbox's destinations view.
func (m *Manager) Destinations(_ context.Context, name string) (*sandboxapi.Destinations, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	info := m.destinationInfo(b)
	live := m.proxyStats(info.bindingID)
	m.mu.Lock()
	opens := slices.Clone(b.proxyOpens)
	m.mu.Unlock()
	now := m.now()
	m.destMu.Lock()
	out := &sandboxapi.Destinations{Name: info.name, Harness: info.harness, Destinations: []sandboxapi.DestinationRow{}}
	t := m.dests[info.name]
	if t == nil && len(live) > 0 {
		t = m.tableLocked(info.name)
	}
	if t != nil {
		m.mergeLiveLocked(t, live, info.harness)
		for _, r := range t.rows {
			if r.attributeProxied(opens, now) {
				t.dirty = true
			}
			out.Destinations = append(out.Destinations, r.view(info.harness))
		}
		for _, u := range t.models {
			out.Models = append(out.Models, *u)
		}
		out.Dropped = t.dropped
	}
	m.destMu.Unlock()
	slices.SortFunc(out.Destinations, func(a, b sandboxapi.DestinationRow) int {
		return cmp.Or(cmp.Compare(destinationRank(a.Kind), destinationRank(b.Kind)), b.LastSeen.Compare(a.LastSeen), cmp.Compare(a.Host, b.Host))
	})
	slices.SortFunc(out.Models, func(a, b sandboxapi.ModelUse) int {
		return cmp.Or(cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.Model, b.Model))
	})
	for i := range out.Destinations {
		out.Destinations[i].Lineage = m.lineage(info.name, out.Destinations[i].PID)
	}
	return out, nil
}

// destinationRank orders the view: shadow AI first, then the model APIs,
// then the refused hosts, then the rest.
func destinationRank(kind string) int {
	switch kind {
	case sandboxapi.DestinationOtherAI, sandboxapi.DestinationUnknownAI:
		return 0
	case sandboxapi.DestinationModelProvider, sandboxapi.DestinationHarnessVendor:
		return 1
	case sandboxapi.DestinationBlocked:
		return 2
	default:
		return 3
	}
}

// view renders a row for the API. Its text is the workload's, so it is made
// safe to print.
func (r *destRow) view(harnessName string) sandboxapi.DestinationRow {
	kind, provider, vendor := r.classify(harnessName)
	total := r.total()
	v := sandboxapi.DestinationRow{
		Host: sandboxapi.DisplayText(r.Host), Ports: slices.Clone(r.Ports), Kind: kind, Provider: sandboxapi.DisplayText(provider),
		Vendor: sandboxapi.DisplayText(vendor), Category: firstNonEmpty(r.Category, r.Refusal), Rule: sandboxapi.DisplayText(r.Rule),
		Sources: slices.Clone(r.Sources), Connections: r.Connections, Tunnels: total.Tunnels, Refused: r.Refused, Blocked: total.Blocked,
		ModelTurns: r.ModelTurns, BytesUp: total.BytesUp, BytesDown: total.BytesDown, PID: r.PID,
		FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
	}
	if v.Sources == nil {
		v.Sources = []string{}
	}
	for _, b := range r.Binaries {
		v.Binaries = append(v.Binaries, sandboxapi.DisplayText(b))
	}
	return v
}

// destinationSummary counts the AI destinations of a sandbox for its
// Egress status line.
func (m *Manager) destinationSummary(name, harnessName string, live map[string]egress.DestinationStats) (modelAPIs, shadow int) {
	m.destMu.Lock()
	defer m.destMu.Unlock()
	t := m.dests[name]
	if t == nil {
		return 0, 0
	}
	m.mergeLiveLocked(t, live, harnessName)
	for _, r := range t.rows {
		switch kind, _, _ := r.classify(harnessName); {
		case kind == sandboxapi.DestinationModelProvider || kind == sandboxapi.DestinationHarnessVendor:
			modelAPIs++
		case sandboxapi.ShadowAIKind(kind):
			shadow++
		}
	}
	return modelAPIs, shadow
}

// destinationsPath is where a sandbox's destinations table is kept.
func (m *Manager) destinationsPath(name string) (string, bool) {
	if !openshell.ValidSandboxName(name) || name == recordDirName {
		return "", false
	}
	return filepath.Join(m.opts.DataDir, "sandboxes", name, destinationsFile), true
}

// destinationsFileV1 is the kept form of a destinations table.
type destinationsFileV1 struct {
	Version       int                   `json:"version"`
	Name          string                `json:"name"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Dropped       int                   `json:"dropped,omitempty"`
	ShadowSession int                   `json:"shadow_session,omitempty"`
	Shadow        map[string]int        `json:"shadow,omitempty"`
	Destinations  []destRow             `json:"destinations"`
	Models        []sandboxapi.ModelUse `json:"models,omitempty"`
}

// flushDestinations writes the tables that changed since their last write
// (only name's, when given) with the proxy counter's current counts. It
// writes under destMu, so a delete's dropDestinations never sees its file
// come back.
func (m *Manager) flushDestinations(only string) {
	m.mu.Lock()
	type target struct {
		name, harness, bindingID string
		opens                    []proxyOpen
	}
	var targets []target
	for name, b := range m.boxes {
		if (only == "" || name == only) && !b.deleted && !b.retained && !b.creating {
			targets = append(targets, target{name, b.rec.Harness, b.rec.BindingID, slices.Clone(b.proxyOpens)})
		}
	}
	m.mu.Unlock()
	now := m.now()
	for _, tg := range targets {
		path, ok := m.destinationsPath(tg.name)
		if !ok {
			continue
		}
		live := m.proxyStats(tg.bindingID)
		m.destMu.Lock()
		if t := m.dests[tg.name]; t != nil {
			m.mergeLiveLocked(t, live, tg.harness)
			for _, r := range t.rows {
				if r.attributeProxied(tg.opens, now) {
					t.dirty = true
				}
			}
			if t.dirty {
				if err := m.writeDestinationsLocked(path, tg.name, t); err != nil {
					m.logf("keep the destinations of %s: %v", tg.name, err)
				} else {
					t.dirty = false
				}
			}
		}
		m.destMu.Unlock()
	}
}

// writeDestinationsLocked keeps t at path. Callers hold destMu.
func (m *Manager) writeDestinationsLocked(path, name string, t *destTable) error {
	file := destinationsFileV1{Version: 1, Name: name, UpdatedAt: m.now().UTC(), Dropped: t.dropped,
		ShadowSession: t.shadowSession, Shadow: t.shadow, Destinations: make([]destRow, 0, len(t.rows))}
	for _, r := range t.rows {
		kept := *r
		kept.Proxy, kept.live, kept.hit = r.total(), counts{}, nil
		file.Destinations = append(file.Destinations, kept)
	}
	slices.SortFunc(file.Destinations, func(a, b destRow) int { return cmp.Compare(a.Host, b.Host) })
	for _, u := range t.models {
		file.Models = append(file.Models, *u)
	}
	slices.SortFunc(file.Models, func(a, b sandboxapi.ModelUse) int {
		return cmp.Or(cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.Model, b.Model))
	})
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return safefile.WritePrivate(path, data)
}

// loadDestinations reads a sandbox's kept destinations table; nil when it
// has none or it is unreadable (logged).
func (m *Manager) loadDestinations(name string) *destTable {
	path, ok := m.destinationsPath(name)
	if !ok {
		return nil
	}
	data, err := safefile.ReadRegularFileBounded(path, destinationsMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var file destinationsFileV1
	if err == nil {
		err = json.Unmarshal(data, &file)
	}
	if err == nil && (file.Version != 1 || file.Name != name) {
		err = errors.New("not this sandbox's destinations")
	}
	if err != nil {
		m.logf("sandbox %s: the kept destinations are unreadable and start over: %v", name, err)
		return nil
	}
	t := &destTable{rows: map[string]*destRow{}, models: map[string]*sandboxapi.ModelUse{}, dropped: file.Dropped,
		shadowSession: file.ShadowSession, shadow: file.Shadow}
	if t.shadow == nil {
		t.shadow = map[string]int{}
	}
	c := m.destinationCatalog()
	for i := range file.Destinations {
		r := file.Destinations[i]
		host := strings.ToLower(r.Host)
		if host == "" || len(host) > 253 || t.rows[host] != nil || len(t.rows) >= sandboxapi.MaxDestinations {
			continue
		}
		r.Host = host
		r.lookup(c)
		t.rows[host] = &r
	}
	for _, u := range file.Models {
		if len(t.models) < maxDestinationModels {
			use := u
			t.models[use.Provider+"\x00"+use.Model] = &use
		}
	}
	return t
}

// dropDestinations forgets a deleted sandbox's destinations: its table, its
// kept file and what the proxy counter counted for its binding. The table
// stays dropped (nil) until forget: a refusal the egress sink still holds,
// or a late OpenShell record, must neither bring it back nor write the file
// again before the sandbox's directory goes.
func (m *Manager) dropDestinations(name, bindingID string) error {
	m.mu.Lock()
	proxy := m.proxy
	m.mu.Unlock()
	if proxy != nil && proxy.Counter() != nil && bindingID != "" {
		proxy.Counter().Forget(bindingID)
	}
	m.destMu.Lock()
	defer m.destMu.Unlock()
	m.dests[name] = nil
	if path, ok := m.destinationsPath(name); ok {
		if err := removeIfExists(path); err != nil {
			return fmt.Errorf("remove the destinations of %s: %w", name, err)
		}
	}
	return nil
}
