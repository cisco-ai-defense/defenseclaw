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
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// TaintFlag is a session-level marker that a particular taint-source rule
// fired in this conversation. It carries a SetAtEvent stamp used by the
// sliding-window decay check.
type TaintFlag struct {
	Tags       []string
	SourceID   string
	SetAtEvent int
	Timestamp  time.Time
}

// FileTaintMeta records that a specific filesystem path holds sensitive
// data (or content propagated from a sensitive source). Keyed by path
// inside SessionTaint.TaintedFiles.
type FileTaintMeta struct {
	Tags           []string
	SourceID       string
	OriginPath     string
	PropagatedFrom string
	SetAtEvent     int
	Timestamp      time.Time
}

// SessionTaint is the per-session state managed by TaintTracker.
type SessionTaint struct {
	Flags        []TaintFlag
	TaintedFiles map[string]FileTaintMeta
	LastSeen     time.Time
	EventCounter int
}

// TaintContext is the pure-data overlay produced by Go and consumed by
// OPA. It conveys the Tracker's view of the session without making any
// severity decisions — those are made in policies/rego/guardrail.rego.
type TaintContext struct {
	HasStrongConsumer       bool     `json:"has_strong_consumer"`
	HasWeakConsumer         bool     `json:"has_weak_consumer"`
	HasTaintSourceInSession bool     `json:"has_taint_source_in_session"`
	TaintedFilesReferenced  []string `json:"tainted_files_referenced"`
	SourceFindings          []string `json:"source_findings"`
	MaxConsumerConfidence   float64  `json:"max_consumer_confidence"`
	NetworkDestExcluded     bool     `json:"network_dest_excluded"`
	EventsSinceSource       int      `json:"events_since_source"`
}

// TaintConfig captures the state-bound configuration loaded from
// policies/guardrail/<tier>/taint.yaml. Policy decision knobs live in
// OPA data.guardrail.taint.<tier>, NOT here.
type TaintConfig struct {
	FlagDecayEvents      int
	FileTaintDecayEvents int
	SensitiveFiles       []string
	NetworkExclusions    []string
	SessionIdleTTL       time.Duration
}

// ---------------------------------------------------------------------------
// Tag constants
//
// taintSourceTag marks rule findings that establish session-level taint
// (e.g. credential file reads, environment dumps). taintConsumerTag
// marks findings that, in a tainted context, indicate exfiltration or
// destructive evidence-tampering. Both tags are applied via YAML rule
// definitions; the gateway never adds or removes them at runtime.
// ---------------------------------------------------------------------------

const (
	taintSourceTag   = "taint-source"
	taintConsumerTag = "taint-consumer"
)

// ---------------------------------------------------------------------------
// Defaults and constructor
// ---------------------------------------------------------------------------

const (
	defaultTaintFlagDecayEvents      = 10
	defaultTaintFileTaintDecayEvents = 30
	defaultTaintMaxSessions          = 200
	defaultTaintSessionIdleTTL       = 1 * time.Hour
	taintStaleSweepFrequency         = 50 // run a stale sweep roughly every N writes
)

// TaintTracker maintains per-session taint state across HTTP and
// WebSocket surfaces. State is bounded on three axes:
//   - maxSessions: total sessions retained (LRU on overflow).
//   - SessionIdleTTL: sessions untouched for longer than the TTL are
//     evicted on amortized writes. Memory hygiene only — never affects
//     taint decisions of live sessions.
//   - Event-count sliding-window decay (FlagDecayEvents,
//     FileTaintDecayEvents): controls when a flag/file is "live" for
//     escalation purposes. Decay never deletes entries; lookup checks
//     freshness lazily.
type TaintTracker struct {
	mu               sync.RWMutex
	sessions         map[string]*SessionTaint
	maxSessions      int
	cfg              TaintConfig
	sensitiveMatcher *globMatcher
	networkMatcher   *cidrHostMatcher

	writesSinceSweep int
	now              func() time.Time
}

// NewTaintTracker creates a tracker with the given config and a session
// cap. A non-positive maxSessions falls back to the default.
func NewTaintTracker(cfg TaintConfig, maxSessions int) *TaintTracker {
	if maxSessions <= 0 {
		maxSessions = defaultTaintMaxSessions
	}
	if cfg.FlagDecayEvents <= 0 {
		cfg.FlagDecayEvents = defaultTaintFlagDecayEvents
	}
	if cfg.FileTaintDecayEvents <= 0 {
		cfg.FileTaintDecayEvents = defaultTaintFileTaintDecayEvents
	}
	if cfg.SessionIdleTTL <= 0 {
		cfg.SessionIdleTTL = defaultTaintSessionIdleTTL
	}
	tt := &TaintTracker{
		sessions:    make(map[string]*SessionTaint),
		maxSessions: maxSessions,
		cfg:         cfg,
		now:         time.Now,
	}
	tt.sensitiveMatcher = newGlobMatcher(cfg.SensitiveFiles)
	tt.networkMatcher = newCIDRHostMatcher(cfg.NetworkExclusions)
	return tt
}

// SetNowFunc lets tests inject a deterministic clock for SessionIdleTTL
// eviction. The clock is never consulted for decay decisions, only for
// idle eviction.
func (tt *TaintTracker) SetNowFunc(f func() time.Time) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if f != nil {
		tt.now = f
	}
}

// SessionCount returns the number of tracked sessions. Useful for tests
// and operator metrics.
func (tt *TaintTracker) SessionCount() int {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	return len(tt.sessions)
}

// ---------------------------------------------------------------------------
// Mutation API
// ---------------------------------------------------------------------------

// Observe is called exactly once per tool-call event to advance the
// session's monotonic EventCounter. All decay decisions consult the
// counter, so this is the single source of truth for "did N events pass".
//
// Observe also stamps LastSeen with the wall-clock time, used only for
// idle-session eviction.
func (tt *TaintTracker) Observe(sessionID string) {
	if sessionID == "" {
		return
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	sess := tt.getOrCreateLocked(sessionID)
	sess.EventCounter++
	sess.LastSeen = tt.now()

	tt.writesSinceSweep++
	if tt.writesSinceSweep >= taintStaleSweepFrequency {
		tt.evictStaleLocked(tt.now())
		tt.writesSinceSweep = 0
	}
	if len(tt.sessions) > tt.maxSessions {
		tt.pruneOldestLocked()
	}
}

// Record stamps session-level taint flags from any findings carrying the
// "taint-source" tag. Re-recording a flag with the same SourceID
// refreshes its SetAtEvent (true sliding window).
func (tt *TaintTracker) Record(sessionID string, findings []RuleFinding) {
	if sessionID == "" || len(findings) == 0 {
		return
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	sess := tt.getOrCreateLocked(sessionID)
	now := tt.now()
	for _, f := range findings {
		if !hasTag(f.Tags, taintSourceTag) {
			continue
		}
		flag := TaintFlag{
			Tags:       append([]string(nil), f.Tags...),
			SourceID:   f.RuleID,
			SetAtEvent: sess.EventCounter,
			Timestamp:  now,
		}
		// Replace existing flag with the same SourceID; otherwise append.
		// Keeping one flag per source bounds memory at O(taint-source rules).
		replaced := false
		for i, existing := range sess.Flags {
			if existing.SourceID == flag.SourceID {
				sess.Flags[i] = flag
				replaced = true
				break
			}
		}
		if !replaced {
			sess.Flags = append(sess.Flags, flag)
		}
	}
}

// RecordShellOps applies file-level taint propagation rules to the
// session based on extracted shell ops. It does NOT scan findings —
// that's Record's job. RecordShellOps walks WriteSources to propagate
// taint through copies and stamps any baseline-sensitive sources as the
// origin of new file taint.
func (tt *TaintTracker) RecordShellOps(sessionID string, ops ShellOps) {
	if sessionID == "" {
		return
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	sess := tt.getOrCreateLocked(sessionID)
	now := tt.now()

	for dst, sources := range ops.WriteSources {
		if dst == "" {
			continue
		}
		var (
			combinedTags []string
			ruleID       string
			origin       string
			propFrom     string
		)
		for _, src := range sources {
			if src == "" {
				continue
			}
			// Existing file taint on src? Propagate.
			if meta, ok := sess.TaintedFiles[src]; ok && tt.fileTaintLive(sess, meta) {
				combinedTags = mergeUnique(combinedTags, meta.Tags)
				if ruleID == "" {
					ruleID = meta.SourceID
				}
				if origin == "" {
					origin = meta.OriginPath
				}
				if propFrom == "" {
					propFrom = src
				}
			}
			// Baseline-sensitive source? Establish a new file taint.
			if tt.sensitiveMatcher != nil && tt.sensitiveMatcher.Match(src) {
				combinedTags = mergeUnique(combinedTags, []string{"file-sensitive"})
				if ruleID == "" {
					ruleID = "BASELINE-SENSITIVE-FILE"
				}
				if origin == "" {
					origin = src
				}
				if propFrom == "" {
					propFrom = src
				}
			}
		}
		if len(combinedTags) == 0 {
			continue
		}
		sess.TaintedFiles[dst] = FileTaintMeta{
			Tags:           combinedTags,
			SourceID:       ruleID,
			OriginPath:     origin,
			PropagatedFrom: propFrom,
			SetAtEvent:     sess.EventCounter,
			Timestamp:      now,
		}
	}
}

// ---------------------------------------------------------------------------
// Read API
// ---------------------------------------------------------------------------

// IsTainted returns true if the session has at least one live taint flag.
// "Live" means within the FlagDecayEvents sliding window.
func (tt *TaintTracker) IsTainted(sessionID string) bool {
	if sessionID == "" {
		return false
	}
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	sess, ok := tt.sessions[sessionID]
	if !ok {
		return false
	}
	for _, f := range sess.Flags {
		if tt.flagLive(sess, f) {
			return true
		}
	}
	return false
}

// IsFileTainted returns the live taint metadata for a specific path in a
// session, or zero+false if the path is not tainted (or has decayed).
func (tt *TaintTracker) IsFileTainted(sessionID, path string) (FileTaintMeta, bool) {
	if sessionID == "" || path == "" {
		return FileTaintMeta{}, false
	}
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	sess, ok := tt.sessions[sessionID]
	if !ok {
		return FileTaintMeta{}, false
	}
	meta, ok := sess.TaintedFiles[path]
	if !ok || !tt.fileTaintLive(sess, meta) {
		return FileTaintMeta{}, false
	}
	return meta, true
}

// BuildTaintContext is a pure read that produces the overlay consumed by
// OPA. It computes whether the current findings + shell ops constitute a
// strong-consumer (file-level evidence), weak-consumer (session-level
// evidence only), or neither, and provides supporting metadata for the
// Rego decision and audit telemetry.
//
// BuildTaintContext does NOT mutate session state — Observe / Record /
// RecordShellOps are the only mutation entrypoints. This separation lets
// the Rego policy be the sole decision-maker.
func (tt *TaintTracker) BuildTaintContext(sessionID string, findings []RuleFinding, ops ShellOps) TaintContext {
	ctx := TaintContext{}
	if sessionID == "" {
		return ctx
	}

	// Identify consumer findings. If there are none, nothing to escalate.
	var consumerFindings []RuleFinding
	for _, f := range findings {
		if hasTag(f.Tags, taintConsumerTag) {
			consumerFindings = append(consumerFindings, f)
		}
	}
	if len(consumerFindings) == 0 {
		return ctx
	}
	for _, f := range consumerFindings {
		if f.Confidence > ctx.MaxConsumerConfidence {
			ctx.MaxConsumerConfidence = f.Confidence
		}
	}

	tt.mu.RLock()
	defer tt.mu.RUnlock()
	sess, ok := tt.sessions[sessionID]
	if !ok {
		// No tracked session ⇒ no strong-or-weak escalation possible.
		// Consumer findings still feed the base verdict.
		return ctx
	}

	// Live source flags? All session field reads below happen under
	// RLock to avoid races with concurrent Observe/Record on the same
	// session pointer.
	var liveSources []string
	mostRecentSourceEvent := -1
	for _, flag := range sess.Flags {
		if tt.flagLive(sess, flag) {
			ctx.HasTaintSourceInSession = true
			liveSources = appendUnique(liveSources, flag.SourceID)
			if flag.SetAtEvent > mostRecentSourceEvent {
				mostRecentSourceEvent = flag.SetAtEvent
			}
		}
	}
	ctx.SourceFindings = liveSources

	// Strong: any consumer references a tainted or baseline-sensitive file.
	// We collect references from the sinks where consumer rules typically
	// fire: UploadSources (curl/wget exfil) and Deletes (rm/dd/shred).
	var refs []string
	refs = append(refs, ops.UploadSources...)
	refs = append(refs, ops.Deletes...)

	var taintedRefs []string
	for _, p := range refs {
		if p == "" {
			continue
		}
		if meta, ok := sess.TaintedFiles[p]; ok && tt.fileTaintLive(sess, meta) {
			taintedRefs = appendUnique(taintedRefs, p)
			continue
		}
		if tt.sensitiveMatcher != nil && tt.sensitiveMatcher.Match(p) {
			taintedRefs = appendUnique(taintedRefs, p)
		}
	}

	if len(taintedRefs) > 0 {
		ctx.HasStrongConsumer = true
		ctx.TaintedFilesReferenced = taintedRefs
	} else if ctx.HasTaintSourceInSession {
		// Weak: consumer fires in a tainted session but doesn't reference
		// a tainted/sensitive file. Rego decides whether to act based on
		// require_taint_source / min_consumer_confidence.
		ctx.HasWeakConsumer = true
	}

	// Network exclusion (used by Rego to suppress weak escalation when
	// the consumer is talking to an internal/loopback destination).
	if ops.NetworkDest != "" && tt.networkMatcher != nil && tt.networkMatcher.IsExcluded(ops.NetworkDest) {
		ctx.NetworkDestExcluded = true
	}

	if mostRecentSourceEvent >= 0 {
		ctx.EventsSinceSource = sess.EventCounter - mostRecentSourceEvent
	}

	return ctx
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getOrCreateLocked returns the session, creating it if missing. Caller
// must hold tt.mu (write).
func (tt *TaintTracker) getOrCreateLocked(sessionID string) *SessionTaint {
	sess, ok := tt.sessions[sessionID]
	if !ok {
		sess = &SessionTaint{
			TaintedFiles: make(map[string]FileTaintMeta),
		}
		tt.sessions[sessionID] = sess
	}
	return sess
}

// flagLive reports whether a flag is within the sliding-window decay.
func (tt *TaintTracker) flagLive(sess *SessionTaint, f TaintFlag) bool {
	return (sess.EventCounter - f.SetAtEvent) <= tt.cfg.FlagDecayEvents
}

// fileTaintLive reports whether a file taint entry is within the
// sliding-window decay.
func (tt *TaintTracker) fileTaintLive(sess *SessionTaint, m FileTaintMeta) bool {
	return (sess.EventCounter - m.SetAtEvent) <= tt.cfg.FileTaintDecayEvents
}

// pruneOldestLocked drops the oldest 25% of sessions by LastSeen.
// Mirrors the ContextTracker pattern. Caller must hold tt.mu (write).
func (tt *TaintTracker) pruneOldestLocked() {
	target := tt.maxSessions * 3 / 4
	if target < 1 {
		target = 1
	}
	if len(tt.sessions) <= target {
		return
	}
	type keyAge struct {
		key  string
		seen time.Time
	}
	ages := make([]keyAge, 0, len(tt.sessions))
	for k, s := range tt.sessions {
		ages = append(ages, keyAge{key: k, seen: s.LastSeen})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].seen.Before(ages[j].seen) })
	toDelete := len(tt.sessions) - target
	for i := 0; i < toDelete && i < len(ages); i++ {
		delete(tt.sessions, ages[i].key)
	}
}

// evictStaleLocked drops any session whose LastSeen is older than
// now-SessionIdleTTL. This is wall-clock based — purely memory hygiene.
// It NEVER affects taint decisions of live sessions.
func (tt *TaintTracker) evictStaleLocked(now time.Time) {
	if tt.cfg.SessionIdleTTL <= 0 {
		return
	}
	cutoff := now.Add(-tt.cfg.SessionIdleTTL)
	for k, s := range tt.sessions {
		if s.LastSeen.Before(cutoff) {
			delete(tt.sessions, k)
		}
	}
}

// ---------------------------------------------------------------------------
// Glob matcher (sensitive_files)
// ---------------------------------------------------------------------------

type globMatcher struct {
	res []*regexp.Regexp
}

// newGlobMatcher compiles a list of glob patterns. Unsupported patterns
// are silently dropped (we'd rather miss a match than crash on a typo
// in operator config).
func newGlobMatcher(patterns []string) *globMatcher {
	if len(patterns) == 0 {
		return nil
	}
	var res []*regexp.Regexp
	for _, p := range patterns {
		if re := compileGlob(p); re != nil {
			res = append(res, re)
		}
	}
	if len(res) == 0 {
		return nil
	}
	return &globMatcher{res: res}
}

// Match returns true if any compiled glob pattern matches path.
func (m *globMatcher) Match(path string) bool {
	if m == nil {
		return false
	}
	for _, re := range m.res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// compileGlob converts a shell-style glob to an anchored regexp.
// Supported metacharacters:
//   - `**`  matches zero-or-more path components (any chars including /)
//   - `**/` at the start of a segment matches zero-or-more directories,
//     so `**/.env` matches both `.env` and `proj/.env`
//   - `*`   matches any chars except `/`
//   - `?`   matches a single char except `/`
//
// Other regex metacharacters are escaped.
func compileGlob(p string) *regexp.Regexp {
	if p == "" {
		return nil
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				// `**/` ⇒ zero-or-more path components. We emit
				// `(?:.*/)?` so a leading `**/` matches the empty
				// prefix as well as multi-level directories.
				if i+2 < len(p) && p[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
				} else {
					b.WriteString(".*")
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// ---------------------------------------------------------------------------
// CIDR + hostname matcher (network_exclusions)
// ---------------------------------------------------------------------------

type cidrHostMatcher struct {
	cidrs     []*net.IPNet
	hostnames map[string]struct{}
}

// newCIDRHostMatcher parses a list of CIDR ranges and bare hostnames
// (e.g. "127.0.0.0/8", "::1", "localhost"). Unparseable entries are
// silently dropped to avoid bricking the engine on operator config typos.
func newCIDRHostMatcher(entries []string) *cidrHostMatcher {
	if len(entries) == 0 {
		return nil
	}
	m := &cidrHostMatcher{hostnames: make(map[string]struct{})}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			m.cidrs = append(m.cidrs, n)
			continue
		}
		// IP literal (no CIDR) — treat as /32 or /128.
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			mask := net.CIDRMask(bits, bits)
			m.cidrs = append(m.cidrs, &net.IPNet{IP: ip, Mask: mask})
			continue
		}
		m.hostnames[strings.ToLower(e)] = struct{}{}
	}
	return m
}

// IsExcluded returns true if urlOrHost matches any configured CIDR or
// hostname. urlOrHost may be a full URL ("https://localhost/foo"), a
// bare hostname, or an IP literal.
func (m *cidrHostMatcher) IsExcluded(urlOrHost string) bool {
	if m == nil || urlOrHost == "" {
		return false
	}
	host := urlOrHost
	if strings.Contains(urlOrHost, "://") {
		if u, err := url.Parse(urlOrHost); err == nil && u.Host != "" {
			host = u.Hostname()
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if _, ok := m.hostnames[host]; ok {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, c := range m.cidrs {
			if c.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Tag helpers
// ---------------------------------------------------------------------------

// mergeUnique appends items from b that aren't already in a.
func mergeUnique(a, b []string) []string {
	for _, item := range b {
		a = appendUnique(a, item)
	}
	return a
}
