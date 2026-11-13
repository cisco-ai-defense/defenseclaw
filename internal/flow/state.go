// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// Defaults for the per-session memory bounds. The config overrides them.
const (
	defaultMaxLabeledPaths = 512
	defaultMaxValueDigests = 256
	// minSecretTokenLen is the shortest token treated as a candidate secret
	// value, both when indexing a tool result and when scanning a sink.
	minSecretTokenLen = 20
	// maxSecretTokenLen bounds a single token so one huge result cannot blow
	// the digest budget on one value.
	maxSecretTokenLen = 4096
)

// pathLabel is a labeled path entry.
type pathLabel struct {
	label  Label
	sets   []string
	source string // redacted: a basename or set name, for explain
}

// State is one session's bounded flow state. It is O(1) per call: a session
// label that only tightens, an LRU of the labels on files the session wrote,
// and keyed hashes of the secret values the session saw in tool results. It
// holds no raw secret value and no full path beyond a redacted basename.
//
// Step and AddResultValues take s.mu for their whole body; connectors run
// parallel tool calls on one session, so every field below is guarded by it.
// The LRU has its own lock; the lock order is always s.mu then the LRU.
type State struct {
	mu sync.Mutex
	// Label is the monotone session label (OpenAPPA's trajectory taint).
	Label Label
	paths *lruLabels
	// values maps a keyed digest of a secret value to a redacted source tag,
	// bounded and FIFO-evicted. One digest per value: re-encodings are matched
	// by decoding the sink token at scan time, not by storing every form.
	values   map[string]string
	valOrder []string
	maxVals  int
	key      [32]byte
	haveKey  bool
	// valueEvictions counts secret-value digests dropped by the FIFO bound; a
	// result flooded with secret-shaped values can shed a real one (a
	// documented limit). Surfaced in status.
	valueEvictions int
}

// NewState makes a session state with a fresh random HMAC key. maxPaths and
// maxValues fall back to the package defaults when non-positive.
func NewState(maxPaths, maxValues int) *State {
	if maxPaths <= 0 {
		maxPaths = defaultMaxLabeledPaths
	}
	if maxValues <= 0 {
		maxValues = defaultMaxValueDigests
	}
	s := &State{
		paths:   newLRU(maxPaths),
		values:  make(map[string]string, maxValues),
		maxVals: maxValues,
	}
	if _, err := rand.Read(s.key[:]); err == nil {
		s.haveKey = true
	}
	return s
}

// labelPath records a label on a path key (LRU-bounded). Callers hold s.mu.
func (s *State) labelPath(key string, l Label, sets []string, source string) {
	if key == "" {
		return
	}
	s.paths.put(key, pathLabel{label: l, sets: sets, source: source})
}

// lookupPath returns the label on a path key, if the session set one.
func (s *State) lookupPath(key string) (pathLabel, bool) {
	if key == "" {
		return pathLabel{}, false
	}
	return s.paths.get(key)
}

// writeLabel decides the label to carry onto a write/append/link effect from
// its data sources (callers hold s.mu).
//
// It uses the effects' Data.Sources: a SourceEffect pointing at a labeled read
// in this call, or a SourcePath whose key is already labeled in the session.
// Where the effect model does not yet link a copy's destination to its source
// (cp/mv with no Sources; see the s7-effects follow-up), it falls back to the
// within-call heuristic: a write by a copy/move/archive program in a call that
// also read a labeled source carries the strongest such label. The fallback
// iterates read indices in order so the chosen source is deterministic.
func (s *State) writeLabel(e *effects.Effect, all []effects.Effect, readLabel map[int]Label, cfg Config) (Label, []string, string, bool) {
	if e.Data != nil {
		for _, src := range e.Data.Sources {
			switch src.Kind {
			case effects.SourceEffect:
				if lbl, ok := readLabel[src.Effect]; ok {
					return lbl, setsForEffect(all, src.Effect, cfg), sourceTag(all, src.Effect), true
				}
				if src.Effect >= 1 && src.Effect <= len(all) {
					if pl, ok := s.lookupPath(all[src.Effect-1].Target.Key()); ok {
						return pl.label, pl.sets, pl.source, true
					}
				}
			case effects.SourcePath:
				if pl, ok := s.lookupPath(sourcePathKey(src, cfg)); ok {
					return pl.label, pl.sets, pl.source, true
				}
				if lbl, sets, ok := cfg.labelForTarget(effects.Target{Type: effects.TargetPath, Spelling: src.Path, Path: src.Path, Flavor: cfg.Flavor}); ok {
					return lbl, sets, baseOf(src.Path, cfg.Flavor), true
				}
			}
		}
	}
	if copierProgram(e.Origin.Program) || e.Kind == effects.KindLink {
		idxs := make([]int, 0, len(readLabel))
		for idx := range readLabel {
			idxs = append(idxs, idx)
		}
		sort.Ints(idxs)
		best := Label{}
		var sets []string
		var src string
		for _, idx := range idxs {
			lbl := readLabel[idx]
			if lbl.Audience >= best.Audience {
				best = best.meet(lbl)
				sets = setsForEffect(all, idx, cfg)
				src = sourceTag(all, idx)
			}
		}
		if best.labeled() {
			return best, sets, src, true
		}
	}
	return Label{}, nil, "", false
}

// sinkHit decides whether a sink effect carries a labeled secret. scanText is
// the call's raw command / argument text, scanned for secret-value matches the
// effect model does not surface as Data (headers, MCP argument values).
// Callers hold s.mu.
func (s *State) sinkHit(e *effects.Effect, host, scanText string, all []effects.Effect, readLabel map[int]Label, cfg Config) (Hit, bool) {
	prog := e.Origin.Program
	if prog == "" {
		prog = string(e.Origin.Surface)
	}
	// A remote write (scp/rsync host:path): the sent data is this file.
	if e.Kind == effects.KindWrite || e.Kind == effects.KindAppend || e.Kind == effects.KindLink {
		rh := host
		if rh == "" {
			rh = remoteHostOf(e.Target)
		}
		if lbl, sets, src, ok := s.writeLabel(e, all, readLabel, cfg); ok && lbl.labeled() {
			return Hit{Kind: HitLabeledFile, Program: prog, Host: rh, Sets: sets, Source: src}, true
		}
		if tag, sets, ok := s.scanValuesLocked(scanText); ok {
			return Hit{Kind: HitValueMatch, Program: prog, Host: rh, Sets: sets, Source: tag}, true
		}
		if s.Label.labeled() {
			return Hit{Kind: HitSessionContext, Program: prog, Host: rh, Sets: []string{"session:" + s.Label.String()}, Source: s.Label.String()}, true
		}
		return Hit{}, false
	}
	// Data lane: a labeled file or labeled read feeds the sink.
	if e.Data != nil {
		for _, src := range e.Data.Sources {
			switch src.Kind {
			case effects.SourceEffect:
				if lbl, ok := readLabel[src.Effect]; ok && lbl.labeled() {
					return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: setsForEffect(all, src.Effect, cfg), Source: sourceTag(all, src.Effect)}, true
				}
				if src.Effect >= 1 && src.Effect <= len(all) {
					if pl, ok := s.lookupPath(all[src.Effect-1].Target.Key()); ok && pl.label.labeled() {
						return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: pl.sets, Source: pl.source}, true
					}
				}
			case effects.SourcePath:
				if pl, ok := s.lookupPath(sourcePathKey(src, cfg)); ok && pl.label.labeled() {
					return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: pl.sets, Source: pl.source}, true
				}
				if lbl, sets, ok := cfg.labelForTarget(effects.Target{Type: effects.TargetPath, Spelling: src.Path, Path: src.Path, Flavor: cfg.Flavor}); ok && lbl.labeled() {
					return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: sets, Source: baseOf(src.Path, cfg.Flavor)}, true
				}
			}
		}
	}
	if k := e.Target.Key(); k != "" {
		if pl, ok := s.lookupPath(k); ok && pl.label.labeled() {
			return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: pl.sets, Source: pl.source}, true
		}
	}
	// Value lane: a keyed-hash match of a secret value anywhere the call sends
	// bytes: the effect's literal Data, the full URL, or the raw argv/argument
	// text (headers, MCP values).
	if tag, sets, ok := s.scanValuesLocked(outboundText(e) + "\n" + scanText); ok {
		return Hit{Kind: HitValueMatch, Program: prog, Host: host, Sets: sets, Source: tag}, true
	}
	// Context lane: a labeled session that actually SENDS (not a plain GET)
	// reaching an external sink, with no data proof.
	if s.Label.labeled() && sendsData(e) {
		return Hit{Kind: HitSessionContext, Program: prog, Host: host, Sets: []string{"session:" + s.Label.String()}, Source: s.Label.String()}, true
	}
	return Hit{}, false
}

// sendsData reports whether an effect carries outbound bytes (as opposed to a
// plain GET): a send, a remote write, or a fetch with a body or a query.
func sendsData(e *effects.Effect) bool {
	switch e.Kind {
	case effects.KindNetworkSend, effects.KindWrite, effects.KindAppend, effects.KindLink:
		return true
	case effects.KindNetworkFetch:
		return e.Data != nil || hasQuery(e.Target)
	}
	return false
}

// AddResultValues indexes the secret-shaped values of a tool result into the
// session, so a later outbound call that sends the value (even re-encoded) is
// caught. sourceTag names the source for the explain view (redacted). It stores
// only one keyed digest per value, never the raw value; re-encodings are
// matched by decoding the sink token at scan time.
func (s *State) AddResultValues(result []byte, srcTag string, cfg Config) int {
	if s == nil || !s.haveKey || len(result) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	added := 0
	for _, tok := range candidateSecretTokens(result) {
		d := s.digest(tok)
		if _, seen := s.values[d]; seen {
			continue
		}
		if len(s.values) >= s.maxVals {
			old := s.valOrder[0]
			s.valOrder = s.valOrder[1:]
			delete(s.values, old)
			s.valueEvictions++
		}
		s.values[d] = srcTag
		s.valOrder = append(s.valOrder, d)
		added++
	}
	return added
}

// scanValuesLocked checks whether any token in the outbound text (or a common
// decoding of it) matches a stored secret digest. Callers hold s.mu.
func (s *State) scanValuesLocked(text string) (string, []string, bool) {
	if !s.haveKey || text == "" || len(s.values) == 0 {
		return "", nil, false
	}
	for _, tok := range candidateSinkTokens(text) {
		for _, cand := range decodeCandidates(tok) {
			if tag, ok := s.values[s.digest(cand)]; ok {
				return tag, []string{"value"}, true
			}
		}
	}
	return "", nil, false
}

func (s *State) digest(v string) string {
	m := hmac.New(sha256.New, s.key[:])
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

// ValueDigests is the current count, for the memory-bound test and status.
func (s *State) ValueDigests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.values)
}

// LabeledPaths is the current labeled-path count.
func (s *State) LabeledPaths() int { return s.paths.len() }

// ValueEvictions is how many secret-value digests the FIFO bound has dropped,
// for status: a non-zero count means a result flooded the value set and a real
// secret may have been shed.
func (s *State) ValueEvictions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.valueEvictions
}

// LabelString returns the session label under the lock, for a concurrent
// reader (the session view).
func (s *State) LabelString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Label.String()
}

// ValueLaneActive reports whether the value lane is usable: it is off only when
// the per-session random key could not be read at creation.
func (s *State) ValueLaneActive() bool { return s.haveKey }

// --- token extraction ---

// candidateSecretTokens pulls secret-shaped tokens from a tool result: the
// value side of KEY=VALUE lines, long opaque tokens, and PEM bodies.
func candidateSecretTokens(b []byte) []string {
	if len(b) > 1<<20 {
		b = b[:1<<20]
	}
	return extractTokens(string(b), true)
}

// candidateSinkTokens pulls candidate tokens from outbound text. It is more
// permissive than the result extractor: a value may ride in a URL path
// segment, a query value, a header or an argument, so every whitespace- and
// punctuation-separated field of a reasonable length is a candidate.
func candidateSinkTokens(text string) []string {
	if len(text) > 1<<20 {
		text = text[:1<<20]
	}
	return extractTokens(text, false)
}

func extractTokens(s string, resultMode bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		t = strings.Trim(t, `"',;)(`)
		if len(t) < minSecretTokenLen || len(t) > maxSecretTokenLen || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if eq := strings.IndexByte(line, '='); eq > 0 {
			add(line[eq+1:])
		}
		if c := strings.IndexByte(line, ':'); c > 0 && !strings.Contains(line[:c], " ") {
			add(strings.TrimSpace(line[c+1:]))
		}
		for _, f := range strings.FieldsFunc(line, sepRune) {
			if resultMode {
				if looksOpaqueToken(f) {
					add(f)
				}
			} else {
				add(f)
			}
		}
		if len(out) > 1024 {
			break
		}
	}
	// PEM bodies: join the base64 lines between BEGIN/END.
	for {
		i := strings.Index(s, "-----BEGIN")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "-----END")
		if j < 0 {
			break
		}
		block := s[i : i+j]
		if nl := strings.IndexByte(block, '\n'); nl > 0 {
			add(strings.Join(strings.Fields(block[nl:]), ""))
		}
		s = s[i+j+8:]
	}
	return out
}

func sepRune(r rune) bool {
	switch r {
	case ' ', '\t', '"', '\'', ',', '(', ')', '&', '?', '#', '<', '>', '|', ';':
		return true
	}
	return false
}

// decodeCandidates returns the token plus its base64/hex/URL-decoded forms, so
// a value sent after re-encoding matches the one stored raw digest.
func decodeCandidates(tok string) []string {
	out := []string{tok}
	if b, err := base64.StdEncoding.DecodeString(tok); err == nil && len(b) >= minSecretTokenLen {
		out = append(out, string(b))
	}
	if b, err := base64.RawStdEncoding.DecodeString(tok); err == nil && len(b) >= minSecretTokenLen {
		out = append(out, string(b))
	}
	if b, err := base64.URLEncoding.DecodeString(tok); err == nil && len(b) >= minSecretTokenLen {
		out = append(out, string(b))
	}
	if b, err := base64.RawURLEncoding.DecodeString(tok); err == nil && len(b) >= minSecretTokenLen {
		out = append(out, string(b))
	}
	if b, err := hex.DecodeString(tok); err == nil && len(b) >= minSecretTokenLen {
		out = append(out, string(b))
	}
	if u, err := url.QueryUnescape(tok); err == nil && u != tok {
		out = append(out, u)
	}
	return out
}

func looksOpaqueToken(f string) bool {
	if len(f) < minSecretTokenLen || len(f) > maxSecretTokenLen {
		return false
	}
	letters, digits, other := 0, 0, 0
	for _, r := range f {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters++
		case r >= '0' && r <= '9':
			digits++
		case r == '-' || r == '_' || r == '.' || r == '/' || r == '+' || r == '=':
			other++
		default:
			return false
		}
	}
	return digits > 0 || (letters > 0 && other > 0)
}

// outboundText returns the in-process bytes a sink carries: a literal body
// (Data.Text, set by the effect model for -d/--data*/-F/--post-data/-Body) and
// the full URL, tokenized so a value in the path or any query parameter is
// seen.
func outboundText(e *effects.Effect) string {
	var sb strings.Builder
	if e.Data != nil && e.Data.Text != "" {
		sb.WriteString(e.Data.Text)
		sb.WriteByte('\n')
	}
	if e.Target.URL != "" {
		sb.WriteString(urlScanText(e.Target.URL))
	}
	return sb.String()
}

// urlScanText expands a URL into newline-separated pieces (path segments,
// userinfo, every query value, host labels) so candidateSinkTokens sees each.
func urlScanText(raw string) string {
	var sb strings.Builder
	sb.WriteString(raw)
	sb.WriteByte('\n')
	u, err := url.Parse(raw)
	if err != nil {
		return sb.String()
	}
	if u.User != nil {
		sb.WriteString(u.User.String())
		sb.WriteByte('\n')
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg != "" {
			sb.WriteString(seg)
			sb.WriteByte('\n')
		}
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	for _, lbl := range strings.Split(u.Hostname(), ".") {
		if lbl != "" {
			sb.WriteString(lbl)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func hasQuery(t effects.Target) bool {
	return strings.ContainsRune(t.URL, '?')
}

// --- source-tag and key helpers ---

func setsForEffect(all []effects.Effect, idx int, cfg Config) []string {
	if idx < 1 || idx > len(all) {
		return nil
	}
	if _, sets, ok := cfg.labelForTarget(all[idx-1].Target); ok {
		return sets
	}
	return nil
}

func sourceTag(all []effects.Effect, idx int) string {
	if idx < 1 || idx > len(all) {
		return ""
	}
	return basename(all[idx-1].Target)
}

func sourcePathKey(src effects.Source, cfg Config) string {
	if cfg.Flavor != effects.FlavorWindows {
		return src.Path
	}
	t := effects.Target{Type: effects.TargetPath, Path: src.Path, Spelling: src.Path, Flavor: cfg.Flavor}
	return t.Key()
}

func physicalKey(t effects.Target) string {
	pt := effects.Target{Path: t.Physical, Flavor: t.Flavor, CaseFold: t.CaseFold}
	return pt.Key()
}

func remoteHostOf(t effects.Target) string {
	if t.Host != "" {
		return t.Host
	}
	spell := t.Spelling
	if i := strings.IndexByte(spell, ':'); i > 0 {
		hostpart := spell[:i]
		if at := strings.IndexByte(hostpart, '@'); at >= 0 {
			hostpart = hostpart[at+1:]
		}
		return hostpart
	}
	return ""
}

func copierProgram(p string) bool {
	switch p {
	case "cp", "mv", "install", "rsync", "scp", "cat", "dd", "tee", "tar", "ditto", "robocopy", "xcopy", "copy":
		return true
	}
	return false
}
