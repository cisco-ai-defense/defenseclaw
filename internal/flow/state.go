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
type State struct {
	mu sync.Mutex
	// Label is the monotone session label (OpenAPPA's trajectory taint).
	Label Label
	paths *lruLabels
	// values maps a keyed digest of a secret value (and its re-encodings) to a
	// redacted source tag, bounded and FIFO-evicted.
	values   map[string]string
	valOrder []string
	maxVals  int
	key      [32]byte
	haveKey  bool
	// counters for status/explain
	readsLabeled int
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

func (s *State) tighten(l Label) {
	s.Label = s.Label.meet(l)
	s.readsLabeled++
}

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
// its data sources. It returns the label, sets, a redacted source tag, and ok.
//
// It uses the effects' Data.Sources: a SourceEffect pointing at a labeled read
// in this call, or a SourcePath whose key is already labeled in the session.
// Where the effect model does not yet link a copy's destination to its source
// (cp/mv with no Sources; see the s7-effects follow-up), it falls back to the
// within-call heuristic: a write by a copy/move/archive program in a call that
// also read a labeled source carries that label.
func (s *State) writeLabel(e *effects.Effect, all []effects.Effect, readLabel map[int]Label, cfg Config) (Label, []string, string, bool) {
	if e.Data != nil {
		for _, src := range e.Data.Sources {
			switch src.Kind {
			case effects.SourceEffect:
				if lbl, ok := readLabel[src.Effect]; ok {
					return lbl, setsForEffect(all, src.Effect, cfg), sourceTag(all, src.Effect), true
				}
				// a labeled intermediate write (staging file)
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
	// Fallback for unlinked copy/move/link (TODO: remove once s7-effects adds
	// cp/mv Sources — see streams/S7 effects follow-up). If this call read a
	// labeled source and the program is a copier/mover/archiver/linker, carry
	// the strongest label read in the call.
	if copierProgram(e.Origin.Program) || e.Kind == effects.KindLink {
		best := Label{}
		var sets []string
		var src string
		for idx, lbl := range readLabel {
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

// sinkHit decides whether a sink effect carries a labeled secret.
func (s *State) sinkHit(e *effects.Effect, host string, all []effects.Effect, readLabel map[int]Label, cfg Config) (Hit, bool) {
	prog := e.Origin.Program
	if prog == "" {
		prog = string(e.Origin.Surface)
	}
	// A remote write (scp/rsync host:path): the sent data is this file. Decide
	// its label the same way a local write would be labeled; a hit means the
	// copied file is labeled, or a labeled source feeds it (copier fallback).
	if e.Kind == effects.KindWrite || e.Kind == effects.KindAppend || e.Kind == effects.KindLink {
		rh := host
		if rh == "" {
			rh = remoteHostOf(e.Target)
		}
		if lbl, sets, src, ok := s.writeLabel(e, all, readLabel, cfg); ok && lbl.labeled() {
			return Hit{Kind: HitLabeledFile, Program: prog, Host: rh, Sets: sets, Source: src}, true
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
	// Target path of the sink itself (git push of a labeled tracked file, an
	// upload whose operand is a labeled path).
	if k := e.Target.Key(); k != "" {
		if pl, ok := s.lookupPath(k); ok && pl.label.labeled() {
			return Hit{Kind: HitLabeledFile, Program: prog, Host: host, Sets: pl.sets, Source: pl.source}, true
		}
	}
	// Value lane: a keyed-hash match of a secret value in the outbound bytes
	// (body text or URL), after re-encoding.
	if tag, sets, ok := s.scanValues(outboundText(e)); ok {
		return Hit{Kind: HitValueMatch, Program: prog, Host: host, Sets: sets, Source: tag}, true
	}
	// Context lane: labeled session reaching an external sink, no data proof.
	if s.Label.labeled() {
		return Hit{Kind: HitSessionContext, Program: prog, Host: host, Sets: []string{"session:" + s.Label.String()}, Source: s.Label.String()}, true
	}
	return Hit{}, false
}

// AddResultValues indexes the secret-shaped values of a tool result into the
// session, so a later outbound call that sends the value (even re-encoded) is
// caught. kindHint names the source for the explain view (redacted). It stores
// only keyed digests, never the raw value.
func (s *State) AddResultValues(result []byte, sourceTag string, cfg Config) int {
	if s == nil || !s.haveKey || len(result) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	added := 0
	for _, tok := range candidateSecretTokens(result) {
		for _, form := range encodings(tok, cfg.Reencodings) {
			d := s.digest(form)
			if _, seen := s.values[d]; seen {
				continue
			}
			if len(s.values) >= s.maxVals {
				// FIFO-evict the oldest digest to keep the bound.
				old := s.valOrder[0]
				s.valOrder = s.valOrder[1:]
				delete(s.values, old)
			}
			s.values[d] = sourceTag
			s.valOrder = append(s.valOrder, d)
			added++
		}
	}
	return added
}

// scanValues checks whether any token in the outbound text matches a stored
// secret digest.
func (s *State) scanValues(text string) (string, []string, bool) {
	if s == nil || !s.haveKey || text == "" || len(s.values) == 0 {
		return "", nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tok := range candidateSecretTokens([]byte(text)) {
		if tag, ok := s.values[s.digest(tok)]; ok {
			return tag, []string{"value"}, true
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

// --- encodings and token extraction ---

// encodings returns the raw token plus, when on, its base64 (std and url),
// hex and URL-percent-encoded forms, so a secret sent after re-encoding still
// matches a stored digest.
func encodings(tok string, on bool) []string {
	out := []string{tok}
	if !on {
		return out
	}
	b := []byte(tok)
	out = append(out,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		url.QueryEscape(tok),
	)
	return out
}

// candidateSecretTokens pulls secret-shaped tokens from a blob: the value side
// of KEY=VALUE lines, long opaque tokens, and PEM bodies. It is deliberately
// simple and bounded; the keyed digest makes a false token harmless (it will
// not match a sink unless the same token is sent).
func candidateSecretTokens(b []byte) []string {
	if len(b) > 1<<20 {
		b = b[:1<<20]
	}
	s := string(b)
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		t = strings.Trim(t, `"',`)
		if len(t) < minSecretTokenLen || len(t) > maxSecretTokenLen || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
		if len(out) > 256 {
			out = out[:256]
		}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if eq := strings.IndexByte(line, '='); eq > 0 {
			add(line[eq+1:])
		}
		if c := strings.IndexByte(line, ':'); c > 0 && !strings.Contains(line[:c], " ") {
			add(strings.TrimSpace(line[c+1:]))
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ',' || r == '(' || r == ')'
		}) {
			if looksOpaqueToken(f) {
				add(f)
			}
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
			body := strings.Join(strings.Fields(block[nl:]), "")
			add(body)
		}
		s = s[i+j+8:]
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
	// A plain English word or a path is not opaque; require some digits or a
	// mix that looks like a token.
	return digits > 0 || (letters > 0 && other > 0)
}

// outboundText returns the in-process bytes a sink carries (a literal body, a
// built URL). Effect.Data.Text is excluded from JSON and holds the body when
// the effect model captured it; the URL carries a query the model built.
func outboundText(e *effects.Effect) string {
	var sb strings.Builder
	if e.Data != nil && e.Data.Text != "" {
		sb.WriteString(e.Data.Text)
		sb.WriteByte('\n')
	}
	if e.Target.URL != "" {
		sb.WriteString(e.Target.URL)
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
	t := effects.Target{Type: effects.TargetPath, Path: src.Path, Spelling: src.Path, Flavor: cfg.Flavor}
	if cfg.Flavor != effects.FlavorWindows {
		return src.Path
	}
	return t.Key()
}

func physicalKey(t effects.Target) string {
	pt := effects.Target{Path: t.Physical, Flavor: t.Flavor, CaseFold: t.CaseFold}
	return pt.Key()
}

func remoteHostOf(t effects.Target) string {
	v := t.Host
	if v != "" {
		return v
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
