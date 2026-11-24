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

// Package revocation is the list of ended sign-ins (B5.1). The leader keeps
// it in one file on its volume (FileStore); every gateway replica pulls it
// every few seconds into an in-memory Snapshot and checks each verified
// person token against it. An entry ends one token (by a hash of its id)
// or every token of a person issued before a time (a watermark). Entries
// live only as long as a token can (identity.MaxPersonTokenLifetime plus
// skew), so the list stays small and needs no schema bump: a gateway that
// does not know the file ignores it.
package revocation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// Life is how long an entry is kept: the longest a person token lives plus
// the verifier's clock skew.
const Life = identity.MaxPersonTokenLifetime + 5*time.Minute

// DefaultMaxTokensPerPerson bounds the token entries of one person; past it
// the person's token entries become one watermark (never dropped).
const DefaultMaxTokensPerPerson = 64

// Entry is one revocation.
type Entry struct {
	Seq uint64 `json:"seq"`
	// Person is the person's issuer#subject (identity.Person.ID).
	Person string `json:"person"`
	// Token is the TokenKey of one ended token; "" for a person-wide entry.
	Token string `json:"token,omitempty"`
	// NotBefore, on a person-wide entry: every token of Person issued
	// before it is refused.
	NotBefore time.Time `json:"not_before,omitempty"`
	// Lift removes Person's watermark (an admin ended it early).
	Lift bool `json:"lift,omitempty"`
	// Overflow marks a watermark made because Person passed the token
	// cap: it stands for ended tokens, so a Lift never removes it.
	Overflow bool      `json:"overflow,omitempty"`
	At       time.Time `json:"at"`
	Until    time.Time `json:"until"`
	By       string    `json:"by,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	// Also, on a Put of a token entry, names more token keys of the same
	// person to end in the same write (a logout ends the ID token and the
	// access token it holds). The store keeps one entry per key and never
	// stores Also.
	Also []string `json:"also,omitempty"`
}

// maxAlso bounds Entry.Also.
const maxAlso = 4

// Delta is what a replica pulls: the entries after its cursor, or every
// entry (Full) when its generation is not the store's.
type Delta struct {
	Generation string  `json:"generation"`
	Seq        uint64  `json:"seq"`
	Full       bool    `json:"full,omitempty"`
	Entries    []Entry `json:"entries"`
}

// Watermark is the not-before time of a person-wide entry made at now: the
// next whole second, so a token whose iat (whole seconds) is at or before
// now is refused.
func Watermark(now time.Time) time.Time { return now.Truncate(time.Second).Add(time.Second) }

// Errors of Check.
var (
	// ErrEnded: the token, or every sign-in of its person before it, was ended.
	ErrEnded = errors.New("revocation: sign-in ended")
	// ErrUnavailable: this replica has not synced the list recently.
	ErrUnavailable = errors.New("revocation: list not synced")
)

// Reason codes the gateway returns for the two errors.
const (
	ReasonEnded       = "signin_ended"
	ReasonUnavailable = "revocation_unavailable"
)

// ---- leader store ----

type fileDoc struct {
	Version    int     `json:"version"`
	Generation string  `json:"generation"`
	Seq        uint64  `json:"seq"`
	Entries    []Entry `json:"entries"`
}

// FileStore is the leader's list, one JSON file written by atomic rename.
type FileStore struct {
	path string
	// MaxTokensPerPerson is the per-person token cap (default 64).
	MaxTokensPerPerson int
	now                func() time.Time

	mu  sync.Mutex
	doc fileDoc
}

// OpenFileStore opens or creates dir/revocations.json.
func OpenFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &FileStore{path: filepath.Join(dir, "revocations.json"), now: time.Now}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.doc = fileDoc{Version: 1, Generation: newGeneration()}
		return s, s.writeLocked()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.doc); err != nil || s.doc.Generation == "" {
		// A list that does not parse cannot be trusted to be complete:
		// refuse to start rather than forget revocations.
		return nil, fmt.Errorf("revocation: %s does not parse; move it aside to start an empty list", s.path)
	}
	return s, nil
}

func newGeneration() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SetClock replaces the clock (tests).
func (s *FileStore) SetClock(now func() time.Time) { s.now = now }

func (s *FileStore) maxTokens() int {
	if s.MaxTokensPerPerson > 0 {
		return s.MaxTokensPerPerson
	}
	return DefaultMaxTokensPerPerson
}

// Put adds e, and a token entry for each key in e.Also, in one write, and
// returns e with its sequence number. A token entry past the person's cap
// becomes a watermark at now for that person.
func (s *FileStore) Put(_ context.Context, e Entry) (Entry, error) {
	if e.Person == "" || (e.Token == "" && e.NotBefore.IsZero() && !e.Lift) {
		return Entry{}, errors.New("revocation: an entry names a person and a token, a time or a lift")
	}
	if len(e.Also) > 0 && e.Token == "" || len(e.Also) > maxAlso {
		return Entry{}, errors.New("revocation: also names at most 4 more tokens of a token entry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.purgeLocked(now)
	prev, prevSeq := append([]Entry(nil), s.doc.Entries...), s.doc.Seq
	also := e.Also
	e.Also, e.Overflow = nil, false
	e.At, e.Until = now, now.Add(Life)
	if e.Lift {
		kept := s.doc.Entries[:0]
		for _, x := range s.doc.Entries {
			if x.Person != e.Person || x.Token != "" || x.Overflow {
				kept = append(kept, x)
			}
		}
		s.doc.Entries = kept
	}
	out := s.addLocked(e, now)
	for _, k := range also {
		if k != "" && k != e.Token {
			x := e
			x.Token = k
			s.addLocked(x, now)
		}
	}
	if err := s.writeLocked(); err != nil {
		s.doc.Entries, s.doc.Seq = prev, prevSeq
		return Entry{}, err
	}
	return out, nil
}

// addLocked appends e with the next sequence number; a token entry past
// the person's cap becomes a watermark at now.
func (s *FileStore) addLocked(e Entry, now time.Time) Entry {
	if e.Token != "" {
		n := 0
		for _, x := range s.doc.Entries {
			if x.Person == e.Person && x.Token != "" {
				n++
			}
		}
		if n >= s.maxTokens() {
			e.Token, e.NotBefore, e.Overflow = "", Watermark(now), true
		}
	}
	s.doc.Seq++
	e.Seq = s.doc.Seq
	s.doc.Entries = append(s.doc.Entries, e)
	return e
}

// Since returns the entries after seq, or all of them when generation is
// not this store's.
func (s *FileStore) Since(_ context.Context, generation string, seq uint64) (Delta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(s.now())
	d := Delta{Generation: s.doc.Generation, Seq: s.doc.Seq, Full: generation != s.doc.Generation || seq > s.doc.Seq}
	for _, e := range s.doc.Entries {
		if d.Full || e.Seq > seq {
			d.Entries = append(d.Entries, e)
		}
	}
	return d, nil
}

func (s *FileStore) purgeLocked(now time.Time) {
	kept := s.doc.Entries[:0]
	for _, e := range s.doc.Entries {
		if now.Before(e.Until) {
			kept = append(kept, e)
		}
	}
	s.doc.Entries = kept
}

func (s *FileStore) writeLocked() error {
	b, err := json.Marshal(s.doc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".revocations-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// ---- leader RPC ----

type sinceIn struct {
	Generation string `json:"generation"`
	Seq        uint64 `json:"seq"`
}

// Serve registers the leader methods over s.
func Serve(srv *leader.Server, s *FileStore) {
	srv.Handle(leader.MethodRevocationPut, leader.Typed(func(ctx context.Context, e Entry) (Entry, error) {
		out, err := s.Put(ctx, e)
		if err != nil {
			return Entry{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return out, nil
	}))
	srv.HandleRead(leader.MethodRevocationSince, leader.Typed(func(ctx context.Context, in sinceIn) (Delta, error) {
		return s.Since(ctx, in.Generation, in.Seq)
	}))
}

// Source is where a replica reads and writes the list.
type Source interface {
	Put(ctx context.Context, e Entry) (Entry, error)
	Since(ctx context.Context, generation string, seq uint64) (Delta, error)
}

// Client is a Source over the leader RPC.
type Client struct{ Leader *leader.Client }

// Put implements Source.
func (c *Client) Put(ctx context.Context, e Entry) (Entry, error) {
	var out Entry
	err := c.Leader.Call(ctx, leader.MethodRevocationPut, leader.NewRequestID(), e, &out)
	return out, err
}

// Since implements Source.
func (c *Client) Since(ctx context.Context, generation string, seq uint64) (Delta, error) {
	var out Delta
	err := c.Leader.Call(ctx, leader.MethodRevocationSince, leader.NewRequestID(), sinceIn{generation, seq}, &out)
	return out, err
}

// ---- replica snapshot ----

// Snapshot is a replica's copy of the list. A nil *Snapshot is revocation
// off: Check accepts every token.
type Snapshot struct {
	// MaxStale is how long a replica answers after its last good pull.
	MaxStale time.Duration
	now      func() time.Time

	mu      sync.RWMutex
	loaded  bool
	synced  time.Time
	gen     string
	seq     uint64
	entries map[uint64]Entry
	// carried are the live entries of an earlier generation of the
	// leader's list, kept until they lapse (RV1-07), in sequence order.
	carried   []Entry
	tokens    map[string]time.Time // person NUL key -> until (tokenSlot)
	notBefore map[string]time.Time // person -> watermark (a lift removes it)
	overflow  map[string]time.Time // person -> watermark past the token cap (never lifted)
	onChange  []func()
	onReset   []func(kept int)
}

// NewSnapshot returns an empty, not yet loaded snapshot.
func NewSnapshot(maxStale time.Duration) *Snapshot {
	return &Snapshot{MaxStale: maxStale, now: time.Now, entries: map[uint64]Entry{}}
}

// SetClock replaces the clock (tests).
func (s *Snapshot) SetClock(now func() time.Time) { s.now = now }

// OnChange registers fn to run after a pull that brought new entries (the
// stream registry closes ended streams there).
func (s *Snapshot) OnChange(fn func()) {
	s.mu.Lock()
	s.onChange = append(s.onChange, fn)
	s.mu.Unlock()
}

// OnReset registers fn to run after a pull that found the leader's list
// reset (a new generation: its volume was recreated, or the file moved
// aside). kept is how many live entries this replica carries over.
func (s *Snapshot) OnReset(fn func(kept int)) {
	s.mu.Lock()
	s.onReset = append(s.onReset, fn)
	s.mu.Unlock()
}

// Cursor is the generation and sequence the next pull starts from.
func (s *Snapshot) Cursor() (string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gen, s.seq
}

// Apply merges a pull and marks the snapshot synced.
func (s *Snapshot) Apply(d Delta) {
	s.mu.Lock()
	now := s.now()
	changed := d.Full && len(s.entries) > 0
	reset := -1
	if d.Full && s.loaded && (d.Generation != s.gen || d.Seq < s.seq) {
		// The leader's list was reset: keep the ends this replica knew
		// until they lapse instead of dropping them without a word.
		old := make([]uint64, 0, len(s.entries))
		for q, e := range s.entries {
			if now.Before(e.Until) {
				old = append(old, q)
			}
		}
		sort.Slice(old, func(i, j int) bool { return old[i] < old[j] })
		for _, q := range old {
			s.carried = append(s.carried, s.entries[q])
		}
		reset = len(old)
	}
	if d.Full {
		s.entries = map[uint64]Entry{}
	}
	for _, e := range d.Entries {
		if _, ok := s.entries[e.Seq]; !ok {
			s.entries[e.Seq] = e
			changed = true
		}
	}
	s.gen, s.seq = d.Generation, d.Seq
	s.rebuildLocked(now)
	s.loaded, s.synced = true, now
	fns, resets := s.onChange, s.onReset
	s.mu.Unlock()
	if reset >= 0 {
		for _, fn := range resets {
			fn(reset)
		}
	}
	if changed {
		for _, fn := range fns {
			fn()
		}
	}
}

// rebuildLocked recomputes the lookup maps in sequence order, so a lift
// removes only the watermarks before it.
func (s *Snapshot) rebuildLocked(now time.Time) {
	seqs := make([]uint64, 0, len(s.entries))
	for q, e := range s.entries {
		if !now.Before(e.Until) {
			delete(s.entries, q)
			continue
		}
		seqs = append(seqs, q)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	carried := s.carried[:0]
	for _, e := range s.carried {
		if now.Before(e.Until) {
			carried = append(carried, e)
		}
	}
	s.carried = carried
	s.tokens, s.notBefore, s.overflow = map[string]time.Time{}, map[string]time.Time{}, map[string]time.Time{}
	apply := func(e Entry) {
		switch {
		case e.Lift:
			delete(s.notBefore, e.Person)
		case e.Token != "":
			if slot := tokenSlot(e.Person, e.Token); e.Until.After(s.tokens[slot]) {
				s.tokens[slot] = e.Until
			}
		case e.Overflow:
			if e.NotBefore.After(s.overflow[e.Person]) {
				s.overflow[e.Person] = e.NotBefore
			}
		case e.NotBefore.After(s.notBefore[e.Person]):
			s.notBefore[e.Person] = e.NotBefore
		}
	}
	// Carried entries are older than every entry of the current list.
	for _, e := range s.carried {
		apply(e)
	}
	for _, q := range seqs {
		apply(s.entries[q])
	}
}

// tokenSlot is where an ended token is looked up: the person who ended it
// and its key. A key is only unique within one person's tokens (a cluster
// JWT is keyed by its jti, which two issuers the cluster trusts can both
// use), so one person's end never refuses another person's token
// (RV3-03, GAP-0790).
func tokenSlot(person, key string) string { return person + "\x00" + key }

// Check reports whether a token of person, with key and issue time, may be
// used: nil, ErrEnded or ErrUnavailable (not loaded, or not synced within
// MaxStale). A nil snapshot accepts every token.
func (s *Snapshot) Check(person, key string, issuedAt time.Time) error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	if !s.loaded || (s.MaxStale > 0 && now.Sub(s.synced) > s.MaxStale) {
		return ErrUnavailable
	}
	if until, ok := s.tokens[tokenSlot(person, key)]; ok && key != "" && now.Before(until) {
		return ErrEnded
	}
	if nb, ok := s.notBefore[person]; ok && issuedAt.Before(nb) {
		return ErrEnded
	}
	if nb, ok := s.overflow[person]; ok && issuedAt.Before(nb) {
		return ErrEnded
	}
	return nil
}

// Active lists the live person-wide entries (admin revoke --list): the
// watermark in force for each person, and each overflow watermark
// (Overflow set), carried entries of an earlier list first.
func (s *Snapshot) Active() []Entry {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var cur []Entry
	for _, e := range s.entries {
		cur = append(cur, e)
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Seq < cur[j].Seq })
	var out []Entry
	seen := map[string]bool{}
	for _, e := range append(append([]Entry(nil), s.carried...), cur...) {
		if e.Token != "" || e.Lift {
			continue
		}
		m := s.notBefore
		if e.Overflow {
			m = s.overflow
		}
		k := e.Person + "\x00" + fmt.Sprint(e.Overflow)
		if nb, ok := m[e.Person]; ok && nb.Equal(e.NotBefore) && !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}

// Pull applies one pull from src now (a revoke reads its own write before it
// answers, instead of waiting for the next Sync tick).
func (s *Snapshot) Pull(ctx context.Context, src Source) error {
	gen, seq := s.Cursor()
	d, err := src.Since(ctx, gen, seq)
	if err != nil {
		return err
	}
	s.Apply(d)
	return nil
}

// Synced is when the last good pull was applied (zero before the first).
func (s *Snapshot) Synced() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.synced
}

// Sync pulls from src every interval until ctx ends. A failed pull keeps
// the last good list; Check refuses once it is older than MaxStale.
func (s *Snapshot) Sync(ctx context.Context, src Source, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, interval+5*time.Second)
		_ = s.Pull(pctx, src)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---- open streams ----

// Stream is who holds an open stream: the person's issuer#subject, the
// TokenKey of the sign-in it was opened with, and that token's issue time.
type Stream struct {
	Person   string
	TokenKey string
	IssuedAt time.Time
}

// Streams is a replica's registry of open streams (attach WebSockets and
// long polls, and any other long-lived per-person stream). A stream whose
// sign-in is ended is closed at once: its context is cancelled. A nil
// *Streams registers nothing (revocation off).
type Streams struct {
	snap *Snapshot

	mu     sync.Mutex
	next   uint64
	closed uint64
	open   map[uint64]openStream
}

type openStream struct {
	who    Stream
	cancel context.CancelFunc
}

// NewStreams returns a registry that closes streams snap says are ended.
func NewStreams(snap *Snapshot) *Streams {
	s := &Streams{snap: snap, open: map[uint64]openStream{}}
	snap.OnChange(func() { s.CloseEnded() })
	return s
}

// Open registers a stream of who and returns a context that is cancelled
// when who's sign-in is ended (or ctx ends), and the release to call when
// the stream closes. Run the stream under the returned context.
func (s *Streams) Open(ctx context.Context, who Stream) (context.Context, func()) {
	if s == nil {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.next++
	id := s.next
	s.open[id] = openStream{who: who, cancel: cancel}
	// A pull that ended who's sign-in between the caller's check and this
	// registration has already run CloseEnded: check again now that the
	// stream is registered (RV1-04).
	if errors.Is(s.snap.Check(who.Person, who.TokenKey, who.IssuedAt), ErrEnded) {
		delete(s.open, id)
		s.closed++
		cancel()
	}
	s.mu.Unlock()
	return ctx, func() {
		s.mu.Lock()
		delete(s.open, id)
		s.mu.Unlock()
		cancel()
	}
}

// CloseEnded closes every open stream whose sign-in is ended and returns
// how many it closed. A stale list closes nothing: staleness refuses new
// requests, it does not end work in progress.
func (s *Streams) CloseEnded() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, o := range s.open {
		if errors.Is(s.snap.Check(o.who.Person, o.who.TokenKey, o.who.IssuedAt), ErrEnded) {
			o.cancel()
			delete(s.open, id)
			n++
			s.closed++
		}
	}
	return n
}

// Closed is how many streams this registry has closed since it started; a
// revoke reports the difference across its pull.
func (s *Streams) Closed() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Count is the number of open streams (tests, doctor).
func (s *Streams) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.open)
}
