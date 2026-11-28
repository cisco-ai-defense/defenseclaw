// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Pending exposures. A capture that could not write the vault (its lock
// was busy, or the write failed) cannot mark the values the model saw
// exposed in it. It records each such value as a pending exposure
// instead: one small file per value in the vault's exposed-pending
// directory, written without the vault lock. Every read of the vault
// applies them: an entry a pending exposure names reads as exposed (list,
// show, capture), Resolve refuses its value, and the next change of the
// vault writes the exposure into the vault and removes the record. A
// value the vault does not hold yet is exposed when a later change stores
// it. So a sandbox never gets a value an agent or the audit log was told
// is exposed, even when the vault was busy at that moment.
//
// A record holds an HMAC of the value under a random salt of its own,
// never the value; in a sealed vault also the value's fingerprint, so a
// writer without the vault key (the gateway, the sandbox daemon) applies
// it.

const (
	pendingDirName = "exposed-pending"
	// MaxPendingExposures bounds the pending exposures a capture adds;
	// maxPendingPerCall bounds what one call writes on the hook path.
	MaxPendingExposures = 64
	maxPendingPerCall   = 16
	// maxPendingRead: past this many records (concurrent writers can pass
	// MaxPendingExposures a little) the vault is not read at all: a record
	// is never skipped.
	maxPendingRead  = 1024
	maxPendingBytes = 4 << 10
	pendingVersion  = 1
	pendingDomain   = "defenseclaw-vault-pending-exposure-v1"
	// pendingKeep is how long a record that names no entry is kept for a
	// value a later capture may store.
	pendingKeep = 30 * 24 * time.Hour
)

var (
	// ErrExposurePending: the vault was not written, and the values the
	// call exposed are recorded as pending exposures.
	ErrExposurePending = errors.New("the exposure is recorded as pending: no sandbox gets the value, and the next change of the vault writes it")
	// ErrExposureNotRecorded: the vault was not written, and the exposure
	// could not be recorded either.
	ErrExposureNotRecorded = errors.New("the exposure could not be recorded")
)

type pendingRecord struct {
	Version int       `json:"version"`
	Salt    string    `json:"salt"`
	MAC     string    `json:"mac"`
	FP      string    `json:"fp,omitempty"`
	At      time.Time `json:"at"`

	salt []byte
	path string
}

// pendingState is what the pending exposures did to a vault as read.
type pendingState struct {
	// open are the records that named no entry when the vault was read.
	open []*pendingRecord
	// done are the record files a write of this vault makes obsolete.
	done []string
	// changed: a record marked an entry exposed that the file does not.
	changed bool
}

func pendingMAC(salt []byte, value string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(pendingDomain))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

func (p *pendingRecord) matchesValue(value string) bool {
	return value != "" && subtle.ConstantTimeCompare([]byte(pendingMAC(p.salt, value)), []byte(p.MAC)) == 1
}

func (p *pendingRecord) matches(r *record) bool {
	switch {
	case r.Value != "":
		return p.matchesValue(r.Value)
	case p.FP != "" && r.FP != "":
		return subtle.ConstantTimeCompare([]byte(p.FP), []byte(r.FP)) == 1
	}
	return false
}

func (s *Store) pendingDir() string { return filepath.Join(s.dir, pendingDirName) }

// readPending returns the pending exposures, oldest first. It fails
// closed: a record that cannot be read or does not parse, or more than
// maxPendingRead of them, is an error (every read of the vault then
// fails, so no value is handed out past an exposure it skipped). Only a
// record removed meanwhile is skipped.
func (s *Store) readPending() ([]*pendingRecord, error) {
	ents, err := os.ReadDir(s.pendingDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the vault's pending exposures: %w", err)
	}
	if len(ents) > maxPendingRead {
		return nil, fmt.Errorf("the vault's pending exposures (%s) hold %d files, more than DefenseClaw reads; "+
			"rotate the secrets your sandboxes captured, then remove that folder", s.pendingDir(), len(ents))
	}
	var out []*pendingRecord
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			// safefile's temporary file of a record being written.
			continue
		}
		path := filepath.Join(s.pendingDir(), name)
		bad := func(why string) error {
			return fmt.Errorf("the vault's pending exposure %s %s; rotate the secrets your sandboxes captured, then remove it", path, why)
		}
		if !strings.HasSuffix(name, ".json") || !e.Type().IsRegular() {
			return nil, bad("is not a record")
		}
		b, err := safefile.ReadRegularFileBounded(path, maxPendingBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, bad("cannot be read: " + err.Error())
		}
		var p pendingRecord
		if json.Unmarshal(b, &p) != nil || p.Version != pendingVersion || p.MAC == "" {
			return nil, bad("is not valid")
		}
		salt, err := base64.RawStdEncoding.DecodeString(p.Salt)
		if err != nil || len(salt) < 16 {
			return nil, bad("is not valid")
		}
		p.salt, p.path = salt, path
		out = append(out, &p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// recordPending records values as pending exposures, one file each,
// without the vault lock; a value a record already names is skipped. f is
// the vault as last read (nil when unread): in a sealed vault the record
// also holds the value's fingerprint.
func (s *Store) recordPending(f *file, values []string) error {
	if len(values) > maxPendingPerCall {
		return fmt.Errorf("%d exposed values in one call; at most %d are recorded", len(values), maxPendingPerCall)
	}
	have, err := s.readPending()
	if err != nil {
		return err
	}
	if err := safefile.ProtectDirectory(s.dir); err != nil {
		return err
	}
	if err := safefile.ProtectDirectory(s.pendingDir()); err != nil {
		return err
	}
next:
	for _, v := range values {
		for _, p := range have {
			// A record past half its keep is written again, so a value
			// exposed again is kept for the full time.
			if p.matchesValue(v) && s.now().Sub(p.At) < pendingKeep/2 {
				continue next
			}
		}
		if len(have) >= MaxPendingExposures {
			return fmt.Errorf("%d exposures are already waiting for the vault to be written", MaxPendingExposures)
		}
		salt := make([]byte, 32)
		id := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		if _, err := rand.Read(id); err != nil {
			return err
		}
		p := &pendingRecord{Version: pendingVersion, Salt: base64.RawStdEncoding.EncodeToString(salt),
			MAC: pendingMAC(salt, v), At: s.now().UTC(), salt: salt}
		if f != nil && f.sealer != nil {
			p.FP = f.sealer.fingerprint(v)
		}
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		p.path = filepath.Join(s.pendingDir(), hex.EncodeToString(id)+".json")
		if err := safefile.Write(p.path, append(b, '\n')); err != nil {
			return fmt.Errorf("write a pending exposure: %w", err)
		}
		have = append(have, p)
	}
	return nil
}

// applyPending marks the entries of f that a pending exposure names
// exposed (in f only) and keeps what a write of f has to do.
func (s *Store) applyPending(f *file) error {
	recs, err := s.readPending()
	if err != nil {
		return err
	}
	f.pending = pendingState{}
	now := s.now()
	for _, p := range recs {
		hit := false
		for i := range f.Entries {
			if r := &f.Entries[i]; p.matches(r) {
				hit = true
				if !r.Exposed {
					r.Exposed = true
					f.pending.changed = true
				}
			}
		}
		switch {
		case hit:
			f.pending.done = append(f.pending.done, p.path)
		case now.Sub(p.At) > pendingKeep && (p.FP != "" || f.sealer == nil):
			// Expired. A record without a fingerprint in a sealed vault is
			// kept: only a reader that opens the values can match it.
			f.pending.done = append(f.pending.done, p.path)
		default:
			f.pending.open = append(f.pending.open, p)
		}
	}
	return nil
}

// applyOpenPending marks an entry a change stored exposed when an open
// pending exposure names its value.
func (f *file) applyOpenPending() {
	open := f.pending.open[:0:0]
	for _, p := range f.pending.open {
		hit := false
		for i := range f.Entries {
			if r := &f.Entries[i]; p.matches(r) {
				hit = true
				if !r.Exposed {
					r.Exposed = true
					f.pending.changed = true
				}
			}
		}
		if hit {
			f.pending.done = append(f.pending.done, p.path)
		} else {
			open = append(open, p)
		}
	}
	f.pending.open = open
}

// pendingExposes reports whether an open pending exposure names value.
func (f *file) pendingExposes(value string) bool {
	for _, p := range f.pending.open {
		if p.matchesValue(value) {
			return true
		}
	}
	return false
}

// dropPending removes the records a write of f made obsolete: under the
// writer lock, once f is on disk.
func (s *Store) dropPending(f *file) {
	for _, path := range f.pending.done {
		_ = os.Remove(path)
	}
	f.pending.done = nil
}

// ApplyPendingExposures writes the pending exposures that name an entry
// into the vault (and removes their records, and expired ones), waiting at
// most wait for the vault lock. With none, it neither locks nor writes.
func (s *Store) ApplyPendingExposures(wait time.Duration) error {
	f, err := s.read()
	if err != nil {
		return err
	}
	if !f.pending.changed && len(f.pending.done) == 0 {
		return nil
	}
	return s.updateWait(wait, needNothing, func(*file) error { return errUnchanged })
}
