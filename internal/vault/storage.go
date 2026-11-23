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

package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrKeyUnavailable is returned when a change or a read needs a
	// sealed vault's values and its key cannot be read here.
	ErrKeyUnavailable = errors.New("the vault key cannot be read")
	// ErrDamaged is returned for a sealed vault DefenseClaw cannot trust:
	// it is never written over.
	ErrDamaged = errors.New("the sealed vault is damaged")
)

// Storage says how the vault is kept, for people.
type Storage struct {
	// Mode is "sealed" or "file".
	Mode string `json:"mode"`
	// Keystore is where a sealed vault's key is ("macOS Keychain").
	Keystore string `json:"keystore,omitempty"`
	// Label is the one line people see.
	Label string `json:"label"`
	// Note says why a file vault is not sealed, or when it will be.
	Note string `json:"note,omitempty"`
	// Pin is how the vault compares with the seal the gateway and the
	// sandbox daemon pinned (PinState): "" when it matches.
	Pin string `json:"pin,omitempty"`
}

// StorageFileLabel is the label of a vault kept as a plain file.
const StorageFileLabel = "file (owner-only, not encrypted)"

// Storage says how the vault is kept now. It reads no key.
func (s *Store) Storage() (Storage, error) {
	f, err := s.read()
	if err != nil {
		return Storage{}, err
	}
	st, err := s.storageOf(f)
	if err != nil {
		return st, err
	}
	switch st.Pin = s.pinLabel(f); st.Pin {
	case "changed":
		st.Note = joinNote(st.Note, "sandboxes capture nothing into this vault: its seal is not the one DefenseClaw pinned "+
			"(the file was changed, or replaced with another vault)")
	case "unsealed":
		st.Note = joinNote(st.Note, "sandboxes capture nothing into this vault: it had been sealed and is now a plain file")
	}
	return st, nil
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func (s *Store) storageOf(f *file) (Storage, error) {
	if f.sealer != nil {
		name := keystoreName(f.sealer.h.Keystore)
		st := Storage{Mode: "sealed", Keystore: name, Label: "sealed (" + name + ")"}
		if s.keys != nil {
			ks, why, err := s.keys()
			switch {
			case err != nil:
				st.Note = err.Error()
			case ks == nil:
				st.Note = "this session does not read the vault key (" + why + "), so commands that need its values " +
					"(add, replace, bind, rename, run --vault) fail; the vault stays sealed"
			}
		}
		return st, nil
	}
	st := Storage{Mode: "file", Label: StorageFileLabel}
	if s.keys != nil {
		ks, why, err := s.keys()
		switch {
		case err != nil:
			st.Note = err.Error()
		case ks == nil:
			st.Note = why
		default:
			st.Note = fmt.Sprintf("the next change seals it with a key in your %s, if DefenseClaw can use it then", ks.Name())
		}
	}
	return st, nil
}

func (s *Store) damaged(why string) error {
	return fmt.Errorf("%w: %s (%s); DefenseClaw will not change it: move it aside to start a new one", ErrDamaged, s.Path(), why)
}

// readKey reads a sealed vault's private key into f.
func (s *Store) readKey(f *file) error {
	if s.keys == nil {
		return fmt.Errorf("%w: the vault %s is sealed and this process does not read its key", ErrKeyUnavailable, s.Path())
	}
	ks, why, err := s.keys()
	if err != nil {
		return err
	}
	if err := s.keyInto(f, ks, why); err != nil {
		return err
	}
	s.repin(f.sealer.h)
	return nil
}

func (s *Store) keyInto(f *file, ks Keystore, why string) error {
	s.mu.Lock()
	cached := s.key
	s.mu.Unlock()
	if cached != nil && cached.h == f.sealer.h {
		f.sealer.priv = cached.priv
		return nil
	}
	name := keystoreName(f.sealer.h.Keystore)
	if ks == nil {
		return fmt.Errorf("%w: the vault %s is sealed with a key in your %s, and %s", ErrKeyUnavailable, s.Path(), name, why)
	}
	if ks.ID() != f.sealer.h.Keystore {
		return fmt.Errorf("%w: the vault %s is sealed with a key in your %s, which this system does not use", ErrKeyUnavailable, s.Path(), name)
	}
	raw, err := ks.Load(f.sealer.h.KeyID)
	if err != nil {
		return fmt.Errorf("%w: the vault %s is sealed with a key in your %s, which cannot be read here: %v", ErrKeyUnavailable, s.Path(), name, err)
	}
	if raw == nil {
		return fmt.Errorf("%w: the vault %s is sealed, but its key is not in your %s (it was removed, or the vault came from another account or computer), so its values cannot be opened; move the file aside and add the secrets again", ErrKeyUnavailable, s.Path(), name)
	}
	defer clear(raw)
	if err := f.sealer.withKey(raw); err != nil {
		return s.damaged(err.Error())
	}
	s.mu.Lock()
	s.key = f.sealer
	s.mu.Unlock()
	return nil
}

// openAll opens every sealed value of f (its key read).
func (s *Store) openAll(f *file) error {
	for i := range f.Entries {
		r := &f.Entries[i]
		if r.Value != "" {
			continue
		}
		v, err := f.sealer.open(r)
		if err != nil {
			return s.damaged(err.Error())
		}
		r.Value = v
	}
	return nil
}

// prepared is the keystore work of one change, done before the lock.
type prepared struct {
	s *Store
	// ks and sealer: the keystore and the key a file vault is sealed with
	// by this change (fresh), or the sealed vault's key (needValues).
	ks     Keystore
	sealer *sealer
	fresh  bool
	// why a file vault stays a file ("" for a store that never seals).
	why string
}

func (s *Store) prepare(n need, change func(*file) error) (*prepared, error) {
	p := &prepared{s: s}
	if s.keys == nil {
		return p, nil
	}
	ks, why, err := s.keys()
	if err != nil {
		return nil, err
	}
	cur, err := s.read()
	if err != nil {
		return nil, err
	}
	if cur.sealer != nil {
		if n == needValues {
			if err := s.keyInto(cur, ks, why); err != nil {
				return nil, err
			}
			p.sealer = cur.sealer
		}
		return p, nil
	}
	if ks == nil {
		p.why = why
		return p, nil
	}
	// A file vault and a keystore: this change seals it. A change that
	// fails on what was just read makes no key.
	if change(cur) != nil {
		return p, nil
	}
	sl, raw, err := newSealer(ks.ID())
	if err != nil {
		return p.fileOnly(ks, err.Error())
	}
	defer clear(raw)
	if err := ks.Save(sl.h.KeyID, raw); err != nil {
		return p.fileOnly(ks, fmt.Sprintf("your %s could not keep the vault key: %v", ks.Name(), err))
	}
	got, err := ks.Load(sl.h.KeyID)
	same := err == nil && bytes.Equal(got, raw)
	clear(got)
	if !same {
		ks.Delete(sl.h.KeyID)
		why := fmt.Sprintf("your %s did not give the vault key back", ks.Name())
		if err != nil {
			why += ": " + err.Error()
		}
		return p.fileOnly(ks, why)
	}
	p.ks, p.sealer, p.fresh = ks, sl, true
	return p, nil
}

// fileOnly keeps a file vault a file for why, or fails the change when
// EnvStore=keychain asks for a sealed vault.
func (p *prepared) fileOnly(ks Keystore, why string) (*prepared, error) {
	if isRequired(ks) {
		return nil, fmt.Errorf("%w: the vault is not changed: %s=keychain asks for a sealed vault, and %s", ErrStoreSetting, EnvStore, why)
	}
	p.why = why
	return p, nil
}

// Seal seals a file vault now (an empty one is made when there is none)
// when this store reads the keystore and the keystore keeps a new key. The
// gateway and the sandbox daemon never read the keystore and keep a file
// vault a file, so the CLI seals it before a sandbox can capture into it.
// It reads no sealed value and no key: a sealed vault is left as it is.
// Without a usable keystore nothing is written and Notice stays empty; when
// a keystore fails to keep the key, Notice says why the vault stays a file.
func (s *Store) Seal() error {
	if s.keys == nil {
		return nil
	}
	f, err := s.read()
	if err != nil {
		return err
	}
	if f.sealer != nil {
		return nil
	}
	ks, _, err := s.keys()
	if err != nil || ks == nil {
		return err
	}
	return s.update(needSeal, func(*file) error { return nil })
}

// apply fits the prepared key to the vault as read under the lock.
func (p *prepared) apply(f *file, n need) error {
	s := p.s
	switch {
	case f.sealer == nil && p.fresh:
		// Every value of a file vault is known: all are sealed at write.
		f.sealer = p.sealer
		return nil
	case f.sealer == nil:
		return nil
	case p.fresh:
		// Another process sealed the vault since it was read.
		p.discard()
		p.sealer = nil
		if n == needValues {
			return errors.New("another DefenseClaw process sealed the vault meanwhile; run the command again")
		}
		return nil
	case n == needValues:
		if s.keys == nil {
			return s.readKey(f)
		}
		if p.sealer == nil || p.sealer.h != f.sealer.h {
			return errors.New("the vault changed while DefenseClaw read its key; run the command again")
		}
		f.sealer = p.sealer
		return s.openAll(f)
	}
	return nil
}

// discard deletes a key made for a change that was not written.
func (p *prepared) discard() {
	if p.fresh {
		p.ks.Delete(p.sealer.h.KeyID)
		p.fresh = false
	}
}

func (p *prepared) done(f *file) {
	switch {
	case p.fresh:
		p.s.mu.Lock()
		p.s.key = p.sealer
		p.s.mu.Unlock()
		p.s.setNotice(fmt.Sprintf("the vault is now sealed: its values are encrypted with a key kept in your %s", p.ks.Name()))
	case f.sealer == nil && p.why != "":
		p.s.setNotice("the vault is a file readable only by you, not encrypted: " + p.why)
	}
}

// encode is the vault as written: a file vault with its values, a sealed
// vault with sealed values only. A sealed vault is never written as a file.
func (s *Store) encode(f *file) ([]byte, error) {
	out := file{Version: fileVersion, Entries: make([]record, 0, len(f.Entries))}
	if f.sealer == nil {
		for _, r := range f.Entries {
			if r.Value == "" {
				return nil, fmt.Errorf("the secret %s has no value", r.Name)
			}
			out.Entries = append(out.Entries, record{Entry: r.Entry, Value: r.Value})
		}
		return json.MarshalIndent(out, "", "  ")
	}
	h := f.sealer.h
	out.Version, out.Seal = sealedVersion, &h
	for i := range f.Entries {
		r := &f.Entries[i]
		rec := record{Entry: r.Entry}
		switch {
		case r.Value != "":
			sealed, err := f.sealer.seal(r)
			if err != nil {
				return nil, err
			}
			rec.Sealed = sealed
			if wantsFingerprint(r) {
				rec.FP = f.sealer.fingerprint(r.Value)
			}
		case r.Sealed != "" && r.sealedFor == f.sealer.infoOf(r):
			rec.Sealed, rec.FP = r.Sealed, r.FP
		default:
			return nil, fmt.Errorf("%w: the secret %s cannot be renamed or bound to a host without the vault key", ErrKeyUnavailable, r.Name)
		}
		out.Entries = append(out.Entries, rec)
	}
	return json.MarshalIndent(out, "", "  ")
}
