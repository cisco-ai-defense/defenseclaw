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

// The pin. The gateway and the sandbox daemon seal captures to the public
// key in the vault header without the private key, so they cannot tell a
// header that a process rewrote (its own public key, key id or fingerprint
// salt) from the real one, nor a sealed vault that was replaced with a
// plain one. The pin is a digest of the header kept beside the vault
// directory, not in it: a process that writes no key first compares the
// vault with it and writes nothing into a vault that does not match (no
// value sealed to another key, no value in the clear).
//
// Who sets it: the CLI when it seals the vault, and when it read the
// private key and that key matches a header that has no pin yet (or one
// pinned on first use); otherwise the first writer that sees a sealed vault
// with no pin (trust on first use). A pin that differs from the header is
// only replaced by `vault list` (CheckPin), after every value opened with
// the key and every fingerprint matched the header's salt. A plain vault
// has no pin; the CLI removes it only when it is told to keep a plain vault
// (DEFENSECLAW_VAULT_STORE=file).
//
// What it does not stop: the pin is a file of the same account. A process
// running as that account can rewrite the vault and the pin together, as
// it can read the keychain while it is unlocked or run DefenseClaw itself
// (the threat model's same-account limit). It stops a change of the vault
// file alone: a header swapped in place, a sealed vault replaced with a
// plain or an older copy (a restore, a sync, a tool that writes only that
// file), and a sealed vault that was deleted.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// PinFileName is the vault pin, in the state directory that holds the
// vault directory.
const PinFileName = "vault-pin.json"

const (
	pinVersion  = 1
	maxPinBytes = 4 << 10
	pinDomain   = "defenseclaw-vault-pin-v1"

	// pinByKey: the CLI read the private key and it matches the header.
	pinByKey = "key"
	// pinByFirstUse: the first writer that saw the sealed vault pinned it.
	pinByFirstUse = "first-use"
)

var (
	// ErrVaultChanged is returned when the vault does not match its pin:
	// a writer that has not read the vault key writes nothing into it.
	ErrVaultChanged = errors.New("the vault changed since DefenseClaw pinned its seal")
	// ErrSealChanged: the sealed vault's header is not the pinned one.
	ErrSealChanged = fmt.Errorf("%w: its seal (public key, key id or fingerprint salt) is not the one DefenseClaw pinned", ErrVaultChanged)
	// ErrSealRemoved: a vault that was sealed is now a plain file or gone.
	ErrSealRemoved = fmt.Errorf("%w: it was sealed and is now a plain file or gone", ErrVaultChanged)
)

// pinRecord is the pin file.
type pinRecord struct {
	Version  int       `json:"version"`
	Keystore string    `json:"keystore"`
	KeyID    string    `json:"key_id"`
	Header   string    `json:"header_sha256"`
	By       string    `json:"by"`
	PinnedAt time.Time `json:"pinned_at"`
}

// pinState is how the vault compares with its pin.
type pinState int

const (
	// pinAbsent: no pin (a plain vault, or a sealed one not pinned yet).
	pinAbsent pinState = iota
	pinMatches
	// pinDiffers: a sealed vault whose header is not the pinned one (or
	// a pin that does not parse).
	pinDiffers
	// pinUnsealed: a pin, and the vault is a plain file or gone.
	pinUnsealed
)

// headerDigest is the pinned digest of a seal header: every field a
// writer without the key relies on.
func headerDigest(h sealHeader) string {
	m := sha256.New()
	for _, p := range []string{pinDomain, h.Keystore, h.KeyID, h.PublicKey, h.FPSalt} {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// PinPath is the vault pin: beside the vault directory, not in it, so a
// vault directory restored or copied in does not bring its own pin.
func (s *Store) PinPath() string { return filepath.Join(filepath.Dir(s.dir), PinFileName) }

var errPinDamaged = errors.New("the vault pin is not valid")

// readPin returns the pin, nil when there is none.
func (s *Store) readPin() (*pinRecord, error) {
	b, err := readStable(s.PinPath(), maxPinBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errPinDamaged
	}
	var p pinRecord
	if json.Unmarshal(b, &p) != nil || p.Version != pinVersion || !keyIDPattern.MatchString(p.KeyID) || len(p.Header) != sha256.Size*2 {
		return nil, errPinDamaged
	}
	return &p, nil
}

// comparePin says how f compares with its pin.
func (s *Store) comparePin(f *file) (pinState, *pinRecord) {
	p, err := s.readPin()
	switch {
	case err != nil && f.sealer == nil:
		return pinUnsealed, nil
	case err != nil:
		return pinDiffers, nil
	case p == nil:
		return pinAbsent, nil
	case f.sealer == nil:
		return pinUnsealed, p
	case p.Header == headerDigest(f.sealer.h):
		return pinMatches, p
	}
	return pinDiffers, p
}

func (s *Store) writePin(h sealHeader, by string) error {
	b, err := json.MarshalIndent(pinRecord{
		Version: pinVersion, Keystore: h.Keystore, KeyID: h.KeyID, Header: headerDigest(h), By: by, PinnedAt: s.now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return safefile.Write(s.PinPath(), append(b, '\n'))
}

func (s *Store) removePin() error {
	if err := os.Remove(s.PinPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// plainAllowed: this CLI was told to keep a plain vault, so a vault that
// was sealed may be written as a plain file (and loses its pin).
func (s *Store) plainAllowed() bool { return s.keys != nil && storeMode() == "file" }

func (s *Store) pinError(st pinState) error {
	if st == pinUnsealed {
		return fmt.Errorf("%w (%s); nothing is written into it until `sandbox vault list` seals it again with a key in your OS keystore, "+
			"or until %s=file says to keep a plain vault", ErrSealRemoved, s.Path(), EnvStore)
	}
	return fmt.Errorf("%w (%s); nothing is written into it until `sandbox vault list` checks it with your vault key", ErrSealChanged, s.Path())
}

// pinUpdate is what a write does to the pin once the vault is written.
type pinUpdate struct {
	write  bool
	by     string
	remove bool
	// resealed: a vault pinned sealed was found plain or gone, and this
	// change seals it again with a new key.
	resealed bool
}

// checkPin decides, under the writer lock, whether a change may write f
// (as read, before the change) and what it does to the pin. fresh: the
// change seals the plain (or missing) vault f with a new key. keyed: the
// writer read the private key and it matches f's header. A header that
// differs from the pin is refused even with the key: only CheckPin, which
// checks every value and fingerprint, pins a new header.
func (s *Store) checkPin(f *file, fresh, keyed bool) (pinUpdate, error) {
	st, p := s.comparePin(f)
	switch st {
	case pinDiffers:
		return pinUpdate{}, s.pinError(st)
	case pinUnsealed:
		switch {
		case fresh:
			return pinUpdate{write: true, by: pinByKey, resealed: true}, nil
		case s.plainAllowed():
			return pinUpdate{remove: true}, nil
		}
		return pinUpdate{}, s.pinError(st)
	case pinAbsent:
		switch {
		case fresh, f.sealer != nil && keyed:
			return pinUpdate{write: true, by: pinByKey}, nil
		case f.sealer != nil:
			return pinUpdate{write: true, by: pinByFirstUse}, nil
		}
	case pinMatches:
		if keyed && p.By != pinByKey {
			return pinUpdate{write: true, by: pinByKey}, nil
		}
	}
	return pinUpdate{}, nil
}

// apply records the pin of the vault as written. A pin that cannot be
// written is not an error: the next writer pins it on first use.
func (u pinUpdate) apply(s *Store, f *file) {
	switch {
	case u.write && f.sealer != nil:
		_ = s.writePin(f.sealer.h, u.by)
		if u.resealed {
			s.setNotice("the vault had been sealed and was found as a plain file or gone; it is sealed again with a new key " +
				"(check its entries: DefenseClaw did not write that plain file)")
		}
	case u.remove && f.sealer == nil:
		_ = s.removePin()
	}
}

// repin pins the vault's header once the CLI read the key and it matched
// (Resolve and the other reads that open values), when it has no pin or
// one pinned on first use: under the writer lock, and only while the
// vault still has that header. A pin that differs is left to CheckPin.
func (s *Store) repin(h sealHeader) {
	if !s.needsRepin(h) {
		return
	}
	unlock, err := lockDir(s.dir, lockWait)
	if err != nil {
		return
	}
	defer unlock()
	if f, err := s.read(); err == nil && f.sealer != nil && f.sealer.h == h && s.needsRepin(h) {
		_ = s.writePin(h, pinByKey)
	}
}

func (s *Store) needsRepin(h sealHeader) bool {
	p, err := s.readPin()
	switch {
	case err != nil:
		return false
	case p == nil:
		return true
	}
	return p.Header == headerDigest(h) && p.By != pinByKey
}

// pinChecked pins f's header after CheckPin opened every value with the
// key: under the writer lock, only while the vault still has that header.
func (s *Store) pinChecked(h sealHeader) error {
	unlock, err := lockDir(s.dir, lockWait)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.read()
	if err != nil {
		return err
	}
	if f.sealer == nil || f.sealer.h != h {
		return errors.New("the vault changed while DefenseClaw checked it; run the command again")
	}
	return s.writePin(h, pinByKey)
}

// verifyWithKey checks a sealed vault against its key: the key matches the
// public key, every value opens (which also binds the key id, the entry
// name and its host), and every fingerprint is the one of its value under
// the header's salt.
func (s *Store) verifyWithKey(f *file) error {
	if s.keys == nil {
		return fmt.Errorf("%w: this process does not read the vault key", ErrKeyUnavailable)
	}
	ks, why, err := s.keys()
	if err != nil {
		return err
	}
	if err := s.keyInto(f, ks, why); err != nil {
		return err
	}
	if err := s.openAll(f); err != nil {
		return err
	}
	for i := range f.Entries {
		r := &f.Entries[i]
		if r.FP != "" && r.FP != f.sealer.fingerprint(r.Value) {
			return s.damaged("its fingerprint salt is not the one its values were written with")
		}
	}
	return nil
}

// PinState says how the vault compares with the pin the gateway checks
// before it captures, for people: "" (nothing to say: matches, or a plain
// vault with no pin), "not pinned yet", "changed" (the sealed vault's
// header is not the pinned one) or "unsealed" (it was sealed and is now a
// plain file or gone). It reads no key.
func (s *Store) PinState() (string, error) {
	f, err := s.read()
	if err != nil {
		return "", err
	}
	return s.pinLabel(f), nil
}

func (s *Store) pinLabel(f *file) string {
	switch st, _ := s.comparePin(f); st {
	case pinAbsent:
		if f.sealer != nil {
			return "not pinned yet"
		}
	case pinDiffers:
		return "changed"
	case pinUnsealed:
		return "unsealed"
	}
	return ""
}

// CheckPin is `sandbox vault list`'s check of the pin: when the vault does
// not match it, a sealed vault is checked with the private key (and pinned
// again when the key matches), and a vault that is no longer sealed is
// sealed again when the keystore keeps a new key. note says what it did;
// err says why the vault stays refused (the list goes on). A vault that
// matches its pin is not touched and no key is read.
func (s *Store) CheckPin() (note string, err error) {
	if s.keys == nil {
		return "", nil
	}
	f, err := s.read()
	if err != nil {
		return "", nil
	}
	switch st, _ := s.comparePin(f); st {
	case pinDiffers:
		if err := s.verifyWithKey(f); err != nil {
			if errors.Is(err, ErrDamaged) {
				return "", fmt.Errorf("the vault %s does not match the seal DefenseClaw pinned, and it does not check out with your vault key (%v): "+
					"the file was changed. Sandboxes capture nothing into it. Move it aside and add your secrets again", s.Path(), err)
			}
			return "", fmt.Errorf("the vault %s does not match the seal DefenseClaw pinned, and DefenseClaw cannot check it with your vault key here (%v), "+
				"so sandboxes capture nothing into it; run this command where your keystore can be read", s.Path(), err)
		}
		if err := s.pinChecked(f.sealer.h); err != nil {
			return "", fmt.Errorf("the vault %s matches your vault key, but its pin could not be written (%v), so sandboxes capture nothing into it", s.Path(), err)
		}
		return "the vault's seal matches your vault key: it is pinned again and sandboxes capture into it again", nil
	case pinUnsealed:
		if s.plainAllowed() {
			if err := s.update(needNothing, func(*file) error { return nil }); err != nil {
				return "", err
			}
			return "the vault had been sealed and is now a plain file; " + EnvStore + "=file keeps it so, and sandboxes capture into it as a plain file", nil
		}
		if err := s.Seal(); err != nil {
			return "", fmt.Errorf("the vault %s had been sealed and is now a plain file or gone; it could not be sealed again (%v), so sandboxes capture nothing into it", s.Path(), err)
		}
		if g, err := s.read(); err == nil && g.sealer != nil && s.pinLabel(g) == "" {
			return "the vault had been sealed and was found as a plain file or gone; it is sealed again with a new key " +
				"(check its entries: DefenseClaw did not write that plain file)", nil
		}
		return "", fmt.Errorf("the vault %s had been sealed and is now a plain file or gone; sandboxes capture nothing into it until it is sealed again: "+
			"run this command where your OS keystore can be read, or set %s=file to keep a plain vault", s.Path(), EnvStore)
	}
	return "", nil
}
