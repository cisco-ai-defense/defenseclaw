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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/keystore"
)

// EnvStore selects where the CLI keeps the vault: auto (the default) seals
// it with a key in the OS keystore when one is usable; keychain asks for a
// sealed vault and fails a change that cannot seal; file keeps it in a file
// readable only by you, not encrypted.
const EnvStore = "DEFENSECLAW_VAULT_STORE"

// ErrStoreSetting is returned when EnvStore cannot be honoured: a value
// that is not known, or keychain with no keystore that keeps the key.
var ErrStoreSetting = errors.New("the vault storage setting cannot be used")

// Keystore keeps a sealed vault's private key.
type Keystore interface {
	// Name is the keystore as people know it ("macOS Keychain").
	Name() string
	// ID is the keystore as a vault header names it.
	ID() string
	// Load returns the key, or nil, nil only when the keystore positively
	// has none (a keystore that cannot tell a missing key from a locked
	// one returns an error). The caller owns the slice and clears it.
	Load(keyID string) ([]byte, error)
	// Save keeps a new key.
	Save(keyID string, key []byte) error
	// Delete removes a key that was never used (best effort).
	Delete(keyID string)
}

const (
	keystoreMac           = "macos-keychain"
	keystoreSecretService = "secret-service"

	keyService = "defenseclaw-vault"
	keyLabel   = "DefenseClaw sandbox vault key"

	// keyTimeout bounds one Secret Service call (a CLI call only).
	keyTimeout = 15 * time.Second
)

// keystoreName is a keystore ID as people know it; "" for an unknown ID.
func keystoreName(id string) string {
	switch id {
	case keystoreMac:
		return "macOS Keychain"
	case keystoreSecretService:
		return "Secret Service"
	}
	return ""
}

func keyAccount(keyID string) string { return "vault-" + keyID }

// keysFromEnv is the keystore EnvStore selects: ks nil with why when the
// vault stays a file; err for a value that is not known.
func keysFromEnv() (ks Keystore, why string, err error) {
	switch mode := storeMode(); mode {
	case "", "auto":
		return osKeystore()
	case "keychain":
		ks, why, err := osKeystore()
		if err != nil {
			return nil, "", err
		}
		if ks == nil {
			return nil, "", fmt.Errorf("%w: %s=keychain asks for a sealed vault, and %s; unset it to keep the vault in a file readable only by you",
				ErrStoreSetting, EnvStore, why)
		}
		return required{ks}, "", nil
	case "file":
		return nil, EnvStore + "=file keeps the vault out of the OS keystore", nil
	default:
		return nil, "", fmt.Errorf("%w: %s=%q is not known; use auto (the default), keychain or file", ErrStoreSetting, EnvStore, mode)
	}
}

func storeMode() string { return strings.ToLower(strings.TrimSpace(os.Getenv(EnvStore))) }

// Required reports whether EnvStore=keychain asks for a sealed vault: a
// command that cannot seal it then fails, whatever the reason.
func Required() bool { return storeMode() == "keychain" }

// required is the keystore EnvStore=keychain asks for: a change that cannot
// seal the vault with it fails instead of keeping a file.
type required struct{ Keystore }

func isRequired(ks Keystore) bool {
	_, ok := ks.(required)
	return ok
}

// hexKey is a key as a keystore item holds it; the caller clears it.
func hexKey(key []byte) []byte {
	b := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(b, key)
	return b
}

// macKeychain keeps vault keys as generic passwords of the default macOS
// keychain, written with the Security framework: the item trusts the
// DefenseClaw binary that made it, so the CLI reads it without a prompt,
// also over SSH while the keychain is unlocked.
type macKeychain struct{ k keystore.Keychain }

func (macKeychain) Name() string { return keystoreName(keystoreMac) }
func (macKeychain) ID() string   { return keystoreMac }

func (m macKeychain) Load(keyID string) ([]byte, error) {
	raw, st := m.k.Find(keyService, keyAccount(keyID))
	switch st {
	case 0:
		defer clear(raw)
		return decodeKey(raw)
	case keystore.StatusItemNotFound:
		return nil, nil
	}
	return nil, errors.New(keystore.MacStatusReason(st))
}

func (m macKeychain) Save(keyID string, key []byte) error {
	enc := hexKey(key)
	defer clear(enc)
	st := m.k.Add(keyService, keyAccount(keyID), enc)
	if st == 0 {
		return nil
	}
	if st == keystore.StatusDuplicateItem {
		return errors.New("the macOS keychain already holds an item for this vault key")
	}
	return errors.New(keystore.MacStatusReason(st))
}

// Delete is a no-op on macOS: removing an item needs an item reference the
// two framework calls do not give, and the security tool would ask the
// person. A key made for a change that was not written stays in the
// keychain as an unused item (service defenseclaw-vault, account
// vault-<key id>): it opens nothing without the vault it was made for, and
// Keychain Access deletes it.
func (macKeychain) Delete(string) {}

// secretService keeps vault keys in the Secret Service through secret-tool.
type secretService struct {
	t keystore.SecretTool
	// timeout bounds one call (0: keyTimeout).
	timeout time.Duration
}

func (s secretService) within(d time.Duration) Keystore {
	s.timeout = d
	return s
}

func (s secretService) limit() time.Duration {
	if s.timeout > 0 {
		return s.timeout
	}
	return keyTimeout
}

func (secretService) Name() string { return keystoreName(keystoreSecretService) }
func (secretService) ID() string   { return keystoreSecretService }

func (s secretService) attrs(keyID string) []string {
	return []string{"service", keyService, "account", keyAccount(keyID)}
}

func (s secretService) Load(keyID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.limit())
	defer cancel()
	raw, found, err := s.t.Lookup(ctx, s.attrs(keyID)...)
	if err != nil {
		return nil, s.ctxError(ctx, err)
	}
	if !found {
		// secret-tool answers a locked keyring whose unlock was dismissed
		// as it answers a missing item, so the key is never reported gone
		// from here: a vault whose key is only locked away stays usable.
		if listed, lerr := s.t.Listed(ctx, s.attrs(keyID)...); lerr == nil && listed {
			return nil, errors.New("the Secret Service holds the vault key, but the keyring is locked or its unlock was dismissed; " +
				"unlock it (log in to your desktop session, or unlock the login keyring) and run the command again")
		}
		return nil, errors.New("the Secret Service gave no vault key: it is not found, or the keyring is locked or its unlock was dismissed; " +
			"unlock the keyring (log in to your desktop session) and run the command again")
	}
	defer clear(raw)
	return decodeKey(raw)
}

func (s secretService) Save(keyID string, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.limit())
	defer cancel()
	enc := hexKey(key)
	defer clear(enc)
	return s.ctxError(ctx, s.t.Store(ctx, keyLabel, enc, s.attrs(keyID)...))
}

func (s secretService) Delete(keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.limit())
	defer cancel()
	_ = s.t.Clear(ctx, s.attrs(keyID)...)
}

func (s secretService) ctxError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("the Secret Service did not answer within %s (it may be waiting to be unlocked)", s.limit())
	}
	return err
}

// decodeKey decodes a keystore item into a new slice; raw is the caller's
// to clear.
func decodeKey(raw []byte) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	key := make([]byte, hex.DecodedLen(len(raw)))
	n, err := hex.Decode(key, raw)
	if err != nil || n != 32 {
		clear(key)
		return nil, errors.New("the keystore item is not a vault key")
	}
	return key, nil
}
