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
// it with a key in the OS keystore when one is usable; file keeps it in a
// file readable only by you, not encrypted.
const EnvStore = "DEFENSECLAW_VAULT_STORE"

// Keystore keeps a sealed vault's private key.
type Keystore interface {
	// Name is the keystore as people know it ("macOS Keychain").
	Name() string
	// ID is the keystore as a vault header names it.
	ID() string
	// Load returns the key, or nil, nil when the keystore has none. The
	// caller owns the returned slice and clears it after use.
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
	switch mode := strings.ToLower(strings.TrimSpace(os.Getenv(EnvStore))); mode {
	case "", "auto", "keychain":
		return osKeystore()
	case "file":
		return nil, EnvStore + "=file keeps the vault out of the OS keystore", nil
	default:
		return nil, "", fmt.Errorf("%s=%q is not known; use auto (the default) or file", EnvStore, mode)
	}
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
		return decodeKey(raw)
	case keystore.StatusItemNotFound:
		return nil, nil
	}
	return nil, errors.New(keystore.MacStatusReason(st))
}

func (m macKeychain) Save(keyID string, key []byte) error {
	st := m.k.Add(keyService, keyAccount(keyID), []byte(hex.EncodeToString(key)))
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
// person. An unused key item is harmless.
func (macKeychain) Delete(string) {}

// secretService keeps vault keys in the Secret Service through secret-tool.
type secretService struct{ t keystore.SecretTool }

func (secretService) Name() string { return keystoreName(keystoreSecretService) }
func (secretService) ID() string   { return keystoreSecretService }

func (s secretService) attrs(keyID string) []string {
	return []string{"service", keyService, "account", keyAccount(keyID)}
}

func (s secretService) Load(keyID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout)
	defer cancel()
	raw, found, err := s.t.Lookup(ctx, s.attrs(keyID)...)
	if err != nil {
		return nil, ctxError(ctx, err)
	}
	if !found {
		return nil, nil
	}
	return decodeKey(raw)
}

func (s secretService) Save(keyID string, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout)
	defer cancel()
	return ctxError(ctx, s.t.Store(ctx, keyLabel, []byte(hex.EncodeToString(key)), s.attrs(keyID)...))
}

func (s secretService) Delete(keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), keyTimeout)
	defer cancel()
	_ = s.t.Clear(ctx, s.attrs(keyID)...)
}

func ctxError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("the Secret Service did not answer within %s (it may be waiting to be unlocked)", keyTimeout)
	}
	return err
}

func decodeKey(raw []byte) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("the keystore item is not a vault key")
	}
	return key, nil
}
