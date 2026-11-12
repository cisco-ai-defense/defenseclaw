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

package auth

// The command-line keychain backends live here, untagged, so their
// command lines are unit-tested on every OS through an injected runner.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	macKeyAccount = "token-key"
	macKeyLabel   = "defenseclaw-substrate-token-key"
	macNotFound   = 44 // errSecItemNotFound as the security tool exits
	sealMagic     = "DCS1"
)

// macKeySealer seals sign-ins with AES-256-GCM under a random key kept as
// a generic password in the macOS login keychain. The key is written by
// "security -i" with the command on stdin, so it never appears in a
// process list; the tokens themselves never pass through the security
// tool. Limit: a locked keychain (an SSH session with no unlocked login
// keychain) makes the security tool fail; the error says so.
type macKeySealer struct {
	run      cmdRunner
	security string

	mu  sync.Mutex
	key []byte
}

func newMacStore(run cmdRunner, security, dir string) *sealedStore {
	return &sealedStore{
		dir:  dir,
		s:    &macKeySealer{run: run, security: security},
		desc: fmt.Sprintf("macOS Keychain (service %s) with sealed files in %s", keychainService, dir),
	}
}

func macError(what string, exit int, stderr string) error {
	msg := fmt.Sprintf("the macOS keychain could not %s (security exit %d", what, exit)
	if l := firstLine(stderr); l != "" {
		msg += ": " + l
	}
	msg += "); unlock it with: security unlock-keychain"
	return noKeychain(msg)
}

func (m *macKeySealer) findKey(ctx context.Context) ([]byte, error) {
	out, stderr, exit, err := m.run(ctx, nil, m.security, "find-generic-password", "-s", keychainService, "-a", macKeyAccount, "-w")
	if err != nil {
		return nil, noKeychain("the macOS keychain cannot be used: " + err.Error())
	}
	switch exit {
	case 0:
		key, derr := hex.DecodeString(strings.TrimSpace(string(out)))
		if derr != nil || len(key) != 32 {
			return nil, fmt.Errorf("the keychain item %s/%s is not a DefenseClaw key; delete it with: security delete-generic-password -s %s -a %s", keychainService, macKeyAccount, keychainService, macKeyAccount)
		}
		return key, nil
	case macNotFound:
		return nil, nil
	default:
		return nil, macError("read the DefenseClaw key", exit, stderr)
	}
}

// getKey returns the key; create makes and stores one when it is missing.
func (m *macKeySealer) getKey(create bool) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key != nil {
		return m.key, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	key, err := m.findKey(ctx)
	if err != nil || key != nil || !create {
		m.key = key
		return key, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -w %s\n", keychainService, macKeyAccount, macKeyLabel, hex.EncodeToString(key))
	_, stderr, exit, err := m.run(ctx, []byte(line), m.security, "-i")
	if err != nil {
		return nil, noKeychain("the macOS keychain cannot be used: " + err.Error())
	}
	if exit != 0 || strings.TrimSpace(stderr) != "" {
		return nil, macError("store the DefenseClaw key", exit, stderr)
	}
	// "security -i" may exit 0 after a failed command: read the key back.
	got, err := m.findKey(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, key) {
		return nil, macError("store the DefenseClaw key", exit, "the key read back does not match")
	}
	m.key = key
	return key, nil
}

func (m *macKeySealer) seal(name string, plain []byte) ([]byte, error) {
	key, err := m.getKey(true)
	if err != nil {
		return nil, err
	}
	return gcmSeal(key, name, plain)
}

func (m *macKeySealer) open(name string, sealed []byte) ([]byte, error) {
	key, err := m.getKey(false)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errors.New("its key is missing from the macOS keychain")
	}
	return gcmOpen(key, name, sealed)
}

func gcmSeal(key []byte, name string, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(sealMagic), nonce...)
	return g.Seal(out, nonce, plain, []byte(name)), nil
}

func gcmOpen(key []byte, name string, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(sealed, []byte(sealMagic)) || len(sealed) < len(sealMagic)+g.NonceSize() {
		return nil, errors.New("the file is not a sealed sign-in")
	}
	rest := sealed[len(sealMagic):]
	plain, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], []byte(name))
	if err != nil {
		return nil, errors.New("it was sealed with another key")
	}
	return plain, nil
}

// secretToolStore keeps each sign-in in the Secret Service through
// secret-tool; the secret goes on stdin, never in arguments.
type secretToolStore struct {
	run cmdRunner
	bin string
}

func secretToolError(what string, exit int, stderr string) error {
	msg := fmt.Sprintf("the Secret Service could not %s (secret-tool exit %d", what, exit)
	if l := firstLine(stderr); l != "" {
		msg += ": " + l
	}
	return noKeychain(msg + "); it needs a running Secret Service such as GNOME Keyring in this session")
}

func (s *secretToolStore) Load(name string) (*Token, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	out, stderr, exit, err := s.run(ctx, nil, s.bin, "lookup", "service", keychainService, "account", name)
	if err != nil {
		return nil, noKeychain("the Secret Service cannot be used: " + err.Error())
	}
	if exit != 0 {
		if exit == 1 && strings.TrimSpace(stderr) == "" {
			return nil, nil // no such item
		}
		return nil, secretToolError("read the sign-in", exit, stderr)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var t Token
	if json.Unmarshal(out, &t) != nil {
		return nil, unreadable(name, "the keyring item is not valid")
	}
	return &t, nil
}

func (s *secretToolStore) Save(name string, t *Token) error {
	if err := ValidName(name); err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	_, stderr, exit, err := s.run(ctx, b, s.bin, "store", "--label=DefenseClaw substrate sign-in ("+name+")", "service", keychainService, "account", name)
	if err != nil {
		return noKeychain("the Secret Service cannot be used: " + err.Error())
	}
	if exit != 0 {
		return secretToolError("save the sign-in", exit, stderr)
	}
	return nil
}

func (s *secretToolStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	_, stderr, exit, err := s.run(ctx, nil, s.bin, "clear", "service", keychainService, "account", name)
	if err != nil {
		return noKeychain("the Secret Service cannot be used: " + err.Error())
	}
	if exit != 0 && strings.TrimSpace(stderr) != "" {
		return secretToolError("delete the sign-in", exit, stderr)
	}
	return nil
}

func (s *secretToolStore) Describe() string {
	return fmt.Sprintf("Secret Service via secret-tool (service %s)", keychainService)
}
