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
	// securityTool is the macOS Security command-line tool. It is always
	// run by this absolute path, never looked up on PATH.
	securityTool  = "/usr/bin/security"
	macKeyAccount = "token-key"
	macKeyLabel   = "defenseclaw-substrate-token-key"
	macNotFound   = 44 // errSecItemNotFound as the security tool exits
	sealMagic     = "DCS1"

	// macNativeAccount is the key item the launcher writes with the
	// Security framework itself (GAP-0165). It trusts the DefenseClaw
	// binary, so reads ask nothing; macKeyAccount is the earlier item,
	// written through the security tool, read once to move the key.
	macNativeAccount = "launcher-key"

	// OSStatus values of the Security framework.
	secItemNotFound           = -25300
	secDuplicateItem          = -25299
	secAuthFailed             = -25293
	secInteractionNotAllowed  = -25308
	secUserCanceled           = -128
	secNoSuchKeychain         = -25294
	secDefaultKeychainMissing = -25307
)

// nativeKeychain is the Security framework calls the launcher needs: find
// and add one generic password of the default keychain. An item added this
// way trusts the calling program (the launcher binary).
type nativeKeychain interface {
	find(service, account string) ([]byte, int32)
	add(service, account string, secret []byte) int32
}

// nativeStatusError says what an OSStatus means for the person.
func nativeStatusError(what string, st int32) error {
	switch st {
	case secInteractionNotAllowed, secAuthFailed:
		return noKeychain("the macOS keychain is locked and this session cannot ask you to unlock it (for example over SSH); unlock it with: security unlock-keychain")
	case secUserCanceled:
		return noKeychain("you declined the macOS keychain request; run the command again and allow DefenseClaw")
	case secNoSuchKeychain, secDefaultKeychainMissing:
		return noKeychain("this account has no default macOS keychain")
	}
	return noKeychain(fmt.Sprintf("the macOS keychain could not %s (status %d)", what, st))
}

// macKeySealer seals sign-ins with AES-256-GCM under a random key kept as
// a generic password in the default (normally the login) macOS keychain.
// The key is written by "security -i" with the command on stdin, so it
// never appears in a process list; the tokens themselves never pass
// through the security tool. Limits: a locked keychain, or a session that
// cannot show the keychain prompt (SSH with no screen), makes the security
// tool fail; the error says so and names the file store.
type macKeySealer struct {
	run cmdRunner
	// native, when set (darwin), keeps the key with the Security framework;
	// nil uses the security tool only.
	native nativeKeychain

	mu  sync.Mutex
	key []byte
}

func newMacStore(run cmdRunner, dir string) *sealedStore {
	return &sealedStore{
		dir: dir,
		s:   &macKeySealer{run: run},
		desc: fmt.Sprintf("sealed files in %s (mode 0600), encrypted with a key kept in your macOS default keychain "+
			"(item service %s, account %s); the item trusts no application, so macOS asks you before any program, "+
			"DefenseClaw included, reads the key, unless you answered Always Allow, which lets any program you run read it with %s",
			dir, keychainService, macKeyAccount, securityTool),
	}
}

func macError(what string, exit int, stderr string) error {
	msg := fmt.Sprintf("the macOS keychain could not %s (security exit %d", what, exit)
	if l := firstLine(stderr); l != "" {
		msg += ": " + l
	}
	msg += "); unlock it with: security unlock-keychain, and allow DefenseClaw when macOS asks"
	return noKeychain(msg)
}

func (m *macKeySealer) findKey(ctx context.Context) ([]byte, error) {
	out, stderr, exit, err := m.run(ctx, nil, securityTool, "find-generic-password", "-s", keychainService, "-a", macKeyAccount, "-w")
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

// macAddKeyLine is the "security -i" command that stores the key.
//
// Trusted applications: security(1) documents "-T appPath" (an application
// that may access the item; repeatable) and "-A" (any application, no
// warning). With neither, the item trusts the application that creates
// it, which here is /usr/bin/security itself, so any program running as
// this user could read the key without a prompt with "security
// find-generic-password -w". "-T" with an empty path gives an empty
// trusted-application list: no application is trusted, and macOS asks the
// user before any program, DefenseClaw included, reads the key (once per
// launcher process; the key is then held in memory). Answering Always
// Allow at that prompt trusts /usr/bin/security again; that is the
// user's choice, and Describe says so.
func macAddKeyLine(hexKey string) string {
	return fmt.Sprintf("add-generic-password -U -s %s -a %s -l %s -T \"\" -w %s\n", keychainService, macKeyAccount, macKeyLabel, hexKey)
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
	if m.native != nil {
		key, err := m.nativeKey(ctx, create)
		if err == nil {
			m.key = key
		}
		return key, err
	}
	key, err := m.findKey(ctx)
	if err != nil || key != nil || !create {
		m.key = key
		return key, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	_, stderr, exit, err := m.run(ctx, []byte(macAddKeyLine(hex.EncodeToString(key))), securityTool, "-i")
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

// nativeKey reads the key from the launcher's own item. When that item is
// missing it moves a key written by an earlier version through the
// security tool (one macOS prompt, once), or makes a new key when create
// is set. Called with m.mu held.
func (m *macKeySealer) nativeKey(ctx context.Context, create bool) ([]byte, error) {
	raw, st := m.native.find(keychainService, macNativeAccount)
	switch st {
	case 0:
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("the keychain item %s/%s is not a DefenseClaw key; delete it with: security delete-generic-password -s %s -a %s", keychainService, macNativeAccount, keychainService, macNativeAccount)
		}
		return key, nil
	case secItemNotFound:
	default:
		return nil, nativeStatusError("read the DefenseClaw key", st)
	}
	legacy, err := m.findKey(ctx)
	if err != nil && !create {
		return nil, err
	}
	key := legacy
	if key == nil {
		if !create {
			return nil, nil
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	if st := m.native.add(keychainService, macNativeAccount, []byte(hex.EncodeToString(key))); st != 0 && st != secDuplicateItem {
		if legacy != nil {
			return legacy, nil // the old item still works; the move is tried again next time
		}
		return nil, nativeStatusError("store the DefenseClaw key", st)
	}
	got, st := m.native.find(keychainService, macNativeAccount)
	if st != 0 || strings.TrimSpace(string(got)) != hex.EncodeToString(key) {
		if legacy != nil {
			return legacy, nil
		}
		return nil, nativeStatusError("store the DefenseClaw key", st)
	}
	if legacy != nil {
		// The key now lives in the launcher's item; the old one, which
		// asked on every read, goes (best effort).
		_, _, _, _ = m.run(ctx, nil, securityTool, "delete-generic-password", "-s", keychainService, "-a", macKeyAccount)
	}
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
