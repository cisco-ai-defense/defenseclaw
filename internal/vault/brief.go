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
	"fmt"
	"os"
	"time"
)

// SealWait bounds each keystore call of a seal on the way to a sandbox
// (`sandbox run`, `start`, `connect`): a keystore that does not answer by
// then leaves the vault a file for this command instead of stalling it.
const SealWait = 2 * time.Second

// Briefly returns s for a seal on the way to a sandbox. A keystore call that
// takes longer than wait fails, which leaves a file vault a file as a
// keystore that cannot keep the key does, and the Secret Service is not
// tried at all from a session that names no D-Bus session bus (an SSH login
// may still have a bus socket whose Secret Service never answers). Vault
// changes keep the full wait: they are what the person asked for. With
// EnvStore=keychain s itself is returned: the person asked for a sealed
// vault, so the command waits for the keystore as a vault change does.
func (s *Store) Briefly(wait time.Duration) *Store {
	if s.keys == nil || Required() {
		return s
	}
	keys := s.keys
	b := Open(s.dir)
	b.now = s.now
	b.keys = func() (Keystore, string, error) {
		ks, why, err := keys()
		if err != nil || ks == nil || isRequired(ks) {
			return ks, why, err
		}
		if ks.ID() == keystoreSecretService && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			return nil, "the Secret Service is not tried on the way to a sandbox from a session with no DBUS_SESSION_BUS_ADDRESS; a vault change still tries it", nil
		}
		return boundKeys(ks, wait), "", nil
	}
	return b
}

// timed is a keystore whose own calls can be bounded (the Secret Service
// ends secret-tool at the bound instead of leaving it running).
type timed interface {
	within(time.Duration) Keystore
}

// bounded fails a keystore call that takes longer than wait. The call
// itself may finish later: a key it then returns is cleared, and a key it
// saved stays unused, as a key from a lost seal race does.
type bounded struct {
	Keystore
	wait time.Duration
}

func boundKeys(ks Keystore, wait time.Duration) Keystore {
	if t, ok := ks.(timed); ok {
		ks = t.within(wait)
	}
	return bounded{Keystore: ks, wait: wait}
}

func (b bounded) late() error {
	return fmt.Errorf("your %s did not answer within %s", b.Name(), b.wait)
}

func (b bounded) Load(keyID string) ([]byte, error) {
	type loaded struct {
		raw []byte
		err error
	}
	ch := make(chan loaded, 1)
	go func() {
		raw, err := b.Keystore.Load(keyID)
		ch <- loaded{raw, err}
	}()
	timer := time.NewTimer(b.wait)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.raw, r.err
	case <-timer.C:
		go func() { clear((<-ch).raw) }()
		return nil, b.late()
	}
}

func (b bounded) Save(keyID string, key []byte) error {
	// The caller clears key when this returns; the call keeps its own copy.
	own := append([]byte(nil), key...)
	ch := make(chan error, 1)
	go func() {
		defer clear(own)
		ch <- b.Keystore.Save(keyID, own)
	}()
	timer := time.NewTimer(b.wait)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-timer.C:
		return b.late()
	}
}

func (b bounded) Delete(keyID string) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Keystore.Delete(keyID)
	}()
	timer := time.NewTimer(b.wait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}
