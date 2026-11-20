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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store keeps sign-ins by context name. Load returns nil, nil when there
// is none; Delete of a missing entry is not an error. Describe names the
// backend and never shows a secret.
type Store interface {
	Load(name string) (*Token, error)
	Save(name string, t *Token) error
	Delete(name string) error
	Describe() string
}

// OpenStore opens the OS keychain store: the macOS Keychain, Windows
// DPAPI, or the Linux Secret Service through secret-tool. It never falls
// back silently: with no usable keychain it fails and names
// DEFENSECLAW_SUBSTRATE_TOKEN_STORE=file, which selects a 0600 file store
// under the state directory.
func OpenStore() (Store, error) { return openStore(os.Getenv(EnvTokenStore)) }

func openStore(mode string) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "file":
		return &fileStore{dir: tokenDir()}, nil
	case "", "auto", "keychain":
		return osStore()
	default:
		return nil, fmt.Errorf("%s=%q is not known; use keychain (the default) or file", EnvTokenStore, mode)
	}
}

func noKeychain(why string) error {
	return fmt.Errorf("%s; or set %s=file to keep the sign-in in a file readable only by you under %s", why, EnvTokenStore, tokenDir())
}

const storeTimeout = 30 * time.Second

// cmdRunner runs a helper (security, secret-tool). exit is the exit code;
// err is set only when the helper could not run.
type cmdRunner func(ctx context.Context, stdin []byte, name string, args ...string) (stdout []byte, stderr string, exit int, err error)

// firstLine is a short, printable first line of a helper's stderr.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clean(s, 160)
}

func unreadable(name, why string) error {
	return fmt.Errorf("the saved sign-in for %q cannot be read (%s); %s", name, why, loginHint)
}

// fileStore keeps one 0600 JSON file per context (selected only by
// DEFENSECLAW_SUBSTRATE_TOKEN_STORE=file).
type fileStore struct{ dir string }

func (f *fileStore) path(name string) string { return filepath.Join(f.dir, name+".json") }

func (f *fileStore) Load(name string) (*Token, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, unreadable(name, "the file cannot be opened")
	}
	var t Token
	if json.Unmarshal(b, &t) != nil {
		return nil, unreadable(name, "the file is not valid JSON")
	}
	return &t, nil
}

func (f *fileStore) Save(name string, t *Token) error {
	if err := ValidName(name); err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return writeFileAtomic(f.path(name), b)
}

func (f *fileStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := os.Remove(f.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete the saved sign-in: %w", err)
	}
	return nil
}

func (f *fileStore) Describe() string {
	return fmt.Sprintf("file %s (%s=file; protected by file permissions only)", f.dir, EnvTokenStore)
}

// sealer encrypts a sign-in for one context name.
type sealer interface {
	seal(name string, plain []byte) ([]byte, error)
	open(name string, sealed []byte) ([]byte, error)
}

// sealedStore keeps one sealed file per context; the key lives in the OS
// keychain (macOS) or the user's DPAPI key (Windows).
type sealedStore struct {
	dir  string
	s    sealer
	desc string
}

func (f *sealedStore) path(name string) string { return filepath.Join(f.dir, name+".sealed") }

func (f *sealedStore) Load(name string) (*Token, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, unreadable(name, "the file cannot be opened")
	}
	plain, err := f.s.open(name, b)
	if err != nil {
		return nil, unreadable(name, err.Error())
	}
	var t Token
	if json.Unmarshal(plain, &t) != nil {
		return nil, unreadable(name, "the content is not valid")
	}
	return &t, nil
}

func (f *sealedStore) Save(name string, t *Token) error {
	if err := ValidName(name); err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	sealed, err := f.s.seal(name, b)
	if err != nil {
		return err
	}
	return writeFileAtomic(f.path(name), sealed)
}

func (f *sealedStore) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if err := os.Remove(f.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete the saved sign-in: %w", err)
	}
	return nil
}

func (f *sealedStore) Describe() string { return f.desc }
