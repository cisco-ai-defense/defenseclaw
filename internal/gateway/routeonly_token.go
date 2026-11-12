// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// routeTokenHeader carries the route credential the connector setup renders
// into the agent configuration (DESIGN 17.5). It never leaves the gateway.
const routeTokenHeader = "X-DC-Route-Auth"

const routeTokenKeyName = ".route-token.key"

// routeTokenStore derives the per-connector route credential of an OSS
// per-user gateway from a key under <dataDir>/hooks (0600, created on first
// use). The credential is HMAC-SHA256(key, "defenseclaw.route.v1" 0
// connector 0 owner), so a gateway token change does not break model calls.
type routeTokenStore struct {
	dir   string
	owner string

	mu  sync.Mutex
	key []byte
}

func newRouteTokenStore(dataDir, owner string) *routeTokenStore {
	return &routeTokenStore{dir: filepath.Join(dataDir, "hooks"), owner: owner}
}

func (s *routeTokenStore) loadKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	path := filepath.Join(s.dir, routeTokenKeyName)
	if key, err := readRouteTokenKey(path); err == nil {
		s.key = key
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		// Another process created it first: use that key.
		key, rerr := readRouteTokenKey(path)
		if rerr == nil {
			s.key = key
		}
		return key, rerr
	}
	if err != nil {
		return nil, err
	}
	_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, werr
	}
	s.key = key
	return key, nil
}

func readRouteTokenKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("route token key %s is not valid", path)
	}
	return key, nil
}

// Token returns the route credential of connector.
func (s *routeTokenStore) Token(connector string) (string, error) {
	key, err := s.loadKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("defenseclaw.route.v1\x00" + connector + "\x00" + s.owner))
	return "dcr1-" + hex.EncodeToString(mac.Sum(nil)), nil
}

// Valid reports whether presented is the route credential of connector.
func (s *routeTokenStore) Valid(connector, presented string) bool {
	if s == nil || presented == "" {
		return false
	}
	want, err := s.Token(connector)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}
