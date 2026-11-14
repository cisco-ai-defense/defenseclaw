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
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// routeTokenHeader carries the route credential the connector setup renders
// into the agent configuration (DESIGN 17.5). It never leaves the gateway.
const routeTokenHeader = "X-DC-Route-Auth"

const (
	routeTokenKeyName     = ".route-token.key"
	routeTokenNextKeyName = ".route-token.key.next"
)

// routeOwner names the account a per-user gateway runs as: the uid on
// Linux and macOS, the user SID on Windows (os/user reports both as Uid).
func routeOwner() string {
	if u, err := user.Current(); err == nil && u.Uid != "" {
		return u.Uid
	}
	return fmt.Sprint(os.Getuid())
}

// routeTokenStore derives the per-connector route credential of an OSS
// per-user gateway from a private key under <dataDir>/hooks (safefile:
// 0600 and a user-only DACL on Windows). The credential is HMAC-SHA256(key,
// "defenseclaw.route.v1" 0 connector 0 owner), so a gateway token change
// does not break model calls. A staged .next key is accepted too (rotation,
// DESIGN 17.5); the keys are re-read when their files change.
type routeTokenStore struct {
	dir   string
	owner string

	mu      sync.Mutex
	key     []byte
	next    []byte
	stamp   string
	checked time.Time
}

func newRouteTokenStore(dataDir, owner string) *routeTokenStore {
	return &routeTokenStore{dir: filepath.Join(dataDir, "hooks"), owner: owner}
}

func readRouteKeyFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("route token key %s is not a regular file", path)
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return nil, fmt.Errorf("route token key %s is not private: %w", path, err)
	}
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

func fileStamp(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "-"
	}
	return fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())
}

// keys returns the current key (created on first use) and the staged next
// key (nil when none). The files are checked at most once a second.
func (s *routeTokenStore) keys() ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	main := filepath.Join(s.dir, routeTokenKeyName)
	next := filepath.Join(s.dir, routeTokenNextKeyName)
	if s.key != nil && time.Since(s.checked) < time.Second {
		return s.key, s.next, nil
	}
	stamp := fileStamp(main) + "|" + fileStamp(next)
	if s.key != nil && stamp == s.stamp {
		s.checked = time.Now()
		return s.key, s.next, nil
	}
	key, err := readRouteKeyFile(main)
	if errors.Is(err, os.ErrNotExist) {
		fresh := make([]byte, 32)
		if _, rerr := rand.Read(fresh); rerr != nil {
			return nil, nil, rerr
		}
		// safefile writes atomically (temp + rename), so a crash never
		// leaves a truncated key.
		if werr := safefile.WritePrivate(main, []byte(hex.EncodeToString(fresh)+"\n")); werr != nil {
			return nil, nil, werr
		}
		key, err = readRouteKeyFile(main)
	}
	if err != nil {
		return nil, nil, err
	}
	nextKey, nerr := readRouteKeyFile(next)
	if nerr != nil && !errors.Is(nerr, os.ErrNotExist) {
		return nil, nil, nerr
	}
	s.key, s.next, s.stamp, s.checked = key, nextKey, fileStamp(main)+"|"+fileStamp(next), time.Now()
	return s.key, s.next, nil
}

func (s *routeTokenStore) derive(key []byte, connector string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("defenseclaw.route.v1\x00" + connector + "\x00" + s.owner))
	return "dcr1-" + hex.EncodeToString(mac.Sum(nil))
}

// Token returns the route credential of connector (from the current key).
func (s *routeTokenStore) Token(connector string) (string, error) {
	key, _, err := s.keys()
	if err != nil {
		return "", err
	}
	return s.derive(key, connector), nil
}

// Valid reports whether presented is the route credential of connector
// under the current or the staged next key.
func (s *routeTokenStore) Valid(connector, presented string) bool {
	if s == nil || presented == "" {
		return false
	}
	key, next, err := s.keys()
	if err != nil {
		return false
	}
	for _, k := range [][]byte{key, next} {
		if k != nil && subtle.ConstantTimeCompare([]byte(s.derive(k, connector)), []byte(presented)) == 1 {
			return true
		}
	}
	return false
}

// reset drops the cached keys, so the next request reads the key files.
func (s *routeTokenStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key, s.next, s.stamp, s.checked = nil, nil, "", time.Time{}
}
