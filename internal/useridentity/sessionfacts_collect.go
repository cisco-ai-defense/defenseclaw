// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The hook's claimed session facts.
//
// A hook runs once per agent event, so the facts are cached. On Linux and
// macOS the cache is ~/.defenseclaw/session-facts.json, kept for five
// minutes and keyed by the inputs that would change the answer (KRB5CCNAME,
// the credential cache's modification time, and the SSH and logind session
// variables): a new kinit or a new login is picked up at once. Windows reads
// its logon session in-process and needs no file.

// SessionFactsCacheTTL is how long the hook reuses its cached facts.
const SessionFactsCacheTTL = 5 * time.Minute

// SessionFactsCacheFileName is the cache file under ~/.defenseclaw.
const SessionFactsCacheFileName = "session-facts.json"

const maxSessionFactsCacheBytes = 4 << 10

type sessionFactsCacheFile struct {
	Key       string    `json:"key"`
	WrittenAt time.Time `json:"written_at"`
	Header    string    `json:"header"`
}

var (
	sessionFactsOnce   sync.Once
	sessionFactsHeader string
)

// CurrentSessionFactsHeader returns the X-DefenseClaw-Session-Facts value
// for the calling process's session, or "" when nothing resolved. Call it
// only from a process that runs as the end user (a hook). The answer is
// computed once per process.
func CurrentSessionFactsHeader() string {
	sessionFactsOnce.Do(func() {
		sessionFactsHeader = currentSessionFactsHeader(time.Now())
	})
	return sessionFactsHeader
}

// cachedSessionFactsHeader returns the cached header for key from path, or
// ok=false when the cache is missing, stale, keyed differently or invalid.
func cachedSessionFactsHeader(path, key string, now time.Time) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSessionFactsCacheBytes {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var cached sessionFactsCacheFile
	if json.Unmarshal(data, &cached) != nil || cached.Key != key {
		return "", false
	}
	age := now.Sub(cached.WrittenAt)
	if age < 0 || age >= SessionFactsCacheTTL {
		return "", false
	}
	if cached.Header != "" {
		if _, ok := ParseSessionFactsHeader(cached.Header); !ok {
			return "", false
		}
	}
	return cached.Header, true
}

// writeSessionFactsCache replaces the cache atomically, owner-only. Errors
// are ignored by the caller: the cache is an optimisation.
func writeSessionFactsCache(path, key, header string, now time.Time) error {
	data, err := json.Marshal(sessionFactsCacheFile{Key: key, WrittenAt: now.UTC(), Header: header})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".session-facts-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Chmod(0o600)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
