// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package vault keeps one person's credentials for their sandboxes.
//
// A vault entry is a secret value bound to the one host it may be sent to.
// When a sandbox starts with the entry, the value goes into an OpenShell
// provider bound to that host; the agent inside the sandbox sees only a
// placeholder, and OpenShell swaps the real value in on the way out to the
// bound host. The vault never returns a value to a caller that only lists
// or shows entries: values are written in and read out only to build a
// sandbox credential (Resolve) or to compare (FindByValue).
//
// The vault lives in the account's own DefenseClaw state directory and is
// written only by processes running as that account (the CLI, the per-user
// gateway, the per-user sandbox daemon). It is one JSON file, mode 0600, in
// a 0700 directory. The sandbox cannot see it: it is never mounted into a
// sandbox. It is not encrypted at rest: anyone who can read files as this
// account can read it, as they can read the shell environment the
// --credential flag takes values from.
package vault

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	// FileName is the vault file inside the vault directory.
	FileName = "vault.json"
	// lockName serializes writers (the CLI and the gateway or daemon).
	lockName = "vault.lock"
	// DirName is the vault directory inside a DefenseClaw state directory.
	DirName = "vault"

	// MaxEntries bounds the vault. A sandbox takes at most 16 credentials.
	MaxEntries = 64
	// MaxValueBytes is the largest value a sandbox credential accepts.
	MaxValueBytes = 16 << 10
	// maxFileBytes bounds the vault file read.
	maxFileBytes = 4 << 20

	fileVersion = 1
)

// Source says how an entry got into the vault.
type Source string

const (
	// SourceManual is an entry the person added.
	SourceManual Source = "manual"
	// SourceCaptured is an entry DefenseClaw took out of a sandboxed
	// agent's prompt or tool call.
	SourceCaptured Source = "captured"
)

// Status is an entry's state as people see it.
type Status string

const (
	// StatusReady: bound to a host, never seen by a model.
	StatusReady Status = "ready"
	// StatusNeedsHost: no host yet, so no sandbox can use it.
	StatusNeedsHost Status = "needs_host"
	// StatusExposed: an agent's model may have seen the value before it
	// was captured; rotate it with the issuer and replace the value.
	StatusExposed Status = "exposed"
)

var (
	// ErrNotFound is returned for an entry name the vault does not hold.
	ErrNotFound = errors.New("no such secret in the vault")
	// ErrExists is returned when adding a name the vault already holds.
	ErrExists = errors.New("the vault already holds a secret with this name")
	// ErrNoHost is returned when resolving an entry with no host.
	ErrNoHost = errors.New("the secret has no host yet")
	// ErrFull is returned when the vault holds MaxEntries entries.
	ErrFull = fmt.Errorf("the vault holds %d secrets, the most it keeps", MaxEntries)
	// ErrExposed is returned when resolving an entry an agent's model may
	// have seen: it must be rotated and replaced before a sandbox uses it.
	ErrExposed = errors.New("an agent's model may have seen this secret's value")
	// ErrBusy is returned when another process holds the vault lock.
	ErrBusy = errors.New("another DefenseClaw process is writing the vault")
)

// Entry is one secret's metadata. It never carries the value.
type Entry struct {
	Name         string     `json:"name"`
	Host         string     `json:"host,omitempty"`
	Port         int        `json:"port,omitempty"`
	Source       Source     `json:"source"`
	Kind         string     `json:"kind,omitempty"`
	Exposed      bool       `json:"exposed,omitempty"`
	CapturedFrom string     `json:"captured_from,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedBy   string     `json:"last_used_by,omitempty"`
	UseCount     int        `json:"use_count,omitempty"`
}

// Status is the entry's state as people see it.
func (e Entry) Status() Status {
	switch {
	case e.Exposed:
		return StatusExposed
	case e.Host == "":
		return StatusNeedsHost
	default:
		return StatusReady
	}
}

// Target is "host" for port 443 and "host:port" otherwise, or "" with no host.
func (e Entry) Target() string {
	if e.Host == "" {
		return ""
	}
	if e.Port == 0 || e.Port == 443 {
		return e.Host
	}
	return e.Host + ":" + strconv.Itoa(e.Port)
}

// record is an entry as it is kept on disk, value included.
type record struct {
	Entry
	Value string `json:"value"`
}

type file struct {
	Version int      `json:"version"`
	Entries []record `json:"entries"`
}

// Store is one account's vault.
type Store struct {
	dir string
	now func() time.Time
}

// Open returns the vault in dir. The directory is created on first write.
func Open(dir string) *Store {
	return &Store{dir: filepath.Clean(dir), now: time.Now}
}

// Dir is the vault directory.
func (s *Store) Dir() string { return s.dir }

// Path is the vault file.
func (s *Store) Path() string { return filepath.Join(s.dir, FileName) }

// DirIn is the vault directory inside a DefenseClaw state directory.
func DirIn(stateDir string) string { return filepath.Join(stateDir, DirName) }

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ValidName checks an entry name: an environment variable name, because the
// sandbox exposes the secret under that name.
func ValidName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%q is not a valid name: use letters, digits and _ and start with a letter or _ (it becomes an environment variable in the sandbox)", name)
	}
	if strings.HasPrefix(strings.ToUpper(name), "DEFENSECLAW_") || strings.HasPrefix(strings.ToUpper(name), "OPENSHELL_") {
		return fmt.Errorf("%q is reserved for DefenseClaw and OpenShell", name)
	}
	return nil
}

// ValidValue checks a secret value: what a sandbox credential accepts.
func ValidValue(value string) error {
	switch {
	case value == "":
		return errors.New("the value is empty")
	case len(value) > MaxValueBytes:
		return fmt.Errorf("the value is longer than %d bytes", MaxValueBytes)
	case strings.ContainsAny(value, "\x00\r\n"):
		return errors.New("the value has a line break or NUL; a sandbox credential is one line")
	case strings.TrimSpace(value) != value:
		return errors.New("the value starts or ends with spaces; paste only the secret")
	}
	return nil
}

var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ParseHost reads "host" or "host:port", the only place a secret may be
// sent. It refuses URLs, paths, user info and wildcards; a host is
// lowercased and loses a trailing dot; no port means 443.
func ParseHost(s string) (string, int, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return "", 0, errors.New("the host is empty")
	}
	if strings.Contains(in, "://") || strings.ContainsAny(in, "/*@ ?#") {
		return "", 0, fmt.Errorf("%q is not a host: give only a name such as api.stripe.com or api.example.com:8443", s)
	}
	host, port := in, 443
	if i := strings.LastIndex(in, ":"); i >= 0 {
		host = in[:i]
		p, err := strconv.Atoi(in[i+1:])
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("%q has no valid port", s)
		}
		port = p
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) > 253 || !hostPattern.MatchString(host) {
		return "", 0, fmt.Errorf("%q is not a DNS host name", s)
	}
	if !strings.Contains(host, ".") && host != "localhost" {
		return "", 0, fmt.Errorf("%q is not a full host name (for example api.stripe.com)", s)
	}
	return host, port, nil
}

// List returns every entry, sorted by name, without values.
func (s *Store) List() ([]Entry, error) {
	f, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(f.Entries))
	for _, r := range f.Entries {
		out = append(out, r.Entry)
	}
	return out, nil
}

// Get returns one entry without its value.
func (s *Store) Get(name string) (Entry, error) {
	f, err := s.read()
	if err != nil {
		return Entry{}, err
	}
	if i := f.index(name); i >= 0 {
		return f.Entries[i].Entry, nil
	}
	return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, name)
}

// Resolve returns an entry and its value, to build a sandbox credential.
// An entry with no host cannot be used.
func (s *Store) Resolve(name string) (Entry, string, error) {
	f, err := s.read()
	if err != nil {
		return Entry{}, "", err
	}
	i := f.index(name)
	if i < 0 {
		return Entry{}, "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	r := f.Entries[i]
	if r.Exposed {
		// A value an agent produced or saw is never handed to a sandbox: it
		// may be the agent's own (a token it planted under a real API's
		// name) or a leaked one. The person rotates it and replaces it.
		return r.Entry, "", fmt.Errorf("%w: %s; rotate it with its issuer, then: defenseclaw sandbox vault replace %s", ErrExposed, name, name)
	}
	if r.Host == "" {
		return r.Entry, "", fmt.Errorf("%w: %s (bind one with: defenseclaw sandbox vault bind %s --host HOST)", ErrNoHost, name, name)
	}
	return r.Entry, r.Value, nil
}

// FindByValue returns the entry that holds value, if any.
func (s *Store) FindByValue(value string) (Entry, bool, error) {
	f, err := s.read()
	if err != nil {
		return Entry{}, false, err
	}
	if i := f.indexValue(value); i >= 0 {
		return f.Entries[i].Entry, true, nil
	}
	return Entry{}, false, nil
}

// AddInput is a new entry.
type AddInput struct {
	Name         string
	Value        string
	Host         string // "host" or "host:port"; empty leaves the entry unbound
	Source       Source
	Kind         string
	Exposed      bool
	CapturedFrom string
}

// Add stores a new entry. It refuses a name the vault holds.
func (s *Store) Add(in AddInput) (Entry, error) {
	if err := ValidName(in.Name); err != nil {
		return Entry{}, err
	}
	if err := ValidValue(in.Value); err != nil {
		return Entry{}, err
	}
	host, port := "", 0
	if strings.TrimSpace(in.Host) != "" {
		var err error
		if host, port, err = ParseHost(in.Host); err != nil {
			return Entry{}, err
		}
	}
	src := in.Source
	if src == "" {
		src = SourceManual
	}
	var added Entry
	err := s.update(func(f *file) error {
		if f.index(in.Name) >= 0 {
			return fmt.Errorf("%w: %s (replace its value with: defenseclaw sandbox vault replace %s)", ErrExists, in.Name, in.Name)
		}
		if j := f.indexValue(in.Value); j >= 0 {
			return fmt.Errorf("the vault already holds this value as %s", f.Entries[j].Name)
		}
		if len(f.Entries) >= MaxEntries {
			return ErrFull
		}
		now := s.now().UTC()
		r := record{Entry: Entry{
			Name: in.Name, Host: host, Port: port, Source: src, Kind: in.Kind,
			Exposed: in.Exposed, CapturedFrom: in.CapturedFrom, CreatedAt: now, UpdatedAt: now,
		}, Value: in.Value}
		f.Entries = append(f.Entries, r)
		added = r.Entry
		return nil
	})
	return added, err
}

// ReplaceValue sets a new value. A replaced value is a fresh one: the entry
// is no longer marked exposed.
func (s *Store) ReplaceValue(name, value string) (Entry, error) {
	if err := ValidValue(value); err != nil {
		return Entry{}, err
	}
	var out Entry
	err := s.update(func(f *file) error {
		i := f.index(name)
		if i < 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		if j := f.indexValue(value); j >= 0 && j != i {
			return fmt.Errorf("the vault already holds this value as %s", f.Entries[j].Name)
		}
		if f.Entries[i].Exposed && f.indexValue(value) == i {
			// Only a new value lifts the exposure: the same one may have
			// been seen by an agent's model.
			return fmt.Errorf("%w: %s still holds that value; rotate it with its issuer and paste the new one", ErrExposed, name)
		}
		f.Entries[i].Value = value
		f.Entries[i].Exposed = false
		f.Entries[i].UpdatedAt = s.now().UTC()
		out = f.Entries[i].Entry
		return nil
	})
	return out, err
}

// Bind sets the host an entry may be sent to.
func (s *Store) Bind(name, target string) (Entry, error) {
	host, port, err := ParseHost(target)
	if err != nil {
		return Entry{}, err
	}
	var out Entry
	err = s.update(func(f *file) error {
		i := f.index(name)
		if i < 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		f.Entries[i].Host, f.Entries[i].Port = host, port
		f.Entries[i].UpdatedAt = s.now().UTC()
		out = f.Entries[i].Entry
		return nil
	})
	return out, err
}

// Rename gives an entry a new name.
func (s *Store) Rename(name, newName string) (Entry, error) {
	if err := ValidName(newName); err != nil {
		return Entry{}, err
	}
	var out Entry
	err := s.update(func(f *file) error {
		i := f.index(name)
		if i < 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		if j := f.index(newName); j >= 0 && j != i {
			return fmt.Errorf("%w: %s", ErrExists, newName)
		}
		f.Entries[i].Name = newName
		f.Entries[i].UpdatedAt = s.now().UTC()
		out = f.Entries[i].Entry
		return nil
	})
	return out, err
}

// Remove deletes an entry. Removing a missing entry is ErrNotFound.
func (s *Store) Remove(name string) error {
	return s.update(func(f *file) error {
		i := f.index(name)
		if i < 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		f.Entries[i].Value = ""
		f.Entries = append(f.Entries[:i], f.Entries[i+1:]...)
		return nil
	})
}

// MarkUsed records that a sandbox started with the named entries.
func (s *Store) MarkUsed(names []string, by string) error {
	if len(names) == 0 {
		return nil
	}
	return s.update(func(f *file) error {
		now := s.now().UTC()
		for _, n := range names {
			if i := f.index(n); i >= 0 {
				t := now
				f.Entries[i].LastUsedAt = &t
				f.Entries[i].LastUsedBy = by
				f.Entries[i].UseCount++
			}
		}
		return nil
	})
}

func (f *file) index(name string) int {
	for i := range f.Entries {
		if f.Entries[i].Name == name {
			return i
		}
	}
	return -1
}

func (f *file) indexValue(value string) int {
	if value == "" {
		return -1
	}
	want := sha256.Sum256([]byte(value))
	found := -1
	for i := range f.Entries {
		got := sha256.Sum256([]byte(f.Entries[i].Value))
		if subtle.ConstantTimeCompare(want[:], got[:]) == 1 && found < 0 {
			found = i
		}
	}
	return found
}

func (s *Store) read() (*file, error) {
	b, err := safefile.ReadRegularFileBounded(s.Path(), maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return &file{Version: fileVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the vault %s: %w", s.Path(), err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("the vault %s is not valid; move it aside to start a new one", s.Path())
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("the vault %s has version %d, which this DefenseClaw does not read", s.Path(), f.Version)
	}
	return &f, nil
}

// update reads, changes and writes the vault under the writer lock.
func (s *Store) update(change func(*file) error) error {
	return s.updateWait(lockWait, change)
}

// updateWait is update with a bounded wait for the writer lock.
func (s *Store) updateWait(wait time.Duration, change func(*file) error) error {
	if err := safefile.ProtectDirectory(s.dir); err != nil {
		return fmt.Errorf("prepare the vault directory %s: %w", s.dir, err)
	}
	unlock, err := lockDir(s.dir, wait)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.read()
	if err != nil {
		return err
	}
	if err := change(f); err != nil {
		return err
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].Name < f.Entries[j].Name })
	f.Version = fileVersion
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := safefile.Write(s.Path(), append(b, '\n')); err != nil {
		return fmt.Errorf("write the vault %s: %w", s.Path(), err)
	}
	return nil
}
