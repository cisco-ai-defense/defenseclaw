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
// sandbox.
//
// Sealed: when the CLI can use an OS keystore (the macOS Keychain, the
// Linux Secret Service), each value is encrypted to the vault's public key
// and the private key stays in the keystore (seal.go). Otherwise, or with
// DEFENSECLAW_VAULT_STORE=file, the values are kept in the file as they
// are, not encrypted: anyone who can read files as this account can read
// them, as they can read the shell environment the --credential flag takes
// values from. A file vault is sealed by the next CLI change once a
// keystore works; a sealed vault is never written back as a file.
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
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	// FileName is the vault file inside the vault directory.
	FileName = "vault.json"
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
	// agent's prompt, tool call or tool output.
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
	// StatusUnconfirmed: captured from a sandbox and not yet confirmed by
	// the person. A sandbox can post its own prompt-shaped hook call, so a
	// captured value may be one the agent planted; no sandbox gets it until
	// the person confirms it (or replaces the value).
	StatusUnconfirmed Status = "unconfirmed"
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
	// ErrUnconfirmed is returned when resolving a captured entry the person
	// has not confirmed.
	ErrUnconfirmed = errors.New("this secret was captured from a sandbox and is not confirmed yet")
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
	// Confirmed: the person confirmed a captured entry is theirs (vault
	// confirm) or replaced its value. Manual entries need no confirmation.
	Confirmed bool `json:"confirmed,omitempty"`
	// FromModel: captured where an agent's model wrote or read the value (a
	// tool call, a tool's output), not from a person's prompt; until the
	// person replaces the value it counts toward the model-side bound
	// (its sandbox's, or MaxCapturedFromModel when no sandbox is named).
	FromModel bool `json:"from_model,omitempty"`
	// Sandbox is the sandbox a captured entry came from, when known.
	Sandbox string `json:"sandbox,omitempty"`
}

// Status is the entry's state as people see it.
func (e Entry) Status() Status {
	switch {
	case e.Exposed:
		return StatusExposed
	case e.Source == SourceCaptured && !e.Confirmed:
		return StatusUnconfirmed
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

// record is an entry as it is kept on disk: with its value in a file
// vault, with its sealed value (and maybe a fingerprint) in a sealed one.
// In memory Value is the value once known: read from a file vault, opened
// with the key, or newly set.
type record struct {
	Entry
	Value  string `json:"value,omitempty"`
	Sealed string `json:"sealed,omitempty"`
	FP     string `json:"fp,omitempty"`

	// sealedFor is what Sealed was sealed for (name, host, port) when it
	// was read: a value this process did not open cannot be moved.
	sealedFor string
}

type file struct {
	Version int         `json:"version"`
	Seal    *sealHeader `json:"seal,omitempty"`
	Entries []record    `json:"entries"`

	// sealer is the parsed Seal header (nil: a file vault).
	sealer *sealer
	// pending is what the pending exposures did to Entries when the vault
	// was read (applyPending).
	pending pendingState
}

// Store is one account's vault.
type Store struct {
	dir string
	now func() time.Time
	// keys reaches the keystore; nil: this store never does.
	keys func() (Keystore, string, error)

	mu     sync.Mutex
	notice string
	// key is the sealed vault's key once read (a CLI process reads it once).
	key *sealer
}

// Open returns the vault in dir for a process that never reads the OS
// keystore: the per-user gateway and sandbox daemon on the hook path. It
// keeps a file vault a file and seals what it writes into a sealed vault
// with the vault's public key; it cannot open sealed values. The directory
// is created on first write.
func Open(dir string) *Store {
	return &Store{dir: filepath.Clean(dir), now: time.Now}
}

// OpenWithKeystore returns the vault in dir for the CLI: it reads the
// private key from the OS keystore DEFENSECLAW_VAULT_STORE selects, and
// seals a file vault on its next change when that keystore works.
func OpenWithKeystore(dir string) *Store {
	s := Open(dir)
	s.keys = keysFromEnv
	return s
}

// OpenWith is OpenWithKeystore with a given keystore (nil: none usable).
func OpenWith(dir string, ks Keystore) *Store {
	s := Open(dir)
	s.keys = func() (Keystore, string, error) {
		if ks == nil {
			return nil, "no keystore is usable", nil
		}
		return ks, "", nil
	}
	return s
}

// Notice is what the last change of this store has to tell the person
// about how the vault is kept ("" when nothing), then forgets it.
func (s *Store) Notice() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.notice
	s.notice = ""
	return n
}

func (s *Store) setNotice(n string) {
	s.mu.Lock()
	s.notice = n
	s.mu.Unlock()
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
	if r.Source == SourceCaptured && !r.Confirmed {
		return r.Entry, "", fmt.Errorf("%w: %s; check it is yours, then: defenseclaw sandbox vault confirm %s", ErrUnconfirmed, name, name)
	}
	if r.Host == "" {
		return r.Entry, "", fmt.Errorf("%w: %s (bind one with: defenseclaw sandbox vault bind %s --host HOST)", ErrNoHost, name, name)
	}
	v := r.Value
	if f.sealer != nil {
		if err := s.readKey(f); err != nil {
			return r.Entry, "", err
		}
		if v, err = f.sealer.open(&r); err != nil {
			return r.Entry, "", s.damaged(err.Error())
		}
	}
	if f.pendingExposes(v) {
		// Recorded exposed while the vault could not be written.
		r.Exposed = true
		return r.Entry, "", fmt.Errorf("%w: %s; rotate it with its issuer, then: defenseclaw sandbox vault replace %s", ErrExposed, name, name)
	}
	return r.Entry, v, nil
}

// FindByValue returns the entry that holds value, if any. In a sealed vault
// a store that reads the keystore opens every value; one that does not
// finds only captured-shape values (by fingerprint).
func (s *Store) FindByValue(value string) (Entry, bool, error) {
	f, err := s.read()
	if err != nil {
		return Entry{}, false, err
	}
	if f.sealer != nil && s.keys != nil {
		if err := s.readKey(f); err != nil {
			return Entry{}, false, err
		}
		if err := s.openAll(f); err != nil {
			return Entry{}, false, err
		}
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
	err := s.update(needValues, func(f *file) error {
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
	err := s.update(needValues, func(f *file) error {
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
		// The person typed this value: it is theirs.
		f.Entries[i].Confirmed = true
		f.Entries[i].UpdatedAt = s.now().UTC()
		out = f.Entries[i].Entry
		return nil
	})
	return out, err
}

// Confirm marks a captured entry as the person's own. An exposed entry
// cannot be confirmed: its value must be rotated and replaced. Hint is the
// last 4 characters of the value, for the person to recognise it.
func (s *Store) Confirm(name string) (Entry, error) {
	var out Entry
	err := s.update(needNothing, func(f *file) error {
		i := f.index(name)
		if i < 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		if f.Entries[i].Exposed {
			return fmt.Errorf("%w: %s; rotate it with its issuer and replace it (defenseclaw sandbox vault replace %s)", ErrExposed, name, name)
		}
		f.Entries[i].Confirmed = true
		f.Entries[i].UpdatedAt = s.now().UTC()
		out = f.Entries[i].Entry
		return nil
	})
	return out, err
}

// Hint returns the last 4 characters of an entry's value (for a person to
// recognise a captured secret before confirming it), or "" for a short one.
func (s *Store) Hint(name string) (string, error) {
	f, err := s.read()
	if err != nil {
		return "", err
	}
	i := f.index(name)
	if i < 0 {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	v := f.Entries[i].Value
	if f.sealer != nil {
		// A sealed value is opened with the keystore key (the CLI only).
		if err := s.readKey(f); err != nil {
			return "", err
		}
		r := f.Entries[i]
		if v, err = f.sealer.open(&r); err != nil {
			return "", s.damaged(err.Error())
		}
	}
	if len(v) < 16 {
		return "", nil
	}
	return v[len(v)-4:], nil
}

// Bind sets the host an entry may be sent to.
func (s *Store) Bind(name, target string) (Entry, error) {
	host, port, err := ParseHost(target)
	if err != nil {
		return Entry{}, err
	}
	var out Entry
	err = s.update(needValues, func(f *file) error {
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
	err := s.update(needValues, func(f *file) error {
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
	return s.update(needNothing, func(f *file) error {
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
	return s.update(needNothing, func(f *file) error {
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

// indexValue finds the entry holding value: by the value itself where it
// is known, else by fingerprint (a sealed vault this process cannot open).
func (f *file) indexValue(value string) int {
	if value == "" {
		return -1
	}
	want := sha256.Sum256([]byte(value))
	fp := ""
	if f.sealer != nil {
		fp = f.sealer.fingerprint(value)
	}
	found := -1
	for i := range f.Entries {
		r := &f.Entries[i]
		match := false
		switch {
		case r.Value != "":
			got := sha256.Sum256([]byte(r.Value))
			match = subtle.ConstantTimeCompare(want[:], got[:]) == 1
		case fp != "" && r.FP != "":
			match = subtle.ConstantTimeCompare([]byte(fp), []byte(r.FP)) == 1
		}
		if match && found < 0 {
			found = i
		}
	}
	return found
}

func (s *Store) read() (*file, error) {
	b, err := readStable(s.Path(), maxFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		// Pending exposures can name a value no vault holds yet.
		f := &file{Version: fileVersion}
		if err := s.applyPending(f); err != nil {
			return nil, err
		}
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the vault %s: %w", s.Path(), err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("the vault %s is not valid; move it aside to start a new one", s.Path())
	}
	switch f.Version {
	case fileVersion:
		if f.Seal != nil {
			return nil, s.damaged("a version 1 vault has a seal header")
		}
		for i := range f.Entries {
			if f.Entries[i].Value == "" || f.Entries[i].Sealed != "" || f.Entries[i].FP != "" {
				return nil, fmt.Errorf("the vault %s is not valid; move it aside to start a new one", s.Path())
			}
		}
	case sealedVersion:
		sl, err := parseHeader(f.Seal)
		if err != nil {
			return nil, s.damaged(err.Error())
		}
		for i := range f.Entries {
			r := &f.Entries[i]
			if r.Value != "" {
				return nil, s.damaged("it holds a value that is not sealed")
			}
			if r.Sealed == "" {
				return nil, s.damaged("an entry has no sealed value")
			}
			r.sealedFor = sl.infoOf(r)
		}
		f.sealer = sl
	default:
		return nil, fmt.Errorf("the vault %s has version %d, which this DefenseClaw does not read", s.Path(), f.Version)
	}
	if err := s.applyPending(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// need says what a change needs of a sealed vault.
type need int

const (
	// needNothing: names and metadata only; new values are sealed with
	// the public key.
	needNothing need = iota
	// needValues: every value open (to compare or to re-seal), so the key.
	needValues
	// needSeal: nothing changes; a file vault is written only when this
	// change seals it (Seal).
	needSeal
)

// update reads, changes and writes the vault under the writer lock.
func (s *Store) update(n need, change func(*file) error) error {
	return s.updateWait(lockWait, n, change)
}

// errUnchanged is what a change returns when it changed nothing: the
// vault is not written.
var errUnchanged = errors.New("the vault is unchanged")

// updateWait is update with a bounded wait for the writer lock. Keystore
// work happens before the lock is taken: a keychain prompt or a slow
// Secret Service never holds the lock a hook call waits on.
func (s *Store) updateWait(wait time.Duration, n need, change func(*file) error) error {
	if err := safefile.ProtectDirectory(s.dir); err != nil {
		return fmt.Errorf("prepare the vault directory %s: %w", s.dir, err)
	}
	p, err := s.prepare(n, change)
	if err != nil {
		return err
	}
	unlock, err := lockDir(s.dir, wait)
	if err != nil {
		p.discard()
		return err
	}
	defer unlock()
	f, err := s.read()
	// The pin is checked against the vault as read: a writer that did not
	// read the key (the gateway, the sandbox daemon, a CLI change that
	// needs no value) writes nothing into a vault whose seal is not the
	// pinned one, or that was sealed and is now a plain file or gone.
	var pu pinUpdate
	var pinErr error
	if err == nil {
		// fresh: apply seals this plain (or missing) vault with the new
		// key. keyed: apply opens it with the key prepare checked against
		// this header (or fails the change).
		fresh := f.sealer == nil && p.fresh
		keyed := f.sealer != nil && n == needValues && s.keys != nil
		pu, pinErr = s.checkPin(f, fresh, keyed)
	}
	if err == nil {
		err = p.apply(f, n)
	}
	if err == nil && n == needSeal && !p.fresh {
		// No key was made, or another process sealed the vault meanwhile:
		// nothing is written.
		p.done(f)
		return nil
	}
	if err == nil {
		err = pinErr
	}
	if err == nil {
		err = change(f)
		if err == nil || errors.Is(err, errUnchanged) {
			// A pending exposure of a value this change stored is
			// written with it.
			f.applyOpenPending()
		}
		if errors.Is(err, errUnchanged) {
			if !p.fresh && !f.pending.changed {
				// Nothing to write: the vault on disk is f as read, and
				// the pin was checked against it.
				p.done(f)
				pu.apply(s, f)
				s.dropPending(f)
				return nil
			}
			// A new key seals the vault, or a pending exposure is
			// written: that is a change to write.
			err = nil
		}
	}
	var b []byte
	if err == nil {
		sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].Name < f.Entries[j].Name })
		b, err = s.encode(f)
	}
	if err == nil {
		if werr := safefile.Write(s.Path(), append(b, '\n')); werr != nil {
			err = fmt.Errorf("write the vault %s: %w", s.Path(), werr)
		}
	}
	if err != nil {
		p.discard()
		return err
	}
	p.done(f)
	pu.apply(s, f)
	s.dropPending(f)
	return nil
}
