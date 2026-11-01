// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Clean-session mirror.
//
// On a Linux or macOS standalone host the gateway keeps every agent
// session's foreign-hook record in its private data directory, so a hook
// that cannot reach the gateway cannot tell a clean session from one that
// must stay blocked. The gateway therefore publishes, in a service-owned
// folder next to its data directory (managed.ForeignHookCleanDir), one small
// read-only entry per agent process and session key it answered allow for,
// while it holds the account's exchange lock. A denial of either key
// removes both entries first, and the hook guardian removes every entry of
// an account before it records a hook removal, so an entry never outlives
// the facts it was written from. The hook reads only the entry of its own
// agent process: a gateway outage under an administrator's open fail mode
// is then decided like for the other connectors (hookexec's managed outage
// path), and every other case keeps the refusal.
//
// Layout: <root>/<uid>/<kind>-<sha256(connector\0kind\0id)[:40]>.json, the
// root and each per-account folder 0711 and service-owned (accounts can open
// an entry by name but cannot list, create, rename or remove one), each
// entry 0644 and service-owned. Windows publishes none.

const (
	// ForeignHookCleanMirrorTTL is how long an entry stays valid after the
	// gateway wrote it.
	ForeignHookCleanMirrorTTL = 12 * time.Hour
	// foreignHookCleanMirrorLimit bounds one entry.
	foreignHookCleanMirrorLimit = 4 << 10
	// foreignHookCleanMirrorSkew is the clock skew allowed for written_at.
	foreignHookCleanMirrorSkew    = time.Minute
	foreignHookCleanMirrorVersion = 1
	// ForeignHookCleanMirrorTempPrefix starts the name of an entry the
	// gateway is still writing (it renames it into place); the lifecycle's
	// mode walk skips such a file.
	ForeignHookCleanMirrorTempPrefix = ".clean-"
)

// foreignHookCleanMirror is one entry.
type foreignHookCleanMirror struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	// Identity is the account's uid.
	Identity string `json:"identity"`
	// ProcessStarted is the agent process identity of the exchange
	// (internal/agentprocess: boot and start time with the process ID).
	ProcessStarted string `json:"process_started"`
	WrittenAt      string `json:"written_at"`
	ExpiresAt      string `json:"expires_at"`
	// StateHash is ForeignHookStateHash of the exchange's scan, for an
	// administrator who reads the entry; the hook does not use it.
	StateHash string `json:"state_hash"`
}

// ForeignHookCleanMirrorCheck names the entry a hook reads.
type ForeignHookCleanMirrorCheck struct {
	// Root is managed.ForeignHookCleanDir of the standalone data directory.
	Root string
	// ServiceUID is the gateway service account (the owner of the data
	// directory); root is always trusted too.
	ServiceUID int
	// CallerUID is the hook process's uid.
	CallerUID int
	Key       SessionKey
	Now       time.Time
}

// posixAccountUID returns identity as a uid when it is one.
func posixAccountUID(identity string) (string, bool) {
	identity = strings.TrimSpace(identity)
	if identity == "" || len(identity) > 10 {
		return "", false
	}
	uid, err := strconv.ParseUint(identity, 10, 32)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(uid, 10), true
}

// foreignHookCleanMirrorPath is the entry of one key kind and ID.
func foreignHookCleanMirrorPath(root, uid, connector, kind, id string) string {
	return sessionPathInDir(filepath.Join(root, uid), connector, kind, id)
}

// foreignHookCleanMirrorKeys lists the key kinds and IDs of key.
func foreignHookCleanMirrorKeys(key SessionKey) [][2]string {
	var out [][2]string
	if key.Process != "" {
		out = append(out, [2]string{sessionKindProcess, key.Process})
	}
	if key.Session != "" {
		out = append(out, [2]string{sessionKindSession, key.Session})
	}
	return out
}

func encodeForeignHookCleanMirror(uid string, key SessionKey, kind, id, state string, now time.Time) ([]byte, error) {
	data, err := json.Marshal(foreignHookCleanMirror{
		Version:        foreignHookCleanMirrorVersion,
		Connector:      key.Connector,
		Kind:           kind,
		ID:             id,
		Identity:       uid,
		ProcessStarted: key.Process,
		WrittenAt:      now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(ForeignHookCleanMirrorTTL).UTC().Format(time.RFC3339Nano),
		StateHash:      state,
	})
	if err != nil {
		return nil, err
	}
	if len(data) > foreignHookCleanMirrorLimit {
		return nil, errors.New("clean-session entry too large")
	}
	return data, nil
}

// decodeForeignHookCleanMirror decodes one entry strictly and checks it
// against the key of check: the process entry (kind p) names the process,
// the session entry (kind s) the session, and both the agent process.
func decodeForeignHookCleanMirror(data []byte, kind string, check ForeignHookCleanMirrorCheck) error {
	if len(data) > foreignHookCleanMirrorLimit {
		return errors.New("clean-session entry too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var entry foreignHookCleanMirror
	if err := decoder.Decode(&entry); err != nil {
		return fmt.Errorf("clean-session entry: %w", err)
	}
	if decoder.More() {
		return errors.New("clean-session entry: trailing data")
	}
	key := check.Key
	switch {
	case entry.Version != foreignHookCleanMirrorVersion:
		return errors.New("clean-session entry: unknown version")
	case entry.Connector != key.Connector || entry.Kind != kind ||
		(kind == sessionKindProcess && entry.ID != key.Process) || (kind == sessionKindSession && entry.ID != key.Session) ||
		(kind != sessionKindProcess && kind != sessionKindSession):
		return errors.New("clean-session entry: another key")
	case entry.ProcessStarted != key.Process:
		return errors.New("clean-session entry: another agent process")
	case entry.Identity != strconv.Itoa(check.CallerUID):
		return errors.New("clean-session entry: another account")
	}
	written, err := time.Parse(time.RFC3339Nano, entry.WrittenAt)
	if err != nil {
		return errors.New("clean-session entry: invalid written_at")
	}
	expires, err := time.Parse(time.RFC3339Nano, entry.ExpiresAt)
	if err != nil {
		return errors.New("clean-session entry: invalid expires_at")
	}
	now := check.Now
	if now.IsZero() {
		now = time.Now()
	}
	switch {
	case written.After(now.Add(foreignHookCleanMirrorSkew)):
		return errors.New("clean-session entry: written in the future")
	case !expires.After(written) || expires.Sub(written) > ForeignHookCleanMirrorTTL:
		return errors.New("clean-session entry: invalid lifetime")
	case !now.Before(expires):
		return errors.New("clean-session entry: expired")
	}
	return nil
}
