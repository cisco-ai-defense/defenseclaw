// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// A non-purge uninstall keeps the gateway state and the guardian ledger so a
// reinstall resumes with the same audit history and device identity. It
// records the identity of each directory it kept, so the next install
// recognizes its own retained state instead of refusing it as an unmanaged
// layout. A directory that was replaced, recreated or re-owned since then no
// longer matches and is still treated as foreign.
//
// Device and inode alone do not identify a directory over time: ext4 and
// XFS hand a freed inode number to the next directory created, so a
// directory deleted and recreated in its place can carry the recorded
// identity. Uninstall therefore also leaves a root-owned marker holding a
// fresh random value inside each kept directory and records only its hash;
// a recreated directory has no marker, and nobody but root can read one to
// copy it.
const (
	retainedStateFileName      = "retained-state.json"
	retainedStateSchemaVersion = 2
	retainedMarkerName         = ".defenseclaw-retained"
	retainedMarkerBytes        = 32
)

type retainedState struct {
	SchemaVersion int           `json:"schema_version"`
	RecordedAt    string        `json:"recorded_at"`
	Dirs          []retainedDir `json:"dirs"`
}

type retainedDir struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	UID   uint32 `json:"uid"`
	// MarkerSHA256 is the hash of the marker uninstall wrote in the directory.
	MarkerSHA256 string `json:"marker_sha256"`
}

func (e *Env) retainedStatePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), retainedStateFileName)
}

func retainedMarkerPath(dir string) string {
	return filepath.Join(dir, retainedMarkerName)
}

func directoryIdentity(path string) (retainedDir, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return retainedDir{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return retainedDir{}, false
	}
	return retainedDir{Dev: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: stat.Uid}, true //nolint:unconvert // Dev is int32 on darwin
}

// writeRetainedMarker replaces the marker in dir with a fresh random value
// and returns the value's hash.
func (e *Env) writeRetainedMarker(dir string) (string, error) {
	value := make([]byte, retainedMarkerBytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	data := []byte(hex.EncodeToString(value) + "\n")
	if err := e.writeFileAtomic(retainedMarkerPath(dir), data, 0o600, rootOwner()); err != nil {
		return "", err
	}
	return sha256Bytes(data), nil
}

// retainedMarkerSHA returns the hash of dir's marker when it is a regular,
// root-owned file.
func (e *Env) retainedMarkerSHA(dir string) (string, bool) {
	path := retainedMarkerPath(dir)
	data, err := readBounded(path, 4*retainedMarkerBytes)
	if err != nil {
		return "", false
	}
	uid, _, err := e.OwnerOf(path)
	if err != nil || uid != 0 {
		return "", false
	}
	return sha256Bytes(data), true
}

// clearRetainedState forgets what a non-purge uninstall kept, once a
// committed deployment owns that state again.
func (e *Env) clearRetainedState() {
	_ = removeFile(e.retainedStatePath())
	for _, dir := range []string{e.Layout.DataDir, e.Layout.GuardianAuthDir} {
		_ = removeFile(retainedMarkerPath(e.P(dir)))
	}
}

// recordRetainedState notes the non-empty state directories a non-purge
// uninstall leaves behind; with nothing kept it removes any stale record.
func (e *Env) recordRetainedState() error {
	state := retainedState{
		SchemaVersion: retainedStateSchemaVersion,
		RecordedAt:    e.Now().UTC().Format(time.RFC3339),
	}
	for _, dir := range []string{e.Layout.DataDir, e.Layout.GuardianAuthDir} {
		_ = removeFile(retainedMarkerPath(e.P(dir)))
		entries, err := os.ReadDir(e.P(dir))
		if err != nil || len(entries) == 0 {
			continue
		}
		identity, ok := directoryIdentity(e.P(dir))
		if !ok {
			continue
		}
		marker, err := e.writeRetainedMarker(e.P(dir))
		if err != nil {
			return err
		}
		identity.Path = dir
		identity.MarkerSHA256 = marker
		state.Dirs = append(state.Dirs, identity)
	}
	if len(state.Dirs) == 0 {
		return removeFile(e.retainedStatePath())
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.retainedStatePath(), append(data, '\n'), 0o600, rootOwner())
}

// loadRetainedState returns the directories the lifecycle kept, keyed by
// layout path. An unreadable, malformed or older record retains nothing.
func (e *Env) loadRetainedState() map[string]retainedDir {
	data, err := readBounded(e.retainedStatePath(), maxInputBytes)
	if err != nil {
		return nil
	}
	var state retainedState
	if err := decodeStrict(data, &state); err != nil || state.SchemaVersion != retainedStateSchemaVersion {
		return nil
	}
	out := make(map[string]retainedDir, len(state.Dirs))
	for _, dir := range state.Dirs {
		if dir.MarkerSHA256 == "" {
			continue
		}
		out[dir.Path] = dir
	}
	return out
}

// retainedByLifecycle reports whether dir is the same directory a previous
// non-purge uninstall recorded as kept: same device, inode and owner, and
// still holding the marker that uninstall wrote.
func (e *Env) retainedByLifecycle(dir string, retained map[string]retainedDir) bool {
	want, ok := retained[dir]
	if !ok {
		return false
	}
	got, ok := directoryIdentity(e.P(dir))
	if !ok || got.Dev != want.Dev || got.Inode != want.Inode || got.UID != want.UID {
		return false
	}
	marker, ok := e.retainedMarkerSHA(e.P(dir))
	return ok && marker == want.MarkerSHA256
}
