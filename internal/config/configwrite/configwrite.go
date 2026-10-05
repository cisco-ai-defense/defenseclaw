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

// Package configwrite is the single writer for config.yaml. Go and Python
// (cli/defenseclaw/config_writer.py) follow the same protocol on the same
// lock, so they interoperate:
//
//  1. Lock config.yaml.lock (O_RDWR|O_CREAT|O_NOFOLLOW, 0600): flock(LOCK_EX)
//     on POSIX, LockFileEx on byte 0 length 1 on Windows. Default timeout
//     DefaultLockTimeout; on timeout the error is ErrLockBusy.
//  2. Read the current bytes and their sha256; when Options.ExpectSHA256 is
//     set and differs, fail with ErrConflict (compare-and-swap).
//  3. Apply the changes as a node-level YAML patch that keeps comments and
//     order.
//  4. Validate the candidate bytes with the canonical validator (schema,
//     runtime semantics, guardrail profiles, asset digests) before writing.
//  5. Write a temp file in the same directory, fsync, rename over the
//     config (MoveFileExW on Windows), fsync the directory. A failed
//     directory fsync is an error.
//  6. Write config.generation.json (GenerationState) the same way, with the
//     generation incremented.
//  7. Release the lock and audit config.change.applied.
//
// Both writers refuse when the host is StandaloneEnterprise() and the actor
// is not ActorLifecycle or ActorMigration. Under SecureClientIntegration()
// nothing changes.
package configwrite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// LockSuffix is appended to the config path for the writer lock; it is
	// the same file Python's locked_config_yaml uses.
	LockSuffix = ".lock"
	// GenerationFileName is the writer's state file, next to config.yaml.
	GenerationFileName = "config.generation.json"
	// DefaultLockTimeout bounds the wait for another writer.
	DefaultLockTimeout = 10 * time.Second
)

// Actors that may write on a managed (StandaloneEnterprise) host.
const (
	ActorMigration = "migration"
	ActorLifecycle = "lifecycle"
)

// Actor prefixes; the suffix is the OS user, token principal or decision ID.
const (
	ActorPrefixCLI      = "cli:"
	ActorPrefixTUI      = "tui:"
	ActorPrefixAPI      = "api:"
	ActorPrefixSandbox  = "sandbox:"
	ActorPrefixHandEdit = "hand-edit:"
)

var (
	// ErrConflict means config.yaml changed after the caller read it.
	ErrConflict = errors.New("configwrite: config.yaml changed since it was read")
	// ErrLockBusy means another writer held the lock past the timeout.
	ErrLockBusy = errors.New("configwrite: another DefenseClaw process is changing config.yaml")
	// ErrManaged means the host is managed and the actor may not write.
	ErrManaged = errors.New("configwrite: this device is managed; policy changes are made in the management plane")
	// ErrNotImplemented is returned until the writer lands.
	ErrNotImplemented = errors.New("configwrite: not implemented yet")
)

// Change is one edit. Path is dotted, with [i] for list items, for example
// asset_policy.skill.denied[0].name. Unset removes the key; Value is then
// ignored.
type Change struct {
	Path  string
	Value any
	Unset bool
}

// Options describe who writes and why.
type Options struct {
	// Actor is ActorMigration, ActorLifecycle or a prefixed actor such as
	// "cli:alice".
	Actor string
	// Reason is a short human sentence recorded in the generation file.
	Reason string
	// ExpectSHA256 is the hex sha256 of the bytes the caller read; empty
	// skips the compare-and-swap check.
	ExpectSHA256 string
	// Timeout bounds the lock wait; zero means DefaultLockTimeout.
	Timeout time.Duration
}

// Result describes a committed write.
type Result struct {
	// Generation is the new config_generation.
	Generation uint64
	// SHA256 is the hex sha256 of the written bytes.
	SHA256 string
	// Changed lists the dotted paths whose value changed.
	Changed []string
	// RestartRequired lists the changed paths that need a gateway restart.
	RestartRequired []string
}

// GenerationState is config.generation.json.
type GenerationState struct {
	// Generation is monotonic; a writer that finds the file missing or
	// corrupt starts from max(previous+1, 1) and sets GenerationReset.
	Generation   uint64 `json:"generation"`
	ConfigSHA256 string `json:"config_sha256"`
	Actor        string `json:"actor"`
	Reason       string `json:"reason,omitempty"`
	// WrittenAt is RFC 3339 UTC.
	WrittenAt       string `json:"written_at"`
	GenerationReset bool   `json:"generation_reset,omitempty"`
}

// Apply edits config.yaml at path under the writer lock and returns the new
// generation.
func Apply(ctx context.Context, path string, changes []Change, opt Options) (Result, error) {
	_, _, _, _ = ctx, path, changes, opt
	return Result{}, ErrNotImplemented
}

// ReplaceDocument writes raw as the whole config.yaml at path under the
// writer lock, after the same validation. Migrations and restores use it.
func ReplaceDocument(ctx context.Context, path string, raw []byte, opt Options) (Result, error) {
	_, _, _, _ = ctx, path, raw, opt
	return Result{}, ErrNotImplemented
}

// LockPath returns the writer lock path for a config path.
func LockPath(configPath string) string { return configPath + LockSuffix }

// GenerationPath returns the config.generation.json path for a config path.
func GenerationPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), GenerationFileName)
}

// ReadGenerationState reads config.generation.json next to configPath. A
// missing file returns os.ErrNotExist (wrapped).
func ReadGenerationState(configPath string) (GenerationState, error) {
	raw, err := os.ReadFile(GenerationPath(configPath))
	if err != nil {
		return GenerationState{}, err
	}
	var state GenerationState
	if err := json.Unmarshal(raw, &state); err != nil {
		return GenerationState{}, fmt.Errorf("configwrite: decode %s: %w", GenerationFileName, err)
	}
	return state, nil
}
